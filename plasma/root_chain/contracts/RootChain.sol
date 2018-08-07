pragma solidity ^0.4.22;

import "./SafeMath.sol";
import "./Math.sol";
import "./PlasmaRLP.sol";
import "./Merkle.sol";
import "./Validate.sol";
import "./PriorityQueue.sol";


/**
 * @title RootChain
 * @dev This contract secures a utxo payments plasma child chain to ethereum.
 */
contract RootChain {
    using SafeMath for uint;
    using Merkle for bytes32;
    using PlasmaRLP for bytes;

    event DepositMade(address indexed depositor, uint indexed depositBlock, address token, uint amount);
    event ExitStarted(address indexed exitor, uint indexed utxoPos, address token, uint amount);
    event BlockSubmitted(bytes32 root, uint timestamp);
    event TokenAdded(address token);
    
    address public operator;
    uint public constant CHILD_BLOCK_INTERVAL = 1000;
    uint public currentChildBlock;
    uint public currentDepositBlock;
    uint public currentFeeExit;

    mapping (uint => ChildBlock) public childChain;
    mapping (uint => Exit) public exits;
    mapping (address => address) public exitsQueues;

    struct Exit {
        address owner;
        address token;
        uint amount;
    }

    struct ChildBlock {
        bytes32 root;
        uint timestamp;
    }

    modifier onlyOperator() {
        require(msg.sender == operator);
        _;
    }

    constructor () public {
        operator = msg.sender;
        currentChildBlock = CHILD_BLOCK_INTERVAL;
        currentDepositBlock = 1;
        currentFeeExit = 1;
        // Support only ETH on deployment; other tokens need to be added explicitly.
        exitsQueues[address(0)] = address(new PriorityQueue());
    }
    
    /**
     * @dev Allows Plasma chain operator to submit block root.
     * @param _root The root of a child chain block.
     */
    function submitBlock(bytes32 _root) public onlyOperator {   
        childChain[currentChildBlock] = ChildBlock({
            root: _root,
            timestamp: block.timestamp
        });

        // Update block numbers.
        currentChildBlock = currentChildBlock.add(CHILD_BLOCK_INTERVAL);
        currentDepositBlock = 1;

        emit BlockSubmitted(_root, block.timestamp);
    }

    /**
     * @dev Allows anyone to deposit funds into the Plasma chain.
     */
    function deposit() public payable {
        // Only allow up to CHILD_BLOCK_INTERVAL deposits per child block.
        require(currentDepositBlock < CHILD_BLOCK_INTERVAL);

        bytes32 root = keccak256(msg.sender, address(0), msg.value);
        uint depositBlock = getDepositBlock();
        childChain[depositBlock] = ChildBlock({
            root: root,
            timestamp: block.timestamp
        });
        currentDepositBlock = currentDepositBlock.add(1);

        emit DepositMade(msg.sender, depositBlock, address(0), msg.value);
    }

    /**
     * @dev Starts an exit from a deposit.
     * @param _depositPos UTXO position of the deposit.
     * @param _token Token type to deposit.
     * @param _amount Deposit amount.
     */
    function startDepositExit(uint _depositPos, address _token, uint _amount) public {
        uint blknum = _depositPos / 1000000000;

        // Check that the given UTXO is a deposit.
        require(blknum % CHILD_BLOCK_INTERVAL != 0);

        // Validate the given owner and amount.
        bytes32 root = childChain[blknum].root;
        bytes32 depositHash = keccak256(msg.sender, _token, _amount);
        require(root == depositHash);

        addExitToQueue(_depositPos, msg.sender, _token, _amount, childChain[blknum].timestamp);
    }

    /**
     * @dev Allows the operator withdraw any allotted fees. Starts an exit to avoid theft.
     * @param _token Token to withdraw.
     * @param _amount Amount in fees to withdraw.
     */
    function startFeeExit(address _token, uint _amount) public onlyOperator {
        addExitToQueue(currentFeeExit, msg.sender, _token, _amount, block.timestamp + 1);
        currentFeeExit = currentFeeExit.add(1);
    }

    /**
     * @dev Starts to exit a specified utxo.
     * @param _utxoPos Position of exiting utxo in format blknum * 10^9 + index * 10^4 + oindex.
     * @param _txBytes The transaction being exited in RLP bytes format.
     * @param _proof Proof of exiting transactions inclusion for the block specified by utxoPos.
     * @param _sigs Both transaction signatures and confirmations
        signatures used to verify that the exiting transaction has been confirmed.
     */
    function startExit(uint _utxoPos, bytes _txBytes, bytes _proof, bytes _sigs) public {
        uint blknum = _utxoPos / 1000000000;
        uint txindex = (_utxoPos % 1000000000) / 10000;
        uint oindex = _utxoPos - blknum * 1000000000 - txindex * 10000; 

        // Check the sender owns this UTXO.
        var exitingTx = _txBytes.createExitingTx(oindex);
        require(msg.sender == exitingTx.exitor);

        // Check the transaction was included in the chain and is correctly signed.
        bytes32 root = childChain[blknum].root; 
        bytes32 merkleHash = keccak256(keccak256(_txBytes), ByteUtils.slice(_sigs, 0, 130));
        require(Validate.checkSigs(keccak256(_txBytes), root, exitingTx.inputCount, _sigs));
        require(merkleHash.checkMembership(txindex, root, _proof));

        addExitToQueue(_utxoPos, exitingTx.exitor, exitingTx.token, exitingTx.amount, childChain[blknum].timestamp);
    }

    /**
     * @dev Allows anyone to challenge an exiting transaction by submitting proof of a double spend on the child chain.
     * @param _cUtxoPos The position of the challenging utxo.
     * @param _eUtxoIndex The output position of the exiting utxo.
     * @param _txBytes The challenging transaction in bytes RLP form.
     * @param _proof Proof of inclusion for the transaction used to challenge.
     * @param _sigs Signatures for the transaction used to challenge.
     * @param _confirmationSig The confirmation signature for the transaction used to challenge.
     */
    function challengeExit(
        uint _cUtxoPos,
        uint _eUtxoIndex,
        bytes _txBytes,
        bytes _proof,
        bytes _sigs,
        bytes _confirmationSig
    )
        public
    {
        uint eUtxoPos = _txBytes.getUtxoPos(_eUtxoIndex);
        uint txindex = (_cUtxoPos % 1000000000) / 10000;
        bytes32 root = childChain[_cUtxoPos / 1000000000].root;
        var txHash = keccak256(_txBytes);
        var confirmationHash = keccak256(txHash, root);
        var merkleHash = keccak256(txHash, _sigs);
        address owner = exits[eUtxoPos].owner;

        // Validate the spending transaction.
        require(owner == ECRecovery.recover(confirmationHash, _confirmationSig));
        require(merkleHash.checkMembership(txindex, root, _proof));

        // Delete the owner but keep the amount to prevent another exit.
        delete exits[eUtxoPos].owner;
    }

    /**
     * @dev Processes any exits that have completed the challenge period. 
     * @param _token Token type to process.
     */
    function finalizeExits(address _token) public {
        uint utxoPos;
        uint exitableAt;
        (utxoPos, exitableAt) = getNextExit(_token);
        Exit memory currentExit = exits[utxoPos];
        PriorityQueue queue = PriorityQueue(exitsQueues[_token]);
        while (exitableAt < block.timestamp) {
            currentExit = exits[utxoPos];

            // FIXME: handle ERC-20 transfer
            require(address(0) == _token);

            currentExit.owner.transfer(currentExit.amount);
            queue.delMin();
            delete exits[utxoPos].owner;

            if (queue.currentSize() > 0) {
                (utxoPos, exitableAt) = getNextExit(_token);
            } else {
                return;
            }
        }
    }

    /**
     * @dev Queries the child chain.
     * @param _blockNumber Number of the block to return.
     * @return Child chain block at the specified block number.
     */
    function getChildChain(uint _blockNumber) public view returns (bytes32, uint) {
        return (childChain[_blockNumber].root, childChain[_blockNumber].timestamp);
    }

    /**
     * @dev Determines the next deposit block number.
     * @return Block number to be given to the next deposit block.
     */
    function getDepositBlock() public view returns (uint) {
        return currentChildBlock.sub(CHILD_BLOCK_INTERVAL).add(currentDepositBlock);
    }

    /**
     * @dev Returns information about an exit.
     * @param _utxoPos Position of the UTXO in the chain.
     * @return A tuple representing the active exit for the given UTXO.
     */
    function getExit(uint _utxoPos)  public  view  returns (address, address, uint) {
        return (exits[_utxoPos].owner, exits[_utxoPos].token, exits[_utxoPos].amount);
    }

    /**
     * @dev Determines the next exit to be processed.
     * @param _token Asset type to be exited.
     * @return A tuple of the position and time when this exit can be processed.
     */
    function getNextExit(address _token) public view returns (uint, uint) {
        uint priority = PriorityQueue(exitsQueues[_token]).getMin();
        uint utxoPos = uint(uint128(priority));
        uint exitableAt = priority >> 128;
        return (utxoPos, exitableAt);
    }
    
    /**
     * @dev Adds an exit to the exit queue.
     * @param _utxoPos Position of the UTXO in the child chain.
     * @param _exitor Owner of the UTXO.
     * @param _token Token to be exited.
     * @param _amount Amount to be exited.
     * @param _createdAt Time when the UTXO was created.
     */
    function addExitToQueue(
        uint _utxoPos,
        address _exitor,
        address _token,
        uint _amount,
        uint _createdAt
    )
        private
    {
        // Check that we're exiting a known token.
        require(exitsQueues[_token] != address(0));

        // Calculate priority.
        uint exitableAt = Math.max(_createdAt + 2 weeks, block.timestamp + 1 weeks);
        uint priority = exitableAt << 128 | _utxoPos;
        
        // Check exit is valid and doesn't already exist.
        require(_amount > 0);
        require(exits[_utxoPos].amount == 0);

        PriorityQueue queue = PriorityQueue(exitsQueues[_token]);
        queue.insert(priority);

        exits[_utxoPos] = Exit({
            owner: _exitor,
            token: _token,
            amount: _amount
        });

        emit ExitStarted(msg.sender, _utxoPos, _token, _amount);
    }
}
