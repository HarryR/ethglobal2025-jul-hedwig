// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

/**
 * @title DestinationHTLC
 * @dev Hash Time Lock Contract for cross-chain atomic swaps
 * @notice Allows resolvers to lock funds that users can claim by revealing a secret
 * @notice This contract is completely trustless - no admin functions or backdoors
 */
contract DestinationHTLC {
    
    // ============ Events ============
    
    event HTLCCreated(
        bytes32 indexed secretHash,
        address indexed userAddress,
        address indexed resolverAddress,
        uint256 amount,
        uint256 deadline
    );
    
    event SecretRevealed(
        bytes32 indexed secretHash,
        bytes32 secret,
        address indexed userAddress,
        uint256 amount
    );
    
    event HTLCRefunded(
        bytes32 indexed secretHash,
        address indexed resolverAddress,
        uint256 amount
    );
    
    // ============ Errors ============
    
    error HTLCNotFound();
    error HTLCNotExpired();
    error HTLCAlreadyClaimed();
    error HTLCDuplicateExists();
    error InvalidDeadline();
    error InsufficientAmount();
    error TransferFailed();
    error InvalidUserAddress();
    
    // ============ Structs ============
    
    struct HTLC {
        address userAddress;        // Who can claim the funds
        address resolverAddress;    // Who deposited the funds
        uint256 amount;            // Amount locked
        uint256 deadline;          // When the lock expires
        bool claimed;              // Whether funds have been claimed/refunded
    }
    
    // ============ State Variables ============
    
    /// @dev Mapping from secret hash to HTLC data
    mapping(bytes32 => HTLC) public htlcs;
    
    // ============ Constructor ============
    
    constructor() {
        // No initialization needed - completely trustless contract
    }
    
    // ============ External Functions ============
    
    /**
     * @notice Create a new HTLC by depositing ETH
     * @param secretHash Hash of the secret that unlocks the funds
     * @param userAddress Address that can claim the funds by revealing the secret
     * @param deadline Unix timestamp when the lock expires
     */
    function createHTLC(
        bytes32 secretHash,
        address userAddress,
        uint256 deadline
    ) external payable {
        // Validate inputs
        if (msg.value == 0) revert InsufficientAmount();
        if (userAddress == address(0)) revert InvalidUserAddress();
        if (htlcs[secretHash].userAddress != address(0)) revert HTLCDuplicateExists();
        
        // Validate deadline
        if (deadline <= block.timestamp) revert InvalidDeadline();
        
        // Create HTLC
        htlcs[secretHash] = HTLC({
            userAddress: userAddress,
            resolverAddress: msg.sender,
            amount: msg.value,
            deadline: deadline,
            claimed: false
        });
        
        emit HTLCCreated(secretHash, userAddress, msg.sender, msg.value, deadline);
    }
    
    /**
     * @notice Reveal the secret to claim funds (gasless for user!)
     * @dev Anyone can call this function, making it gasless for the actual user
     * @param secret The preimage of the secret hash
     */
    function revealSecret(bytes32 secret) external {
        bytes32 secretHash = sha256(abi.encodePacked(secret));
        
        if (htlcs[secretHash].userAddress == address(0)) revert HTLCNotFound();
        
        HTLC storage htlc = htlcs[secretHash];
        
        if (htlc.claimed) revert HTLCAlreadyClaimed();
        
        // Mark as claimed first (CEI pattern)
        htlc.claimed = true;
        
        // Transfer funds to user
        uint256 amount = htlc.amount;
        address userAddress = htlc.userAddress;
        
        (bool success, ) = payable(userAddress).call{value: amount}("");
        if (!success) revert TransferFailed();
        
        emit SecretRevealed(secretHash, secret, userAddress, amount);
    }
    
    /**
     * @notice Claim refund after the deadline has passed
     * @param secretHash Hash of the secret for the HTLC to refund
     */
    function claimRefund(bytes32 secretHash) external {
        if (htlcs[secretHash].userAddress == address(0)) revert HTLCNotFound();
        
        HTLC storage htlc = htlcs[secretHash];
        
        if (htlc.claimed) revert HTLCAlreadyClaimed();
        if (block.timestamp < htlc.deadline) revert HTLCNotExpired();
        
        // Mark as claimed first (CEI pattern)
        htlc.claimed = true;
        
        // Transfer funds back to resolver
        uint256 amount = htlc.amount;
        address resolverAddress = htlc.resolverAddress;
        
        (bool success, ) = payable(resolverAddress).call{value: amount}("");
        if (!success) revert TransferFailed();
        
        emit HTLCRefunded(secretHash, resolverAddress, amount);
    }
    
    // ============ View Functions ============
    
    /**
     * @notice Get HTLC information
     * @param secretHash Hash of the secret
     * @return userAddress Address that can claim the funds
     * @return resolverAddress Address that deposited the funds
     * @return amount Amount locked in the HTLC
     * @return deadline When the lock expires
     * @return claimed Whether the HTLC has been claimed or refunded
     */
    function getHTLCInfo(bytes32 secretHash) 
        external 
        view 
        returns (
            address userAddress,
            address resolverAddress,
            uint256 amount,
            uint256 deadline,
            bool claimed
        ) 
    {
        if (htlcs[secretHash].userAddress == address(0)) revert HTLCNotFound();
        
        HTLC storage htlc = htlcs[secretHash];
        return (
            htlc.userAddress,
            htlc.resolverAddress,
            htlc.amount,
            htlc.deadline,
            htlc.claimed
        );
    }
    
    /**
     * @notice Check if an HTLC exists for a given secret hash
     * @param secretHash Hash of the secret
     * @return exists True if the HTLC exists
     */
    function doesHTLCExist(bytes32 secretHash) external view returns (bool) {
        return htlcs[secretHash].userAddress != address(0);
    }
    
    /**
     * @notice Hash a secret using SHA256
     * @param secret The secret to hash
     * @return Hash of the secret
     */
    function hashSecret(bytes32 secret) external pure returns (bytes32) {
        return sha256(abi.encodePacked(secret));
    }
    
    /**
     * @notice Check if an HTLC is claimable (not claimed and not expired)
     * @param secretHash Hash of the secret
     * @return claimable True if the HTLC can be claimed
     */
    function isClaimable(bytes32 secretHash) external view returns (bool) {
        HTLC storage htlc = htlcs[secretHash];
        return htlc.userAddress != address(0) && !htlc.claimed && block.timestamp < htlc.deadline;
    }
    
    /**
     * @notice Check if an HTLC is refundable (not claimed and expired)
     * @param secretHash Hash of the secret
     * @return refundable True if the HTLC can be refunded
     */
    function isRefundable(bytes32 secretHash) external view returns (bool) {
        HTLC storage htlc = htlcs[secretHash];
        return htlc.userAddress != address(0) && !htlc.claimed && block.timestamp >= htlc.deadline;
    }
}
