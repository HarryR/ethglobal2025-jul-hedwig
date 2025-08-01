// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import { ECDSA } from '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';

contract SourceHTLC {
    // Error constants
    error InsufficientBalance();
    error EscrowNotFound();
    error EscrowAlreadyResolved();
    error OrderExpired();
    error InvalidSecret();
    error NotAuthorized();
    error TimeoutNotReached();
    error InvalidOrderHash();
    error WrongDestinationChain();
    error WrongDestinationToken();
    error WrongDestinationAmount();
    error WrongDestinationAddress();
    error InvalidUserSignature();
    error InvalidResolverSignature();
    error InvalidArbitratorSignature();
    error DuplicateOrder();

    // Escrow status constants
    uint8 constant STATUS_ACTIVE = 0;
    uint8 constant STATUS_RESOLVED = 1;

    // EIP-712 Domain
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(address userAddress,address resolverAddress,uint256 userAmount,uint256 resolverAmount,address venueAddress,uint256 venueFee,address arbitratorAddress,uint256 arbitratorAttentionFee,uint256 arbitratorUsageFee,bytes32 secretHash,uint256 submissionDeadline,uint256 resolverActionDeadline,bytes32 destinationChain,bytes destinationAddress,bytes destinationToken,uint256 destinationAmount)"
    );

    bytes32 public constant ARBITRATOR_DECISION_TYPEHASH = keccak256(
        "ArbitratorDecision(uint8 decision,bytes32 secretHash,uint256 deadline,bytes32 destinationChain,bytes destinationToken,uint256 destinationAmount,bytes destinationAddress)"
    );

    bytes32 public immutable DOMAIN_SEPARATOR;

    struct Order {
        address userAddress;
        address resolverAddress;
        uint256 userAmount;
        uint256 resolverAmount;
        address venueAddress;
        uint256 venueFee;
        address arbitratorAddress;
        uint256 arbitratorAttentionFee;
        uint256 arbitratorUsageFee;
        bytes32 secretHash;
        uint256 submissionDeadline;
        uint256 resolverActionDeadline;
        bytes32 destinationChain;
        bytes destinationAddress;
        bytes destinationToken;
        uint256 destinationAmount;
    }

    struct ArbitratorDecision {
        bool decision;
        bytes32 secretHash;
        uint256 deadline;
        bytes32 destinationChain;
        bytes destinationToken;
        uint256 destinationAmount;
        bytes destinationAddress;
    }

    // State variables
    mapping(address => uint256) public resolverBalances;
    mapping(bytes32 => Order) public activeEscrows;

    // Events
    event OrderVerified(
        bytes32 indexed orderHash,
        address indexed userAddress,
        address indexed resolverAddress,
        address arbitratorAddress,
        uint256 timestamp
    );

    event EscrowCreated(bytes32 indexed orderHash, uint256 timestamp);
    event EscrowResolved(bytes32 indexed orderHash, string resolution);

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("SourceHTLC"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    // Helper function to recover address from signature (compressed format)
    function recoverSigner(bytes32 digest, bytes32 r, bytes32 vs)
        internal pure
        returns (address)
    {
        return ECDSA.recover(digest, r, vs);
    }

    // Hash functions
    function hashSecret(bytes memory secret)
        public pure
        returns (bytes32)
    {
        return sha256(secret);
    }

    function order_hash(Order memory order)
        public view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(
                    ORDER_TYPEHASH,
                    order.userAddress,
                    order.resolverAddress,
                    order.userAmount,
                    order.resolverAmount,
                    order.venueAddress,
                    order.venueFee,
                    order.arbitratorAddress,
                    order.arbitratorAttentionFee,
                    order.arbitratorUsageFee,
                    order.secretHash,
                    order.submissionDeadline,
                    order.resolverActionDeadline,
                    order.destinationChain,
                    keccak256(order.destinationAddress),
                    keccak256(order.destinationToken),
                    order.destinationAmount
                ))));
    }

    // Verify order signatures
    function order_verify(Order memory order, bytes32 r, bytes32 vs)
        internal view
    {
        bytes32 orderHash = order_hash(order);
        
        // Verify resolver signature
        address recoveredResolver = recoverSigner(orderHash, r, vs);
        if (recoveredResolver != order.resolverAddress) revert InvalidResolverSignature();
    }

    function internal_hashDecision(ArbitratorDecision memory decision)
        internal pure
        returns (bytes32)
    {
        return keccak256(abi.encode(
            ARBITRATOR_DECISION_TYPEHASH,
            decision.decision,
            decision.secretHash,
            decision.deadline,
            decision.destinationChain,
            keccak256(decision.destinationToken),
            decision.destinationAmount,
            keccak256(decision.destinationAddress)
        ));
    }

    function decision_make(
        bytes32 orderHash,
        bool status
    )
        public view
        returns (bytes memory abiEncodedDecision, bytes32 structHash)
    {
        Order storage order = activeEscrows[orderHash];
        if (order.userAddress == address(0)) revert EscrowNotFound();

        ArbitratorDecision memory decision = ArbitratorDecision({
            decision: status,
            secretHash: order.secretHash,
            deadline: order.resolverActionDeadline,
            destinationChain: order.destinationChain,
            destinationToken: order.destinationToken,
            destinationAmount: order.destinationAmount,
            destinationAddress: order.destinationAddress
        });

        structHash = internal_hashDecision(decision);
        abiEncodedDecision = abi.encode(decision);
    }

    // Verify arbitrator decision using EIP-712
    function decision_verify(
        Order memory order,
        ArbitratorDecision memory decision,
        bytes32 r,
        bytes32 vs
    )
        internal pure
    {
        // Verify decision matches order parameters
        if (decision.destinationChain != order.destinationChain) revert WrongDestinationChain();
        if (keccak256(decision.destinationToken) != keccak256(order.destinationToken)) revert WrongDestinationToken();
        if (decision.destinationAmount != order.destinationAmount) revert WrongDestinationAmount();
        if (keccak256(decision.destinationAddress) != keccak256(order.destinationAddress)) revert WrongDestinationAddress();

        bytes32 structHash = internal_hashDecision(decision);
        address recoveredArbitrator = recoverSigner(structHash, r, vs);
        if (recoveredArbitrator != order.arbitratorAddress) revert InvalidArbitratorSignature();
    }

    // Resolver deposits balance to participate in swaps
    function resolver_deposit(address resolverAddr)
        external payable
    {
        resolverBalances[resolverAddr] += msg.value;
    }

    // Resolver withdraws available balance
    function resolver_withdraw(uint256 amount)
        external
    {
        if (resolverBalances[msg.sender] < amount) revert InsufficientBalance();
        
        resolverBalances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // Create escrow with signed order
    function escrow_create(
        Order memory order,
        bytes32 r,
        bytes32 vs
    )
        external payable
    {
        if (msg.value != order.userAmount) revert InsufficientBalance();
        if (block.timestamp > order.submissionDeadline) revert OrderExpired();
        
        // Verify resolver signature
        order_verify(order, r, vs);
        
        // Create order hash
        bytes32 orderHash = order_hash(order);
        
        // Check escrow doesn't already exist
        if (activeEscrows[orderHash].userAddress != address(0)) {
            revert DuplicateOrder();
        }
        
        // Check resolver has sufficient balance
        uint256 requiredBalance = order.resolverAmount + order.venueFee + order.arbitratorAttentionFee;
        if (resolverBalances[order.resolverAddress] < requiredBalance) revert InsufficientBalance();
        
        // Check arbitrator usage fee constraint
        if (order.arbitratorUsageFee > order.resolverAmount) revert InvalidOrderHash();
        
        // Lock resolver funds and pay immediate fees
        resolverBalances[order.resolverAddress] -= requiredBalance;
        
        // Pay venue fee
        if (order.venueFee > 0) {
            payable(order.venueAddress).transfer(order.venueFee);
        }
        
        // Pay arbitrator attention fee
        if (order.arbitratorAttentionFee > 0) {
            payable(order.arbitratorAddress).transfer(order.arbitratorAttentionFee);
        }
        
        // Create escrow state
        activeEscrows[orderHash] = order;
        
        emit OrderVerified(orderHash, order.userAddress, order.resolverAddress, order.arbitratorAddress, block.timestamp);
        emit EscrowCreated(orderHash, block.timestamp);
    }

    function internal_order_get(bytes32 orderHash)
        internal view
        returns (Order storage order)
    {
        order = activeEscrows[orderHash];
        if (order.userAddress == address(0)) revert EscrowNotFound();
    }

    // Resolver reveals secret to claim funds (happy path)
    function escrow_resolve_secret(bytes32 orderHash, bytes memory secret)
        external
    {
        Order storage order = internal_order_get(orderHash);
        
        // Verify secret
        bytes32 secretHash = hashSecret(secret);
        if (secretHash != order.secretHash) revert InvalidSecret();
        
        // Transfer funds to resolver
        uint256 totalAmount = order.userAmount + order.resolverAmount;
        address resolverAddress = order.resolverAddress;

        delete activeEscrows[orderHash];

        payable(resolverAddress).transfer(totalAmount);        
        emit EscrowResolved(orderHash, "SECRET_REVEALED");
    }

    // Resolver exits early, accepts penalty
    function escrow_resolve_early(bytes32 orderHash, bytes32 r, bytes32 vs)
        external
    {
        Order storage order = internal_order_get(orderHash);
        
        // Create early exit message
        bytes32 exitMessage = keccak256(abi.encodePacked("EARLY_EXIT", orderHash));
        address recoveredResolver = recoverSigner(exitMessage, r, vs);
        if (recoveredResolver != order.resolverAddress) revert InvalidResolverSignature();
        
        // Transfer all funds to user (user gets back their money + resolver penalty)
        uint256 totalAmount = order.userAmount + order.resolverAmount;        
        address userAddress = order.userAddress;

        delete activeEscrows[orderHash];

        payable(userAddress).transfer(totalAmount);        
        emit EscrowResolved(orderHash, "EARLY_EXIT");
    }

    // Arbitrator resolves dispute
    function escrow_arbitrate(
        bytes32 orderHash,
        ArbitratorDecision memory decision,
        bytes32 r,
        bytes32 vs
    ) external {
        Order storage order = internal_order_get(orderHash);

        decision_verify(order, decision, r, vs);

        if (decision.decision) {
            // Resolver wins: gets user funds + (resolver amount - usage fee)
            uint256 arbitratorUsageFee = order.arbitratorUsageFee;
            uint256 resolverGets = (order.userAmount + order.resolverAmount) - arbitratorUsageFee;
            address resolverAddress = order.resolverAddress;
            address arbitratorAddress = order.arbitratorAddress;

            delete activeEscrows[orderHash];

            payable(resolverAddress).transfer(resolverGets);
            payable(arbitratorAddress).transfer(arbitratorUsageFee);
        }
        else {
            // User wins: gets their money back + full resolver penalty
            uint256 totalAmount = order.userAmount + order.resolverAmount;
            address userAddress = order.userAddress;

            delete activeEscrows[orderHash];
            payable(userAddress).transfer(totalAmount);
        }
        
        emit EscrowResolved(orderHash, decision.decision ? "ARBITRATOR_SUCCESS" : "ARBITRATOR_FAILURE");
    }

    // User claims timeout refund
    function escrow_timeout(bytes32 orderHash)
        external
    {
        Order storage order = internal_order_get(orderHash);

        address userAddress = order.userAddress;

        // Check timeout reached
        if (block.timestamp <= order.resolverActionDeadline) revert TimeoutNotReached();
        
        // Transfer all funds to user (user gets back their money + resolver penalty)
        uint256 totalAmount = order.userAmount + order.resolverAmount;

        delete activeEscrows[orderHash];
        
        payable(userAddress).transfer(totalAmount);
        
        emit EscrowResolved(orderHash, "TIMEOUT_REFUND");
    }

    function resolver_balance(address resolver)
        external view
        returns (uint256)
    {
        return resolverBalances[resolver];
    }

    function order_get(bytes32 orderHash)
        external view
        returns (
            bool exists,
            Order memory order
        )
    {
        exists = order.userAddress != address(0);
        order = activeEscrows[orderHash];
    }
}