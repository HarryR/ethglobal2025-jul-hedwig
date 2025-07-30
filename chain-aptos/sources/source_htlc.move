// SPDX-License-Identifier: AGPL-3.0-only

module htlc::source_htlc {
    use std::bcs;
    use std::signer;
    use std::vector;
    use std::error;
    use aptos_framework::timestamp;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::account;
    use aptos_std::table::{Self, Table};
    use aptos_std::ed25519;
    use aptos_std::bcs_stream;
    use aptos_std::from_bcs;

    // Error codes
    const E_INSUFFICIENT_BALANCE: u64 = 3;
    const E_ESCROW_NOT_FOUND: u64 = 5;
    const E_ESCROW_ALREADY_RESOLVED: u64 = 6;
    const E_ORDER_EXPIRED: u64 = 7;
    const E_INVALID_SECRET: u64 = 8;
    const E_NOT_AUTHORIZED: u64 = 9;
    const E_TIMEOUT_NOT_REACHED: u64 = 10;
    const E_INVALID_ORDER_HASH: u64 = 11;
    const E_WRONG_DESTINATION_CHAIN: u64 = 12;
    const E_WRONG_DESTINATION_TOKEN: u64 = 13;
    const E_WRONG_DESTINATION_AMOUNT: u64 = 14;
    const E_WRONG_DESTINATION_ADDRESS: u64 = 15;

    const E_INVALID_USER_SIGNATURE: u64 = 10001;
    const E_INVALID_RESOLVER_SIGNATURE: u64 = 10002;
    const E_INVALID_ARBITRATOR_SIGNATURE: u64 = 10003;

    // Escrow status constants
    const STATUS_ACTIVE: u8 = 0;
    const STATUS_RESOLVED: u8 = 1;

    /// Stores the resource account's signer capability
    /// This is stored at the module deployer's address, not the resource account
    struct SignerCapability has key {
        cap: account::SignerCapability
    }

    /// Core order structure
    struct Order has copy, drop, store {
        user_public_key: vector<u8>,      // 32-byte Ed25519 public key
        resolver_public_key: vector<u8>,  // 32-byte Ed25519 public key
        user_amount: u64,
        resolver_amount: u64,
        venue_address: address,
        venue_fee: u64,
        arbitrator_public_key: vector<u8>, // 32-byte Ed25519 public key
        arbitrator_attention_fee: u64,
        arbitrator_usage_fee: u64,
        secret_hash: vector<u8>,
        submission_deadline: u64,
        resolver_action_deadline: u64,
        destination_chain: vector<u8>,
        destination_address: vector<u8>,
        destination_token: vector<u8>,
        destination_amount: u256,
    }

    /// State of an active escrow
    struct EscrowState has store {
        order: Order,
        user_deposited: u64,
        resolver_locked: u64,
        creation_timestamp: u64,
        status: u8,
    }

    /// Main contract resource
    struct PersistentState has key {
        resolver_balances: Table<address, u64>,
        active_escrows: Table<vector<u8>, EscrowState>,
    }

    #[event]
    struct OrderVerified has drop, store {
        order_hash: vector<u8>,
        user_address: address,
        resolver_address: address,
        arbitrator_address: address,
        timestamp: u64,
    }

    struct ArbitratorDecision has drop, store {
        decision: u8,
        secret_hash: vector<u8>,
        deadline: u64,        
        destination_chain: vector<u8>,
        destination_token: vector<u8>,
        destination_amount: u256,
        destination_address: vector<u8>
    }

    fun decode_arbitrator_decision(stream: &mut bcs_stream::BCSStream): ArbitratorDecision {
        ArbitratorDecision {
            decision: bcs_stream::deserialize_u8(stream),
            secret_hash: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            deadline: bcs_stream::deserialize_u64(stream),            
            destination_chain: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            destination_token: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            destination_amount: bcs_stream::deserialize_u256(stream),
            destination_address: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),                        
        }
    }

    fun verify_arbitrator_decision(
        order:&Order,
        decision_bcs:vector<u8>,
        arbitrator_sig:vector<u8>
    ):ArbitratorDecision
    {
        let arb_sig = ed25519::new_signature_from_bytes(arbitrator_sig);
        let arb_pk = ed25519::new_unvalidated_public_key_from_bytes(order.arbitrator_public_key);
        assert!(
            ed25519::signature_verify_strict(&arb_sig, &arb_pk, decision_bcs),
            E_INVALID_ARBITRATOR_SIGNATURE
        );

        let decision = decode_arbitrator_decision(&mut bcs_stream::new(decision_bcs));
        assert!(decision.destination_chain == order.destination_chain, E_WRONG_DESTINATION_CHAIN);
        assert!(decision.destination_token == order.destination_token, E_WRONG_DESTINATION_TOKEN);
        assert!(decision.destination_amount == order.destination_amount, E_WRONG_DESTINATION_AMOUNT);
        assert!(decision.destination_address == order.destination_address, E_WRONG_DESTINATION_ADDRESS);

        decision
    }

    fun pubkey2address(pk: vector<u8>): address {
        let user_pk = ed25519::new_unvalidated_public_key_from_bytes(pk);
        let user_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&user_pk);
        let derived_user_address = from_bcs::to_address(user_auth_key);
        derived_user_address
    }

    /// Decode Order struct from BCS stream
    fun decode_order(stream: &mut bcs_stream::BCSStream): Order {
        Order {
            user_public_key: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            resolver_public_key: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            user_amount: bcs_stream::deserialize_u64(stream),
            resolver_amount: bcs_stream::deserialize_u64(stream),
            venue_address: bcs_stream::deserialize_address(stream),
            venue_fee: bcs_stream::deserialize_u64(stream),
            arbitrator_public_key: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            arbitrator_attention_fee: bcs_stream::deserialize_u64(stream),
            arbitrator_usage_fee: bcs_stream::deserialize_u64(stream),
            secret_hash: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            submission_deadline: bcs_stream::deserialize_u64(stream),
            resolver_action_deadline: bcs_stream::deserialize_u64(stream),
            destination_chain: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            destination_address: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            destination_token: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            destination_amount: bcs_stream::deserialize_u256(stream),
        }
    }

    /// This runs automatically when the module is first published
    /// Creates a resource account and stores the capability
    fun init_module(deployer: &signer) {
        // Create a resource account with a deterministic seed
        let (resource_signer, signer_cap) = account::create_resource_account(
            deployer, 
            b"htlc::source_htlc"  // Fixed seed ensures deterministic address
        );
        
        // Initialize the registry on the resource account
        move_to(&resource_signer, PersistentState {
            resolver_balances: table::new(),
            active_escrows: table::new(),
        });
        
        // Store the signer capability at the deployer's address
        // Only this module can access it due to the struct being defined here
        move_to(deployer, SignerCapability {
            cap: signer_cap
        });
    }

    /// Internal helper to get the resource account signer
    fun get_resource_signer(): signer acquires SignerCapability {
        let signer_cap = &borrow_global<SignerCapability>(@htlc).cap;
        account::create_signer_with_capability(signer_cap)
    }

    // Get the resource account address (for transparency)
    #[view]
    public fun get_registry_address(): address acquires SignerCapability {
        let resource_signer = get_resource_signer();
        signer::address_of(&resource_signer)
    }
    
    // We don't verify user signature for order creation
    // If somebody wants to pay for a users order, sure... go for it
    fun verify_order_internal(
        order_bcs: vector<u8>,
        //user_signature: vector<u8>,
        resolver_signature: vector<u8>
    ): (Order,OrderVerified) {

        // Deserialize the BCS-encoded order
        let order = decode_order(&mut bcs_stream::new(order_bcs));
        
        // 1. Verify user signature
        let user_pk = ed25519::new_unvalidated_public_key_from_bytes(order.user_public_key);
        /*        
        let user_sig = ed25519::new_signature_from_bytes(user_signature);
        assert!(
            ed25519::signature_verify_strict(&user_sig, &user_pk, order_bcs),
            E_INVALID_USER_SIGNATURE
        );
        */

        // 2. Verify resolver signature  
        let resolver_pk = ed25519::new_unvalidated_public_key_from_bytes(order.resolver_public_key);
        let resolver_sig = ed25519::new_signature_from_bytes(resolver_signature);
        assert!(
            ed25519::signature_verify_strict(&resolver_sig, &resolver_pk, order_bcs),
            E_INVALID_RESOLVER_SIGNATURE
        );

        // 4. Verify addresses match the signers
        // User address should match the derived address from user public key
        let user_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&user_pk);
        let derived_user_address = from_bcs::to_address(user_auth_key);

        // Resolver address should match the derived address from resolver public key
        let resolver_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&resolver_pk);
        let derived_resolver_address = from_bcs::to_address(resolver_auth_key);

        // Arbitrator address should match the derived address from arbitrator public key
        let arbitrator_pk = ed25519::new_unvalidated_public_key_from_bytes(order.arbitrator_public_key);
        let arbitrator_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&arbitrator_pk);
        let derived_arbitrator_address = from_bcs::to_address(arbitrator_auth_key);

        // 5. Create order hash for event (simple hash of BCS-encoded order)
        let order_hash = hash_order(order_bcs);

        (order, OrderVerified {
            order_hash: order_hash,
            user_address: derived_user_address,
            resolver_address: derived_resolver_address,
            arbitrator_address: derived_arbitrator_address,
            timestamp: aptos_framework::timestamp::now_seconds(),
        })
    }

    /// Resolver deposits balance to participate in swaps
    /// Anybody can topup anybody elses balance
    public entry fun deposit_resolver_balance(
        caller: &signer,
        resolver_addr: address,
        amount: u64
    )
        acquires SignerCapability, PersistentState
    {
        let registry_addr = get_registry_address();
        let state = borrow_global_mut<PersistentState>(registry_addr);
        
        // Transfer coins to contract
        coin::transfer<AptosCoin>(caller, registry_addr, amount);
        
        // Update balance
        if (table::contains(&state.resolver_balances, resolver_addr)) {
            let current_balance = table::borrow_mut(&mut state.resolver_balances, resolver_addr);
            *current_balance = *current_balance + amount;
        } else {
            table::add(&mut state.resolver_balances, resolver_addr, amount);
        };
    }

    /// Resolver withdraws available balance
    public entry fun withdraw_resolver_balance(
        resolver: &signer,
        amount: u64
    )
        acquires SignerCapability, PersistentState
    {
        let resolver_addr = signer::address_of(resolver);
        let registry_addr = get_registry_address();
        let state = borrow_global_mut<PersistentState>(registry_addr);
        
        assert!(table::contains(&state.resolver_balances, resolver_addr), error::not_found(E_INSUFFICIENT_BALANCE));
        
        let current_balance = table::borrow_mut(&mut state.resolver_balances, resolver_addr);
        assert!(*current_balance >= amount, error::invalid_argument(E_INSUFFICIENT_BALANCE));
        
        *current_balance = *current_balance - amount;
        
        // Transfer coins back to resolver
        let resource_signer = get_resource_signer();
        coin::transfer<AptosCoin>(&resource_signer, resolver_addr, amount);
    }

    #[view]
    public fun hash_secret(secret: vector<u8>): vector<u8> {
        std::hash::sha2_256(secret)
    }

    #[view]
    public fun hash_order(order_bcs: vector<u8>): vector<u8> {
        std::hash::sha2_256(order_bcs)
    }

    /// Create escrow with signed order
    public entry fun create_escrow(
        tx_submitter: &signer,
        order_bcs: vector<u8>,
        //user_signature: vector<u8>,
        resolver_signature: vector<u8>,
    ) acquires SignerCapability, PersistentState {
        let state = borrow_global_mut<PersistentState>(get_registry_address());
        let current_time = timestamp::now_seconds();
        
        // Reconstruct order from parameters
        let (order,order_verified) = verify_order_internal(order_bcs, /*user_signature,*/ resolver_signature);

        // Check submission deadline
        assert!(current_time <= order.submission_deadline, error::invalid_argument(E_ORDER_EXPIRED));

        // Hash the order to get unique ID
        let order_hash = hash_order(order_bcs);
        
        // Check escrow doesn't already exist
        assert!(!table::contains(&state.active_escrows, order_hash), error::already_exists(E_ESCROW_ALREADY_RESOLVED));        
        
        // Check resolver has sufficient balance
        let required_balance = order.resolver_amount + order.venue_fee + order.arbitrator_attention_fee;
        assert!(table::contains(&state.resolver_balances, order_verified.resolver_address), error::not_found(E_INSUFFICIENT_BALANCE));
        let resolver_balance = table::borrow(&state.resolver_balances, order_verified.resolver_address);
        assert!(*resolver_balance >= required_balance, error::invalid_argument(E_INSUFFICIENT_BALANCE));
        
        // Check arbitrator usage fee constraint
        assert!(order.arbitrator_usage_fee <= order.resolver_amount, error::invalid_argument(E_INVALID_ORDER_HASH));
        
        // Transfer user funds to contract
        let registry_addr = get_registry_address();
        coin::transfer<AptosCoin>(tx_submitter, registry_addr, order.user_amount);
        
        // Lock resolver funds and pay immediate fees
        let resolver_balance_mut = table::borrow_mut(&mut state.resolver_balances, order_verified.resolver_address);
        *resolver_balance_mut = *resolver_balance_mut - required_balance;
        
        let resource_signer = get_resource_signer();

        // Pay venue fee        
        coin::transfer<AptosCoin>(&resource_signer, order.venue_address, order.venue_fee);
        
        // Pay arbitrator attention fee
        coin::transfer<AptosCoin>(&resource_signer, order_verified.arbitrator_address, order.arbitrator_attention_fee);
        
        // Create escrow state
        let escrow_state = EscrowState {
            order: order,
            user_deposited: order.user_amount,
            resolver_locked: order.resolver_amount,
            creation_timestamp: current_time,
            status: STATUS_ACTIVE,
        };
        
        table::add(&mut state.active_escrows, order_hash, escrow_state);
    }

    /// Resolver reveals secret to claim funds (happy path)
    public entry fun resolve_with_secret(
        _caller: &signer,
        order_hash: vector<u8>,
        secret: vector<u8>,
    ) acquires SignerCapability, PersistentState {
        let state = borrow_global_mut<PersistentState>(get_registry_address());
        
        assert!(table::contains(&state.active_escrows, order_hash), error::not_found(E_ESCROW_NOT_FOUND));
        let escrow = table::borrow_mut(&mut state.active_escrows, order_hash);
        assert!(escrow.status == STATUS_ACTIVE, error::invalid_state(E_ESCROW_ALREADY_RESOLVED));
        
        // Verify secret
        let secret_hash = hash_secret(secret);
        assert!(secret_hash == escrow.order.secret_hash, error::invalid_argument(E_INVALID_SECRET));
        
        // Mark as resolved
        escrow.status = STATUS_RESOLVED;
        
        // Transfer funds to resolver
        let total_amount = escrow.user_deposited + escrow.resolver_locked;
        let resource_signer = get_resource_signer();
        coin::transfer<AptosCoin>(&resource_signer, pubkey2address(escrow.order.resolver_public_key), total_amount);
    }

    /// Resolver exits early, accepts penalty
    public entry fun resolve_early_exit(
        order_hash: vector<u8>,
        resolver_signature: vector<u8>,
    ) acquires SignerCapability, PersistentState {
        let state = borrow_global_mut<PersistentState>(get_registry_address());
        
        assert!(table::contains(&state.active_escrows, order_hash), error::not_found(E_ESCROW_NOT_FOUND));
        let escrow = table::borrow_mut(&mut state.active_escrows, order_hash);
        assert!(escrow.status == STATUS_ACTIVE, error::invalid_state(E_ESCROW_ALREADY_RESOLVED));
        
        // Verify resolver signature on "early exit" message
        let exit_message = b"EARLY_EXIT";
        vector::append(&mut exit_message, order_hash);
        let resolver_pk = ed25519::new_unvalidated_public_key_from_bytes(escrow.order.resolver_public_key);
        let resolver_sig = ed25519::new_signature_from_bytes(resolver_signature);
        assert!(
            ed25519::signature_verify_strict(&resolver_sig, &resolver_pk, exit_message),
            E_INVALID_RESOLVER_SIGNATURE
        );
        
        // Mark as resolved
        escrow.status = STATUS_RESOLVED;
        
        // Transfer all funds to user (user gets back their money + resolver penalty)
        let total_amount = escrow.user_deposited + escrow.resolver_locked;
        let resource_signer = get_resource_signer();

        let user_address = pubkey2address(escrow.order.user_public_key);
        coin::transfer<AptosCoin>(&resource_signer, user_address, total_amount);
    }

    /// Arbitrator resolves dispute  
    public entry fun resolve_with_arbitrator(
        order_hash: vector<u8>,
        success: bool,
        arbitrator_signature: vector<u8>
    ) acquires SignerCapability, PersistentState {
        let state = borrow_global_mut<PersistentState>(get_registry_address());
        
        assert!(table::contains(&state.active_escrows, order_hash), error::not_found(E_ESCROW_NOT_FOUND));
        let escrow = table::borrow_mut(&mut state.active_escrows, order_hash);
        assert!(escrow.status == STATUS_ACTIVE, error::invalid_state(E_ESCROW_ALREADY_RESOLVED));
        
        // Verify arbitrator signature
        let decision_message = if (success) b"SUCCESS" else b"FAILURE";
        vector::append(&mut decision_message, order_hash);
        let arbitrator_pk = ed25519::new_unvalidated_public_key_from_bytes(escrow.order.arbitrator_public_key);
        let arbitrator_sig = ed25519::new_signature_from_bytes(arbitrator_signature);
        assert!(
            ed25519::signature_verify_strict(&arbitrator_sig, &arbitrator_pk, decision_message),
            E_INVALID_ARBITRATOR_SIGNATURE
        );
        
        // Mark as resolved
        escrow.status = STATUS_RESOLVED;
        
        let resource_signer = get_resource_signer();
        if (success) {
            // Resolver wins: gets user funds + (resolver amount - usage fee)
            let resolver_gets = escrow.user_deposited + (escrow.resolver_locked - escrow.order.arbitrator_usage_fee);
            coin::transfer<AptosCoin>(&resource_signer, pubkey2address(escrow.order.resolver_public_key), resolver_gets);
            coin::transfer<AptosCoin>(&resource_signer, pubkey2address(escrow.order.arbitrator_public_key), escrow.order.arbitrator_usage_fee);
        } else {
            // User wins: gets their money back + full resolver penalty
            let total_amount = escrow.user_deposited + escrow.resolver_locked;
            coin::transfer<AptosCoin>(&resource_signer, pubkey2address(escrow.order.user_public_key), total_amount);
        };
    }

    /// User claims timeout refund
    public entry fun claim_timeout_refund(
        user: &signer,
        order_hash: vector<u8>,
    ) acquires SignerCapability, PersistentState {
        let user_addr = signer::address_of(user);
        let state = borrow_global_mut<PersistentState>(get_registry_address());
        let current_time = timestamp::now_seconds();
        
        assert!(table::contains(&state.active_escrows, order_hash), error::not_found(E_ESCROW_NOT_FOUND));
        let escrow = table::borrow_mut(&mut state.active_escrows, order_hash);
        assert!(escrow.status == STATUS_ACTIVE, error::invalid_state(E_ESCROW_ALREADY_RESOLVED));
        assert!(user_addr == pubkey2address(escrow.order.user_public_key), error::permission_denied(E_NOT_AUTHORIZED));
        
        // Check timeout reached
        assert!(current_time > escrow.order.resolver_action_deadline, error::invalid_argument(E_TIMEOUT_NOT_REACHED));
        
        // Mark as resolved
        escrow.status = STATUS_RESOLVED;
        
        // Transfer all funds to user (user gets back their money + resolver penalty)
        let resource_signer = get_resource_signer();
        let total_amount = escrow.user_deposited + escrow.resolver_locked;
        coin::transfer<AptosCoin>(&resource_signer, user_addr, total_amount);
    }

    /// Mutual resolution by both parties
    public entry fun resolve_mutual(
        order_hash: vector<u8>,
        user_gets: u64,
        resolver_gets: u64,
        user_signature: vector<u8>,
        resolver_signature: vector<u8>,
    ) acquires SignerCapability, PersistentState {
        let state = borrow_global_mut<PersistentState>(get_registry_address());
        
        assert!(table::contains(&state.active_escrows, order_hash), error::not_found(E_ESCROW_NOT_FOUND));
        let escrow = table::borrow_mut(&mut state.active_escrows, order_hash);
        assert!(escrow.status == STATUS_ACTIVE, error::invalid_state(E_ESCROW_ALREADY_RESOLVED));
        
        // Verify total matches available funds
        let total_available = escrow.user_deposited + escrow.resolver_locked;
        assert!(user_gets + resolver_gets == total_available, error::invalid_argument(E_INVALID_ORDER_HASH));
        
        // Create mutual agreement message
        let agreement_message = b"MUTUAL_AGREEMENT:";
        vector::append(&mut agreement_message, order_hash);
        vector::append(&mut agreement_message, bcs::to_bytes(&user_gets));
        vector::append(&mut agreement_message, bcs::to_bytes(&resolver_gets));
        
        // Verify both signatures
        let user_pk = ed25519::new_unvalidated_public_key_from_bytes(escrow.order.user_public_key);
        let user_sig = ed25519::new_signature_from_bytes(user_signature);
        assert!(
            ed25519::signature_verify_strict(&user_sig, &user_pk, agreement_message),
            E_INVALID_USER_SIGNATURE
        );

        let resolver_pk = ed25519::new_unvalidated_public_key_from_bytes(escrow.order.resolver_public_key);
        let resolver_sig = ed25519::new_signature_from_bytes(resolver_signature);
        assert!(
            ed25519::signature_verify_strict(&resolver_sig, &resolver_pk, agreement_message),
            E_INVALID_RESOLVER_SIGNATURE
        );
        
        // Mark as resolved
        escrow.status = STATUS_RESOLVED;
        
        // Transfer funds according to agreement
        let resource_signer = get_resource_signer();
        if (user_gets > 0) {
            coin::transfer<AptosCoin>(&resource_signer, pubkey2address(escrow.order.user_public_key), user_gets);
        };
        if (resolver_gets > 0) {
            coin::transfer<AptosCoin>(&resource_signer, pubkey2address(escrow.order.resolver_public_key), resolver_gets);
        };
    }

    #[view]
    public fun get_resolver_balance(resolver: address): u64
        acquires SignerCapability, PersistentState
    {
        let state = borrow_global<PersistentState>(get_registry_address());
        if (table::contains(&state.resolver_balances, resolver)) {
            *table::borrow(&state.resolver_balances, resolver)
        } else {
            0
        }
    }

    #[view]
    public fun get_escrow_state(order_hash: vector<u8>): (bool, Order, u64, u64, u64, u8)
        acquires SignerCapability, PersistentState
    {
        let state = borrow_global<PersistentState>(get_registry_address());
        if (table::contains(&state.active_escrows, order_hash)) {
            let escrow = table::borrow(&state.active_escrows, order_hash);
            (true, escrow.order, escrow.user_deposited, escrow.resolver_locked, escrow.creation_timestamp, escrow.status)
        } else {
            (false, Order {
                user_public_key: vector::empty(),
                resolver_public_key: vector::empty(),
                user_amount: 0,
                resolver_amount: 0,
                venue_address: @0x0,
                venue_fee: 0,
                arbitrator_public_key: vector::empty(),
                arbitrator_attention_fee: 0,
                arbitrator_usage_fee: 0,
                secret_hash: vector::empty(),
                submission_deadline: 0,
                resolver_action_deadline: 0,
                destination_chain: vector::empty(),
                destination_address: vector::empty(),
                destination_token: vector::empty(),
                destination_amount: 0,
            }, 0, 0, 0, 0)
        }
    }

    // Run sigtest1.py to re-generate parameters
    #[test(aptos_framework = @aptos_framework)]
    fun test_verify_order_signatures_success(aptos_framework: &signer) {
        // Initialize timestamp for testing
        aptos_framework::timestamp::set_time_has_started_for_testing(aptos_framework);
        let order_bcs = vector[0x20, 0x23, 0x88, 0x34, 0xd0, 0xdf, 0xe0, 0x8f, 0x03, 0x51, 0xe3, 0x46, 0x46, 0x03, 0x08, 0xa2, 0xa1, 0xa6, 0x2a, 0x62, 0x24, 0x14, 0xf7, 0x48, 0xca, 0xf7, 0x92, 0x56, 0x94, 0x89, 0x1e, 0xe3, 0x8e, 0x20, 0xee, 0x16, 0xca, 0x24, 0xa2, 0x05, 0x61, 0xc7, 0x77, 0x57, 0x5a, 0x46, 0xa7, 0xf7, 0x57, 0xf1, 0xdf, 0x1a, 0x06, 0x02, 0x05, 0x0c, 0x97, 0xdb, 0x59, 0x5c, 0xd8, 0x36, 0xbb, 0x6a, 0x3c, 0xad, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x84, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5d, 0x86, 0x00, 0xbe, 0x73, 0x70, 0xc5, 0xff, 0xf4, 0x0a, 0x2c, 0x6b, 0xd9, 0x5d, 0xf8, 0x4d, 0xec, 0xf0, 0x82, 0x97, 0xb0, 0xa3, 0x14, 0x57, 0x2e, 0x20, 0x06, 0xc8, 0xf3, 0xe4, 0x2b, 0xde, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x7b, 0xc9, 0xb5, 0xa3, 0xa7, 0xae, 0x69, 0x83, 0xfb, 0x27, 0x29, 0x77, 0xab, 0x2e, 0x8d, 0xd4, 0x0b, 0x0c, 0x56, 0x15, 0x0d, 0xf1, 0x4b, 0x32, 0x9a, 0xf1, 0x38, 0x1e, 0xd6, 0x40, 0x2b, 0xd1, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x51, 0x75, 0x28, 0xb6, 0x7e, 0x23, 0xa0, 0x5a, 0xed, 0x3e, 0x69, 0x8c, 0xe2, 0x9a, 0x21, 0x8f, 0xbe, 0x5d, 0x7a, 0x69, 0x60, 0x26, 0x3e, 0x12, 0xe5, 0x8e, 0x9d, 0xa4, 0x6a, 0x78, 0xe1, 0xaa, 0x10, 0xff, 0x53, 0x65, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0d, 0x54, 0x65, 0x00, 0x00, 0x00, 0x00, 0x20, 0xb5, 0xa5, 0xef, 0x9c, 0x42, 0x01, 0x33, 0xd6, 0x14, 0x15, 0x3d, 0x91, 0xda, 0x4e, 0x39, 0x9f, 0x6a, 0xd3, 0xbd, 0x23, 0x1c, 0xfa, 0x3d, 0xbf, 0x70, 0xd6, 0x0f, 0xfe, 0x99, 0x36, 0xf4, 0x09, 0x14, 0x8a, 0x6d, 0x85, 0xeb, 0xb8, 0xef, 0x38, 0x67, 0x5a, 0x35, 0x08, 0xa2, 0xda, 0x58, 0xb5, 0xf6, 0xce, 0xe0, 0x85, 0x39, 0x14, 0xff, 0xa8, 0xfd, 0xe1, 0x3d, 0x26, 0x5e, 0x80, 0x7f, 0xc7, 0x82, 0xa9, 0x82, 0x49, 0xc0, 0xfd, 0x5a, 0x7c, 0x6f, 0x47, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        // Signatures
        let resolver_signature = vector[0xb9, 0xbd, 0x31, 0x60, 0x66, 0xe7, 0xcc, 0x79, 0xcb, 0x03, 0xd6, 0x51, 0x9d, 0xf5, 0x26, 0x98, 0x32, 0x04, 0xa1, 0x25, 0x27, 0x2d, 0xce, 0xdc, 0x5c, 0xd6, 0x90, 0xb0, 0x03, 0xa9, 0xf1, 0x24, 0x5b, 0xea, 0x92, 0x6e, 0xae, 0x3b, 0xb1, 0x96, 0x27, 0xa4, 0x54, 0xe7, 0x89, 0xb6, 0x3f, 0x8b, 0xd9, 0x13, 0x8c, 0x0d, 0x56, 0x27, 0x7b, 0x5f, 0xe6, 0x55, 0x9c, 0x5c, 0x3b, 0x66, 0xcb, 0x05];
        
        // Expected addresses
        let expected_user_address = @0x4efa7259ca6c9375a68f2b47d433fce04dbbe4440b4276d9745da4bd5a093ff0;
        let expected_resolver_address = @0xc1c97481e7ae71e4dac6d05de8d9df6a667d64fe4dc2aa3651a41b86061e5c56;
        let expected_arbitrator_address = @0x6d085c0c39098a0ac46e07b6fda894bebcdce8591fc8cf2394b72bb2ef1414bb;
    
        // This should succeed
        let (order, verified) = verify_order_internal(
            order_bcs,
            //user_signature,
            resolver_signature
        );

        assert!(verified.user_address == expected_user_address);
        assert!(verified.resolver_address == expected_resolver_address);
        assert!(verified.arbitrator_address == expected_arbitrator_address);

        let arb_decision = vector[0x01, 0x20, 0x51, 0x75, 0x28, 0xb6, 0x7e, 0x23, 0xa0, 0x5a, 0xed, 0x3e, 0x69, 0x8c, 0xe2, 0x9a, 0x21, 0x8f, 0xbe, 0x5d, 0x7a, 0x69, 0x60, 0x26, 0x3e, 0x12, 0xe5, 0x8e, 0x9d, 0xa4, 0x6a, 0x78, 0xe1, 0xaa, 0x20, 0x0d, 0x54, 0x65, 0x00, 0x00, 0x00, 0x00, 0x20, 0xb5, 0xa5, 0xef, 0x9c, 0x42, 0x01, 0x33, 0xd6, 0x14, 0x15, 0x3d, 0x91, 0xda, 0x4e, 0x39, 0x9f, 0x6a, 0xd3, 0xbd, 0x23, 0x1c, 0xfa, 0x3d, 0xbf, 0x70, 0xd6, 0x0f, 0xfe, 0x99, 0x36, 0xf4, 0x09, 0x14, 0xff, 0xa8, 0xfd, 0xe1, 0x3d, 0x26, 0x5e, 0x80, 0x7f, 0xc7, 0x82, 0xa9, 0x82, 0x49, 0xc0, 0xfd, 0x5a, 0x7c, 0x6f, 0x47, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x8a, 0x6d, 0x85, 0xeb, 0xb8, 0xef, 0x38, 0x67, 0x5a, 0x35, 0x08, 0xa2, 0xda, 0x58, 0xb5, 0xf6, 0xce, 0xe0, 0x85, 0x39];
        let arb_decision_signature = vector[0x9f, 0xac, 0x71, 0xeb, 0x93, 0x55, 0x16, 0x04, 0x99, 0x5b, 0x52, 0x31, 0xac, 0x67, 0xac, 0x3c, 0x4b, 0x2d, 0x35, 0x12, 0xb5, 0x2e, 0xed, 0xa2, 0xbd, 0xbd, 0xc6, 0x1b, 0x3e, 0xfa, 0x02, 0x56, 0x27, 0x36, 0xcf, 0xb8, 0x59, 0x4a, 0xe1, 0xdf, 0xe3, 0x34, 0x2a, 0x2c, 0x6f, 0x79, 0xff, 0x8d, 0xdd, 0x34, 0x90, 0x75, 0xdf, 0x1e, 0xdb, 0x7e, 0x76, 0x63, 0x34, 0xc4, 0x24, 0xd6, 0x8f, 0x00];
        let decision = verify_arbitrator_decision(&order, arb_decision, arb_decision_signature);
    }
}