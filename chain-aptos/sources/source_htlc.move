module htlc::source_htlc {
    use std::bcs;
    use std::signer;
    use std::vector;
    use std::error;
    use aptos_framework::timestamp;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::account;
    use aptos_framework::event;
    use aptos_std::table::{Self, Table};
    use aptos_std::ed25519;
    use aptos_std::bcs_stream;
    use aptos_std::from_bcs;

    // Error codes
    const E_NOT_INITIALIZED: u64 = 1;
    const E_ALREADY_INITIALIZED: u64 = 2;
    const E_INSUFFICIENT_BALANCE: u64 = 3;
    const E_INVALID_SIGNATURE: u64 = 4;
    const E_ESCROW_NOT_FOUND: u64 = 5;
    const E_ESCROW_ALREADY_RESOLVED: u64 = 6;
    const E_ORDER_EXPIRED: u64 = 7;
    const E_INVALID_SECRET: u64 = 8;
    const E_NOT_AUTHORIZED: u64 = 9;
    const E_TIMEOUT_NOT_REACHED: u64 = 10;
    const E_INVALID_ORDER_HASH: u64 = 11;

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
    struct PersistantState has key {
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
        move_to(&resource_signer, PersistantState {
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
    

    fun verify_order_internal(
        order_bcs: vector<u8>,
        user_signature: vector<u8>,
        resolver_signature: vector<u8>
    ): (Order,OrderVerified) {

        // Deserialize the BCS-encoded order
        let order = decode_order(&mut bcs_stream::new(order_bcs));
        
        // 1. Verify user signature
        let user_pk = ed25519::new_unvalidated_public_key_from_bytes(order.user_public_key);
        let user_sig = ed25519::new_signature_from_bytes(user_signature);
        assert!(
            ed25519::signature_verify_strict(&user_sig, &user_pk, order_bcs),
            E_INVALID_USER_SIGNATURE
        );

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
        let order_hash = std::hash::sha3_256(order_bcs);

        (order, OrderVerified {
            order_hash: order_hash,
            user_address: derived_user_address,
            resolver_address: derived_resolver_address,
            arbitrator_address: derived_arbitrator_address,
            timestamp: aptos_framework::timestamp::now_seconds(),
        })
    }

    public entry fun verify_order_signatures(
        _caller: &signer,
        order_bcs: vector<u8>,
        user_signature: vector<u8>,
        resolver_signature: vector<u8>
    ) {
        let (_,verification_result) = verify_order_internal(
            order_bcs,
            user_signature,
            resolver_signature
        );

        event::emit(verification_result);
    }

    /// Resolver deposits balance to participate in swaps
    public entry fun deposit_resolver_balance(resolver: &signer, amount: u64)
        acquires SignerCapability, PersistantState
    {
        let resolver_addr = signer::address_of(resolver);
        let registry_addr = get_registry_address();
        let state = borrow_global_mut<PersistantState>(registry_addr);
        
        // Transfer coins to contract
        coin::transfer<AptosCoin>(resolver, registry_addr, amount);
        
        // Update balance
        if (table::contains(&state.resolver_balances, resolver_addr)) {
            let current_balance = table::borrow_mut(&mut state.resolver_balances, resolver_addr);
            *current_balance = *current_balance + amount;
        } else {
            table::add(&mut state.resolver_balances, resolver_addr, amount);
        };
    }

    /// Resolver withdraws available balance
    public entry fun withdraw_resolver_balance(resolver: &signer, amount: u64)
        acquires SignerCapability, PersistantState
    {
        let resolver_addr = signer::address_of(resolver);
        let registry_addr = get_registry_address();
        let state = borrow_global_mut<PersistantState>(registry_addr);
        
        assert!(table::contains(&state.resolver_balances, resolver_addr), error::not_found(E_INSUFFICIENT_BALANCE));
        
        let current_balance = table::borrow_mut(&mut state.resolver_balances, resolver_addr);
        assert!(*current_balance >= amount, error::invalid_argument(E_INSUFFICIENT_BALANCE));
        
        *current_balance = *current_balance - amount;
        
        // Transfer coins back to resolver
        let resource_signer = get_resource_signer();
        coin::transfer<AptosCoin>(&resource_signer, resolver_addr, amount);
    }

    /// Create escrow with signed order
    public entry fun create_escrow(
        tx_submitter: &signer,
        order_bcs: vector<u8>,
        user_signature: vector<u8>,
        resolver_signature: vector<u8>,
    ) acquires SignerCapability, PersistantState {
        let state = borrow_global_mut<PersistantState>(get_registry_address());
        let current_time = timestamp::now_seconds();
        
        // Reconstruct order from parameters
        let (order,order_verified) = verify_order_internal(order_bcs, user_signature, resolver_signature);

        // Check submission deadline
        assert!(current_time <= order.submission_deadline, error::invalid_argument(E_ORDER_EXPIRED));

        // Hash the order to get unique ID
        let order_hash = std::hash::sha3_256(order_bcs);
        
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
        resolver: &signer,
        order_hash: vector<u8>,
        secret: vector<u8>,
    ) acquires SignerCapability, PersistantState {
        let resolver_addr = signer::address_of(resolver);
        let state = borrow_global_mut<PersistantState>(get_registry_address());
        
        assert!(table::contains(&state.active_escrows, order_hash), error::not_found(E_ESCROW_NOT_FOUND));
        let escrow = table::borrow_mut(&mut state.active_escrows, order_hash);
        assert!(escrow.status == STATUS_ACTIVE, error::invalid_state(E_ESCROW_ALREADY_RESOLVED));
        assert!(resolver_addr == pubkey2address(escrow.order.resolver_public_key), error::permission_denied(E_NOT_AUTHORIZED));
        
        // Verify secret
        let secret_hash = std::hash::sha3_256(secret);
        assert!(secret_hash == escrow.order.secret_hash, error::invalid_argument(E_INVALID_SECRET));
        
        // Mark as resolved
        escrow.status = STATUS_RESOLVED;
        
        // Transfer funds to resolver
        let total_amount = escrow.user_deposited + escrow.resolver_locked;
        let resource_signer = get_resource_signer();
        coin::transfer<AptosCoin>(&resource_signer, resolver_addr, total_amount);
    }

    /// Resolver exits early, accepts penalty
    public entry fun resolve_early_exit(
        order_hash: vector<u8>,
        resolver_signature: vector<u8>,
    ) acquires SignerCapability, PersistantState {
        let state = borrow_global_mut<PersistantState>(get_registry_address());
        
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
    ) acquires SignerCapability, PersistantState {
        let state = borrow_global_mut<PersistantState>(get_registry_address());
        
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
    ) acquires SignerCapability, PersistantState {
        let user_addr = signer::address_of(user);
        let state = borrow_global_mut<PersistantState>(get_registry_address());
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
    ) acquires SignerCapability, PersistantState {
        let state = borrow_global_mut<PersistantState>(get_registry_address());
        
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
        //verify_signature(&agreement_message, &user_signature, &escrow.order.user_public_key);

        let resolver_pk = ed25519::new_unvalidated_public_key_from_bytes(escrow.order.resolver_public_key);
        let resolver_sig = ed25519::new_signature_from_bytes(resolver_signature);
        assert!(
            ed25519::signature_verify_strict(&resolver_sig, &resolver_pk, agreement_message),
            E_INVALID_RESOLVER_SIGNATURE
        );
        //verify_signature(&agreement_message, &resolver_signature, &escrow.order.resolver_public_key);
        
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

    // Helper functions

    // View functions

    #[view]
    public fun get_resolver_balance(resolver: address): u64
        acquires SignerCapability, PersistantState
    {
        let state = borrow_global<PersistantState>(get_registry_address());
        if (table::contains(&state.resolver_balances, resolver)) {
            *table::borrow(&state.resolver_balances, resolver)
        } else {
            0
        }
    }

    #[view]
    public fun get_escrow_state(order_hash: vector<u8>): (bool, Order, u64, u64, u64, u8)
        acquires SignerCapability, PersistantState
    {
        let state = borrow_global<PersistantState>(get_registry_address());
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
            }, 0, 0, 0, 0)
        }
    }
}