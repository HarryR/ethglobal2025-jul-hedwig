module htlc_addr::htlc_source {
    use std::signer;
    use std::vector;
    use std::error;
    use aptos_framework::timestamp;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_std::table::{Self, Table};
    use aptos_std::ed25519;
    use aptos_std::aptos_hash;

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

    // Escrow status constants
    const STATUS_ACTIVE: u8 = 0;
    const STATUS_RESOLVED: u8 = 1;

    /// Order structure that gets hashed to create unique nonce
    struct Order has copy, drop, store {
        user_address: address,
        resolver_address: address,
        user_public_key: vector<u8>,      // 32-byte Ed25519 public key
        resolver_public_key: vector<u8>,  // 32-byte Ed25519 public key
        user_amount: u64,
        resolver_amount: u64,
        venue_address: address,
        venue_fee: u64,
        arbitrator_address: address,
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
    struct HTLCContract has key {
        resolver_balances: Table<address, u64>,
        active_escrows: Table<vector<u8>, EscrowState>,
    }

    /// Initialize the contract (call once)
    public entry fun initialize(admin: &signer) {
        let admin_addr = signer::address_of(admin);
        assert!(!exists<HTLCContract>(admin_addr), error::already_exists(E_ALREADY_INITIALIZED));
        
        move_to(admin, HTLCContract {
            resolver_balances: table::new(),
            active_escrows: table::new(),
        });
    }

    /// Resolver deposits balance to participate in swaps
    public entry fun deposit_resolver_balance(resolver: &signer, amount: u64) acquires HTLCContract {
        let resolver_addr = signer::address_of(resolver);
        let contract = borrow_global_mut<HTLCContract>(@htlc_addr);
        
        // Transfer coins to contract
        coin::transfer<AptosCoin>(resolver, @htlc_addr, amount);
        
        // Update balance
        if (table::contains(&contract.resolver_balances, resolver_addr)) {
            let current_balance = table::borrow_mut(&mut contract.resolver_balances, resolver_addr);
            *current_balance = *current_balance + amount;
        } else {
            table::add(&mut contract.resolver_balances, resolver_addr, amount);
        };
    }

    /// Resolver withdraws available balance
    public entry fun withdraw_resolver_balance(resolver: &signer, amount: u64) acquires HTLCContract {
        let resolver_addr = signer::address_of(resolver);
        let contract = borrow_global_mut<HTLCContract>(@htlc_addr);
        
        assert!(table::contains(&contract.resolver_balances, resolver_addr), error::not_found(E_INSUFFICIENT_BALANCE));
        
        let current_balance = table::borrow_mut(&mut contract.resolver_balances, resolver_addr);
        assert!(*current_balance >= amount, error::invalid_argument(E_INSUFFICIENT_BALANCE));
        
        *current_balance = *current_balance - amount;
        
        // Transfer coins back to resolver
        coin::transfer<AptosCoin>(&get_contract_signer(), resolver_addr, amount);
    }

    /// Create escrow with signed order
    public entry fun create_escrow(
        user: &signer,
        user_address: address,
        resolver_address: address,
        user_public_key: vector<u8>,
        resolver_public_key: vector<u8>,
        user_amount: u64,
        resolver_amount: u64,
        venue_address: address,
        venue_fee: u64,
        arbitrator_address: address,
        arbitrator_attention_fee: u64,
        arbitrator_usage_fee: u64,
        secret_hash: vector<u8>,
        submission_deadline: u64,
        resolver_action_deadline: u64,
        user_signature: vector<u8>,
        resolver_signature: vector<u8>,
    ) acquires HTLCContract {
        let user_addr = signer::address_of(user);
        let contract = borrow_global_mut<HTLCContract>(@htlc_addr);
        let current_time = timestamp::now_seconds();
        
        // Reconstruct order from parameters
        let order = Order {
            user_address,
            resolver_address,
            user_public_key,
            resolver_public_key,
            user_amount,
            resolver_amount,
            venue_address,
            venue_fee,
            arbitrator_address,
            arbitrator_attention_fee,
            arbitrator_usage_fee,
            secret_hash,
            submission_deadline,
            resolver_action_deadline,
        };
        
        // Check submission deadline
        assert!(current_time <= order.submission_deadline, error::invalid_argument(E_ORDER_EXPIRED));
        
        // Verify user is correct
        assert!(user_addr == order.user_address, error::permission_denied(E_NOT_AUTHORIZED));
        
        // Hash the order to get unique ID
        let order_hash = hash_order(&order);
        
        // Check escrow doesn't already exist
        assert!(!table::contains(&contract.active_escrows, order_hash), error::already_exists(E_ESCROW_ALREADY_RESOLVED));
        
        // Verify signatures
        verify_order_signature(&order, &user_signature, &order.user_public_key);
        verify_order_signature(&order, &resolver_signature, &order.resolver_public_key);
        
        // Check resolver has sufficient balance
        let required_balance = order.resolver_amount + order.venue_fee + order.arbitrator_attention_fee;
        assert!(table::contains(&contract.resolver_balances, order.resolver_address), error::not_found(E_INSUFFICIENT_BALANCE));
        let resolver_balance = table::borrow(&contract.resolver_balances, order.resolver_address);
        assert!(*resolver_balance >= required_balance, error::invalid_argument(E_INSUFFICIENT_BALANCE));
        
        // Check arbitrator usage fee constraint
        assert!(order.arbitrator_usage_fee <= order.resolver_amount, error::invalid_argument(E_INVALID_ORDER_HASH));
        
        // Transfer user funds to contract
        coin::transfer<AptosCoin>(user, @htlc_addr, order.user_amount);
        
        // Lock resolver funds and pay immediate fees
        let resolver_balance_mut = table::borrow_mut(&mut contract.resolver_balances, order.resolver_address);
        *resolver_balance_mut = *resolver_balance_mut - required_balance;
        
        // Pay venue fee
        coin::transfer<AptosCoin>(&get_contract_signer(), order.venue_address, order.venue_fee);
        
        // Pay arbitrator attention fee
        coin::transfer<AptosCoin>(&get_contract_signer(), order.arbitrator_address, order.arbitrator_attention_fee);
        
        // Create escrow state
        let escrow_state = EscrowState {
            order: order,
            user_deposited: order.user_amount,
            resolver_locked: order.resolver_amount,
            creation_timestamp: current_time,
            status: STATUS_ACTIVE,
        };
        
        table::add(&mut contract.active_escrows, order_hash, escrow_state);
    }

    /// Resolver reveals secret to claim funds (happy path)
    public entry fun resolve_with_secret(
        resolver: &signer,
        order_hash: vector<u8>,
        secret: vector<u8>,
    ) acquires HTLCContract {
        let resolver_addr = signer::address_of(resolver);
        let contract = borrow_global_mut<HTLCContract>(@htlc_addr);
        
        assert!(table::contains(&contract.active_escrows, order_hash), error::not_found(E_ESCROW_NOT_FOUND));
        let escrow = table::borrow_mut(&mut contract.active_escrows, order_hash);
        assert!(escrow.status == STATUS_ACTIVE, error::invalid_state(E_ESCROW_ALREADY_RESOLVED));
        assert!(resolver_addr == escrow.order.resolver_address, error::permission_denied(E_NOT_AUTHORIZED));
        
        // Verify secret
        let secret_hash = aptos_hash::blake2b_256(secret);
        assert!(secret_hash == escrow.order.secret_hash, error::invalid_argument(E_INVALID_SECRET));
        
        // Mark as resolved
        escrow.status = STATUS_RESOLVED;
        
        // Transfer funds to resolver
        let total_amount = escrow.user_deposited + escrow.resolver_locked;
        coin::transfer<AptosCoin>(&get_contract_signer(), resolver_addr, total_amount);
    }

    /// Resolver exits early, accepts penalty
    public entry fun resolve_early_exit(
        order_hash: vector<u8>,
        resolver_signature: vector<u8>,
    ) acquires HTLCContract {
        let contract = borrow_global_mut<HTLCContract>(@htlc_addr);
        
        assert!(table::contains(&contract.active_escrows, order_hash), error::not_found(E_ESCROW_NOT_FOUND));
        let escrow = table::borrow_mut(&mut contract.active_escrows, order_hash);
        assert!(escrow.status == STATUS_ACTIVE, error::invalid_state(E_ESCROW_ALREADY_RESOLVED));
        
        // Verify resolver signature on "early exit" message
        let exit_message = b"EARLY_EXIT";
        vector::append(&mut exit_message, order_hash);
        verify_signature(&exit_message, &resolver_signature, &escrow.order.resolver_public_key);
        
        // Mark as resolved
        escrow.status = STATUS_RESOLVED;
        
        // Transfer all funds to user (user gets back their money + resolver penalty)
        let total_amount = escrow.user_deposited + escrow.resolver_locked;
        coin::transfer<AptosCoin>(&get_contract_signer(), escrow.order.user_address, total_amount);
    }

    /// Arbitrator resolves dispute  
    public entry fun resolve_with_arbitrator(
        order_hash: vector<u8>,
        success: bool,
        arbitrator_signature: vector<u8>,
        arbitrator_public_key: vector<u8>,  // Arbitrator PK not stored in order
    ) acquires HTLCContract {
        let contract = borrow_global_mut<HTLCContract>(@htlc_addr);
        
        assert!(table::contains(&contract.active_escrows, order_hash), error::not_found(E_ESCROW_NOT_FOUND));
        let escrow = table::borrow_mut(&mut contract.active_escrows, order_hash);
        assert!(escrow.status == STATUS_ACTIVE, error::invalid_state(E_ESCROW_ALREADY_RESOLVED));
        
        // Verify arbitrator signature
        let decision_message = if (success) b"SUCCESS" else b"FAILURE";
        vector::append(&mut decision_message, order_hash);
        verify_signature(&decision_message, &arbitrator_signature, &arbitrator_public_key);
        
        // Mark as resolved
        escrow.status = STATUS_RESOLVED;
        
        if (success) {
            // Resolver wins: gets user funds + (resolver amount - usage fee)
            let resolver_gets = escrow.user_deposited + (escrow.resolver_locked - escrow.order.arbitrator_usage_fee);
            coin::transfer<AptosCoin>(&get_contract_signer(), escrow.order.resolver_address, resolver_gets);
            coin::transfer<AptosCoin>(&get_contract_signer(), escrow.order.arbitrator_address, escrow.order.arbitrator_usage_fee);
        } else {
            // User wins: gets their money back + full resolver penalty
            let total_amount = escrow.user_deposited + escrow.resolver_locked;
            coin::transfer<AptosCoin>(&get_contract_signer(), escrow.order.user_address, total_amount);
        };
    }

    /// User claims timeout refund
    public entry fun claim_timeout_refund(
        user: &signer,
        order_hash: vector<u8>,
    ) acquires HTLCContract {
        let user_addr = signer::address_of(user);
        let contract = borrow_global_mut<HTLCContract>(@htlc_addr);
        let current_time = timestamp::now_seconds();
        
        assert!(table::contains(&contract.active_escrows, order_hash), error::not_found(E_ESCROW_NOT_FOUND));
        let escrow = table::borrow_mut(&mut contract.active_escrows, order_hash);
        assert!(escrow.status == STATUS_ACTIVE, error::invalid_state(E_ESCROW_ALREADY_RESOLVED));
        assert!(user_addr == escrow.order.user_address, error::permission_denied(E_NOT_AUTHORIZED));
        
        // Check timeout reached
        assert!(current_time > escrow.order.resolver_action_deadline, error::invalid_argument(E_TIMEOUT_NOT_REACHED));
        
        // Mark as resolved
        escrow.status = STATUS_RESOLVED;
        
        // Transfer all funds to user (user gets back their money + resolver penalty)
        let total_amount = escrow.user_deposited + escrow.resolver_locked;
        coin::transfer<AptosCoin>(&get_contract_signer(), user_addr, total_amount);
    }

    /// Mutual resolution by both parties
    public entry fun resolve_mutual(
        order_hash: vector<u8>,
        user_gets: u64,
        resolver_gets: u64,
        user_signature: vector<u8>,
        resolver_signature: vector<u8>,
    ) acquires HTLCContract {
        let contract = borrow_global_mut<HTLCContract>(@htlc_addr);
        
        assert!(table::contains(&contract.active_escrows, order_hash), error::not_found(E_ESCROW_NOT_FOUND));
        let escrow = table::borrow_mut(&mut contract.active_escrows, order_hash);
        assert!(escrow.status == STATUS_ACTIVE, error::invalid_state(E_ESCROW_ALREADY_RESOLVED));
        
        // Verify total matches available funds
        let total_available = escrow.user_deposited + escrow.resolver_locked;
        assert!(user_gets + resolver_gets == total_available, error::invalid_argument(E_INVALID_ORDER_HASH));
        
        // Create mutual agreement message
        let agreement_message = b"MUTUAL_AGREEMENT:";
        vector::append(&mut agreement_message, order_hash);
        vector::append(&mut agreement_message, vector::empty<u8>());
        // TODO: Serialize user_gets and resolver_gets properly
        
        // Verify both signatures
        verify_signature(&agreement_message, &user_signature, &escrow.order.user_public_key);
        verify_signature(&agreement_message, &resolver_signature, &escrow.order.resolver_public_key);
        
        // Mark as resolved
        escrow.status = STATUS_RESOLVED;
        
        // Transfer funds according to agreement
        if (user_gets > 0) {
            coin::transfer<AptosCoin>(&get_contract_signer(), escrow.order.user_address, user_gets);
        };
        if (resolver_gets > 0) {
            coin::transfer<AptosCoin>(&get_contract_signer(), escrow.order.resolver_address, resolver_gets);
        };
    }

    // Helper functions

    /// Hash an order to create unique identifier
    fun hash_order(order: &Order): vector<u8> {
        use std::bcs;
        
        // Serialize the order struct using BCS
        let serialized = bcs::to_bytes(order);
        
        // Hash with Blake2b-256 for efficiency
        aptos_hash::blake2b_256(serialized)
    }

    /// Verify signature on order hash
    fun verify_order_signature(
        order: &Order,
        signature: &vector<u8>,
        public_key: &vector<u8>,
    ) {
        let order_hash = hash_order(order);
        verify_signature(&order_hash, signature, public_key);
    }

    /// Generic signature verification
    fun verify_signature(
        message: &vector<u8>,
        signature: &vector<u8>,
        public_key: &vector<u8>,
    ) {
        // Create Ed25519 objects
        let pk_obj = ed25519::new_unvalidated_public_key_from_bytes(*public_key);
        let sig_obj = ed25519::new_signature_from_bytes(*signature);
        
        // Verify signature
        assert!(ed25519::signature_verify_strict(&sig_obj, &pk_obj, *message), error::invalid_argument(E_INVALID_SIGNATURE));
    }

    /// Get contract signer (placeholder - needs proper implementation)
    fun get_contract_signer(): signer {
        // TODO: Implement proper resource account signer
        // This is a placeholder and won't work in practice
        abort(99)
    }

    // View functions

    #[view]
    public fun get_resolver_balance(resolver: address): u64 acquires HTLCContract {
        let contract = borrow_global<HTLCContract>(@htlc_addr);
        if (table::contains(&contract.resolver_balances, resolver)) {
            *table::borrow(&contract.resolver_balances, resolver)
        } else {
            0
        }
    }

    #[view]
    public fun get_escrow_state(order_hash: vector<u8>): (bool, Order, u64, u64, u64, u8) acquires HTLCContract {
        let contract = borrow_global<HTLCContract>(@htlc_addr);
        if (table::contains(&contract.active_escrows, order_hash)) {
            let escrow = table::borrow(&contract.active_escrows, order_hash);
            (true, escrow.order, escrow.user_deposited, escrow.resolver_locked, escrow.creation_timestamp, escrow.status)
        } else {
            (false, Order {
                user_address: @0x0,
                resolver_address: @0x0,
                user_public_key: vector::empty(),
                resolver_public_key: vector::empty(),
                user_amount: 0,
                resolver_amount: 0,
                venue_address: @0x0,
                venue_fee: 0,
                arbitrator_address: @0x0,
                arbitrator_attention_fee: 0,
                arbitrator_usage_fee: 0,
                secret_hash: vector::empty(),
                submission_deadline: 0,
                resolver_action_deadline: 0,
            }, 0, 0, 0, 0)
        }
    }
}