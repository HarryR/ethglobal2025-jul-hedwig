module htlc_addr::destination_htlc {
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::timestamp;
    use aptos_framework::event;
    use std::hash;
    use std::signer;

    /// Error codes
    const E_HTLC_NOT_FOUND: u64 = 1;
    const E_INVALID_SECRET: u64 = 2;
    const E_NOT_EXPIRED: u64 = 3;
    const E_ALREADY_CLAIMED: u64 = 4;
    const E_UNAUTHORIZED: u64 = 5;
    const E_INSUFFICIENT_FUNDS: u64 = 6;

    /// Simple HTLC structure
    struct HTLC has key {
        secret_hash: vector<u8>,       // 32-byte hash - acts as order ID
        user_address: address,         // Gets funds on secret reveal
        resolver_address: address,     // Gets refund on timeout
        locked_funds: Coin<AptosCoin>, // The actual locked coins
        deadline: u64,                 // When resolver can claim refund
        claimed: bool,                 // Prevent double claims
    }

    #[event]
    struct HTLCCreated has drop, store {
        secret_hash: vector<u8>,
        user_address: address,
        resolver_address: address,
        amount: u64,
        deadline: u64,
    }

    #[event]
    struct SecretRevealed has drop, store {
        secret_hash: vector<u8>,
        secret: vector<u8>,
        user_address: address,
        amount: u64,
    }

    #[event]
    struct HTLCRefunded has drop, store {
        secret_hash: vector<u8>,
        resolver_address: address,
        amount: u64,
    }

    /// Create a new HTLC (resolver deposits funds)
    public entry fun create_htlc(
        resolver: &signer,
        secret_hash: vector<u8>,
        user_address: address,
        amount: u64,
        deadline: u64
    ) {
        let resolver_addr = signer::address_of(resolver);
        
        // Ensure deadline is in the future
        assert!(deadline > timestamp::now_seconds(), E_NOT_EXPIRED);
        
        // Withdraw funds from resolver
        let locked_funds = coin::withdraw<AptosCoin>(resolver, amount);
        
        // Create HTLC struct
        let htlc = HTLC {
            secret_hash,
            user_address,
            resolver_address: resolver_addr,
            locked_funds,
            deadline,
            claimed: false,
        };
        
        // Store HTLC at resolver's address with secret_hash as key
        // Note: This is simplified - in practice you might want a different storage strategy
        move_to(resolver, htlc);
        
        // Emit event
        event::emit(HTLCCreated {
            secret_hash,
            user_address,
            resolver_address: resolver_addr,
            amount,
            deadline,
        });
    }

    /// User reveals secret to claim funds
    public entry fun reveal_secret(
        user: &signer,
        resolver_address: address,
        secret: vector<u8>
    ) acquires HTLC {
        let user_addr = signer::address_of(user);
        
        // Check if HTLC exists
        assert!(exists<HTLC>(resolver_address), E_HTLC_NOT_FOUND);
        
        let htlc = borrow_global_mut<HTLC>(resolver_address);
        
        // Verify user is authorized
        assert!(htlc.user_address == user_addr, E_UNAUTHORIZED);
        
        // Verify not already claimed
        assert!(!htlc.claimed, E_ALREADY_CLAIMED);
        
        // Verify secret matches hash
        let computed_hash = hash::sha3_256(secret);
        assert!(computed_hash == htlc.secret_hash, E_INVALID_SECRET);
        
        // Mark as claimed
        htlc.claimed = true;
        
        // Get amount for event
        let amount = coin::value(&htlc.locked_funds);
        
        // Transfer funds to user
        let funds = coin::extract_all(&mut htlc.locked_funds);
        coin::deposit(user_addr, funds);
        
        // Emit event
        event::emit(SecretRevealed {
            secret_hash: htlc.secret_hash,
            secret,
            user_address: user_addr,
            amount,
        });
    }

    /// Resolver claims refund after timeout
    public entry fun claim_refund(
        resolver: &signer,
    ) acquires HTLC {
        let resolver_addr = signer::address_of(resolver);
        
        // Check if HTLC exists
        assert!(exists<HTLC>(resolver_addr), E_HTLC_NOT_FOUND);
        
        let htlc = borrow_global_mut<HTLC>(resolver_addr);
        
        // Verify not already claimed
        assert!(!htlc.claimed, E_ALREADY_CLAIMED);
        
        // Verify deadline has passed
        assert!(timestamp::now_seconds() >= htlc.deadline, E_NOT_EXPIRED);
        
        // Mark as claimed
        htlc.claimed = true;
        
        // Get amount for event
        let amount = coin::value(&htlc.locked_funds);
        
        // Return funds to resolver
        let funds = coin::extract_all(&mut htlc.locked_funds);
        coin::deposit(resolver_addr, funds);
        
        // Emit event
        event::emit(HTLCRefunded {
            secret_hash: htlc.secret_hash,
            resolver_address: resolver_addr,
            amount,
        });
    }

    #[view]
    public fun get_htlc_info(resolver_address: address): (vector<u8>, address, address, u64, u64, bool) acquires HTLC {
        assert!(exists<HTLC>(resolver_address), E_HTLC_NOT_FOUND);
        
        let htlc = borrow_global<HTLC>(resolver_address);
        (
            htlc.secret_hash,
            htlc.user_address,
            htlc.resolver_address,
            coin::value(&htlc.locked_funds),
            htlc.deadline,
            htlc.claimed
        )
    }

    #[view]
    public fun htlc_exists(resolver_address: address): bool {
        exists<HTLC>(resolver_address)
    }

    #[view]
    public fun hash_secret(secret: vector<u8>): vector<u8> {
        hash::sha3_256(secret)
    }
}
