module htlc::destination_htlc {
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_framework::timestamp;
    use aptos_framework::event;
    use aptos_framework::table::{Self, Table};
    use aptos_framework::account;
    use std::hash;
    use std::signer;

    /// Error codes
    const E_HTLC_NOT_FOUND: u64 = 1;
    const E_NOT_EXPIRED: u64 = 3;
    const E_ALREADY_CLAIMED: u64 = 4;
    const E_DUPLICATE_HTLC: u64 = 5;

    /// Stores the resource account's signer capability
    /// This is stored at the module deployer's address, not the resource account
    struct SignerCapability has key {
        cap: account::SignerCapability
    }

    /// Global registry for all HTLCs, stored at the resource account
    struct HTLCRegistry has key {
        htlcs: Table<vector<u8>, HTLC>
    }

    /// Simple HTLC structure
    struct HTLC has store {
        user_address: address,
        resolver_address: address,
        locked_funds: Coin<AptosCoin>,
        deadline: u64,
        claimed: bool,
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

    /// This runs automatically when the module is first published
    /// Creates a resource account and stores the capability
    fun init_module(deployer: &signer) {
        // Create a resource account with a deterministic seed
        let (resource_signer, signer_cap) = account::create_resource_account(
            deployer, 
            b"htlc::destination_htlc"  // Fixed seed ensures deterministic address
        );
        
        // Initialize the registry on the resource account
        move_to(&resource_signer, HTLCRegistry {
            htlcs: table::new()
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

    /// Create a new HTLC (resolver deposits funds)
    public entry fun create_htlc(
        resolver: &signer,
        secret_hash: vector<u8>,
        user_address: address,
        amount: u64,
        deadline: u64
    ) acquires SignerCapability, HTLCRegistry {
        let resolver_addr = signer::address_of(resolver);
        
        // Ensure deadline is in the future
        assert!(deadline > timestamp::now_seconds(), E_NOT_EXPIRED);
        
        // Get the resource account address
        let resource_addr = get_registry_address();
        let registry = borrow_global_mut<HTLCRegistry>(resource_addr);
        
        // Ensure HTLC doesn't already exist for this secret_hash
        assert!(!table::contains(&registry.htlcs, secret_hash), E_DUPLICATE_HTLC);
        
        // Withdraw funds from resolver
        let locked_funds = coin::withdraw<AptosCoin>(resolver, amount);
        
        // Create HTLC struct
        let htlc = HTLC {
            user_address,
            resolver_address: resolver_addr,
            locked_funds,
            deadline,
            claimed: false,
        };
        
        // Store HTLC in registry
        table::add(&mut registry.htlcs, secret_hash, htlc);
        
        // Emit event
        event::emit(HTLCCreated {
            secret_hash,
            user_address,
            resolver_address: resolver_addr,
            amount,
            deadline,
        });
    }

    /// Anyone can reveal secret to send funds to user (gasless for user!)
    public entry fun reveal_secret(
        _caller: &signer,
        secret: vector<u8>
    ) acquires SignerCapability, HTLCRegistry {
        let secret_hash = hash::sha3_256(secret);
    
        let resource_addr = get_registry_address();
        let registry = borrow_global_mut<HTLCRegistry>(resource_addr);
        assert!(table::contains(&registry.htlcs, secret_hash), E_HTLC_NOT_FOUND);
        
        let htlc = table::borrow_mut(&mut registry.htlcs, secret_hash);
        
        // Verify not already claimed
        assert!(!htlc.claimed, E_ALREADY_CLAIMED);
        
        // Mark as claimed
        htlc.claimed = true;
        
        // Get amount for event
        let amount = coin::value(&htlc.locked_funds);
        let user_address = htlc.user_address;
        
        // Transfer funds to user
        let funds = coin::extract_all(&mut htlc.locked_funds);
        coin::deposit(user_address, funds);
        
        // Emit event
        event::emit(SecretRevealed {
            secret_hash,
            secret,
            user_address,
            amount,
        });
    }

    /// Resolver claims refund after timeout
    public entry fun claim_refund(
        secret_hash: vector<u8>
    ) acquires SignerCapability, HTLCRegistry {
        let resource_addr = get_registry_address();
        let registry = borrow_global_mut<HTLCRegistry>(resource_addr);
        assert!(table::contains(&registry.htlcs, secret_hash), E_HTLC_NOT_FOUND);
        
        let htlc = table::borrow_mut(&mut registry.htlcs, secret_hash);
        
        // Verify not already claimed
        assert!(!htlc.claimed, E_ALREADY_CLAIMED);
        
        // Verify deadline has passed
        assert!(timestamp::now_seconds() >= htlc.deadline, E_NOT_EXPIRED);
        
        // Mark as claimed
        htlc.claimed = true;
        
        // Get values for event and refund
        let amount = coin::value(&htlc.locked_funds);
        let resolver_address = htlc.resolver_address;
        
        // Return funds to resolver
        let funds = coin::extract_all(&mut htlc.locked_funds);
        coin::deposit(resolver_address, funds);
        
        // Emit event
        event::emit(HTLCRefunded {
            secret_hash,
            resolver_address,
            amount,
        });
    }

    #[view]
    public fun get_htlc_info(secret_hash: vector<u8>): (address, address, u64, u64, bool) acquires SignerCapability, HTLCRegistry {
        let resource_addr = get_registry_address();
        let registry = borrow_global<HTLCRegistry>(resource_addr);
        assert!(table::contains(&registry.htlcs, secret_hash), E_HTLC_NOT_FOUND);
        
        let htlc = table::borrow(&registry.htlcs, secret_hash);
        (
            htlc.user_address,
            htlc.resolver_address,
            coin::value(&htlc.locked_funds),
            htlc.deadline,
            htlc.claimed
        )
    }

    #[view]
    public fun htlc_exists(secret_hash: vector<u8>): bool acquires SignerCapability, HTLCRegistry {
        let resource_addr = get_registry_address();
        if (!exists<HTLCRegistry>(resource_addr)) {
            return false
        };
        
        let registry = borrow_global<HTLCRegistry>(resource_addr);
        table::contains(&registry.htlcs, secret_hash)
    }

    #[view]
    public fun hash_secret(secret: vector<u8>): vector<u8> {
        hash::sha3_256(secret)
    }
}
