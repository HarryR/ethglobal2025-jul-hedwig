module htlc_verify_test1::order_verification {
    use aptos_std::ed25519;
    use aptos_std::from_bcs;
    use aptos_std::bcs_stream;
    use aptos_framework::event;
    use std::vector;

    /// Error codes
    const E_INVALID_USER_SIGNATURE: u64 = 1;
    const E_INVALID_RESOLVER_SIGNATURE: u64 = 2;
    const E_INVALID_ARBITRATOR_SIGNATURE: u64 = 3;
    const E_ADDRESS_MISMATCH: u64 = 4;

    /// Core order structure (now includes arbitrator_public_key)
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
        arbitrator_public_key: vector<u8>, // 32-byte Ed25519 public key (ADDED)
        arbitrator_attention_fee: u64,
        arbitrator_usage_fee: u64,
        secret_hash: vector<u8>,
        submission_deadline: u64,
        resolver_action_deadline: u64,
    }

    /// Decode Order struct from BCS stream
    fun decode_order(stream: &mut bcs_stream::BCSStream): Order {
        Order {
            user_address: bcs_stream::deserialize_address(stream),
            resolver_address: bcs_stream::deserialize_address(stream),
            user_public_key: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            resolver_public_key: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            user_amount: bcs_stream::deserialize_u64(stream),
            resolver_amount: bcs_stream::deserialize_u64(stream),
            venue_address: bcs_stream::deserialize_address(stream),
            venue_fee: bcs_stream::deserialize_u64(stream),
            arbitrator_address: bcs_stream::deserialize_address(stream),
            arbitrator_public_key: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            arbitrator_attention_fee: bcs_stream::deserialize_u64(stream),
            arbitrator_usage_fee: bcs_stream::deserialize_u64(stream),
            secret_hash: bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s)),
            submission_deadline: bcs_stream::deserialize_u64(stream),
            resolver_action_deadline: bcs_stream::deserialize_u64(stream),
        }
    }

    #[event]
    struct OrderVerified has drop, store {
        order_hash: vector<u8>,
        user_address: address,
        resolver_address: address,
        arbitrator_address: address,
        timestamp: u64,
    }

    /// Extract a fixed number of bytes from the vector starting at offset
    fun extract_bytes(data: &vector<u8>, offset: &mut u64, length: u64): vector<u8> {
        let result = vector::empty<u8>();
        let i = 0;
        while (i < length) {
            vector::push_back(&mut result, *vector::borrow(data, (*offset + i)));
            i = i + 1;
        };
        *offset = *offset + length;
        result
    }
    
    /// Extract a vector<u8> (with ULEB128 length prefix)
    fun extract_vector(data: &vector<u8>, offset: &mut u64): vector<u8> {
        // For simplicity, assume length is encoded as a single byte (works for lengths < 128)
        let length = (*vector::borrow(data, *offset) as u64);
        *offset = *offset + 1;
        extract_bytes(data, offset, length)
    }
    
    /// Extract a u64 value (8 bytes little endian)
    fun extract_u64(data: &vector<u8>, offset: &mut u64): u64 {
        let bytes = extract_bytes(data, offset, 8);
        from_bcs::to_u64(bytes)
    }
    public entry fun verify_order_signatures(
        _caller: &signer,
        order_bcs: vector<u8>,
        user_signature: vector<u8>,
        resolver_signature: vector<u8>,
        arbitrator_signature: vector<u8>,
        arbitrator_public_key: vector<u8>
    ) {
        // Deserialize the BCS-encoded order
        let order = decode_order(&mut bcs_stream::new(order_bcs));
        
        // 1. Verify user signature
        let user_pk = ed25519::new_unvalidated_public_key_from_bytes(order.user_public_key);
        let user_sig = ed25519::new_signature_from_bytes(user_signature);
        assert!(
            ed25519::signature_verify_strict_t(&user_sig, &user_pk, order),
            E_INVALID_USER_SIGNATURE
        );

        // 2. Verify resolver signature  
        let resolver_pk = ed25519::new_unvalidated_public_key_from_bytes(order.resolver_public_key);
        let resolver_sig = ed25519::new_signature_from_bytes(resolver_signature);
        assert!(
            ed25519::signature_verify_strict_t(&resolver_sig, &resolver_pk, order),
            E_INVALID_RESOLVER_SIGNATURE
        );

        // 3. Verify arbitrator signature
        let arbitrator_pk = ed25519::new_unvalidated_public_key_from_bytes(arbitrator_public_key);
        let arbitrator_sig = ed25519::new_signature_from_bytes(arbitrator_signature);
        assert!(
            ed25519::signature_verify_strict_t(&arbitrator_sig, &arbitrator_pk, order),
            E_INVALID_ARBITRATOR_SIGNATURE
        );

        // 4. Verify addresses match the signers
        // User address should match the derived address from user public key
        let user_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&user_pk);
        let derived_user_address = from_bcs::to_address(user_auth_key);
        assert!(derived_user_address == order.user_address, E_ADDRESS_MISMATCH);

        // Resolver address should match the derived address from resolver public key
        let resolver_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&resolver_pk);
        let derived_resolver_address = from_bcs::to_address(resolver_auth_key);
        assert!(derived_resolver_address == order.resolver_address, E_ADDRESS_MISMATCH);

        // Arbitrator address should match the derived address from arbitrator public key
        let arbitrator_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&arbitrator_pk);
        let derived_arbitrator_address = from_bcs::to_address(arbitrator_auth_key);
        assert!(derived_arbitrator_address == order.arbitrator_address, E_ADDRESS_MISMATCH);

        // 5. Create order hash for event (simple hash of BCS-encoded order)
        let order_hash = std::hash::sha3_256(order_bcs);

        // 6. Emit verification event
        event::emit(OrderVerified {
            order_hash,
            user_address: order.user_address,
            resolver_address: order.resolver_address,
            arbitrator_address: order.arbitrator_address,
            timestamp: aptos_framework::timestamp::now_seconds(),
        });
    }

    #[view]
    public fun derive_address_from_public_key(public_key: vector<u8>): address {
        let pk = ed25519::new_unvalidated_public_key_from_bytes(public_key);
        let auth_key = ed25519::unvalidated_public_key_to_authentication_key(&pk);
        from_bcs::to_address(auth_key)
    }

    #[view]
    public fun hash_order(order_bcs: vector<u8>): vector<u8> {
        std::hash::sha3_256(order_bcs)
    }

    //#[test_only]
    //use aptos_framework::account as test_account;

    #[test]
    fun test_order_verification() {
        // This test would need to be run with actual signatures
        // For now, it's just a structure test
        let order = Order {
            user_address: @0x1,
            resolver_address: @0x2,
            user_public_key: vector::empty(),
            resolver_public_key: vector::empty(),
            user_amount: 1000,
            resolver_amount: 2000,
            venue_address: @0x3,
            venue_fee: 10,
            arbitrator_address: @0x4,
            arbitrator_attention_fee: 5,
            arbitrator_usage_fee: 15,
            secret_hash: b"test_hash",
            submission_deadline: 1234567890,
            resolver_action_deadline: 1234567900,
        };

        let order_hash = hash_order(order);
        assert!(vector::length(&order_hash) == 32, 0); // SHA3-256 produces 32-byte hash
    }
}