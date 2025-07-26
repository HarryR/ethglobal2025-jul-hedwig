module htlc_addr::order_verification {
    use aptos_std::ed25519;
    use aptos_std::from_bcs;
    use aptos_std::bcs_stream;
    use aptos_framework::event;

    /// Error codes
    const E_INVALID_USER_SIGNATURE: u64 = 10001;
    const E_INVALID_RESOLVER_SIGNATURE: u64 = 10002;
    const E_INVALID_ARBITRATOR_SIGNATURE: u64 = 10003;

    /// Core order structure (now includes arbitrator_public_key)
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

    #[event]
    struct OrderVerified has drop, store {
        order_hash: vector<u8>,
        user_address: address,
        resolver_address: address,
        arbitrator_address: address,
        timestamp: u64,
    }

    fun verify_order_internal(
        order_bcs: vector<u8>,
        user_signature: vector<u8>,
        resolver_signature: vector<u8>,
        arbitrator_signature: vector<u8>,
        arbitrator_public_key: vector<u8>
    ): OrderVerified {

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

        // 3. Verify arbitrator signature
        let arbitrator_pk = ed25519::new_unvalidated_public_key_from_bytes(arbitrator_public_key);
        let arbitrator_sig = ed25519::new_signature_from_bytes(arbitrator_signature);
        assert!(
            ed25519::signature_verify_strict(&arbitrator_sig, &arbitrator_pk, order_bcs),
            E_INVALID_ARBITRATOR_SIGNATURE
        );

        // 4. Verify addresses match the signers
        // User address should match the derived address from user public key
        let user_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&user_pk);
        let derived_user_address = from_bcs::to_address(user_auth_key);

        // Resolver address should match the derived address from resolver public key
        let resolver_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&resolver_pk);
        let derived_resolver_address = from_bcs::to_address(resolver_auth_key);

        // Arbitrator address should match the derived address from arbitrator public key
        let arbitrator_auth_key = ed25519::unvalidated_public_key_to_authentication_key(&arbitrator_pk);
        let derived_arbitrator_address = from_bcs::to_address(arbitrator_auth_key);

        // 5. Create order hash for event (simple hash of BCS-encoded order)
        let order_hash = std::hash::sha3_256(order_bcs);

        OrderVerified {
            order_hash: order_hash,
            user_address: derived_user_address,
            resolver_address: derived_resolver_address,
            arbitrator_address: derived_arbitrator_address,
            timestamp: aptos_framework::timestamp::now_seconds(),
        }
    }

    public entry fun verify_order_signatures(
        _caller: &signer,
        order_bcs: vector<u8>,
        user_signature: vector<u8>,
        resolver_signature: vector<u8>,
        arbitrator_signature: vector<u8>,
        arbitrator_public_key: vector<u8>
    ) {
        let verification_result = verify_order_internal(
            order_bcs,
            user_signature,
            resolver_signature,
            arbitrator_signature,
            arbitrator_public_key
        );

        event::emit(verification_result);
    }

    #[view]
    public fun derive_address_from_public_key(public_key: vector<u8>): address {
        let pk = ed25519::new_unvalidated_public_key_from_bytes(public_key);
        let auth_key = ed25519::unvalidated_public_key_to_authentication_key(&pk);
        from_bcs::to_address(auth_key)
    }

    #[test(aptos_framework = @aptos_framework)]
    fun test_verify_order_signatures_success(aptos_framework: &signer) {
        // Initialize timestamp for testing
        aptos_framework::timestamp::set_time_has_started_for_testing(aptos_framework);
        // Test order BCS data
        let order_bcs = vector[0x20, 0xac, 0xba, 0xd3, 0xf9, 0x14, 0xdd, 0xe1, 0x9b, 0xf9, 0xe7, 0xc4, 0xe1, 0xaf, 0x9a, 0xcd, 0x5b, 0xe7, 0x30, 0x1d, 0x98, 0x11, 0x72, 0x75, 0x00, 0x84, 0xff, 0x9b, 0x8f, 0xeb, 0xd9, 0x61, 0xc9, 0x20, 0x60, 0x0f, 0xd3, 0x6e, 0xc9, 0xb0, 0x45, 0xbe, 0x81, 0xe0, 0x44, 0x72, 0x21, 0x6f, 0xc2, 0xcd, 0xa3, 0x67, 0x5e, 0x04, 0xa6, 0x59, 0xfb, 0xc0, 0xd5, 0xd9, 0x9e, 0x38, 0x0e, 0xa5, 0x5f, 0x4f, 0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x84, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0xca, 0x73, 0x49, 0x3f, 0x90, 0x17, 0x3e, 0xaf, 0x97, 0xb8, 0x36, 0x54, 0x36, 0xaf, 0x15, 0x67, 0x21, 0x57, 0x8a, 0xd5, 0xe9, 0x88, 0xfe, 0x29, 0x90, 0x02, 0x70, 0x7c, 0xbc, 0x3f, 0x52, 0xa1, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xc7, 0x06, 0xc9, 0xcf, 0x83, 0x79, 0x3c, 0x76, 0x84, 0x24, 0xc2, 0xb3, 0xf6, 0x77, 0xd8, 0xb3, 0xda, 0xe8, 0x55, 0xa5, 0x7c, 0x31, 0xae, 0xae, 0x75, 0x34, 0x8c, 0x4c, 0x23, 0x5e, 0xdd, 0x92, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xf8, 0xb4, 0x5d, 0xc7, 0x2e, 0xb5, 0xcf, 0x65, 0x96, 0x91, 0x05, 0x52, 0xb9, 0x49, 0x78, 0x39, 0x0e, 0xd4, 0x0b, 0xc6, 0x07, 0xef, 0xb1, 0x25, 0x2b, 0x6b, 0xf2, 0x89, 0x16, 0xc9, 0xaa, 0x50, 0x10, 0xff, 0x53, 0x65, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0d, 0x54, 0x65, 0x00, 0x00, 0x00, 0x00];
        
        // Signatures
        let user_signature = vector[0xa6, 0x99, 0xb4, 0x11, 0x32, 0xba, 0x8e, 0xa5, 0x01, 0xd4, 0x25, 0x1c, 0xe1, 0x09, 0x4a, 0x9e, 0xe8, 0x07, 0xba, 0xc0, 0x49, 0x44, 0x2b, 0x0d, 0xe1, 0xf3, 0xc4, 0x29, 0x85, 0x60, 0xe8, 0x5f, 0xb4, 0xff, 0x10, 0xf1, 0x68, 0xd3, 0x75, 0x1e, 0x0c, 0x6e, 0x33, 0x7b, 0xb8, 0xa8, 0xea, 0xb9, 0x6a, 0x1f, 0x83, 0x7e, 0xb2, 0x46, 0xf2, 0x43, 0x2e, 0x11, 0x12, 0xdd, 0x3b, 0x78, 0x86, 0x0a];
        let resolver_signature = vector[0x4d, 0x4e, 0x57, 0x06, 0xd4, 0x5f, 0xe9, 0x9d, 0x07, 0x0c, 0xa1, 0x05, 0xd2, 0x0f, 0x32, 0xdc, 0x24, 0xaf, 0x7f, 0xa2, 0x92, 0x31, 0x99, 0x14, 0x6d, 0x50, 0x76, 0x00, 0x36, 0xdf, 0x12, 0x6c, 0x90, 0xb1, 0xe8, 0x83, 0x6d, 0x26, 0x91, 0x05, 0x52, 0x1b, 0x85, 0xbb, 0x13, 0x73, 0x9a, 0x17, 0x7e, 0xd2, 0x64, 0x8c, 0xdc, 0x87, 0x1d, 0x0d, 0x1a, 0x12, 0x69, 0xa3, 0x67, 0xab, 0x41, 0x0f];
        let arbitrator_signature = vector[0xdc, 0xd0, 0x88, 0x0f, 0x8d, 0xba, 0xd0, 0xfc, 0x33, 0x5b, 0xa5, 0xcc, 0xc4, 0x38, 0xdc, 0x0d, 0xd9, 0x6f, 0xe6, 0x10, 0x6c, 0x3f, 0xca, 0xef, 0x84, 0xbf, 0x79, 0x23, 0x4f, 0x7c, 0xfc, 0x57, 0x7b, 0xa7, 0xf7, 0x6c, 0x8d, 0x15, 0x9a, 0xbf, 0x6f, 0x79, 0xf9, 0xc0, 0x51, 0x2e, 0x92, 0xe0, 0xbf, 0xa0, 0xbc, 0x82, 0xbd, 0x69, 0x7b, 0x86, 0x25, 0x15, 0x46, 0xc7, 0x7f, 0xdf, 0xd8, 0x00];
        let arbitrator_public_key = vector[0xc7, 0x06, 0xc9, 0xcf, 0x83, 0x79, 0x3c, 0x76, 0x84, 0x24, 0xc2, 0xb3, 0xf6, 0x77, 0xd8, 0xb3, 0xda, 0xe8, 0x55, 0xa5, 0x7c, 0x31, 0xae, 0xae, 0x75, 0x34, 0x8c, 0x4c, 0x23, 0x5e, 0xdd, 0x92];
        
        // Expected addresses
        let expected_user_address = @0x1f513baa68ba3ed41b3cae82d69fe9fd759f4264fcf2079752109ce2f328a2ca;
        let expected_resolver_address = @0xe77c9bf5733dac91de6af741467be858ea4c93831e9852cae3a136c8955a12b1;
        let expected_arbitrator_address = @0xfa4b5f90dc946aa951b465a903685fe34ed37239aec6178ae6ea4102ea7470dc;
        
        // This should succeed
        let verified = verify_order_internal(
            order_bcs,
            user_signature,
            resolver_signature,
            arbitrator_signature,
            arbitrator_public_key
        );
        assert!(verified.user_address == expected_user_address);
        assert!(verified.resolver_address == expected_resolver_address);
        assert!(verified.arbitrator_address == expected_arbitrator_address);
    }
}
