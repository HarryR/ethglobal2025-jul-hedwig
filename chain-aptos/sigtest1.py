#!/usr/bin/env python3
"""
Python script to create and sign HTLC Order structures matching the Move contract
"""

from os import urandom
import hashlib
from typing import Dict, Any
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.account import Account
from aptos_sdk.bcs import Serializer
from aptos_sdk.account_address import AccountAddress

class HTLCOrder:
    """
    HTLC Order structure matching the Move contract exactly
    """
    def __init__(self,
                 user_public_key: bytes,
                 resolver_public_key: bytes,
                 user_amount: int,
                 resolver_amount: int,
                 venue_address: AccountAddress,
                 venue_fee: int,
                 arbitrator_public_key: bytes,  # THIS WAS MISSING!
                 arbitrator_attention_fee: int,
                 arbitrator_usage_fee: int,
                 secret_hash: bytes,
                 submission_deadline: int,
                 resolver_action_deadline: int,
                 destination_chain: bytes,
                 destination_address: bytes):
        self.user_public_key = user_public_key
        self.resolver_public_key = resolver_public_key
        self.user_amount = user_amount
        self.resolver_amount = resolver_amount
        self.venue_address = venue_address
        self.venue_fee = venue_fee
        self.arbitrator_public_key = arbitrator_public_key  # Added this field
        self.arbitrator_attention_fee = arbitrator_attention_fee
        self.arbitrator_usage_fee = arbitrator_usage_fee
        self.secret_hash = secret_hash
        self.submission_deadline = submission_deadline
        self.resolver_action_deadline = resolver_action_deadline
        self.destination_chain = destination_chain
        self.destination_address = destination_address

    def to_bcs(self) -> bytes:
        """
        Serialize the order to BCS format matching the Move struct exactly
        """
        serializer = Serializer()
        
        # Serialize fields in exact order as defined in Move struct
        serializer.to_bytes(self.user_public_key)              # vector<u8>
        serializer.to_bytes(self.resolver_public_key)          # vector<u8>
        serializer.u64(self.user_amount)                       # u64
        serializer.u64(self.resolver_amount)                   # u64
        serializer.struct(self.venue_address)                  # address
        serializer.u64(self.venue_fee)                         # u64
        serializer.to_bytes(self.arbitrator_public_key)        # vector<u8> - ADDED THIS
        serializer.u64(self.arbitrator_attention_fee)          # u64
        serializer.u64(self.arbitrator_usage_fee)              # u64
        serializer.to_bytes(self.secret_hash)                  # vector<u8>
        serializer.u64(self.submission_deadline)               # u64
        serializer.u64(self.resolver_action_deadline)          # u64
        serializer.to_bytes(self.destination_chain)            # vector<u8>
        serializer.to_bytes(self.destination_address)          # vector<u8>
        
        return serializer.output()

    def hash(self) -> bytes:
        """
        Create SHA3-256 hash of the BCS-encoded order
        """
        bcs_data = self.to_bcs()
        return hashlib.sha3_256(bcs_data).digest()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON serialization
        """
        return {
            "user_public_key": self.user_public_key.hex(),
            "resolver_public_key": self.resolver_public_key.hex(),
            "user_amount": self.user_amount,
            "resolver_amount": self.resolver_amount,
            "venue_address": str(self.venue_address),
            "venue_fee": self.venue_fee,
            "arbitrator_public_key": self.arbitrator_public_key.hex(),  # Added this
            "arbitrator_attention_fee": self.arbitrator_attention_fee,
            "arbitrator_usage_fee": self.arbitrator_usage_fee,
            "secret_hash": self.secret_hash.hex(),
            "submission_deadline": self.submission_deadline,
            "resolver_action_deadline": self.resolver_action_deadline,
            "destination_chain": self.destination_chain.hex(),
            "destination_address": self.destination_address.hex()
        }

def create_test_order_and_sign() -> Dict[str, Any]:
    """
    Create a test HTLC order with deterministic values for testing
    """
    # Generate three accounts
    user_account = Account.generate()
    resolver_account = Account.generate() 
    arbitrator_account = Account.generate()
    venue_account = Account.generate()
    
    # Create deterministic secret for testing
    secret = b"test_secret_for_htlc_verification_32"  # 32 bytes
    secret_hash = hashlib.sha3_256(secret).digest()

    destination_chain = urandom(32)
    destination_address = urandom(20)
    
    # Use fixed timestamp for testing
    current_time = 1700000000  # Fixed timestamp for reproducible tests
    
    # Create the order
    order = HTLCOrder(
        user_public_key=bytes(user_account.public_key().to_crypto_bytes()),
        resolver_public_key=bytes(resolver_account.public_key().to_crypto_bytes()),
        user_amount=1000000,  # 1M
        resolver_amount=2000000,  # 2M
        venue_address=venue_account.address(),
        venue_fee=50,
        arbitrator_public_key=bytes(arbitrator_account.public_key().to_crypto_bytes()),  # Fixed this
        arbitrator_attention_fee=25,
        arbitrator_usage_fee=100,
        secret_hash=secret_hash,
        submission_deadline=current_time + 3600,
        resolver_action_deadline=current_time + 7200,
        destination_chain=destination_chain,
        destination_address=destination_address,
    )
    
    # Get BCS-encoded order for signing
    order_bcs = order.to_bcs()
    
    # Sign the order with all three parties
    user_signature = user_account.sign(order_bcs)
    resolver_signature = resolver_account.sign(order_bcs)
    arbitrator_signature = arbitrator_account.sign(order_bcs)
    
    print("=== Test HTLC Order Created and Signed ===")
    print(f"Order hash: {order.hash().hex()}")
    print(f"Order BCS length: {len(order_bcs)} bytes")
    print(f"User address: {user_account.address()}")
    print(f"Resolver address: {resolver_account.address()}")
    print(f"Arbitrator address: {arbitrator_account.address()}")
    print()
    
    return {
        "order": order.to_dict(),
        "order_bcs": order_bcs.hex(),
        "order_hash": order.hash().hex(),
        "secret": secret.hex(),
        "signatures": {
            "user_signature": str(user_signature),
            "resolver_signature": str(resolver_signature),
            "arbitrator_signature": str(arbitrator_signature)
        },
        "accounts": {
            "user_private_key": str(user_account.private_key),
            "resolver_private_key": str(resolver_account.private_key),
            "arbitrator_private_key": str(arbitrator_account.private_key),
            "venue_private_key": str(venue_account.private_key),            
        },
        "public_keys": {
            "user_address": user_account.auth_key(),            
            "user_public_key": str(user_account.public_key()),
            "resolver_public_key": str(resolver_account.public_key()),
            "resolver_address": resolver_account.auth_key(),
            "arbitrator_public_key": str(arbitrator_account.public_key()),
            "arbitrator_address": arbitrator_account.auth_key(),
            "venue_public_key": str(venue_account.public_key()),
            "venue_address": venue_account.auth_key(),
        }
    }

def generate_move_test_constants(order_data: Dict[str, Any]) -> str:
    """
    Generate Move test constants that can be embedded in your test file
    """
    order_bcs = order_data["order_bcs"]
    user_sig = order_data["signatures"]["user_signature"][2:]  # Remove 0x
    resolver_sig = order_data["signatures"]["resolver_signature"][2:]
    
    # Convert hex strings to Move vector format
    def hex_to_move_vector(hex_str: str) -> str:
        bytes_list = [f"0x{hex_str[i:i+2]}" for i in range(0, len(hex_str), 2)]
        return f"vector[{', '.join(bytes_list)}]"
    
    move_test = f"""
    // Test constants for HTLC order verification
    // Generated by Python script - embed these in your Move tests
    
    #[test(aptos_framework = @aptos_framework)]
    fun test_verify_order_signatures_success(aptos_framework: &signer) {{
        // Initialize timestamp for testing
        aptos_framework::timestamp::set_time_has_started_for_testing(aptos_framework);
        let order_bcs = {hex_to_move_vector(order_bcs)};
        
        // Signatures
        let user_signature = {hex_to_move_vector(user_sig)};
        let resolver_signature = {hex_to_move_vector(resolver_sig)};
        
        // Expected addresses
        let expected_user_address = @0x{order_data['public_keys']['user_address'][2:]};
        let expected_resolver_address = @0x{order_data['public_keys']['resolver_address'][2:]};
        let expected_arbitrator_address = @0x{order_data['public_keys']['arbitrator_address'][2:]};
    
        // This should succeed
        let (_, verified) = verify_order_internal(
            order_bcs,
            user_signature,
            resolver_signature
        );

        assert!(verified.user_address == expected_user_address);
        assert!(verified.resolver_address == expected_resolver_address);
        assert!(verified.arbitrator_address == expected_arbitrator_address);
    }}
    
    // Test data breakdown:
    // User amount: {order_data['order']['user_amount']}
    // Resolver amount: {order_data['order']['resolver_amount']}
    // Venue fee: {order_data['order']['venue_fee']}
    // Arbitrator attention fee: {order_data['order']['arbitrator_attention_fee']}
    // Arbitrator usage fee: {order_data['order']['arbitrator_usage_fee']}
    // Submission deadline: {order_data['order']['submission_deadline']}
    // Resolver action deadline: {order_data['order']['resolver_action_deadline']}
    // Secret hash: {order_data['order']['secret_hash']}
    """
    
    return move_test

def main():
    """
    Main function to generate test data for Move contract
    """
    print("Generating test HTLC order for Move contract embedding...\n")
    
    # Create test order and sign it
    order_data = create_test_order_and_sign()
    
    # Generate Move test code
    move_test_code = generate_move_test_constants(order_data)
    
    print("=== Move Test Code ===")
    print(move_test_code)
    
    # Save everything
    #import json
    #with open("htlc_test_data.json", "w") as f:
    #    json.dump(order_data, f, indent=2)

if __name__ == "__main__":
    main()