#!/usr/bin/env python3
"""
Python script to create and sign HTLC Order structures
"""

import time
import secrets
import hashlib
from typing import Dict, Any, Tuple
from aptos_sdk.account import Account
from aptos_sdk.bcs import Serializer
from aptos_sdk.account_address import AccountAddress

class HTLCOrder:
    """
    HTLC Order structure matching the Move contract
    """
    def __init__(self,
                 user_address: AccountAddress,
                 resolver_address: AccountAddress, 
                 user_public_key: bytes,
                 resolver_public_key: bytes,
                 user_amount: int,
                 resolver_amount: int,
                 venue_address: AccountAddress,
                 venue_fee: int,
                 arbitrator_address: AccountAddress,
                 arbitrator_attention_fee: int,
                 arbitrator_usage_fee: int,
                 secret_hash: bytes,
                 submission_deadline: int,
                 resolver_action_deadline: int):
        
        self.user_address = user_address
        self.resolver_address = resolver_address
        self.user_public_key = user_public_key
        self.resolver_public_key = resolver_public_key
        self.user_amount = user_amount
        self.resolver_amount = resolver_amount
        self.venue_address = venue_address
        self.venue_fee = venue_fee
        self.arbitrator_address = arbitrator_address
        self.arbitrator_attention_fee = arbitrator_attention_fee
        self.arbitrator_usage_fee = arbitrator_usage_fee
        self.secret_hash = secret_hash
        self.submission_deadline = submission_deadline
        self.resolver_action_deadline = resolver_action_deadline

    def to_bcs(self) -> bytes:
        """
        Serialize the order to BCS format matching the Move struct exactly
        """
        serializer = Serializer()
        
        # Serialize fields in exact order as defined in Move struct
        serializer.struct(self.user_address)                    # address
        serializer.struct(self.resolver_address)                # address  
        serializer.to_bytes(self.user_public_key)              # vector<u8>
        serializer.to_bytes(self.resolver_public_key)          # vector<u8>
        serializer.u64(self.user_amount)                       # u64
        serializer.u64(self.resolver_amount)                   # u64
        serializer.struct(self.venue_address)                  # address
        serializer.u64(self.venue_fee)                         # u64
        serializer.struct(self.arbitrator_address)             # address
        serializer.u64(self.arbitrator_attention_fee)          # u64
        serializer.u64(self.arbitrator_usage_fee)              # u64
        serializer.to_bytes(self.secret_hash)                  # vector<u8>
        serializer.u64(self.submission_deadline)               # u64
        serializer.u64(self.resolver_action_deadline)          # u64
        
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
            "user_address": str(self.user_address),
            "resolver_address": str(self.resolver_address),
            "user_public_key": self.user_public_key.hex(),
            "resolver_public_key": self.resolver_public_key.hex(),
            "user_amount": self.user_amount,
            "resolver_amount": self.resolver_amount,
            "venue_address": str(self.venue_address),
            "venue_fee": self.venue_fee,
            "arbitrator_address": str(self.arbitrator_address),
            "arbitrator_attention_fee": self.arbitrator_attention_fee,
            "arbitrator_usage_fee": self.arbitrator_usage_fee,
            "secret_hash": self.secret_hash.hex(),
            "submission_deadline": self.submission_deadline,
            "resolver_action_deadline": self.resolver_action_deadline
        }

def create_random_order_and_sign() -> Dict[str, Any]:
    """
    Create a random HTLC order and sign it with three random keypairs
    """
    # Generate three random accounts
    user_account = Account.generate()
    resolver_account = Account.generate() 
    arbitrator_account = Account.generate()
    
    # Generate random venue address
    venue_account = Account.generate()
    
    # Create random secret and hash it
    secret = secrets.token_bytes(32)
    secret_hash = hashlib.sha3_256(secret).digest()
    
    # Get current timestamp
    current_time = int(time.time())
    
    # Create the order with random data
    order = HTLCOrder(
        user_address=user_account.address(),
        resolver_address=resolver_account.address(),
        user_public_key=bytes(user_account.public_key().to_crypto_bytes()),
        resolver_public_key=bytes(resolver_account.public_key().to_crypto_bytes()),
        user_amount=secrets.randbelow(1000000) + 1000,  # 1000 to 1M
        resolver_amount=secrets.randbelow(2000000) + 2000,  # 2000 to 2M
        venue_address=venue_account.address(),
        venue_fee=secrets.randbelow(100) + 10,  # 10 to 110
        arbitrator_address=arbitrator_account.address(),
        arbitrator_attention_fee=secrets.randbelow(50) + 5,  # 5 to 55
        arbitrator_usage_fee=secrets.randbelow(200) + 20,  # 20 to 220
        secret_hash=secret_hash,
        submission_deadline=current_time + 3600,  # 1 hour from now
        resolver_action_deadline=current_time + 7200  # 2 hours from now
    )
    
    # Get BCS-encoded order for signing
    order_bcs = order.to_bcs()
    
    # Sign the order with all three parties
    user_signature = user_account.sign(order_bcs)
    resolver_signature = resolver_account.sign(order_bcs)
    arbitrator_signature = arbitrator_account.sign(order_bcs)
    
    # Verify signatures locally
    user_valid = user_account.public_key().verify(order_bcs, user_signature)
    resolver_valid = resolver_account.public_key().verify(order_bcs, resolver_signature)
    arbitrator_valid = arbitrator_account.public_key().verify(order_bcs, arbitrator_signature)
    
    print("=== Random HTLC Order Created and Signed ===")
    print(f"Order hash: {order.hash().hex()}")
    print(f"Order BCS length: {len(order_bcs)} bytes")
    print(f"User signature valid: {user_valid}")
    print(f"Resolver signature valid: {resolver_valid}")
    print(f"Arbitrator signature valid: {arbitrator_valid}")
    print()
    
    # Return all the data needed for the Move contract
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
        "private_keys": {
            "user_private_key": str(user_account.private_key),
            "resolver_private_key": str(resolver_account.private_key),
            "arbitrator_private_key": str(arbitrator_account.private_key)
        },
        "public_keys": {
            "user_public_key": str(user_account.public_key()),
            "resolver_public_key": str(resolver_account.public_key()),
            "arbitrator_public_key": str(arbitrator_account.public_key())
        }
    }

def create_move_function_call_data(order_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create the exact function call data for the Move contract
    """
    # Convert order BCS data to bytes
    order_bcs_bytes = bytes.fromhex(order_data["order_bcs"])
    
    # Convert signatures to bytes (remove '0x' prefix)
    user_sig_bytes = bytes.fromhex(order_data["signatures"]["user_signature"][2:])
    resolver_sig_bytes = bytes.fromhex(order_data["signatures"]["resolver_signature"][2:])
    arbitrator_sig_bytes = bytes.fromhex(order_data["signatures"]["arbitrator_signature"][2:])
    arbitrator_pubkey_bytes = bytes.fromhex(order_data["public_keys"]["arbitrator_public_key"][2:])
    
    return {
        "function": "YOUR_MODULE_ADDRESS::order_verification::verify_order_signatures",
        "type_arguments": [],
        "arguments": [
            order_bcs_bytes,         # order_bcs: vector<u8>
            user_sig_bytes,          # user_signature: vector<u8>
            resolver_sig_bytes,      # resolver_signature: vector<u8>
            arbitrator_sig_bytes,    # arbitrator_signature: vector<u8>
            arbitrator_pubkey_bytes  # arbitrator_public_key: vector<u8>
        ]
    }

def verify_signatures_locally(order_data: Dict[str, Any]) -> bool:
    """
    Verify all signatures locally before sending to chain
    """
    from aptos_sdk.ed25519 import PublicKey as Ed25519PublicKey, Signature as Ed25519Signature
    
    try:
        order_bcs = bytes.fromhex(order_data["order_bcs"])
        
        # Verify user signature
        user_pk = Ed25519PublicKey.from_str(order_data["public_keys"]["user_public_key"])
        user_sig = Ed25519Signature.from_str(order_data["signatures"]["user_signature"])
        user_valid = user_pk.verify(order_bcs, user_sig)
        
        # Verify resolver signature
        resolver_pk = Ed25519PublicKey.from_str(order_data["public_keys"]["resolver_public_key"])
        resolver_sig = Ed25519Signature.from_str(order_data["signatures"]["resolver_signature"])
        resolver_valid = resolver_pk.verify(order_bcs, resolver_sig)
        
        # Verify arbitrator signature
        arbitrator_pk = Ed25519PublicKey.from_str(order_data["public_keys"]["arbitrator_public_key"])
        arbitrator_sig = Ed25519Signature.from_str(order_data["signatures"]["arbitrator_signature"])
        arbitrator_valid = arbitrator_pk.verify(order_bcs, arbitrator_sig)
        
        print(f"Local verification - User: {user_valid}, Resolver: {resolver_valid}, Arbitrator: {arbitrator_valid}")
        
        return user_valid and resolver_valid and arbitrator_valid
        
    except Exception as e:
        print(f"Local verification error: {e}")
        return False

def main():
    """
    Main function to demonstrate the complete flow
    """
    print("Creating random HTLC order with three signatures...\n")
    
    # Create random order and sign it
    order_data = create_random_order_and_sign()
    
    # Verify signatures locally
    print("Verifying signatures locally...")
    local_valid = verify_signatures_locally(order_data)
    print(f"All signatures valid locally: {local_valid}\n")
    
    # Create Move function call data
    print("Move contract function call data:")
    move_call_data = create_move_function_call_data(order_data)
    print(f"Function: {move_call_data['function']}")
    print(f"Arguments count: {len(move_call_data['arguments'])}")
    print()
    
    # Print summary
    print("=== Summary ===")
    print(f"User address: {order_data['order']['user_address']}")
    print(f"Resolver address: {order_data['order']['resolver_address']}")
    print(f"Arbitrator address: {order_data['order']['arbitrator_address']}")
    print(f"User amount: {order_data['order']['user_amount']}")
    print(f"Resolver amount: {order_data['order']['resolver_amount']}")
    print(f"Order hash: {order_data['order_hash']}")
    
    return order_data

if __name__ == "__main__":
    # Run the example
    order_data = main()
    
    # Optionally save to file
    import json
    with open("htlc_order_example.json", "w") as f:
        json.dump(order_data, f, indent=2)
    print("\nOrder data saved to htlc_order_example.json")