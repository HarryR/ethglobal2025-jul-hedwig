#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
HTLC Arbitrator Daemon - API service for signing HTLC deposit proofs.

This daemon acts as an uninterested third party that verifies and signs
HTLC parameters using EIP-712 structured data signing.
"""

import argparse
import asyncio
import json
import os
import sys
import time
import hashlib
from typing import Any, Dict, Optional

from quart import Quart, request, jsonify
from web3 import AsyncWeb3
from web3.exceptions import ContractLogicError
from eth_account import Account
from hexbytes import HexBytes

# Contract ABI for DestinationHTLC (view functions only)
with open('abis/DestinationHTLC.json', 'r') as handle:
    CONTRACT_ABI = json.load(handle)

def load_config(params_file: str) -> Dict[str, Any]:
    """Load configuration from params file."""
    if not os.path.exists(params_file):
        raise ValueError(f"Params file {params_file} not found")
    
    with open(params_file, 'r') as f:
        config = json.load(f)
    
    # Ensure we have required fields
    required_fields = ['node_url', 'chain_id', 'dhtlc_address', 'network']
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Required field '{field}' missing from params file")
    
    return config


class ArbitratorDaemon:
    """HTLC Arbitrator Daemon that signs deposit proofs using EIP-712."""
    
    def __init__(self, config: Dict[str, Any], arbitrator_account: Account):
        self.config = config
        self.network = config['network']
        self.arbitrator_account = arbitrator_account
        
        # Initialize web3 client
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(config['node_url']))
        
        # Create contract instance
        self.dhtlc_address = AsyncWeb3.to_checksum_address(config['dhtlc_address'])
        self.contract = self.w3.eth.contract(
            address=self.dhtlc_address,
            abi=CONTRACT_ABI
        )

    async def initialize(self):
        """Initialize the daemon by checking connection."""
        is_connected = await self.w3.is_connected()
        if not is_connected:
            raise ConnectionError(f"Could not connect to {self.config['node_url']}")
        
        # Get chain ID to verify network
        chain_id = int(await self.w3.eth.chain_id)
        expected_chain_id = int(self.config.get('chain_id'))
        if not expected_chain_id or chain_id != expected_chain_id:
            raise RuntimeError(f"⚠️  Warning: Connected to chain ID {chain_id}, expected {expected_chain_id}")
        
        print(f"✅ Arbitrator address: {self.arbitrator_account.address}")
        print(f"✅ Contract address: {self.dhtlc_address}")
        print(f"✅ Chain ID: {chain_id}")
    
    async def get_htlc_info(self, secret_hash: HexBytes) -> Optional[Dict[str, Any]]:
        """Get HTLC information from the contract."""
        try:
            result = await self.contract.functions.getHTLCInfo(secret_hash).call()
            
            # Match the actual Solidity struct: (userAddress, resolverAddress, amount, deadline)
            return {
                "user_address": result[0],
                "resolver_address": result[1], 
                "amount": result[2],
                "deadline": result[3]
            }
        except ContractLogicError:
            # HTLC doesn't exist
            return None
    
    async def does_htlc_exist(self, secret_hash: HexBytes) -> bool:
        """Check if HTLC exists."""
        return await self.contract.functions.doesHTLCExist(secret_hash).call()
    
    async def decision_make(self, status: bool, secret_hash: HexBytes, deadline: int,
                           destination_chain: HexBytes, destination_token: bytes,
                           destination_amount: int, destination_address: bytes):
        """Call the contract's decision_make function to get ABI encoded decision and hash."""
        return await self.contract.functions.decision_make(
            status, secret_hash, deadline, destination_chain, 
            destination_token, destination_amount, destination_address
        ).call()
    
    async def hash_secret(self, secret: HexBytes) -> HexBytes:
        """Call the contract's hashSecret view function."""
        result = await self.contract.functions.hashSecret(secret).call()
        return HexBytes(result)

    async def health_check(self):
        """Perform a comprehensive health check including contract verification."""
        # Test secret for verification
        test_secret = HexBytes(os.urandom(32))
        expected_hash = HexBytes(hashlib.sha256(test_secret).digest())
        
        # Call the contract's hashSecret function
        contract_hash = await self.hash_secret(test_secret)
        
        # Verify the hash matches
        if contract_hash != expected_hash:
            raise ValueError(f"Contract hash verification failed. Expected {expected_hash.hex()}, got {contract_hash.hex()}")

    async def close(self):
        """Clean up resources."""
        if hasattr(self.w3.provider, 'session') and self.w3.provider.session:
            await self.w3.provider.session.close()


def parse_hex(x: str | bytes) -> bytes:
    """Parse hex string or bytes into bytes."""
    if isinstance(x, bytes):
        return x
    if x.startswith('0x'):
        x = x[2:]
    return bytes.fromhex(x)


def create_account(args: argparse.Namespace) -> Account:
    """Create or load account based on arguments."""
    if args.random_key:
        print("🎲 Generating random account...")
        account = Account.create()
        print("Private Key:", account.key.hex())
        return account
    
    elif args.private_key:
        key = args.private_key
        if key.startswith("0x"):
            key = key[2:]
        print("🔑 Loading account from provided private key...")
        return Account.from_key(key)
    
    elif args.private_key_env:
        key = os.getenv(args.private_key_env)
        if not key:
            raise ValueError(f"Environment variable {args.private_key_env} not found")
        if key.startswith("0x"):
            key = key[2:]
        print(f"🔑 Loading account from environment variable {args.private_key_env}...")
        return Account.from_key(key)
    
    else:
        raise ValueError("No account method specified. Use --private-key, --private-key-env, or --random-key")


def create_quart_app(daemon: ArbitratorDaemon) -> Quart:
    """Create and configure the Quart application."""
    app = Quart(__name__)

    @app.route('/ethereum/<network>/arbitrate.ethereum', methods=['POST'])
    async def arbitrate_ethereum(network: str):
        """Arbitrate an Ethereum HTLC request."""
        
        # Validate network matches daemon configuration  
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        
        # Parse request JSON
        data = await request.get_json()
        if not data:
            raise ValueError("No JSON data provided")

        secret_hash = parse_hex(data['secret_hash'])
        deadline = int(data['deadline'])
        destination_amount = int(data['destination_amount'])
        destination_chain = parse_hex(data['destination_chain'])
        destination_token = parse_hex(data['destination_token'])
        destination_address = data['destination_address']

        # Check if HTLC exists
        htlc_exists = await daemon.does_htlc_exist(HexBytes(secret_hash))
        
        # Get HTLC info if it exists (for validation)
        info = None
        if htlc_exists:
            info = await daemon.get_htlc_info(HexBytes(secret_hash))
            if not info:
                return jsonify({
                    "success": False,
                    "error": "HTLC exists but info retrieval failed",
                    "code": "CONTRACT_ERROR",
                }), 500

            # Validate parameters against contract data
            if deadline != info['deadline']:
                return jsonify({
                    "success": False,
                    "error": f"Deadline mismatch, got {deadline} expected {info['deadline']}",
                    "code": "WRONG_DEADLINE",
                }), 400

            # Convert destination address to checksum format for comparison
            destination_address_checksum = AsyncWeb3.to_checksum_address(destination_address)
            if destination_address_checksum != info['user_address']:
                return jsonify({
                    "success": False,
                    "error": f"Destination address mismatch, got {destination_address_checksum} expected {info['user_address']}",
                    "code": "WRONG_ADDRESS",
                }), 400

            if destination_amount != info['amount']:
                return jsonify({
                    "success": False,
                    "error": f"Destination amount mismatch, got {destination_amount} expected {info['amount']}",
                    "code": "WRONG_AMOUNT",
                }), 400

        # Determine current state
        current_time = int(time.time())
        deadline_passed = current_time >= deadline

        # Binary decision logic:
        # Status True: Before deadline AND HTLC exists → Success
        # Status False: After deadline AND HTLC doesn't exist → Failure
        # Everything else: Error
        if not deadline_passed and htlc_exists:
            status = True  # Success: deposited on time
        elif deadline_passed and not htlc_exists:
            status = False  # Failure: didn't deposit
        else:
            # Error cases
            if deadline_passed and htlc_exists:
                error_msg = "HTLC exists but deadline has passed (late deposit)"
                error_code = "LATE_DEPOSIT"
            else:  # not deadline_passed and not htlc_exists
                error_msg = "Deadline hasn't passed but HTLC doesn't exist (premature request)"
                error_code = "PREMATURE_REQUEST"
            
            return jsonify({
                "success": False,
                "error": error_msg,
                "code": error_code,
            }), 400

        # Get decision structure and hash from contract
        decision_result = await daemon.decision_make(
            status,
            HexBytes(secret_hash),
            deadline,
            HexBytes(destination_chain),
            destination_token,
            destination_amount,
            destination_address.encode('utf-8')
        )
        
        # decision_result is a tuple: (abi_encoded_decision, struct_hash)
        abi_encoded_decision = decision_result[0]
        struct_hash = decision_result[1]

        # Sign the struct hash
        # Sign the raw hash directly since contract already did EIP-712 encoding
        signed_message = daemon.arbitrator_account.signHash(struct_hash)
        
        # Create both r,s,v and r,vs formats
        r = signed_message.r
        s = signed_message.s  
        v = signed_message.v
        
        # Pack r and vs (v and s combined)
        vs = (v << 255) | s
        
        signature_data = {
            'r': hex(r),
            's': hex(s),
            'v': v,
            'vs': hex(vs),
            'signature': signed_message.signature.hex()
        }

        return jsonify({
            'success': True,
            'decision': {
                'decision': status,
                'secretHash': '0x' + secret_hash.hex(),
                'deadline': deadline,
                'destinationChain': '0x' + destination_chain.hex(),
                'destinationToken': '0x' + destination_token.hex(),
                'destinationAmount': destination_amount,
                'destinationAddress': destination_address
            },
            'structHash': '0x' + struct_hash.hex(),
            'abiEncodedDecision': '0x' + abi_encoded_decision.hex(),
            'signature': signature_data,
            'arbitrator_address': daemon.arbitrator_account.address,
            'htlc_info': info
        })

    @app.route('/ethereum/<network>/health.arbitrator', methods=['GET'])
    async def health_check_endpoint(network: str):
        """Health check endpoint for arbitrator daemon."""
        
        # Validate network matches daemon configuration  
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        
        await daemon.health_check()
        return jsonify({
            "status": "healthy",
            "arbitrator_address": daemon.arbitrator_account.address,
            "dhtlc_address": daemon.dhtlc_address,
            "network": daemon.network
        })
                
    return app


async def main():
    """Main function to start the arbitrator daemon."""
    parser = argparse.ArgumentParser(description="HTLC Arbitrator Daemon for Ethereum")
    
    # Configuration file (required)
    parser.add_argument("params_file", help="JSON file containing deployment parameters")
    
    # Account configuration (mutually exclusive)
    account_group = parser.add_mutually_exclusive_group(required=True)
    account_group.add_argument("--private-key", help="Private key in hex format")
    account_group.add_argument("--private-key-env", help="Environment variable containing private key")    
    account_group.add_argument("--random-key", action="store_true", help="Generate random account")
    
    # Server configuration
    parser.add_argument("--port", type=int, default=7402, help="Port to run the server on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the server to")
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.params_file)
    
    print(f"📋 Configuration loaded:")
    print(f"   Contract: {config['dhtlc_address']}")
    print(f"   Node URL: {config['node_url']}")
    print(f"   Chain ID: {config['chain_id']}")
    
    # Create account
    arbitrator_account = create_account(args)
    
    # Initialize daemon
    daemon = ArbitratorDaemon(
        config=config,
        arbitrator_account=arbitrator_account
    )
    
    # Initialize connection
    await daemon.initialize()
    
    # Perform initial health check
    await daemon.health_check()
    
    # Create Quart app
    app = create_quart_app(daemon)
    
    print(f"🚀 Starting HTLC Arbitrator Daemon on {args.host}:{args.port}")
    print(f"   Endpoints:")
    print(f"     POST /ethereum/{config['network']}/arbitrate.ethereum")
    print(f"     GET /ethereum/{config['network']}/health.arbitrator")
    
    try:
        # Run Quart app
        await app.run_task(host=args.host, port=args.port, debug=False)
    finally:
        # Clean up
        await daemon.close()


if __name__ == "__main__":
    asyncio.run(main())