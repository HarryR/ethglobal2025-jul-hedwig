#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
HTLC Helper Daemon - API service for revealing secrets and claiming refunds.

This daemon handles HTLC claiming operations by calling reveal_secret and 
claim_refund methods on the destination_htlc contract.
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
from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.async_client import RestClient
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)

# Default network configurations (fallback if not in params file)
DEFAULT_NETWORK_CONFIGS = {
    "localnet": {
        "node_url": "http://127.0.0.1:8080",
        "faucet_url": "http://127.0.0.1:8081",
        "indexer_url": "http://127.0.0.1:8090/v1/graphql",
        "chain_id": 4,
    },
    "devnet": {
        "node_url": "https://api.devnet.aptoslabs.com/v1",
        "faucet_url": "https://faucet.devnet.aptoslabs.com",
        "indexer_url": "https://api.devnet.aptoslabs.com/v1/graphql",
        "chain_id": 123,
    },
    "testnet": {
        "node_url": "https://api.testnet.aptoslabs.com/v1",
        "faucet_url": None,
        "indexer_url": "https://api.testnet.aptoslabs.com/v1/graphql", 
        "chain_id": 2,
    },
    "mainnet": {
        "node_url": "https://api.mainnet.aptoslabs.com/v1",
        "faucet_url": None,
        "indexer_url": "https://api.mainnet.aptoslabs.com/v1/graphql",
        "chain_id": 1,
    }
}


def load_config(params_file: Optional[str], args: argparse.Namespace) -> Dict[str, Any]:
    """Load configuration from params file and command line arguments."""
    config = {}
    
    # Load from params file first
    if params_file and os.path.exists(params_file):
        print(f"📄 Loading config from {params_file}")
        with open(params_file, 'r') as f:
            config = json.load(f)
    
    # Command line arguments take precedence
    if args.network:
        config['network'] = args.network
    if args.contract_address:
        config['contract_address'] = args.contract_address
    if args.node_url:
        config['node_url'] = args.node_url
    if args.indexer_url:
        config['indexer_url'] = args.indexer_url
    if args.chain_id:
        config['chain_id'] = args.chain_id
    
    # Ensure we have required fields
    if 'network' not in config:
        raise ValueError("Network must be specified in params file or command line")
    if 'contract_address' not in config:
        raise ValueError("Contract address must be specified in params file or command line")
    
    # Fill in defaults if not specified
    network = config['network']
    if network in DEFAULT_NETWORK_CONFIGS:
        defaults = DEFAULT_NETWORK_CONFIGS[network]
        for key, value in defaults.items():
            if key not in config:
                config[key] = value
    
    return config


class HTLCArbitratorClient(RestClient):
    """Extended RestClient for HTLC helper operations."""
    
    async def get_htlc_info(
        self,
        contract_address: AccountAddress,
        secret_hash: bytes
    ) -> Optional[Dict[str, Any]]:
        """Get HTLC information from the contract."""
        try:
            result = json.loads(await self.view(
                f"{contract_address}::destination_htlc::get_htlc_info",
                [],
                [secret_hash.hex()]
            ))
            
            if result and len(result) >= 5:
                return {
                    "user_address": result[0],
                    "resolver_address": result[1], 
                    "amount": int(result[2]),
                    "deadline": int(result[3]),
                    "claimed": bool(result[4])
                }
            return None
        except Exception as e:
            print(f"❌ Error getting HTLC info: {e}")
            return None
    
    async def hash_secret(self, contract_address: AccountAddress, secret: bytes) -> bytes:
        """Call the contract's hash_secret view function."""
        result = json.loads(await self.view(
            f"{contract_address}::destination_htlc::hash_secret",
            [],
            [secret.hex()]
        ))
        # The result is returned as a list with hex string
        if result and len(result) > 0:
            hash_hex = result[0]
            if hash_hex.startswith("0x"):
                hash_hex = hash_hex[2:]
            return bytes.fromhex(hash_hex)
        return b""


class ArbitratorDaemon:
    """HTLC Arbitrator Daemon that signs deposit proofs."""
    
    def __init__(self, config: Dict[str, Any], claimer: Account):
        self.network = config['network']
        self.config = config
        self.contract_address = AccountAddress.from_str(config['contract_address'])
        self.claimer = claimer
        
        # Initialize clients
        self.rest_client = HTLCArbitratorClient(config['node_url'])
    
    async def get_balance(self, address:str) -> int:
        account_addr = AccountAddress.from_str(address)
        return await self.rest_client.account_balance(account_addr)
    
    async def get_htlc_info(self, secret_hash:str) -> dict:
        if secret_hash.startswith('0x'):
            secret_hash = secret_hash[2:]
        secret_hash_bytes = bytes.fromhex(secret_hash)
        return await self.rest_client.get_htlc_info(self.contract_address, secret_hash_bytes)

    async def health_check(self) -> Dict[str, Any]:
        """Perform a comprehensive health check including contract verification."""
        #try:
        # Test secret for verification
        test_secret = b"test_secret_123"
        expected_hash = hashlib.sha256(test_secret).digest()
        
        print("🔍 Performing contract health check...")
        print(f"   Testing with secret: {test_secret.hex()}")
        print(f"   Expected hash: {expected_hash.hex()}")
        
        # Call the contract's hash_secret function
        contract_hash = await self.rest_client.hash_secret(self.contract_address, test_secret)
        print(f"   Contract returned: {contract_hash.hex()}")
        
        # Verify the hash matches
        if contract_hash == expected_hash:
            print("✅ Contract health check passed!")
            return {
                "status": "healthy",
                "contract_responsive": True,
                "hash_verification": "passed",
                "network": self.network,
                "claimer_address": str(self.claimer.address()),
                "contract_address": str(self.contract_address),
                "node_url": self.config.get('node_url'),
                "chain_id": self.config.get('chain_id')
            }
        else:
            print("❌ Hash verification failed!")
            return {
                "status": "unhealthy",
                "contract_responsive": True,
                "hash_verification": "failed",
                "error": f"Expected {expected_hash.hex()}, got {contract_hash.hex()}",
                "network": self.network,
                "claimer_address": str(self.claimer.address()),
                "contract_address": str(self.contract_address)
            }

    async def close(self):
        """Clean up resources."""
        await self.rest_client.close()


def create_account(args: argparse.Namespace) -> Account:
    """Create or load account based on arguments."""
    if args.random_key:
        print("🎲 Generating random account...")
        account = Account.generate()
        print("Private Key", account.private_key.hex())
        return account
    
    elif args.private_key:
        key = args.private_key
        if key.startswith("0x"):
            key = key[2:]
        print("🔑 Loading account from provided private key...")
        return Account.load_key(key)
    
    elif args.private_key_env:
        key = os.getenv(args.private_key_env)
        if not key:
            raise ValueError(f"Environment variable {args.private_key_env} not found")
        if key.startswith("0x"):
            key = key[2:]
        print(f"🔑 Loading account from environment variable {args.private_key_env}...")
        return Account.load_key(key)
    
    else:
        raise ValueError("No account method specified. Use --private-key, --private-key-env, or --random-key")

def parse_hex(x:str|bytes):
    if isinstance(x, bytes):
        return x
    if x.startswith('0x'):
        x = x[2:]
    return bytes.fromhex(x)

def arbitrator_sign(
    acct:Account,
    status: int,
    secret_hash: bytes,
    deadline:int,
    destination_chain:bytes,
    destination_token:bytes,
    destination_amount:int,
    destination_address:bytes):
    ser = Serializer()
    ser.u8(status)                  # arbitrator_status
    ser.to_bytes(secret_hash)       # secret_hash
    ser.u64(deadline)               # deadline
    ser.to_bytes(destination_chain)
    ser.to_bytes(destination_token)
    ser.u256(destination_amount)         
    ser.to_bytes(destination_address)
    decision_bcs = ser.output()
    return {
        'decision_bcs': decision_bcs.hex(),
        'decision_sig': str(acct.sign(decision_bcs))
    }

def create_flask_app(daemon: ArbitratorDaemon) -> Quart:
    """Create and configure the Flask application."""
    app = Quart(__name__)

    @app.route('/aptos/<network>/arbitrate.aptos', methods=['POST'])
    async def arbitrate_aptos(network:str):
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
        destination_amount = data['destination_amount']
        destination_chain = parse_hex(data['destination_chain'])
        destination_token = parse_hex(data['destination_token'])
        destination_address = parse_hex(data['destination_address'])

        # native gas token is 0
        expected_token = bytes([0])

        expected_chain = f"aptos-{network}"
        expected_chain_bytes = expected_chain.encode('utf-8')
        expected_chain_hash_bytes = hashlib.sha256(expected_chain_bytes).digest()
        if destination_chain != expected_chain_hash_bytes:
            return jsonify({
                "success": False,
                "error": f"Destination chain mismatch, got {destination_chain.hex()} expected {expected_chain_hash_bytes.hex()}",
                "code": "WRONG_CHAIN",
            }), 400

        info = await daemon.get_htlc_info(secret_hash)

        if deadline != info['deadline']:
            return jsonify({
                "success": False,
                "error": f"Deadline mismatch, got {deadline} expected {info['deadline']}",
                "code": "WRONG_DEADLINE",
            }), 400

        if destination_token != expected_token:
            return jsonify({
                "success": False,
                "error": f"Destination token mismatch, got {destination_token.hex()} expected {expected_token.hex()}",
                "code": "WRONG_TOKEN",
            }), 400

        if destination_address != parse_hex(info['user_address']):
            return jsonify({
                "success": False,
                "error": f"Destination address mismatch, got {destination_address} expected {info['user_address']}",
                "code": "WRONG_ADDRESS",
            }), 400

        if destination_amount != info['amount']:
            return jsonify({
                "success": False,
                "error": f"Destination amount mismatch, got {destination_amount} expected {info['amount']}",
                "code": "WRONG_AMOUNT",
            }), 400

        # Sign it in a format 
        signature = arbitrator_sign(
            acct=daemon.claimer,
            secret_hash=secret_hash,
            deadline=deadline,
            destination_address=destination_address,
            destination_amount=destination_amount,
            destination_chain=destination_chain,
            destination_token=destination_token)

        return jsonify({
            'info': info,
            'signature': str(signature),
        })

    @app.route('/aptos/<network>/health.arbitrator', methods=['GET'])
    async def health_check_endpoint(network: str):
        """Health check endpoint for arbitrator daemon."""
        
        # Validate network matches daemon configuration  
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        
        # Perform async health check
        health_result = await daemon.health_check()
        status_code = 200 if health_result["status"] == "healthy" else 503
        return jsonify(health_result), status_code
                
    return app


async def main():
    """Main function to start the arbitrator daemon."""
    parser = argparse.ArgumentParser(description="HTLC Arbitrator Daemon")
    
    # Configuration file
    parser.add_argument("--params-file", help="JSON file containing deployment parameters")
    
    # Network and contract configuration (can override params file)
    parser.add_argument("--network", choices=DEFAULT_NETWORK_CONFIGS.keys(),
                       help="Network to connect to")
    parser.add_argument("--contract-address", help="Address where the HTLC contract is deployed")
    parser.add_argument("--node-url", help="RPC node URL")
    parser.add_argument("--indexer-url", help="Indexer URL")
    parser.add_argument("--chain-id", type=int, help="Chain ID")
    
    # Account configuration (mutually exclusive)
    account_group = parser.add_mutually_exclusive_group()
    account_group.add_argument("--private-key", help="Private key in hex format")
    account_group.add_argument("--private-key-env", help="Environment variable containing private key")    
    account_group.add_argument("--random-key", action="store_true", help="Generate random account")
    
    # Server configuration
    parser.add_argument("--port", type=int, default=7302, help="Port to run the server on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the server to")
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.params_file, args)
    
    print(f"📋 Configuration loaded:")
    print(f"   Network: {config['network']}")
    print(f"   Contract: {config['contract_address']}")
    print(f"   Node URL: {config['node_url']}")
    
    # Create account
    claimer = create_account(args)
    print(f"🔑 Claimer address: {claimer.address()}")
    
    # Initialize daemon
    daemon = ArbitratorDaemon(
        config=config,
        claimer=claimer
    )
    
    # Perform initial health check
    print("🏥 Performing initial health check...")
    health_result = await daemon.health_check()
    
    if health_result["status"] != "healthy":
        print("❌ Initial health check failed!")
        print(f"   Error: {health_result.get('error', 'Unknown error')}")
        sys.exit(1)
    
    print("✅ Initial health check passed - daemon is ready!")
    
    # Create Flask app
    app = create_flask_app(daemon)
    
    print(f"🚀 Starting HTLC Arbitrator Daemon on {args.host}:{args.port}")
    print(f"   Endpoints:")
    print(f"     POST /aptos/{config['network']}/arbitrate/0x<secret_hash>")
    print(f"     GET /aptos/{config['network']}/health.arbitrator")
    
    # Run Flask app
    await app.run_task(host=args.host, port=args.port, debug=False)

    # Clean up
    if 'daemon' in locals():
        await daemon.close()

if __name__ == "__main__":
    asyncio.run(main())
