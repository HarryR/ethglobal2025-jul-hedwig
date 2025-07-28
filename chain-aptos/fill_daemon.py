#!/usr/bin/env python3
"""
HTLC Fill Daemon - Internal service for creating HTLCs by depositing funds.

This daemon acts as a resolver that creates HTLCs by calling the create_htlc
method on the destination_htlc contract.
"""

import argparse
import asyncio
import json
import os
import sys
from typing import Any, Dict, Optional

from flask import Flask, request, jsonify
from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.async_client import FaucetClient, RestClient
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import (
    EntryFunction,
    TransactionArgument,
    TransactionPayload,
)
import hashlib

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
    if args.faucet_url:
        config['faucet_url'] = args.faucet_url
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

class HTLCClient(RestClient):
    """Extended RestClient for HTLC operations."""
    
    async def create_htlc(
        self,
        contract_address: AccountAddress,
        resolver: Account,
        secret_hash: bytes,
        user_address: AccountAddress,
        amount: int,
        deadline: int
    ) -> str:
        """Create a new HTLC by calling the contract's create_htlc function."""
        
        payload = EntryFunction.natural(
            f"{contract_address}::destination_htlc",
            "create_htlc",
            [],
            [
                TransactionArgument(secret_hash, Serializer.sequence_serializer(Serializer.u8)),
                TransactionArgument(user_address, Serializer.struct),
                TransactionArgument(amount, Serializer.u64),
                TransactionArgument(deadline, Serializer.u64),
            ],
        )
        
        signed_transaction = await self.create_bcs_signed_transaction(
            resolver, TransactionPayload(payload)
        )
        return await self.submit_bcs_transaction(signed_transaction)
    
    async def hash_secret(self, contract_address: AccountAddress, secret: bytes) -> bytes:
        """Call the contract's hash_secret view function."""
        try:
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
        except Exception as e:
            print(f"❌ Error calling hash_secret: {e}")
            return b""


class FillDaemon:
    """HTLC Fill Daemon that creates HTLCs by depositing funds."""
    
    def __init__(self, config: Dict[str, Any], resolver: Account, use_faucet: bool = False):
        self.network = config['network']
        self.config = config
        self.contract_address = AccountAddress.from_str(config['contract_address'])
        self.resolver = resolver
        self.use_faucet = use_faucet
        
        # Initialize clients
        self.rest_client = HTLCClient(config['node_url'])
        self.faucet_client = None
        
        if use_faucet and config.get('faucet_url'):
            self.faucet_client = FaucetClient(
                config['faucet_url'],
                self.rest_client,
                os.getenv("FAUCET_AUTH_TOKEN")
            )
    
    async def initialize(self, fund_amount: int = 10_000_000):
        """Initialize the daemon by funding the account if needed."""
        if self.use_faucet and self.faucet_client:
            print(f"💰 Funding resolver account with {fund_amount} octas...")
            await self.faucet_client.fund_account(self.resolver.address(), fund_amount)
            
            # Check balance
            balance = await self.rest_client.account_balance(self.resolver.address())
            print(f"✅ Resolver balance: {balance} octas")
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform a comprehensive health check including contract verification."""
        try:
            # Test secret for verification
            test_secret = b"test_secret_123"
            expected_hash = hashlib.sha3_256(test_secret).digest()
            
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
                    "resolver_address": str(self.resolver.address()),
                    "contract_address": str(self.contract_address),
                    "node_url": self.config.get('node_url'),
                    "faucet_url": self.config.get('faucet_url'),
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
                    "resolver_address": str(self.resolver.address()),
                    "contract_address": str(self.contract_address)
                }
                
        except Exception as e:
            print(f"❌ Contract health check failed: {e}")
            return {
                "status": "unhealthy",
                "contract_responsive": False,
                "hash_verification": "error",
                "error": str(e),
                "network": self.network,
                "resolver_address": str(self.resolver.address()),
                "contract_address": str(self.contract_address)
            }
    
    async def create_htlc_transaction(
        self,
        secret_hash: str,
        user_address: str,
        amount: int,
        deadline: int
    ) -> Dict[str, Any]:
        """Create an HTLC and return transaction information."""
        try:
            # Convert hex string to bytes
            if secret_hash.startswith("0x"):
                secret_hash = secret_hash[2:]
            secret_hash_bytes = bytes.fromhex(secret_hash)
            
            user_addr = AccountAddress.from_str(user_address)
            
            print(f"🔒 Creating HTLC:")
            print(f"   Secret hash: 0x{secret_hash}")
            print(f"   User address: {user_address}")
            print(f"   Amount: {amount} octas")
            print(f"   Deadline: {deadline}")
            
            # Submit transaction
            txn_hash = await self.rest_client.create_htlc(
                self.contract_address,
                self.resolver,
                secret_hash_bytes,
                user_addr,
                amount,
                deadline
            )
            
            # Wait for transaction confirmation
            txn_result = await self.rest_client.wait_for_transaction(txn_hash)
            
            # Extract gas information
            gas_used = int(txn_result.get("gas_used", 0))
            gas_unit_price = int(txn_result.get("gas_unit_price", 0))
            gas_fee = gas_used * gas_unit_price
            
            print(f"✅ HTLC created successfully!")
            print(f"   Transaction: {txn_hash}")
            print(f"   Gas used: {gas_used}")
            print(f"   Gas fee: {gas_fee} octas")
            
            return {
                "success": True,
                "transaction_hash": txn_hash,
                "gas_used": gas_used,
                "gas_fee": gas_fee,
                "htlc_created": {
                    "secret_hash": f"0x{secret_hash}",
                    "user_address": user_address,
                    "resolver_address": str(self.resolver.address()),
                    "amount": amount,
                    "deadline": deadline
                }
            }
            
        except Exception as e:
            print(f"❌ Error creating HTLC: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "transaction_hash": None
            }
    
    async def close(self):
        """Clean up resources."""
        await self.rest_client.close()


def create_account(args: argparse.Namespace) -> Account:
    """Create or load account based on arguments."""
    if args.random_key:
        print("🎲 Generating random account...")
        return Account.generate()
    
    elif args.use_faucet:
        print("🎲 Generating random account for faucet funding...")
        return Account.generate()
    
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
        raise ValueError("No account method specified. Use --private-key, --private-key-env, --use-faucet, or --random-key")


def create_flask_app(daemon: FillDaemon) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    @app.route('/aptos/<network>/<order_id>', methods=['POST'])
    def create_htlc_endpoint(network: str, order_id: str):
        """Endpoint to create an HTLC."""
        
        # Validate network matches daemon configuration
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        
        # Parse request JSON
        try:
            data = request.get_json()
            if not data:
                raise ValueError("No JSON data provided")
            
            secret_hash = data.get("secret_hash")
            user_address = data.get("user_address") 
            amount = data.get("amount")
            deadline = data.get("deadline")
            
            # Validate required fields
            if not all([secret_hash, user_address, amount, deadline]):
                raise ValueError("Missing required fields: secret_hash, user_address, amount, deadline")
            
            # Validate types
            if not isinstance(amount, int) or amount <= 0:
                raise ValueError("Amount must be a positive integer")
            
            if not isinstance(deadline, int) or deadline <= 0:
                raise ValueError("Deadline must be a positive integer (unix timestamp)")
                
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Invalid request: {str(e)}"
            }), 400
        
        # Create HTLC asynchronously
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                daemon.create_htlc_transaction(secret_hash, user_address, amount, deadline)
            )
            loop.close()
            
            status_code = 200 if result["success"] else 500
            return jsonify(result), status_code
            
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Internal error: {str(e)}"
            }), 500
    
    @app.route('/aptos/<network>', methods=['GET'])
    def health_check_endpoint(network: str):
        """Health check endpoint."""
        
        # Validate network matches daemon configuration
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        
        # Perform async health check
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            health_result = loop.run_until_complete(daemon.health_check())
            loop.close()
            
            status_code = 200 if health_result["status"] == "healthy" else 503
            return jsonify(health_result), status_code
            
        except Exception as e:
            return jsonify({
                "status": "unhealthy",
                "error": f"Health check failed: {str(e)}"
            }), 503
    
    return app


async def main():
    """Main function to start the fill daemon."""
    parser = argparse.ArgumentParser(description="HTLC Fill Daemon")
    
    # Configuration file
    parser.add_argument("--params-file", help="JSON file containing deployment parameters")
    
    # Network and contract configuration (can override params file)
    parser.add_argument("--network", choices=DEFAULT_NETWORK_CONFIGS.keys(),
                       help="Network to connect to")
    parser.add_argument("--contract-address", help="Address where the HTLC contract is deployed")
    parser.add_argument("--node-url", help="RPC node URL")
    parser.add_argument("--faucet-url", help="Faucet URL")
    parser.add_argument("--indexer-url", help="Indexer URL")
    parser.add_argument("--chain-id", type=int, help="Chain ID")
    
    # Account configuration (mutually exclusive)
    account_group = parser.add_mutually_exclusive_group()
    account_group.add_argument("--private-key", help="Private key in hex format")
    account_group.add_argument("--private-key-env", help="Environment variable containing private key")
    account_group.add_argument("--use-faucet", action="store_true",
                             help="Generate random account and fund from faucet")
    account_group.add_argument("--random-key", action="store_true",
                             help="Generate random account (no faucet funding)")
    
    # Server configuration
    parser.add_argument("--port", type=int, default=7300, help="Port to run the server on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the server to")
    parser.add_argument("--fund-amount", type=int, default=10_000_000,
                       help="Amount to fund account with when using faucet (in octas)")
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = load_config(args.params_file, args)
        
        print(f"📋 Configuration loaded:")
        print(f"   Network: {config['network']}")
        print(f"   Contract: {config['contract_address']}")
        print(f"   Node URL: {config['node_url']}")
        print(f"   Faucet URL: {config.get('faucet_url', 'None')}")
        
        # Create account
        resolver = create_account(args)
        print(f"🏦 Resolver address: {resolver.address()}")
        
        # Initialize daemon
        daemon = FillDaemon(
            config=config,
            resolver=resolver,
            use_faucet=args.use_faucet or args.random_key
        )
        
        # Fund account if needed
        if args.use_faucet:
            await daemon.initialize(args.fund_amount)
        
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
        
        print(f"🚀 Starting HTLC Fill Daemon on {args.host}:{args.port}")
        print(f"   Endpoint: POST /aptos/{config['network']}/<order_id>")
        print(f"   Health check: GET /aptos/{config['network']}")
        
        # Run Flask app
        app.run(host=args.host, port=args.port, debug=False)
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)
    finally:
        # Clean up
        if 'daemon' in locals():
            await daemon.close()


if __name__ == "__main__":
    asyncio.run(main())
