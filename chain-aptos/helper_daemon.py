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
from aptos_sdk.async_client import FaucetClient, RestClient
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


class HTLCHelperClient(RestClient):
    """Extended RestClient for HTLC helper operations."""
    
    async def reveal_secret(
        self,
        contract_address: AccountAddress,
        caller: Account,
        secret: bytes
    ) -> str:
        """Reveal secret to claim HTLC funds."""
        
        payload = EntryFunction.natural(
            f"{contract_address}::destination_htlc",
            "reveal_secret",
            [],
            [
                TransactionArgument(secret, Serializer.sequence_serializer(Serializer.u8)),
            ],
        )
        
        signed_transaction = await self.create_bcs_signed_transaction(
            caller, TransactionPayload(payload)
        )
        return await self.submit_bcs_transaction(signed_transaction)
    
    async def claim_refund(
        self,
        contract_address: AccountAddress,
        caller: Account,
        secret_hash: bytes
    ) -> str:
        """Claim refund after HTLC timeout."""
        
        payload = EntryFunction.natural(
            f"{contract_address}::destination_htlc",
            "claim_refund",
            [],
            [
                TransactionArgument(secret_hash, Serializer.sequence_serializer(Serializer.u8)),
            ],
        )
        
        signed_transaction = await self.create_bcs_signed_transaction(
            caller, TransactionPayload(payload)
        )
        return await self.submit_bcs_transaction(signed_transaction)
    
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


class HelperDaemon:
    """HTLC Helper Daemon that reveals secrets and claims refunds."""
    
    def __init__(self, config: Dict[str, Any], claimer: Account, use_faucet: bool = False):
        self.network = config['network']
        self.config = config
        self.contract_address = AccountAddress.from_str(config['contract_address'])
        self.claimer = claimer
        self.use_faucet = use_faucet
        
        # Initialize clients
        self.rest_client = HTLCHelperClient(config['node_url'])
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
            balance = await self.rest_client.account_balance(self.claimer.address())
            if balance < fund_amount:
                print("Existing balance", balance)
                print(f"💰 Funding claimer account with {fund_amount} octas...")
                await self.faucet_client.fund_account(self.claimer.address(), fund_amount)            
            # Check balance
            balance = await self.rest_client.account_balance(self.claimer.address())
            print(f"✅ Claimer balance: {balance} octas")
    
    async def get_balance(self, address:str) -> int:
        account_addr = AccountAddress.from_str(address)
        return await self.rest_client.account_balance(account_addr)
    
    async def txwait(self, transaction_id:str) -> dict:
        await self.rest_client.wait_for_transaction(transaction_id)
        return await self.rest_client.transaction_by_hash(transaction_id)

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
                "claimer_address": str(self.claimer.address()),
                "contract_address": str(self.contract_address)
            }
    
    async def reveal_secret_transaction(
        self,
        secret_bytes: bytes
    ) -> Dict[str, Any]:
        """Reveal secret to claim HTLC funds."""
        # Calculate hash for verification
        calculated_hash = hashlib.sha256(secret_bytes).digest()
        calculated_hash_hex = calculated_hash.hex()
        
        print(f"🔓 Revealing secret:")
        print(f"   Secret: {secret_bytes.hex()}")
        print(f"   Secret hash: {calculated_hash_hex}")
        
        # Get HTLC info first
        htlc_info = await self.rest_client.get_htlc_info(self.contract_address, calculated_hash)
        if not htlc_info:
            return {
                "success": False,
                "error": f"HTLC not found for secret hash {calculated_hash_hex}"
            }
        
        if htlc_info["claimed"]:
            return {
                "success": False,
                "error": "HTLC already claimed"
            }
        
        # Submit reveal transaction
        txn_hash = await self.rest_client.reveal_secret(
            self.contract_address,
            self.claimer,
            secret_bytes
        )
        
        # Wait for transaction confirmation
        await self.rest_client.wait_for_transaction(txn_hash)
        txn_result = await self.rest_client.transaction_by_hash(txn_hash)
        
        # Extract gas information
        gas_used = int(txn_result.get("gas_used", 0))
        gas_unit_price = int(txn_result.get("gas_unit_price", 0))
        gas_fee = gas_used * gas_unit_price
        
        print(f"✅ Secret revealed successfully!")
        print(f"   Transaction: {txn_hash}")
        print(f"   Gas used: {gas_used}")
        print(f"   Gas fee: {gas_fee} octas")
        
        return {
            "success": True,
            "transaction_hash": txn_hash,
            "gas_used": gas_used,
            "gas_fee": gas_fee,
            "revealed": {
                "secret_hash": f"0x{calculated_hash_hex}",
                "secret": f"0x{secret_bytes.hex()}",
                "user_address": htlc_info["user_address"],
                "amount": htlc_info["amount"]
            }
        }

    
    async def claim_refund_transaction(
        self,
        secret_hash: str
    ) -> Dict[str, Any]:
        """Claim refund after HTLC timeout."""
        try:
            # Convert hex string to bytes
            if secret_hash.startswith("0x"):
                secret_hash = secret_hash[2:]
            secret_hash_bytes = bytes.fromhex(secret_hash)
            
            print(f"💰 Claiming refund:")
            print(f"   Secret hash: {secret_hash}")
            
            # Get HTLC info first
            htlc_info = await self.rest_client.get_htlc_info(self.contract_address, secret_hash_bytes)
            if not htlc_info:
                return {
                    "success": False,
                    "error": f"HTLC not found for secret hash {secret_hash}"
                }
            
            if htlc_info["claimed"]:
                return {
                    "success": False,
                    "error": "HTLC already claimed"
                }
            
            # Check if deadline has passed (this will be enforced by contract anyway)            
            current_time = int(time.time())
            if current_time < htlc_info["deadline"]:
                return {
                    "success": False,
                    "error": f"HTLC not yet expired. Deadline: {htlc_info['deadline']}, Current: {current_time}"
                }
            
            # Submit refund transaction
            txn_hash = await self.rest_client.claim_refund(
                self.contract_address,
                self.claimer,
                secret_hash_bytes
            )
            
            # Wait for transaction confirmation
            txn_result = await self.rest_client.wait_for_transaction(txn_hash)
            
            # Extract gas information
            gas_used = int(txn_result.get("gas_used", 0))
            gas_unit_price = int(txn_result.get("gas_unit_price", 0))
            gas_fee = gas_used * gas_unit_price
            
            print(f"✅ Refund claimed successfully!")
            print(f"   Transaction: {txn_hash}")
            print(f"   Gas used: {gas_used}")
            print(f"   Gas fee: {gas_fee} octas")
            
            return {
                "success": True,
                "transaction_hash": txn_hash,
                "gas_used": gas_used,
                "gas_fee": gas_fee,
                "refunded": {
                    "secret_hash": f"0x{secret_hash}",
                    "resolver_address": htlc_info["resolver_address"],
                    "amount": htlc_info["amount"]
                }
            }
            
        except Exception as e:
            print(f"❌ Error claiming refund: {str(e)}")
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


def create_flask_app(daemon: HelperDaemon) -> Quart:
    """Create and configure the Flask application."""
    app = Quart(__name__)

    @app.route('/aptos/<network>/balance/<account>', methods=['GET'])
    async def get_balance(network:str, account:str):
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        balance = await daemon.get_balance(account)
        return jsonify({'balance': balance})
    
    @app.route('/aptos/<network>/txwait/<transaction_id>', methods=['GET'])
    async def txwait(network:str, transaction_id:str):
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        result = await daemon.txwait(transaction_id)
        return jsonify(result)
    
    @app.route('/aptos/<network>/reveal', methods=['POST'])
    async def reveal_secret_endpoint(network: str):
        """Endpoint to reveal a secret and claim HTLC funds."""
        
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
        
        secret_str:str = data["secret"]
        if not secret_str:
            raise ValueError("Missing required field: secret")
        
        if secret_str.startswith('0x'):
            secret_str = secret_str[2:]
        secret_bytes = bytes.fromhex(secret_str)            
        
        # Reveal secret asynchronously
        result = await daemon.reveal_secret_transaction(secret_bytes)
        status_code = 200 if result["success"] else 400
        return jsonify(result), status_code
    
    @app.route('/aptos/<network>/refund', methods=['POST'])
    async def claim_refund_endpoint(network: str):
        """Endpoint to claim refund after HTLC timeout."""
        
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
        
        secret_hash = data.get("secret_hash")
        
        # Validate required fields
        if not secret_hash:
            raise ValueError("Missing required field: secret_hash")
        
        # Claim refund asynchronously
        result = await daemon.claim_refund_transaction(secret_hash)
        status_code = 200 if result["success"] else 400
        return jsonify(result), status_code
    
    @app.route('/aptos/<network>/health.helper', methods=['GET'])
    async def health_check_endpoint(network: str):
        """Health check endpoint for helper daemon."""
        
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
    """Main function to start the helper daemon."""
    parser = argparse.ArgumentParser(description="HTLC Helper Daemon")
    
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
    parser.add_argument("--use-faucet", action="store_true",
                        help="Generate random account and fund from faucet")
    
    # Account configuration (mutually exclusive)
    account_group = parser.add_mutually_exclusive_group()
    account_group.add_argument("--private-key", help="Private key in hex format")
    account_group.add_argument("--private-key-env", help="Environment variable containing private key")    
    account_group.add_argument("--random-key", action="store_true",
                             help="Generate random account (no faucet funding)")
    
    # Server configuration
    parser.add_argument("--port", type=int, default=7301, help="Port to run the server on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the server to")
    parser.add_argument("--fund-amount", type=int, default=10_000_000,
                       help="Amount to fund account with when using faucet (in octas)")
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.params_file, args)
    
    print(f"📋 Configuration loaded:")
    print(f"   Network: {config['network']}")
    print(f"   Contract: {config['contract_address']}")
    print(f"   Node URL: {config['node_url']}")
    print(f"   Faucet URL: {config.get('faucet_url', 'None')}")
    
    # Create account
    claimer = create_account(args)
    print(f"🔑 Claimer address: {claimer.address()}")
    
    # Initialize daemon
    daemon = HelperDaemon(
        config=config,
        claimer=claimer,
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
    
    print(f"🚀 Starting HTLC Helper Daemon on {args.host}:{args.port}")
    print(f"   Endpoints:")
    print(f"     POST /aptos/{config['network']}/reveal")
    print(f"     POST /aptos/{config['network']}/refund") 
    print(f"     GET /aptos/{config['network']}/health.helper")
    
    # Run Flask app
    await app.run_task(host=args.host, port=args.port, debug=False)

    # Clean up
    if 'daemon' in locals():
        await daemon.close()


if __name__ == "__main__":
    asyncio.run(main())
