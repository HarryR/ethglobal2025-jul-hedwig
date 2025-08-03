#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
HTLC Quote Daemon - API service for providing signed order quotes.

This daemon acts as a resolver that provides signed quotes for cross-chain
atomic swaps using the SourceHTLC contract format.
"""

import argparse
import asyncio
import json
import os
import time
import hashlib
from typing import Any, Dict

from quart import Quart, request, jsonify
from web3 import AsyncWeb3
from eth_account import Account
from hexbytes import HexBytes

# Contract ABI for SourceHTLC (view functions only)
with open('abis/SourceHTLC.json', 'r') as handle:
    CONTRACT_ABI = json.load(handle)

def load_config(params_file: str) -> Dict[str, Any]:
    """Load configuration from params file."""
    if not os.path.exists(params_file):
        raise ValueError(f"Params file {params_file} not found")
    
    with open(params_file, 'r') as f:
        config = json.load(f)
    
    # Ensure we have required fields
    required_fields = ['node_url', 'chain_id', 'shtlc_address', 'network']
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Required field '{field}' missing from params file")
    
    return config

class QuoteDaemon:
    """HTLC Quote Daemon that provides signed order quotes."""
    
    def __init__(self, config: Dict[str, Any], resolver_account: Account):
        self.config = config
        self.network = config['network']
        self.resolver_account = resolver_account
        
        # Initialize web3 client
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(config['node_url']))
        
        # Create contract instance
        self.shtlc_address = AsyncWeb3.to_checksum_address(config['shtlc_address'])
        self.shtlc_contract = self.w3.eth.contract(
            address=self.shtlc_address,
            abi=CONTRACT_ABI)

        # PoC configuration - fixed parameters for simplicity
        self.venue_address = self.resolver_account.address  # For PoC, resolver is also venue
        self.arbitrator_address = config.get('arbitrator_address', self.resolver_account.address)
        self.venue_fee_rate = 0.001  # 0.1%
        self.arbitrator_attention_fee = int(0.0001 * 10**18)  # 0.0001 ETH
        self.arbitrator_usage_fee_rate = 0.005  # 0.5%
        self.submission_deadline_offset = 3600  # 1 hour
        self.resolver_action_deadline_offset = 7200  # 2 hours

    async def resolver_deposit(self, amount:int):
        function = self.shtlc_contract.functions.resolver_deposit(self.resolver_account.address)
        
        # Get nonce and gas price
        nonce = await self.w3.eth.get_transaction_count(self.resolver_account.address)
        gas_price = await self.w3.eth.gas_price
        
        # Estimate gas
        gas_estimate = await function.estimate_gas({
            'from': self.resolver_account.address,
            'value': amount,
            'gasPrice': gas_price
        })
        
        # Build transaction
        transaction = await function.build_transaction({
            'from': self.resolver_account.address,
            'value': amount,
            'gas': gas_estimate,
            'gasPrice': gas_price,
            'nonce': nonce,
        })
        
        # Sign transaction
        signed_txn = self.w3.eth.account.sign_transaction(transaction, self.resolver_account.key)
        
        # Send transaction
        tx_hash = await self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        
        return tx_hash.hex()

    async def initialize(self):
        """Initialize the daemon by checking connection."""
        is_connected = await self.w3.is_connected()
        if not is_connected:
            raise ConnectionError(f"Could not connect to {self.config['node_url']}")

        # Get chain ID to verify network
        chain_id = await self.w3.eth.chain_id
        expected_chain_id = int(self.config.get('chain_id'))
        if not expected_chain_id or chain_id != expected_chain_id:
            raise RuntimeError(f"⚠️ Connected to chain ID {chain_id}, expected {expected_chain_id}")
        
        resolver_balance = await self.shtlc_contract.functions.resolver_balance(self.resolver_account.address).call()        
        topup_threshold = self.config['topup']
        if resolver_balance < topup_threshold:
            print(f"⚠️ Reslover balance below topup threshold, balance: {resolver_balance} - threshold: {topup_threshold}")
            need_topup = topup_threshold - resolver_balance
            # Check resolver balance
            native_balance = await self.w3.eth.get_balance(self.resolver_account.address)
            if native_balance < need_topup:
                raise RuntimeError(f"⚠️ Insufficient balance to topup resolver balance, have {native_balance}, need {need_topup}")
            await self.resolver_deposit(need_topup)
            resolver_balance = await self.shtlc_contract.functions.resolver_balance(self.resolver_account.address).call()
        print("✅ Resolver SourceHTLC balance", resolver_balance)
        print(f"✅ Resolver address: {self.resolver_account.address}")
        print(f"✅ Source HTLC address: {self.shtlc_address}")
        print(f"✅ Chain ID: {chain_id}")

    async def health_check(self):
        """Perform a health check."""
        # Basic connectivity test
        is_connected = await self.w3.is_connected()
        if not is_connected:
            raise ConnectionError("Web3 connection failed")
        return await self.shtlc_contract.functions.resolver_balance(self.resolver_account.address).call()

    async def create_order_hash(self, order: Dict[str, Any]) -> str:
        """Calculate order hash using contract method."""
        # Convert order dict to contract format
        order_tuple = (
            order['userAddress'],
            order['resolverAddress'], 
            order['userAmount'],
            order['resolverAmount'],
            order['venueAddress'],
            order['venueFee'],
            order['arbitratorAddress'],
            order['arbitratorAttentionFee'],
            order['arbitratorUsageFee'],
            HexBytes(order['secretHash']),
            order['submissionDeadline'],
            order['resolverActionDeadline'],
            HexBytes(order['destinationChain']),
            order['destinationAddress'].encode('utf-8'),
            order['destinationToken'],
            order['destinationAmount']
        )
        order_hash = await self.shtlc_contract.functions.order_hash(order_tuple).call()
        return order_hash.hex()

    async def create_quote(
        self,
        user_address: str,
        source_amount: int,
        destination_chain: str,
        destination_amount: int,
        secret_hash: str
    ) -> Dict[str, Any]:
        # Validate basic parameters
        if source_amount < 0:
            raise ValueError("Source amount too small")
        if source_amount > int(10 * 10**18):  # Max 10 ETH  
            raise ValueError("Source amount too large")
        if destination_amount <= 0:
            raise ValueError("Destination amount must be positive")

        # Calculate fees
        venue_fee = int(source_amount * self.venue_fee_rate)
        arbitrator_usage_fee = int(source_amount * self.arbitrator_usage_fee_rate)

        # Set resolver amount (collateral penalty)
        resolver_amount = int(source_amount * 0.1)  # 10% penalty for PoC

        # Check resolver balance in SourceHTLC
        resolver_balance = await self.shtlc_contract.functions.resolver_balance(self.resolver_account.address).call()
        if resolver_balance < resolver_amount:
            raise RuntimeError(f"⚠️  Warning: Low resolver balance in SourceHTLC contract, required {resolver_amount} actual {resolver_balance}")

        # Calculate deadlines
        current_time = int(time.time())
        submission_deadline = current_time + self.submission_deadline_offset
        resolver_action_deadline = current_time + self.resolver_action_deadline_offset

        # Hash destination chain identifier
        destination_chain_bytes = destination_chain.encode('utf-8')
        destination_chain_hash = hashlib.sha256(destination_chain_bytes).digest()

        # Build order
        destinationToken = b'\x00' * 32
        order = {
            'userAddress': AsyncWeb3.to_checksum_address(user_address),
            'resolverAddress': self.resolver_account.address,
            'userAmount': source_amount,
            'resolverAmount': resolver_amount,
            'venueAddress': self.venue_address,
            'venueFee': venue_fee,
            'arbitratorAddress': self.arbitrator_address,
            'arbitratorAttentionFee': self.arbitrator_attention_fee,
            'arbitratorUsageFee': arbitrator_usage_fee,
            'secretHash': secret_hash,
            'submissionDeadline': submission_deadline,
            'resolverActionDeadline': resolver_action_deadline,
            'destinationChain': '0x' + destination_chain_hash.hex(),
            'destinationAddress': user_address,  # Same user address on destination
            'destinationToken': '0x' + destinationToken.hex(),  # Native ETH (zero bytes)
            'destinationAmount': destination_amount
        }
        return order

    async def sign_order(self, order: Dict[str, Any]) -> Dict[str, str]:
        """Sign an order using EIP-712."""
        # Get order hash from contract
        order_hash = await self.create_order_hash(order)
        
        # Sign the order hash
        signed_message = self.resolver_account.unsafe_sign_hash(HexBytes(order_hash))
        
        # Create both r,s,v and r,vs formats
        r = signed_message.r
        s = signed_message.s  
        v = signed_message.v
        
        # Pack r and vs (v and s combined)
        vs = (v << 255) | s
        
        result = {
            'r': hex(r),
            's': hex(s),
            'v': v,
            'vs': hex(vs),
            'signature': '0x' + signed_message.signature.hex(),
            'order_hash': '0x' + order_hash
        }
        print("Result is", result)
        return result

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


def create_quart_app(daemon: QuoteDaemon) -> Quart:
    """Create and configure the Quart application."""
    app = Quart(__name__)

    @app.route('/ethereum/<network>/quote.resolver', methods=['POST'])
    async def quote_resolver(network: str):
        """Provide a signed quote for a cross-chain swap."""
        
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

        user_address = data.get('user_address')
        source_amount = data.get('source_amount')
        destination_chain = data.get('destination_chain')
        destination_amount = data.get('destination_amount')
        secret_hash = data.get('secret_hash')

        # Validate required fields
        if not all([user_address, source_amount, destination_chain, destination_amount, secret_hash]):
            return jsonify({
                "success": False,
                "error": "Missing required fields: user_address, source_amount, destination_chain, destination_amount, secret_hash"
            }), 400

        # Validate types
        if not isinstance(source_amount, int) or source_amount <= 0:
            return jsonify({
                "success": False,
                "error": "source_amount must be a positive integer (wei)"
            }), 400
        
        if not isinstance(destination_amount, int) or destination_amount <= 0:
            return jsonify({
                "success": False,
                "error": "destination_amount must be a positive integer (wei)"
            }), 400

        # Validate addresses
        try:
            AsyncWeb3.to_checksum_address(user_address)
        except:
            return jsonify({
                "success": False,
                "error": "Invalid user_address format"
            }), 400

        # Validate secret hash
        if not secret_hash.startswith('0x') or len(secret_hash) != 66:
            return jsonify({
                "success": False,
                "error": "secret_hash must be 32-byte hex string (0x...)"
            }), 400

        # Create quote
        order = await daemon.create_quote(
            user_address,
            source_amount,
            destination_chain,
            destination_amount,
            secret_hash
        )

        # Sign the order
        signature_data = await daemon.sign_order(order)

        return jsonify({
            'success': True,
            'order': order,
            'signature': signature_data,
            'resolver_address': daemon.resolver_account.address,
            'quote_timestamp': int(time.time())
        })

    @app.route('/ethereum/<network>/health.quote', methods=['GET'])
    async def health_check_endpoint(network: str):
        """Health check endpoint for quote daemon."""
        
        # Validate network matches daemon configuration  
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        
        await daemon.health_check()
        return jsonify({
            "status": "healthy",
            "resolver_address": daemon.resolver_account.address,
            "shtlc_address": daemon.shtlc_address,
            "network": daemon.network
        })
                
    return app


async def main():
    """Main function to start the quote daemon."""
    parser = argparse.ArgumentParser(description="HTLC Quote Daemon for Ethereum")
    
    # Configuration file (required)
    parser.add_argument("params_file", help="JSON file containing deployment parameters")
    
    # Account configuration (mutually exclusive)
    account_group = parser.add_mutually_exclusive_group(required=True)
    account_group.add_argument("--private-key", help="Private key in hex format")
    account_group.add_argument("--private-key-env", help="Environment variable containing private key")    
    account_group.add_argument("--random-key", action="store_true", help="Generate random account")
    
    parser.add_argument("--topup", type=int, help="Keep resolver balance above this value (wei)")

    # Server configuration
    parser.add_argument("--port", type=int, default=7403, help="Port to run the server on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the server to")
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.params_file)
    topup = config.get('topup', args.topup)
    if topup is None:
        topup = 0
    topup = int(topup)
    config['topup'] = topup
    
    print(f"📋 Configuration loaded:")
    print(f"   Source HTLC Contract: {config['shtlc_address']}")
    print(f"   Node URL: {config['node_url']}")
    print(f"   Chain ID: {config['chain_id']}")
    
    # Create account
    resolver_account = create_account(args)
    print(f"🔑 Resolver address: {resolver_account.address}")
    
    # Initialize daemon
    daemon = QuoteDaemon(
        config=config,
        resolver_account=resolver_account
    )
    
    # Initialize connection
    await daemon.initialize()
    
    # Perform initial health check
    print("🏥 Performing initial health check...")
    await daemon.health_check()
    print("✅ Initial health check passed - daemon is ready!")
    
    # Create Quart app
    app = create_quart_app(daemon)
    
    print(f"🚀 Starting HTLC Quote Daemon on {args.host}:{args.port}")
    print(f"   Endpoints:")
    print(f"     POST /ethereum/{config['network']}/quote.resolver")
    print(f"     GET /ethereum/{config['network']}/health.quote")
    
    try:
        # Run Quart app
        await app.run_task(host=args.host, port=args.port, debug=False)
    finally:
        # Clean up
        await daemon.close()


if __name__ == "__main__":
    asyncio.run(main())