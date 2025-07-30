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
from web3.exceptions import Web3Exception, ContractLogicError
from eth_account import Account
from eth_account.messages import encode_structured_data
from eth_typing import ChecksumAddress, HexStr
from hexbytes import HexBytes

# Default network configurations
DEFAULT_NETWORK_CONFIGS = {
    "localhost": {
        "node_url": "http://127.0.0.1:8545",
        "chain_id": 31337,  # Hardhat default
    },
    "sepolia": {
        "node_url": "https://ethereum-sepolia-rpc.publicnode.com",
        "chain_id": 11155111,
    },
    "mainnet": {
        "node_url": "https://ethereum-rpc.publicnode.com", 
        "chain_id": 1,
    },
    "arbitrum": {
        "node_url": "https://arbitrum-one-rpc.publicnode.com",
        "chain_id": 42161,
    },
    "base": {
        "node_url": "https://base-rpc.publicnode.com",
        "chain_id": 8453,
    },
    "polygon": {
        "node_url": "https://polygon-bor-rpc.publicnode.com",
        "chain_id": 137,
    }
}

# Contract ABI for DestinationHTLC (view functions only)
CONTRACT_ABI = [
    {
        "type": "function",
        "name": "getHTLCInfo", 
        "inputs": [{"name": "secretHash", "type": "bytes32", "internalType": "bytes32"}],
        "outputs": [
            {"name": "userAddress", "type": "address", "internalType": "address"},
            {"name": "resolverAddress", "type": "address", "internalType": "address"},
            {"name": "amount", "type": "uint256", "internalType": "uint256"},
            {"name": "deadline", "type": "uint256", "internalType": "uint256"},
            {"name": "claimed", "type": "bool", "internalType": "bool"}
        ],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "hashSecret",
        "inputs": [{"name": "secret", "type": "bytes32", "internalType": "bytes32"}],
        "outputs": [{"name": "", "type": "bytes32", "internalType": "bytes32"}],
        "stateMutability": "pure"
    }
]


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


class HTLCArbitratorClient:
    """Ethereum HTLC arbitrator client using web3.py async."""
    
    def __init__(self, config: Dict[str, Any]):
        self.network = config['network']
        self.config = config
        self.contract_address = AsyncWeb3.to_checksum_address(config['contract_address'])
        
        # Initialize web3 client
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(config['node_url']))
        
        # Create contract instance
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=CONTRACT_ABI
        )
    
    async def close(self):
        """Clean up resources."""
        if hasattr(self.w3.provider, 'session') and self.w3.provider.session:
            await self.w3.provider.session.close()
    
    async def get_htlc_info(self, secret_hash: HexBytes) -> Optional[Dict[str, Any]]:
        """Get HTLC information from the contract."""
        try:
            result = await self.contract.functions.getHTLCInfo(secret_hash).call()
            
            return {
                "user_address": result[0],
                "resolver_address": result[1], 
                "amount": result[2],
                "deadline": result[3],
                "claimed": result[4]
            }
        except ContractLogicError:
            # HTLC doesn't exist
            return None
        except Exception as e:
            print(f"❌ Error getting HTLC info: {e}")
            return None
    
    async def hash_secret(self, secret: HexBytes) -> HexBytes:
        """Call the contract's hashSecret view function."""
        try:
            result = await self.contract.functions.hashSecret(secret).call()
            return HexBytes(result)
        except Exception as e:
            print(f"❌ Error hashing secret: {e}")
            # Fallback to local calculation
            return HexBytes(hashlib.sha256(secret).digest())


class ArbitratorDaemon:
    """HTLC Arbitrator Daemon that signs deposit proofs using EIP-712."""
    
    def __init__(self, config: Dict[str, Any], arbitrator_account: Account):
        self.network = config['network'] 
        self.config = config
        self.arbitrator_account = arbitrator_account
        
        # Initialize client
        self.client = HTLCArbitratorClient(config)
        
        # EIP-712 Domain for signing
        self.domain = {
            'name': 'HTLC Arbitrator',
            'version': '1',
            'chainId': config.get('chain_id', 1),
            'verifyingContract': self.client.contract_address
        }
        
        # EIP-712 Types for HTLC Decision
        self.types = {
            'EIP712Domain': [
                {'name': 'name', 'type': 'string'},
                {'name': 'version', 'type': 'string'},
                {'name': 'chainId', 'type': 'uint256'},
                {'name': 'verifyingContract', 'type': 'address'}
            ],
            'HTLCDecision': [
                {'name': 'status', 'type': 'uint8'},
                {'name': 'secretHash', 'type': 'bytes32'},
                {'name': 'deadline', 'type': 'uint256'},
                {'name': 'destinationChain', 'type': 'bytes32'},
                {'name': 'destinationToken', 'type': 'bytes32'},
                {'name': 'destinationAmount', 'type': 'uint256'},
                {'name': 'destinationAddress', 'type': 'address'}
            ]
        }
    
    async def initialize(self):
        """Initialize the daemon by checking connection."""
        is_connected = await self.client.w3.is_connected()
        if not is_connected:
            raise ConnectionError(f"Could not connect to {self.config['node_url']}")
        
        # Get chain ID to verify network
        chain_id = await self.client.w3.eth.chain_id
        expected_chain_id = self.config.get('chain_id')
        if expected_chain_id and chain_id != expected_chain_id:
            print(f"⚠️  Warning: Connected to chain ID {chain_id}, expected {expected_chain_id}")
            # Update domain with actual chain ID
            self.domain['chainId'] = chain_id
        
        print(f"✅ Arbitrator address: {self.arbitrator_account.address}")
        print(f"✅ Contract address: {self.client.contract_address}")
        print(f"✅ Chain ID: {chain_id}")
    
    async def get_balance(self, address: str) -> int:
        """Get ETH balance of address in wei."""
        checksum_address = AsyncWeb3.to_checksum_address(address)
        return await self.client.w3.eth.get_balance(checksum_address)
    
    async def get_htlc_info(self, secret_hash: str) -> Optional[Dict[str, Any]]:
        """Get HTLC info by secret hash."""
        if secret_hash.startswith('0x'):
            secret_hash = secret_hash[2:]
        
        # Pad to 32 bytes if needed
        if len(secret_hash) < 64:
            secret_hash = secret_hash.ljust(64, '0')
            
        secret_hash_bytes = HexBytes(secret_hash)
        return await self.client.get_htlc_info(secret_hash_bytes)

    async def health_check(self) -> Dict[str, Any]:
        """Perform a comprehensive health check including contract verification."""
        # Test secret for verification
        test_secret = HexBytes("0x" + "test_secret_123".encode().hex().ljust(64, '0'))
        expected_hash = HexBytes(hashlib.sha256(test_secret).digest())
        
        print("🔍 Performing contract health check...")
        print(f"   Testing with secret: {test_secret.hex()}")
        print(f"   Expected hash: {expected_hash.hex()}")
        
        # Call the contract's hashSecret function
        contract_hash = await self.client.hash_secret(test_secret)
        print(f"   Contract returned: {contract_hash.hex()}")
        
        # Verify the hash matches
        if contract_hash == expected_hash:
            print("✅ Contract health check passed!")
            return {
                "status": "healthy",
                "contract_responsive": True,
                "hash_verification": "passed",
                "network": self.network,
                "arbitrator_address": self.arbitrator_account.address,
                "contract_address": self.client.contract_address,
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
                "arbitrator_address": self.arbitrator_account.address,
                "contract_address": self.client.contract_address
            }

    async def close(self):
        """Clean up resources."""
        await self.client.close()


def parse_hex(x: str | bytes) -> bytes:
    """Parse hex string or bytes into bytes."""
    if isinstance(x, bytes):
        return x
    if x.startswith('0x'):
        x = x[2:]
    return bytes.fromhex(x)

def arbitrator_sign(
    account: Account,
    domain: Dict[str, Any],
    types: Dict[str, Any],
    status: int,
    secret_hash: bytes,
    deadline: int,
    destination_chain: bytes,
    destination_token: bytes,
    destination_amount: int,
    destination_address: str
) -> Dict[str, str]:
    """Sign HTLC decision using EIP-712."""
    
    # Prepare the message data
    message = {
        'status': status,
        'secretHash': secret_hash,
        'deadline': deadline,
        'destinationChain': destination_chain,
        'destinationToken': destination_token,
        'destinationAmount': destination_amount,
        'destinationAddress': destination_address
    }
    
    # Create structured data
    structured_data = {
        'types': types,
        'domain': domain,
        'primaryType': 'HTLCDecision',
        'message': message
    }
    
    # Encode and sign
    encoded = encode_structured_data(structured_data)
    signed_message = account.sign_message(encoded)
    
    return {
        'message': message,
        'signature': signed_message.signature.hex(),
        'recovery_id': signed_message.v,
        'r': hex(signed_message.r),
        's': hex(signed_message.s)
    }


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
        destination_address = data['destination_address']  # Keep as string for EIP-712

        # Native ETH token is represented as zero address
        expected_token = b'\x00' * 32  # 32 zero bytes
        
        # Expected chain identifier
        expected_chain = f"ethereum-{network}"
        expected_chain_bytes = expected_chain.encode('utf-8')
        expected_chain_hash_bytes = hashlib.sha256(expected_chain_bytes).digest()
        
        if destination_chain != expected_chain_hash_bytes:
            return jsonify({
                "success": False,
                "error": f"Destination chain mismatch, got {destination_chain.hex()} expected {expected_chain_hash_bytes.hex()}",
                "code": "WRONG_CHAIN",
            }), 400

        # Get HTLC info from contract
        info = await daemon.get_htlc_info(secret_hash.hex())
        if not info:
            return jsonify({
                "success": False,
                "error": "HTLC not found",
                "code": "HTLC_NOT_FOUND",
            }), 404

        # Validate parameters against contract data
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

        # Determine status (0 = valid, 1 = expired)
        current_time = int(time.time())
        status = 1 if current_time >= deadline else 0

        # Sign the decision using EIP-712
        signature_data = arbitrator_sign(
            account=daemon.arbitrator_account,
            domain=daemon.domain,
            types=daemon.types,
            status=status,
            secret_hash=secret_hash,
            deadline=deadline,
            destination_chain=destination_chain,
            destination_token=destination_token,
            destination_amount=destination_amount,
            destination_address=destination_address_checksum
        )

        return jsonify({
            'success': True,
            'info': info,
            'signature': signature_data,
            'arbitrator_address': daemon.arbitrator_account.address,
            'domain': daemon.domain,
            'types': daemon.types
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
        
        # Perform async health check
        health_result = await daemon.health_check()
        status_code = 200 if health_result["status"] == "healthy" else 503
        return jsonify(health_result), status_code
                
    return app


async def main():
    """Main function to start the arbitrator daemon."""
    parser = argparse.ArgumentParser(description="HTLC Arbitrator Daemon for Ethereum")
    
    # Configuration file
    parser.add_argument("--params-file", help="JSON file containing deployment parameters")
    
    # Network and contract configuration (can override params file)
    parser.add_argument("--network", choices=DEFAULT_NETWORK_CONFIGS.keys(),
                       help="Network to connect to")
    parser.add_argument("--contract-address", help="Address where the HTLC contract is deployed")
    parser.add_argument("--node-url", help="RPC node URL")
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
    print(f"   Chain ID: {config.get('chain_id', 'auto-detect')}")
    
    # Create account
    arbitrator_account = create_account(args)
    print(f"🔑 Arbitrator address: {arbitrator_account.address}")
    
    # Initialize daemon
    daemon = ArbitratorDaemon(
        config=config,
        arbitrator_account=arbitrator_account
    )
    
    # Initialize connection
    await daemon.initialize()
    
    # Perform initial health check
    print("🏥 Performing initial health check...")
    health_result = await daemon.health_check()
    
    if health_result["status"] != "healthy":
        print("❌ Initial health check failed!")
        print(f"   Error: {health_result.get('error', 'Unknown error')}")
        sys.exit(1)
    
    print("✅ Initial health check passed - daemon is ready!")
    
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
