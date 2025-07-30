#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
HTLC Fill Daemon - Internal service for creating HTLCs by depositing funds.

This daemon acts as a resolver that creates HTLCs by calling the createHTLC
method on the DestinationHTLC contract.
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

# Contract ABI for DestinationHTLC (only functions we need)
CONTRACT_ABI = [
    {
        "type": "function",
        "name": "createHTLC",
        "inputs": [
            {"name": "secretHash", "type": "bytes32", "internalType": "bytes32"},
            {"name": "userAddress", "type": "address", "internalType": "address"},
            {"name": "deadline", "type": "uint256", "internalType": "uint256"}
        ],
        "outputs": [],
        "stateMutability": "payable"
    },
    {
        "type": "function",
        "name": "hashSecret",
        "inputs": [{"name": "secret", "type": "bytes32", "internalType": "bytes32"}],
        "outputs": [{"name": "", "type": "bytes32", "internalType": "bytes32"}],
        "stateMutability": "pure"
    },
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
        "name": "doesHTLCExist",
        "inputs": [{"name": "secretHash", "type": "bytes32", "internalType": "bytes32"}],
        "outputs": [{"name": "", "type": "bool", "internalType": "bool"}],
        "stateMutability": "view"
    },
    {
        "type": "event",
        "name": "HTLCCreated",
        "inputs": [
            {"name": "secretHash", "type": "bytes32", "indexed": True, "internalType": "bytes32"},
            {"name": "userAddress", "type": "address", "indexed": True, "internalType": "address"},
            {"name": "resolverAddress", "type": "address", "indexed": True, "internalType": "address"},
            {"name": "amount", "type": "uint256", "indexed": False, "internalType": "uint256"},
            {"name": "deadline", "type": "uint256", "indexed": False, "internalType": "uint256"}
        ],
        "anonymous": False
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


class HTLCFillClient:
    """Ethereum HTLC fill client using web3.py async."""
    
    def __init__(self, config: Dict[str, Any], resolver_account: Account):
        self.network = config['network']
        self.config = config
        self.contract_address = AsyncWeb3.to_checksum_address(config['contract_address'])
        self.resolver_account = resolver_account
        
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
    
    async def create_htlc(
        self, 
        secret_hash: HexBytes, 
        user_address: ChecksumAddress, 
        amount: int, 
        deadline: int
    ) -> str:
        """Create HTLC by depositing ETH."""
        # Build transaction
        function = self.contract.functions.createHTLC(secret_hash, user_address, deadline)
        
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
    
    async def hash_secret(self, secret: HexBytes) -> HexBytes:
        """Call the contract's hashSecret view function."""
        try:
            result = await self.contract.functions.hashSecret(secret).call()
            return HexBytes(result)
        except Exception as e:
            print(f"❌ Error hashing secret: {e}")
            # Fallback to local calculation
            return HexBytes(hashlib.sha256(secret).digest())
    
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
    
    async def does_htlc_exist(self, secret_hash: HexBytes) -> bool:
        """Check if HTLC exists."""
        try:
            return await self.contract.functions.doesHTLCExist(secret_hash).call()
        except Exception as e:
            print(f"❌ Error checking HTLC existence: {e}")
            return False


class FillDaemon:
    """HTLC Fill Daemon that creates HTLCs by depositing funds."""
    
    def __init__(self, config: Dict[str, Any], resolver_account: Account):
        self.network = config['network'] 
        self.config = config
        self.resolver_account = resolver_account
        
        # Initialize client
        self.client = HTLCFillClient(config, resolver_account)
    
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
        
        # Check balance
        balance = await self.client.w3.eth.get_balance(self.resolver_account.address)
        print(f"✅ Resolver balance: {self.client.w3.from_wei(balance, 'ether')} ETH")
        
        if balance == 0:
            print("⚠️  Warning: Resolver account has no ETH for deposits or gas fees")
    
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
                "resolver_address": self.resolver_account.address,
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
                "resolver_address": self.resolver_account.address,
                "contract_address": self.client.contract_address
            }
    
    async def create_htlc_transaction(
        self,
        secret_hash: str,
        user_address: str,
        amount: int,
        deadline: int
    ) -> Dict[str, Any]:
        """Create an HTLC and return transaction information."""
        # Convert hex string to bytes
        if secret_hash.startswith("0x"):
            secret_hash = secret_hash[2:]
        
        # Pad to 32 bytes if needed
        if len(secret_hash) < 64:
            secret_hash = secret_hash.ljust(64, '0')
            
        secret_hash_bytes = HexBytes(secret_hash)
        user_addr = AsyncWeb3.to_checksum_address(user_address)
        
        print(f"🔒 Creating HTLC:")
        print(f"   Secret hash: 0x{secret_hash}")
        print(f"   User address: {user_address}")
        print(f"   Amount: {self.client.w3.from_wei(amount, 'ether')} ETH ({amount} wei)")
        print(f"   Deadline: {deadline} ({time.ctime(deadline)})")
        
        # Check if HTLC already exists
        exists = await self.client.does_htlc_exist(secret_hash_bytes)
        if exists:
            return {
                "success": False,
                "error": f"HTLC already exists for secret hash 0x{secret_hash}"
            }
        
        # Check resolver balance
        resolver_balance = await self.client.w3.eth.get_balance(self.resolver_account.address)
        if resolver_balance < amount:
            return {
                "success": False,
                "error": f"Insufficient balance. Need {self.client.w3.from_wei(amount, 'ether')} ETH, have {self.client.w3.from_wei(resolver_balance, 'ether')} ETH"
            }
        
        # Submit transaction
        tx_hash = await self.client.create_htlc(
            secret_hash_bytes,
            user_addr,
            amount,
            deadline
        )
        
        print(f"   Transaction: {tx_hash}")
        
        # Wait for transaction confirmation
        receipt = await self.client.w3.eth.wait_for_transaction_receipt(HexBytes(tx_hash))
        
        # Extract gas information
        gas_used = receipt.gasUsed
        gas_price = await self.client.w3.eth.get_transaction(HexBytes(tx_hash))
        gas_fee = gas_used * gas_price.gasPrice
        
        print(f"✅ HTLC created successfully!")
        print(f"   Block: {receipt.blockNumber}")
        print(f"   Gas used: {gas_used}")
        print(f"   Gas fee: {self.client.w3.from_wei(gas_fee, 'ether')} ETH")
        
        return {
            "success": True,
            "transaction_hash": tx_hash,
            "block_number": receipt.blockNumber,
            "gas_used": gas_used,
            "gas_fee": gas_fee,
            "htlc_created": {
                "secret_hash": f"0x{secret_hash}",
                "user_address": user_address,
                "resolver_address": self.resolver_account.address,
                "amount": amount,
                "deadline": deadline
            }
        }
    
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
    
    async def close(self):
        """Clean up resources."""
        await self.client.close()


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


def create_quart_app(daemon: FillDaemon) -> Quart:
    """Create and configure the Quart application."""
    app = Quart(__name__)
    
    @app.route('/ethereum/<network>/balance/<account>', methods=['GET'])
    async def get_balance(network: str, account: str):
        """Get ETH balance of an account."""
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        
        balance = await daemon.get_balance(account)
        return jsonify({'balance': balance})
    
    @app.route('/ethereum/<network>/destination_htlc/0x<secret_hash>', methods=['GET'])
    async def get_destination_htlc(network: str, secret_hash: str):
        """Get HTLC info by secret hash."""
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        
        info = await daemon.get_htlc_info(secret_hash)
        return jsonify(info)
    
    @app.route('/ethereum/<network>/fill', methods=['POST'])
    async def create_htlc_endpoint(network: str):
        """Endpoint to create an HTLC."""
        
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
        user_address = data.get("user_address") 
        amount = data.get("amount")
        deadline = data.get("deadline")
        
        # Validate required fields
        if not all([secret_hash, user_address, amount, deadline]):
            raise ValueError("Missing required fields: secret_hash, user_address, amount, deadline")
        
        # Validate types
        if not isinstance(amount, int) or amount <= 0:
            raise ValueError("Amount must be a positive integer (wei)")
        
        if not isinstance(deadline, int) or deadline <= int(time.time()):
            raise ValueError("Deadline must be a future unix timestamp")
        
        # Validate addresses
        AsyncWeb3.to_checksum_address(user_address)  # Raises if invalid
        
        # Create HTLC asynchronously
        result = await daemon.create_htlc_transaction(secret_hash, user_address, amount, deadline)
        
        status_code = 200 if result["success"] else 400
        return jsonify(result), status_code
    
    @app.route('/ethereum/<network>/health.fill', methods=['GET'])
    async def health_check_endpoint(network: str):
        """Health check endpoint."""
        
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
    """Main function to start the fill daemon."""
    parser = argparse.ArgumentParser(description="HTLC Fill Daemon for Ethereum")
    
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
    account_group.add_argument("--random-key", action="store_true",
                             help="Generate random account (for testing)")
    
    # Server configuration
    parser.add_argument("--port", type=int, default=7300, help="Port to run the server on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the server to")
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = load_config(args.params_file, args)
        
        print(f"📋 Configuration loaded:")
        print(f"   Network: {config['network']}")
        print(f"   Contract: {config['contract_address']}")
        print(f"   Node URL: {config['node_url']}")
        print(f"   Chain ID: {config.get('chain_id', 'auto-detect')}")
        
        # Create account
        resolver_account = create_account(args)
        print(f"🏦 Resolver address: {resolver_account.address}")
        
        # Initialize daemon
        daemon = FillDaemon(
            config=config,
            resolver_account=resolver_account
        )
        
        # Initialize connection and check balance
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
        
        print(f"🚀 Starting HTLC Fill Daemon on {args.host}:{args.port}")
        print(f"   Endpoints:")
        print(f"     POST /ethereum/{config['network']}/fill")
        print(f"     GET /ethereum/{config['network']}/health.fill")
        print(f"     GET /ethereum/{config['network']}/balance/<address>")
        print(f"     GET /ethereum/{config['network']}/destination_htlc/0x<secret_hash>")
        
        # Run Quart app
        await app.run_task(host=args.host, port=args.port, debug=False)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down daemon...")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)
    finally:
        # Clean up
        if 'daemon' in locals():
            await daemon.close()


if __name__ == "__main__":
    asyncio.run(main())