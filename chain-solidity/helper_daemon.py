#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
HTLC Helper Daemon - API service for revealing secrets and claiming refunds.

This daemon handles HTLC claiming operations by calling revealSecret and 
claimRefund methods on the DestinationHTLC contract.
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

# Contract ABI for DestinationHTLC
CONTRACT_ABI = [
    {
        "type": "function",
        "name": "revealSecret",
        "inputs": [{"name": "secret", "type": "bytes32", "internalType": "bytes32"}],
        "outputs": [],
        "stateMutability": "nonpayable"
    },
    {
        "type": "function", 
        "name": "claimRefund",
        "inputs": [{"name": "secretHash", "type": "bytes32", "internalType": "bytes32"}],
        "outputs": [],
        "stateMutability": "nonpayable"
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
        "type": "function",
        "name": "hashSecret",
        "inputs": [{"name": "secret", "type": "bytes32", "internalType": "bytes32"}],
        "outputs": [{"name": "", "type": "bytes32", "internalType": "bytes32"}],
        "stateMutability": "pure"
    },
    {
        "type": "function",
        "name": "isClaimable",
        "inputs": [{"name": "secretHash", "type": "bytes32", "internalType": "bytes32"}],
        "outputs": [{"name": "claimable", "type": "bool", "internalType": "bool"}],
        "stateMutability": "view"
    },
    {
        "type": "function",
        "name": "isRefundable", 
        "inputs": [{"name": "secretHash", "type": "bytes32", "internalType": "bytes32"}],
        "outputs": [{"name": "refundable", "type": "bool", "internalType": "bool"}],
        "stateMutability": "view"
    },
    {
        "type": "event",
        "name": "SecretRevealed",
        "inputs": [
            {"name": "secretHash", "type": "bytes32", "indexed": True, "internalType": "bytes32"},
            {"name": "secret", "type": "bytes32", "indexed": False, "internalType": "bytes32"},
            {"name": "userAddress", "type": "address", "indexed": True, "internalType": "address"},
            {"name": "amount", "type": "uint256", "indexed": False, "internalType": "uint256"}
        ],
        "anonymous": False
    },
    {
        "type": "event",
        "name": "HTLCRefunded",
        "inputs": [
            {"name": "secretHash", "type": "bytes32", "indexed": True, "internalType": "bytes32"},
            {"name": "resolverAddress", "type": "address", "indexed": True, "internalType": "address"},
            {"name": "amount", "type": "uint256", "indexed": False, "internalType": "uint256"}
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
    if args.dhtlc_address:
        config['dhtlc_address'] = args.dhtlc_address
    if args.node_url:
        config['node_url'] = args.node_url
    if args.chain_id:
        config['chain_id'] = int(args.chain_id)
    
    # Ensure we have required fields
    if 'network' not in config:
        raise ValueError("Network must be specified in params file or command line")
    if 'dhtlc_address' not in config:
        raise ValueError("Contract address must be specified in params file or command line")
    
    # Fill in defaults if not specified
    network = config['network']
    if network in DEFAULT_NETWORK_CONFIGS:
        defaults = DEFAULT_NETWORK_CONFIGS[network]
        for key, value in defaults.items():
            if key not in config:
                config[key] = value
    
    return config


class HTLCHelperClient:
    """Ethereum HTLC helper client using web3.py async."""
    
    def __init__(self, config: Dict[str, Any], claimer_account: Account):
        self.network = config['network']
        self.config = config
        self.dhtlc_address = AsyncWeb3.to_checksum_address(config['dhtlc_address'])
        self.claimer_account = claimer_account
        
        # Initialize web3 client
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(config['node_url']))
        
        # Create contract instance
        self.contract = self.w3.eth.contract(
            address=self.dhtlc_address,
            abi=CONTRACT_ABI
        )
    
    async def close(self):
        """Clean up resources."""
        if hasattr(self.w3.provider, 'session') and self.w3.provider.session:
            await self.w3.provider.session.close()
    
    async def reveal_secret(self, secret: HexBytes) -> str:
        """Reveal secret to claim HTLC funds."""
        # Build transaction
        function = self.contract.functions.revealSecret(secret)
        
        # Get nonce and gas price
        nonce = await self.w3.eth.get_transaction_count(self.claimer_account.address)
        gas_price = await self.w3.eth.gas_price
        
        # Estimate gas
        gas_estimate = await function.estimate_gas({
            'from': self.claimer_account.address,
            'gasPrice': gas_price
        })
        
        # Build transaction
        transaction = await function.build_transaction({
            'from': self.claimer_account.address,
            'gas': gas_estimate,
            'gasPrice': gas_price,
            'nonce': nonce,
        })
        
        # Sign transaction
        signed_txn = self.w3.eth.account.sign_transaction(transaction, self.claimer_account.key)
        
        # Send transaction
        tx_hash = await self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        
        return tx_hash.hex()
    
    async def claim_refund(self, secret_hash: HexBytes) -> str:
        """Claim refund after HTLC timeout."""
        # Build transaction
        function = self.contract.functions.claimRefund(secret_hash)
        
        # Get nonce and gas price
        nonce = await self.w3.eth.get_transaction_count(self.claimer_account.address)
        gas_price = await self.w3.eth.gas_price
        
        # Estimate gas
        gas_estimate = await function.estimate_gas({
            'from': self.claimer_account.address,
            'gasPrice': gas_price
        })
        
        # Build transaction
        transaction = await function.build_transaction({
            'from': self.claimer_account.address,
            'gas': gas_estimate,
            'gasPrice': gas_price,
            'nonce': nonce,
        })
        
        # Sign transaction
        signed_txn = self.w3.eth.account.sign_transaction(transaction, self.claimer_account.key)
        
        # Send transaction
        tx_hash = await self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        
        return tx_hash.hex()
    
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
    
    async def hash_secret(self, secret: HexBytes) -> HexBytes:
        """Call the contract's hashSecret view function."""
        result = await self.contract.functions.hashSecret(secret).call()
        return HexBytes(result)
            
    
    async def does_htlc_exist(self, secret_hash: HexBytes) -> bool:
        """Check if HTLC exists."""
        return await self.contract.functions.doesHTLCExist(secret_hash).call()
    
    async def is_claimable(self, secret_hash: HexBytes) -> bool:
        """Check if HTLC is claimable."""
        return await self.contract.functions.isClaimable(secret_hash).call()
    
    async def is_refundable(self, secret_hash: HexBytes) -> bool:
        """Check if HTLC is refundable."""
        return await self.contract.functions.isRefundable(secret_hash).call()


class HelperDaemon:
    """HTLC Helper Daemon that reveals secrets and claims refunds."""
    
    def __init__(self, config: Dict[str, Any], claimer_account: Account):
        self.network = config['network'] 
        self.config = config
        self.claimer_account = claimer_account
        
        # Initialize client
        self.client = HTLCHelperClient(config, claimer_account)
    
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
        balance = await self.client.w3.eth.get_balance(self.claimer_account.address)
        print(f"✅ Claimer balance: {self.client.w3.from_wei(balance, 'ether')} ETH")
        
        if balance == 0:
            print("⚠️  Warning: Claimer account has no ETH for gas fees")
    
    async def get_balance(self, address: str) -> int:
        """Get ETH balance of address in wei."""
        checksum_address = AsyncWeb3.to_checksum_address(address)
        return await self.client.w3.eth.get_balance(checksum_address)
    
    async def get_htlc_info(self, secret_hash: str) -> Optional[Dict[str, Any]]:
        """Get HTLC info by secret hash."""
        if secret_hash.startswith('0x'):
            secret_hash = secret_hash[2:]
        secret_hash_bytes = HexBytes(secret_hash)
        return await self.client.get_htlc_info(secret_hash_bytes)
    
    async def txwait(self, transaction_id: str) -> Dict[str, Any]:
        """Wait for transaction and return receipt."""
        tx_hash = HexBytes(transaction_id)
        receipt = await self.client.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Convert receipt to dict format for JSON serialization
        return {
            "transactionHash": receipt.transactionHash.hex(),
            "blockNumber": receipt.blockNumber,
            "blockHash": receipt.blockHash.hex(),
            "transactionIndex": receipt.transactionIndex,
            "from": receipt["from"],
            "to": receipt.to,
            "gasUsed": receipt.gasUsed,
            "cumulativeGasUsed": receipt.cumulativeGasUsed,
            "status": receipt.status,
            "logs": [
                {
                    "address": log.address,
                    "topics": [topic.hex() for topic in log.topics],
                    "data": log.data.hex()
                } for log in receipt.logs
            ]
        }

    async def health_check(self) -> Dict[str, Any]:
        """Perform a comprehensive health check including contract verification."""
        try:
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
                    "claimer_address": self.claimer_account.address,
                    "dhtlc_address": self.client.dhtlc_address,
                    "node_url": self.config.get('node_url'),
                    "chain_id": int(self.config.get('chain_id'))
                }
            else:
                print("❌ Hash verification failed!")
                return {
                    "status": "unhealthy",
                    "contract_responsive": True,
                    "hash_verification": "failed",
                    "error": f"Expected {expected_hash.hex()}, got {contract_hash.hex()}",
                    "network": self.network,
                    "claimer_address": self.claimer_account.address,
                    "dhtlc_address": self.client.dhtlc_address
                }
        except Exception as e:
            print(f"❌ Health check failed: {e}")
            return {
                "status": "unhealthy",
                "contract_responsive": False,
                "error": str(e),
                "network": self.network,
                "claimer_address": self.claimer_account.address,
                "dhtlc_address": self.client.dhtlc_address
            }
    
    async def reveal_secret_transaction(self, secret_bytes: HexBytes) -> Dict[str, Any]:
        """Reveal secret to claim HTLC funds."""
        try:
            # Calculate hash for verification
            calculated_hash = HexBytes(hashlib.sha256(secret_bytes).digest())
            calculated_hash_hex = calculated_hash.hex()
            
            print(f"🔓 Revealing secret:")
            print(f"   Secret: {secret_bytes.hex()}")
            print(f"   Secret hash: {calculated_hash_hex}")
            
            # Get HTLC info first
            htlc_info = await self.client.get_htlc_info(calculated_hash)
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
            tx_hash = await self.client.reveal_secret(secret_bytes)
            
            # Wait for transaction confirmation
            receipt = await self.client.w3.eth.wait_for_transaction_receipt(HexBytes(tx_hash))
            
            # Extract gas information
            gas_used = receipt.gasUsed
            gas_price = await self.client.w3.eth.get_transaction(HexBytes(tx_hash))
            gas_fee = gas_used * gas_price.gasPrice
            
            print(f"✅ Secret revealed successfully!")
            print(f"   Transaction: {tx_hash}")
            print(f"   Gas used: {gas_used}")
            print(f"   Gas fee: {self.client.w3.from_wei(gas_fee, 'ether')} ETH")
            
            return {
                "success": True,
                "transaction_hash": tx_hash,
                "gas_used": gas_used,
                "gas_fee": gas_fee,
                "revealed": {
                    "secret_hash": f"0x{calculated_hash_hex}",
                    "secret": f"0x{secret_bytes.hex()}",
                    "user_address": htlc_info["user_address"],
                    "amount": htlc_info["amount"]
                }
            }
        except ContractLogicError as e:
            error_msg = str(e)
            print(f"❌ Contract error revealing secret: {error_msg}")
            return {
                "success": False,
                "error": f"Contract error: {error_msg}",
                "transaction_hash": None
            }
        except Exception as e:
            print(f"❌ Error revealing secret: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "transaction_hash": None
            }
    
    async def claim_refund_transaction(self, secret_hash: str) -> Dict[str, Any]:
        """Claim refund after HTLC timeout."""
        try:
            # Convert hex string to bytes
            if secret_hash.startswith("0x"):
                secret_hash = secret_hash[2:]
            secret_hash_bytes = HexBytes(secret_hash)
            
            print(f"💰 Claiming refund:")
            print(f"   Secret hash: {secret_hash}")
            
            # Get HTLC info first
            htlc_info = await self.client.get_htlc_info(secret_hash_bytes)
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
            tx_hash = await self.client.claim_refund(secret_hash_bytes)
            
            # Wait for transaction confirmation
            receipt = await self.client.w3.eth.wait_for_transaction_receipt(HexBytes(tx_hash))
            
            # Extract gas information
            gas_used = receipt.gasUsed
            gas_price = await self.client.w3.eth.get_transaction(HexBytes(tx_hash))
            gas_fee = gas_used * gas_price.gasPrice
            
            print(f"✅ Refund claimed successfully!")
            print(f"   Transaction: {tx_hash}")
            print(f"   Gas used: {gas_used}")
            print(f"   Gas fee: {self.client.w3.from_wei(gas_fee, 'ether')} ETH")
            
            return {
                "success": True,
                "transaction_hash": tx_hash,
                "gas_used": gas_used,
                "gas_fee": gas_fee,
                "refunded": {
                    "secret_hash": f"0x{secret_hash}",
                    "resolver_address": htlc_info["resolver_address"],
                    "amount": htlc_info["amount"]
                }
            }
        except ContractLogicError as e:
            error_msg = str(e)
            print(f"❌ Contract error claiming refund: {error_msg}")
            return {
                "success": False,
                "error": f"Contract error: {error_msg}",
                "transaction_hash": None
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


def create_quart_app(daemon: HelperDaemon) -> Quart:
    """Create and configure the Quart application."""
    app = Quart(__name__)

    @app.route('/ethereum/<network>/balance/<account>', methods=['GET'])
    async def get_balance(network: str, account: str):
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        balance = await daemon.get_balance(account)
        return jsonify({'balance': balance})
    
    @app.route('/ethereum/<network>/destination_htlc/0x<secret_hash>', methods=['GET'])
    async def get_destination_htlc(network: str, secret_hash: str):
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        info = await daemon.get_htlc_info(secret_hash)
        return jsonify(info)
    
    @app.route('/ethereum/<network>/txwait/<transaction_id>', methods=['GET'])
    async def txwait(network: str, transaction_id: str):
        if network != daemon.network:
            return jsonify({
                "success": False,
                "error": f"Network mismatch. Daemon configured for {daemon.network}, request for {network}"
            }), 400
        result = await daemon.txwait(transaction_id)
        return jsonify(result)
    
    @app.route('/ethereum/<network>/reveal', methods=['POST'])
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
        
        secret_str: str = data.get("secret")
        if not secret_str:
            raise ValueError("Missing required field: secret")
        
        if secret_str.startswith('0x'):
            secret_str = secret_str[2:]
        
        # Pad to 32 bytes if needed
        if len(secret_str) < 64:
            secret_str = secret_str.ljust(64, '0')
        
        secret_bytes = HexBytes(secret_str)
        
        # Reveal secret asynchronously
        result = await daemon.reveal_secret_transaction(secret_bytes)
        status_code = 200 if result["success"] else 400
        return jsonify(result), status_code
    
    @app.route('/ethereum/<network>/refund', methods=['POST'])
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
    
    @app.route('/ethereum/<network>/health.helper', methods=['GET'])
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
    parser = argparse.ArgumentParser(description="HTLC Helper Daemon for Ethereum")
    
    # Configuration file
    parser.add_argument("--params-file", help="JSON file containing deployment parameters")
    
    # Network and contract configuration (can override params file)
    parser.add_argument("--network", choices=DEFAULT_NETWORK_CONFIGS.keys(),
                       help="Network to connect to")
    parser.add_argument("--dhtlc-address", help="Address where the DestinationHTLC contract is deployed")
    parser.add_argument("--node-url", help="RPC node URL")
    parser.add_argument("--chain-id", type=int, help="Chain ID")
    
    # Account configuration (mutually exclusive)
    account_group = parser.add_mutually_exclusive_group()
    account_group.add_argument("--private-key", help="Private key in hex format")
    account_group.add_argument("--private-key-env", help="Environment variable containing private key")    
    account_group.add_argument("--random-key", action="store_true",
                             help="Generate random account (for testing)")
    
    # Server configuration
    parser.add_argument("--port", type=int, default=7401, help="Port to run the server on")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the server to")
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.params_file, args)
    
    print(f"📋 Configuration loaded:")
    print(f"   Network: {config['network']}")
    print(f"   Contract: {config['dhtlc_address']}")
    print(f"   Node URL: {config['node_url']}")
    print(f"   Chain ID: {config.get('chain_id', 'auto-detect')}")
    
    # Create account
    claimer_account = create_account(args)
    print(f"🔑 Claimer address: {claimer_account.address}")
    
    # Initialize daemon
    daemon = HelperDaemon(
        config=config,
        claimer_account=claimer_account
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
    
    print(f"🚀 Starting HTLC Helper Daemon on {args.host}:{args.port}")
    print(f"   Endpoints:")
    print(f"     POST /ethereum/{config['network']}/reveal")
    print(f"     POST /ethereum/{config['network']}/refund") 
    print(f"     GET /ethereum/{config['network']}/health.helper")
    print(f"     GET /ethereum/{config['network']}/balance/<address>")
    print(f"     GET /ethereum/{config['network']}/destination_htlc/0x<secret_hash>")
    print(f"     GET /ethereum/{config['network']}/txwait/<tx_hash>")
    
    try:
        # Run Quart app
        await app.run_task(host=args.host, port=args.port, debug=False)
    finally:
        # Clean up
        await daemon.close()


if __name__ == "__main__":
    asyncio.run(main())
