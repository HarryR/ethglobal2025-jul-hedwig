#!/usr/bin/env python3
"""
Enhanced Aptos contract deployment script with network selection and account options.

Usage examples:
    python deploy.py --network devnet --use-faucet
    python deploy.py --network testnet --private-key 0x123...
    python deploy.py --network mainnet --private-key-env DEPLOYER_KEY
    python deploy.py --network localnet --use-faucet
"""

import argparse
import asyncio
import os
import sys
import glob
from typing import List, Dict, Any, Optional

from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.aptos_cli_wrapper import AptosCLIWrapper
from aptos_sdk.async_client import FaucetClient, RestClient
from aptos_sdk.package_publisher import PackagePublisher

# Package configuration - will be read from Move.toml
# PACKAGE_NAME = "example"  # Removed - now read from Move.toml

# Network configurations
NETWORK_CONFIGS = {
    "localnet": {
        "node_url": "http://127.0.0.1:8080",
        "faucet_url": "http://127.0.0.1:8081",
        "indexer_url": "http://127.0.0.1:8090/v1/graphql",
        "chain_id": 4,  # Default localnet chain ID
    },
    "devnet": {
        "node_url": "https://api.devnet.aptoslabs.com/v1",
        "faucet_url": "https://faucet.devnet.aptoslabs.com",
        "indexer_url": "https://api.devnet.aptoslabs.com/v1/graphql",
        "chain_id": 123,  # Devnet chain ID
    },
    "testnet": {
        "node_url": "https://api.testnet.aptoslabs.com/v1",
        "faucet_url": None,  # No public faucet for testnet
        "indexer_url": "https://api.testnet.aptoslabs.com/v1/graphql", 
        "chain_id": 2,  # Testnet chain ID
    },
    "mainnet": {
        "node_url": "https://api.mainnet.aptoslabs.com/v1",
        "faucet_url": None,  # No faucet for mainnet
        "indexer_url": "https://api.mainnet.aptoslabs.com/v1/graphql",
        "chain_id": 1,  # Mainnet chain ID
    }
}


class DeploymentClient(RestClient):
    """Extended REST client for deployment operations."""
    
    def __init__(self, base_url: str):
        super().__init__(base_url)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Deploy Aptos Move contracts with network and account options",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --network devnet --use-faucet
  %(prog)s --network testnet --private-key 0x123abc...
  %(prog)s --network mainnet --private-key-env DEPLOYER_PRIVATE_KEY
  %(prog)s --network localnet --use-faucet
  %(prog)s --list-modules  # Check what modules will be deployed
  %(prog)s --force-build --network devnet --use-faucet  # Force rebuild
        """
    )
    
    # Network selection
    parser.add_argument(
        "--network", "-n",
        choices=list(NETWORK_CONFIGS.keys()),
        default="devnet",
        help="Target network for deployment (default: devnet)"
    )
    
    # Custom network URLs (override presets)
    parser.add_argument("--node-url", help="Custom node API URL")
    parser.add_argument("--faucet-url", help="Custom faucet URL")
    parser.add_argument("--indexer-url", help="Custom indexer URL")
    
    # Account management
    account_group = parser.add_mutually_exclusive_group(required=True)
    account_group.add_argument(
        "--use-faucet",
        action="store_true",
        help="Generate random account and fund with faucet"
    )
    account_group.add_argument(
        "--private-key",
        help="Private key hex string (with or without 0x prefix)"
    )
    account_group.add_argument(
        "--private-key-env",
        help="Environment variable name containing private key"
    )
    
    # Package options
    parser.add_argument(
        "--package-dir", "-p",
        default=".",
        help="Path to Move package directory (default: current directory)"
    )
    parser.add_argument(
        "--named-addresses",
        help="Additional named addresses as JSON string, e.g. '{\"addr1\": \"0x123\"}'"
    )
    
    # Deployment options
    parser.add_argument(
        "--fund-amount",
        type=int,
        default=10_000_000,
        help="Amount to fund account from faucet in octas (default: 10,000,000)"
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        default=True,
        help="Skip compilation step (default: True - assumes pre-built)"
    )
    parser.add_argument(
        "--force-build", 
        action="store_true",
        help="Force compilation even when skip-build is default"
    )
    parser.add_argument(
        "--list-modules",
        action="store_true", 
        help="List modules that would be deployed and exit"
    )
    
    return parser.parse_args()


def get_network_config(args: argparse.Namespace) -> Dict[str, Any]:
    """Get network configuration, applying any custom overrides."""
    config = NETWORK_CONFIGS[args.network].copy()
    
    # Apply custom URL overrides
    if args.node_url:
        config["node_url"] = args.node_url
    if args.faucet_url:
        config["faucet_url"] = args.faucet_url
    if args.indexer_url:
        config["indexer_url"] = args.indexer_url
        
    return config


def create_account(args: argparse.Namespace) -> Account:
    """Create or load account based on arguments."""
    if args.use_faucet:
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
        raise ValueError("No account method specified")


def get_package_name_from_toml(package_dir: str) -> str:
    """Extract package name from Move.toml file."""
    toml_path = os.path.join(package_dir, "Move.toml")
    if not os.path.exists(toml_path):
        raise ValueError(f"Move.toml not found in {package_dir}")
    
    with open(toml_path, 'r') as f:
        for line in f:
            if line.strip().startswith('name ='):
                # Extract name from: name = "package_name"
                return line.split('=')[1].strip().strip('"\'')
    
    raise ValueError("Package name not found in Move.toml")


def get_named_addresses_from_toml(package_dir: str) -> List[str]:
    """Extract all named addresses from Move.toml file."""
    toml_path = os.path.join(package_dir, "Move.toml")
    if not os.path.exists(toml_path):
        raise ValueError(f"Move.toml not found in {package_dir}")
    
    named_addresses = []
    in_addresses_section = False
    
    with open(toml_path, 'r') as f:
        for line in f:
            line = line.strip()
            
            # Check if we're entering the [addresses] section
            if line == '[addresses]':
                in_addresses_section = True
                continue
            
            # Check if we're entering a different section
            if line.startswith('[') and line != '[addresses]':
                in_addresses_section = False
                continue
            
            # If we're in the addresses section and the line has an assignment
            if in_addresses_section and '=' in line and not line.startswith('#'):
                address_name = line.split('=')[0].strip()
                if address_name:  # Make sure it's not empty
                    named_addresses.append(address_name)
    
    return named_addresses


def list_modules_to_deploy(package_dir: str) -> List[str]:
    """List all module files that would be deployed."""
    package_name = get_package_name_from_toml(package_dir)
    bytecode_modules_dir = os.path.join(
        package_dir, "build", package_name, "bytecode_modules"
    )
    
    if not os.path.exists(bytecode_modules_dir):
        return []
    
    module_files = glob.glob(os.path.join(bytecode_modules_dir, "*.mv"))
    return [os.path.basename(f) for f in sorted(module_files)]


async def deploy_contract(args: argparse.Namespace) -> AccountAddress:
    """Deploy the contract package."""
    network_config = get_network_config(args)
    
    print(f"🚀 Deploying to {args.network}")
    print(f"📡 Node URL: {network_config['node_url']}")
    
    # Get package name from Move.toml
    package_name = get_package_name_from_toml(args.package_dir)
    print(f"📦 Package: {package_name}")
    
    # Create account
    deployer = create_account(args)
    print(f"📍 Deployer address: {deployer.address()}")
    
    # Initialize clients
    rest_client = DeploymentClient(network_config["node_url"])
    
    # Check balance
    balance = await rest_client.account_balance(deployer.address())
    print(f"💳 Account balance: {balance} octas")
    
    # Parse named addresses - automatically map all addresses from Move.toml to deployer address
    package_named_addresses = get_named_addresses_from_toml(args.package_dir)
    named_addresses = {}
    
    # Map all named addresses from Move.toml to the deployer address
    for addr_name in package_named_addresses:
        named_addresses[addr_name] = deployer.address()
    
    # Also include the package name mapping for compatibility
    named_addresses[package_name] = deployer.address()
    
    # Apply any additional addresses from command line
    if args.named_addresses:
        import json
        additional_addresses = json.loads(args.named_addresses)
        named_addresses.update(additional_addresses)
    
    # Only build if explicitly requested
    should_build = args.force_build or not args.skip_build
    if should_build:
        print(f"🏗️  Compiling package at {args.package_dir}...")
        print(f"📋 Named addresses: {named_addresses}")
        
        # Format named addresses properly for CLI (space-separated, not comma-separated)
        formatted_addresses = {}
        for name, addr in named_addresses.items():
            # Ensure address is a string
            if hasattr(addr, 'hex'):
                formatted_addresses[name] = addr.hex()
            else:
                formatted_addresses[name] = str(addr)
        
        # Call CLI directly since AptosCLIWrapper.compile_package() formats incorrectly
        import subprocess
        cli_path = os.getenv('APTOS_CLI_PATH', 'aptos')
        
        # Build the command
        cmd = [
            cli_path, 'move', 'compile',
            '--save-metadata',
            '--package-dir', args.package_dir
        ]
        
        # Add named addresses as a single comma-separated argument
        if formatted_addresses:
            named_addr_pairs = []
            for name, addr in formatted_addresses.items():
                named_addr_pairs.append(f"{name}={addr}")
            cmd.extend(['--named-addresses', ','.join(named_addr_pairs)])
        
        print(f"🔧 Running: {' '.join(cmd)}")
        
        # Execute the command
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=args.package_dir)
        
        if result.returncode != 0:
            print(f"❌ Compilation failed:")
            print(f"Command: {' '.join(cmd)}")
            if result.stdout:
                print(f"Output: {result.stdout}")
            if result.stderr:
                print(f"Error: {result.stderr}")
            raise RuntimeError("Move compilation failed")
        
        print("✅ Compilation successful!")
        if result.stdout:
            print(result.stdout)
            
    else:
        print("⏭️  Skipping build step - using pre-compiled modules")
    
    # Read compiled modules
    bytecode_modules_dir = os.path.join(
        args.package_dir, "build", package_name, "bytecode_modules"
    )
    
    if not os.path.exists(bytecode_modules_dir):
        raise ValueError(f"Build directory not found: {bytecode_modules_dir}\n"
                        f"Please build your package first or use --force-build")
    
    modules = []
    module_files = glob.glob(os.path.join(bytecode_modules_dir, "*.mv"))
    
    if not module_files:
        raise ValueError(f"No compiled modules found in {bytecode_modules_dir}\n"
                        f"Please build your package first or use --force-build")
    
    print(f"📦 Loading {len(module_files)} modules:")
    for module_file in sorted(module_files):
        module_name = os.path.basename(module_file)
        print(f"   • {module_name}")
        with open(module_file, "rb") as f:
            modules.append(f.read())
    
    # Read package metadata
    metadata_path = os.path.join(
        args.package_dir, "build", package_name, "package-metadata.bcs"
    )
    
    if not os.path.exists(metadata_path):
        raise ValueError(f"Package metadata not found at {metadata_path}\n"
                        f"Please build your package first or use --force-build")
    
    with open(metadata_path, "rb") as f:
        metadata = f.read()

    faucet_client = None
    if args.use_faucet:
        if not network_config["faucet_url"]:
            raise ValueError(f"No faucet available for {args.network}")
        faucet_client = FaucetClient(
            network_config["faucet_url"], 
            rest_client,
            os.getenv("FAUCET_AUTH_TOKEN")
        )
        print(f"💰 Funding account with {args.fund_amount} octas...")
        await faucet_client.fund_account(deployer.address(), args.fund_amount)
    
    # Deploy package
    print("🚢 Publishing package...")
    package_publisher = PackagePublisher(rest_client)
    txn_hash = await package_publisher.publish_package(deployer, metadata, modules)
    
    print(f"⏳ Waiting for transaction {txn_hash}...")
    await rest_client.wait_for_transaction(txn_hash)
    
    print("✅ Deployment successful!")
    print(f"🎯 Contract address: {deployer.address()}")
    print(f"🔗 Transaction: {txn_hash}")
    
    await rest_client.close()
    return deployer.address()


async def main():
    """Main deployment function."""
    args = parse_arguments()
    
    try:
        # List modules if requested
        if args.list_modules:
            modules = list_modules_to_deploy(args.package_dir)
            if modules:
                print("📦 Modules to be deployed:")
                for module in modules:
                    print(f"   • {module}")
            else:
                package_name = get_package_name_from_toml(args.package_dir)
                build_dir = os.path.join(args.package_dir, "build", package_name, "bytecode_modules")
                print(f"❌ No modules found in {build_dir}")
                print("💡 Please build your package first")
            return
        
        # Deploy contract
        contract_address = await deploy_contract(args)
        
        # Print summary
        network_config = get_network_config(args)
        print("\n" + "="*50)
        print("🎉 DEPLOYMENT SUMMARY")
        print("="*50)
        print(f"Network: {args.network}")
        print(f"Contract Address: {contract_address}")
        print(f"Node URL: {network_config['node_url']}")
        if network_config.get('indexer_url'):
            print(f"Indexer URL: {network_config['indexer_url']}")
        
    except KeyboardInterrupt:
        print("\n❌ Deployment cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())