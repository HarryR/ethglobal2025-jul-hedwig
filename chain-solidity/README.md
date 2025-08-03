# Helper API

A trustless cross-chain atomic swap system using Hash Time Lock Contracts (HTLCs) with resolver-based architecture and arbitration support. This system enables trustless atomic swaps between Ethereum chains using a dual-contract HTLC architecture:

 * Source Chain: Users deposit funds and resolvers provide collateral
 * Destination Chain: Resolvers deposit funds that users can claim by revealing secrets
 * Arbitration: Optional dispute resolution for failed swaps
 * Gasless Claiming: Anyone can reveal secrets, making claims gasless for end users

## Deployments

### Monad (Testnet)

```python
{
  node_url: 'https://testnet-rpc.monad.xyz/',
  chain_id: '10143',
  dhtlc_address: '0x818A96735512744e4602BEe6290fD1cFC453ff97',
  shtlc_address: '0xE91b6dcB054EA11650cA758e1aD6F4Ec197d2029',
  network: 'monad-testnet'
}
```

 * DestinationHTLC: https://testnet.monadexplorer.com/address/0x818A96735512744e4602BEe6290fD1cFC453ff97?tab=Contract
 * SourceHTLC: https://testnet.monadexplorer.com/address/0xE91b6dcB054EA11650cA758e1aD6F4Ec197d2029?tab=Contract

### Etherlink (Testnet)

```python
{
  node_url: 'https://node.ghostnet.etherlink.com/',
  chain_id: '128123',
  dhtlc_address: '0x818A96735512744e4602BEe6290fD1cFC453ff97',
  shtlc_address: '0xE91b6dcB054EA11650cA758e1aD6F4Ec197d2029',
  network: 'etherlink-testnet'
}
```

 * DestinationHTLC: https://testnet.explorer.etherlink.com/address/0x818A96735512744e4602BEe6290fD1cFC453ff97
 * SourceHTLC: https://testnet.explorer.etherlink.com/address/0xE91b6dcB054EA11650cA758e1aD6F4Ec197d2029


## How To Run

```bash
make pnpm-install compile test
```

Then start the daemons:

```bash
make python-requirements
./start.sh
```

Then you can run the test script

```bash
./dest_destination.py
```

## Further Information

### Components

On-chain we have two contacts:

 * SourceHTLC Contract: Manages escrows on the source chain with resolver collateral
 * DestinationHTLC Contract: Simple HTLC for fund claiming on destination chain

Then additional off-chain daemons:

 * Fill Daemon: Creates HTLCs by depositing funds on destination chain
 * Helper Daemon: Reveals secrets and claims refunds
 * Quote Daemon: Provides signed quotes for cross-chain swaps
 * Arbitrator Daemon: Signs proof of deposit (or lack of deposit) within/after deadline


## Daemons

### Fill Daemon (`fill_daemon.py`)

**Purpose**: Creates HTLCs by depositing funds on destination chains.

**Functionality**:
- Deposits ETH to create HTLCs
- Validates requests and checks balances
- Provides transaction management
- Runs on port 7400 (default)

### Helper Daemon (`helper_daemon.py`)

**Purpose**: Handles HTLC operations - revealing secrets and claiming refunds.

**Functionality**:
- Reveals secrets to claim funds (gasless for users)
- Claims refunds after timeouts
- Transaction waiting and status checking
- Runs on port 7401 (default)

### Quote Daemon (`quote_daemon.py`)

**Purpose**: Provides signed quotes for cross-chain swaps as a resolver.

**Functionality**:
- Generates EIP-712 signed orders
- Manages resolver collateral in SourceHTLC
- Calculates fees and deadlines
- Runs on port 7403 (default)

### Arbitrator Daemon (`arbitrator_daemon.py`)

**Purpose**: Provides EIP-712 signed arbitration decisions for dispute resolution.

**Functionality**:
- Verifies HTLC deposit proofs on destination chains
- Signs arbitration decisions using EIP-712 structured data
- Validates HTLC parameters against contract state
- Binary decision logic (success/failure based on timing and deposits)
- Runs on port 7402 (default)

## API Endpoints

> **Network Configuration**: Each daemon must be run separately for each network. Replace `{network}` in URLs with the target network (e.g., `ethereum`, `sepolia`, `polygon`, etc.). Each network requires its own daemon instance running on different ports.

### Fill Daemon (Port 7400)

#### Create HTLC
```http
POST /ethereum/{network}/fill
Content-Type: application/json

{
  "secret_hash": "0x...",
  "user_address": "0x...",
  "amount": 1000000000000000000,
  "deadline": 1735689600
}
```

#### Health Check
```http
GET /ethereum/{network}/health.fill
```

#### Get Balance
```http
GET /ethereum/{network}/balance/{address}
```

#### Get HTLC Info
```http
GET /ethereum/{network}/destination_htlc/0x{secret_hash}
```

### Helper Daemon (Port 7401)

#### Reveal Secret
```http
POST /ethereum/{network}/reveal
Content-Type: application/json

{
  "secret": "0x..."
}
```

#### Claim Refund
```http
POST /ethereum/{network}/refund
Content-Type: application/json

{
  "secret_hash": "0x..."
}
```

#### Wait for Transaction
```http
GET /ethereum/{network}/txwait/{transaction_id}
```

#### Health Check
```http
GET /ethereum/{network}/health.helper
```

### Arbitrator Daemon (Port 7402)

#### Submit Arbitration Request
```http
POST /ethereum/{network}/arbitrate.ethereum
Content-Type: application/json

{
  "secret_hash": "0x...",
  "deadline": 1735689600,
  "destination_amount": 1000000000000000000,
  "destination_chain": "0x...",
  "destination_token": "0x...",
  "destination_address": "0x..."
}
```

**Response**:
```json
{
  "success": true,
  "decision": {
    "decision": true,
    "secretHash": "0x...",
    "deadline": 1735689600,
    "destinationChain": "0x...",
    "destinationToken": "0x...",
    "destinationAmount": 1000000000000000000,
    "destinationAddress": "0x..."
  },
  "structHash": "0x...",
  "abiEncodedDecision": "0x...",
  "signature": {
    "r": "0x...",
    "s": "0x...",
    "v": 27,
    "vs": "0x...",
    "signature": "0x..."
  },
  "arbitrator_address": "0x...",
  "htlc_info": {
    "user_address": "0x...",
    "resolver_address": "0x...",
    "amount": 1000000000000000000,
    "deadline": 1735689600
  }
}
```

#### Health Check
```http
GET /ethereum/{network}/health.arbitrator
```

### Quote Daemon (Port 7403)

#### Get Quote
```http
POST /ethereum/{network}/quote.resolver
Content-Type: application/json

{
  "user_address": "0x...",
  "source_amount": 1000000000000000000,
  "destination_chain": "ethereum-sepolia",
  "destination_amount": 1000000000000000000,
  "secret_hash": "0x..."
}
```

**Response**:
```json
{
  "success": true,
  "order": {
    "userAddress": "0x...",
    "resolverAddress": "0x...",
    "userAmount": 1000000000000000000,
    "resolverAmount": 100000000000000000,
    "venueAddress": "0x...",
    "venueFee": 1000000000000000,
    "arbitratorAddress": "0x...",
    "arbitratorAttentionFee": 100000000000000,
    "arbitratorUsageFee": 5000000000000000,
    "secretHash": "0x...",
    "submissionDeadline": 1735693200,
    "resolverActionDeadline": 1735696800,
    "destinationChain": "0x...",
    "destinationAddress": "0x...",
    "destinationToken": "0x...",
    "destinationAmount": 1000000000000000000
  },
  "signature": {
    "r": "0x...",
    "s": "0x...",
    "v": 27,
    "vs": "0x...",
    "signature": "0x...",
    "order_hash": "0x..."
  },
  "resolver_address": "0x...",
  "quote_timestamp": 1735689600
}
```

#### Health Check
```http
GET /ethereum/{network}/health.quote
```