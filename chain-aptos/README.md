# Aptos support

## Setup

No need to install Aptos CLI globally, we download Aptos CLI & install python dependencies as regular user.

```bash
make download python-deps
```

Then start the local node, for testing etc. if you don't want to use devnet

```bash
make localnet
```

## Deploying

This will magically deploy stuff onto devnet, including using faucet. It uses `deploy.py` which can also deploy to localnet, testnet & mainnet.

```bash
make devnet-deploy
```

All deployed contracts are immutable, no 'admin' backdoor BS.
Storage & funds are managed using the Resource account pattern, meaning deployer has no access to anything.

## Running

There are several components necessary:

```bash
make devnet-filldaemon &  # runs on port 7300
make devnet-helper &      # runs on port 7301
make devnet-arbitrator &  # runs on port 7302
```

# Daemon APIs

These daemon APIs are for internal use by the resolver only.
For production deployment there must be authentication & session encryption etc. + firewalls.

## Arbitrator API (port 7302)

Where `<network>` is e.g. `devnet` or `mainnet`.

The arbitrator daemon verifies HTLC deposits on-chain, and signs if the deposit exists

### Arbitrate

 * Signs the secret hash, in a format usable by Aptos contracts

`POST /aptos/<network>/arbitrate.aptos`

#### Input JSON:

```python
```

#### Output JSON:

```python
```

## Helper API (port 7301)

Where `<network>` is e.g. `devnet` or `mainnet`.

The helper daemon pays gas to perform the `claim` and `reveal` stages.
It uses a different key from the resolver, but is an internal service used by the resolver infrastructure.

### Get Destination HTLC Info

* Get destination HTLC info 

`GET /aptos/<network>/destination_htlc/0x<secret_hash>`

#### Response JSON:

```python
{
    'amount': 7901,
    'claimed': False,
    'deadline': 1753796927,
    'resolver_address': '0xa816d6...',
    'user_address': '0xf225...'
}
```

### Balance

* Checks an Aptos account balance

`GET /aptos/<network>/balance/<account>`

#### Response JSON:

```json
{
    "balance": 1234
}
```

### Wait for Transaction

`GET /aptos/<network>/wait/0x<txid>`

Will wait until transaction has been mined, then returns the transaction data

#### Response JSON
```python
{  
    'accumulator_root_hash': '0x567...',
    'changes': [
        {
            'address': ...
        }
    ],
    ...
}
```

### Reveal

`POST /aptos/<network>/reveal`

 * Calls `<htlc>::destination_htlc::reveal_secret`
 * Only callable if user provides the secret for the HTLC
 * Moves coins to user address (completing the swap)

#### Input JSON:

```json
{
    "secret": "0x...",
}
```

#### Response JSON:

```json
{
  "success": true,
  "transaction_hash": "0x...",
  "gas_used": 1234,
  "gas_fee": 100,
  "revealed": {
    "secret_hash": "0x1234...",
    "secret": "0x...", 
    "user_address": "0xabc...",
    "amount": 1000000
  }
}
```

### Refund

`POST /aptos/<network>/refund`

 * Calls `<htlc>::destination_htlc::claim_refund`
 * Only callable after HTLC has expired
 * Returns coins to Resolver address

#### Input JSON:

```json
{
    "secret_hash": "0x1234..."
}
```

#### Response JSON:

```json
{
  "success": true,
  "transaction_hash": "0x...",
  "gas_used": 1234,
  "gas_fee": 100,
  "refunded": {
    "secret_hash": "0x1234...",
    "resolver_address": "0xdef...",
    "amount": 1000000
  }
}
```

### Health Check

`GET /aptos/<network>/health.helper`

#### Response JSON:

```python
{
    'chain_id': 123,
    'claimer_address': '0xa816d62d4f44564320f740a320406c1c0bd3b3bcad231dc833969fce9e35db31',
    'contract_address': '0x694de91f031435577f402d7a1362b4d00b5f239a73e484e5a87e315a53ba06f6',
    'contract_responsive': True,
    'faucet_url': 'https://faucet.devnet.aptoslabs.com',
    'hash_verification': 'passed',
    'network': 'devnet',
    'node_url': 'https://api.devnet.aptoslabs.com/v1',
    'status': 'healthy'
}
```

## Fill Daemon API (port 7300)

Where `<network>` is e.g. `devnet` or `mainnet`.

The fill daemon is an internal API for the resolver to submit HTLCs to aptos chains.

It holds the resolver key, and thus controls resolver funds.

### Fill

`POST /aptos/<network>/fill`

#### Input JSON:

```json
{
    "secret_hash": "0x1234abcd...",
    "user_address": "0x789def...",
    "amount": 1000000,
    "deadline": 1738123456
}
```

#### Response JSON:


### Health Check

`GET /aptos/<network>/health.fill`

#### Response JSON:

```python
{
    'chain_id': 123,
    'contract_address': '0x694de91f031435577f402d7a1362b4d00b5f239a73e484e5a87e315a53ba06f6',
    'contract_responsive': True,
    'faucet_url': 'https://faucet.devnet.aptoslabs.com',
    'hash_verification': 'passed',
    'network': 'devnet',
    'node_url': 'https://api.devnet.aptoslabs.com/v1',
    'resolver_address': '0xa816d62d4f44564320f740a320406c1c0bd3b3bcad231dc833969fce9e35db31', 
    'status': 'healthy'
}
```

## Mobile Wallet

Using Petra Wallet: https://petra.app/

 Generate deep links that opens the app
  - https://petra.app/docs/mobile-deeplinks
