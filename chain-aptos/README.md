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
make deploy-devnet
```

All deployed contracts are immutable, no 'admin' backdoor BS.
Storage is using the Resource account pattern.

## Mobile Wallet

Using Petra Wallet: https://petra.app/

 Generate deep links that opens the app
  - https://petra.app/docs/mobile-deeplinks
