## Helper API

```bash
# Start the daemon with localhost network
python3 ethereum_htlc_helper.py \
  --network localhost \
  --contract-address 0x123...abc \
  --private-key-env PRIVATE_KEY \
  --port 7401

# Example API calls
curl -X POST http://localhost:7401/ethereum/localhost/reveal \
  -H "Content-Type: application/json" \
  -d '{"secret": "0x6d7973656372657431323300000000000000000000000000000000000000000000"}'

curl http://localhost:7401/ethereum/localhost/balance/0x123...abc

curl http://localhost:7401/ethereum/localhost/destination_htlc/0xabc...123
```

## Run Tests

```bash
pnpm install
pnpm hardhat test
```