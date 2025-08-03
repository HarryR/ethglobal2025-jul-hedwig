# Yes, hard-coding keys is bad, but this is a hackathon and I don't care
PRIVATE_KEY?=0x1801f47c7a7969c2078fdacc04a5c911b62c7d1f77f07d6afeca48111294cc92

# 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 account
LOCALNET_PRIVATE_KEY?=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

all:
	@echo $(MAKE) compile test
	@echo Then run: $(MAKE) hardhat-node
	@echo Then run: $(MAKE) deploy-localnet
	@echo Then run: python3 test_destination.py

python-requirements:
	python3 -mpip install --break-system-packages --user -r requirements.txt

pnpm-install:
	pnpm install

.PHONY: test compile
compile: hardhat-compile
test: hardhat-test

hardhat-%:
	pnpm hardhat $*

deploy-localnet:
	pnpm hardhat --network hardhat_local deploy

deploy-monad-testnet:
	PRIVATE_KEY=$(PRIVATE_KEY) pnpm hardhat --network monad-testnet deploy

### 

deploy-etherlink-testnet:
	PRIVATE_KEY=$(PRIVATE_KEY) pnpm hardhat --network etherlink-testnet deploy

daemon-arbitrator-localnet:
	python3 arbitrator.py --private-key $(LOCALNET_PRIVATE_KEY) hardhat_local.json

daemon-quote-localnet:
	python3 quote_daemon.py --private-key $(LOCALNET_PRIVATE_KEY) --topup 1000000 hardhat_local.json

daemon-filler-localnet:
	python3 fill_daemon.py --params-file hardhat_local.json --private-key $(LOCALNET_PRIVATE_KEY)

daemon-helper-localnet:
	python3 helper_daemon.py --params-file hardhat_local.json --private-key $(LOCALNET_PRIVATE_KEY)

###

daemon-arbitrator-monad-testnet:
	python3 arbitrator.py --private-key $(PRIVATE_KEY) monad-testnet.json

daemon-quote-monad-testnet:
	python3 quote_daemon.py --private-key $(PRIVATE_KEY) --topup 1000000 monad-testnet.json

daemon-filler-monad-testnet:
	python3 fill_daemon.py --params-file monad-testnet.json --private-key $(PRIVATE_KEY)

daemon-helper-monad-testnet:
	python3 helper_daemon.py --params-file monad-testnet.json --private-key $(PRIVATE_KEY)

###

daemon-arbitrator-etherlink-testnet:
	python3 arbitrator.py --private-key $(PRIVATE_KEY) etherlink-testnet.json

daemon-quote-etherlink-testnet:
	python3 quote_daemon.py --private-key $(PRIVATE_KEY) --topup 1000000 etherlink-testnet.json

daemon-filler-etherlink-testnet:
	python3 fill_daemon.py --params-file etherlink-testnet.json --private-key $(PRIVATE_KEY)

daemon-helper-etherlink-testnet:
	python3 helper_daemon.py --params-file etherlink-testnet.json --private-key $(PRIVATE_KEY)
