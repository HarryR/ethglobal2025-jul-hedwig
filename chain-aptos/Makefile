# See: https://aptos.dev/build/cli/install-cli/install-cli-linux
APTOS_CLI_VERSION?=7.6.1
APTOS_CLI_ARCH?=Linux-x86_64
APTOS_CLI_ZIP=aptos-cli-$(APTOS_CLI_VERSION)-$(APTOS_CLI_ARCH).zip
APTOS_CLI_URL=https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v$(APTOS_CLI_VERSION)/$(APTOS_CLI_ZIP)
APTOS?=./aptos
PYTHON?=python3

all: compile test

# See: https://github.com/aptos-labs/aptos-python-sdk
python-deps:
	$(PYTHON) -mpip install --user --break-system-packages -r requirements.txt

test: aptos
	$(APTOS) move test --package-dir contracts

build compile: aptos
	$(APTOS) move compile --save-metadata --package-dir contracts --dev

devnet-deploy:
	APTOS_CLI_PATH=$(APTOS) python3 deploy.py --network devnet --use-faucet --force-build

devnet-filldaemon:
	$(PYTHON) fill_daemon.py --params-file devnet.json --private-key 0xa692455191ed752fd4f55499c73de38a0fc921150221194cf0e779f0da823b42 # --use-faucet

devnet-helper:
	$(PYTHON) helper_daemon.py --params-file devnet.json --private-key 0xa692455191ed752fd4f55499c73de38a0fc921150221194cf0e779f0da823b42 # --use-faucet

# See: https://aptos.dev/network/nodes/localnet
localnet:
	$(APTOS) node run-local-testnet --force-restart --assume-yes --with-indexer-api

download: $(APTOS_CLI_ZIP)

$(APTOS): $(APTOS_CLI_ZIP)
	unzip $<
	touch $@
	chmod +x $@

$(APTOS_CLI_ZIP):
	wget -O "$@" "$(APTOS_CLI_URL)"
