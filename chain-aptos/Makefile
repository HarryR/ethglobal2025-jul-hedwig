# See: https://aptos.dev/build/cli/install-cli/install-cli-linux
APTOS_CLI_VERSION?=7.6.1
APTOS_CLI_ARCH?=Linux-x86_64
APTOS_CLI_ZIP=aptos-cli-$(APTOS_CLI_VERSION)-$(APTOS_CLI_ARCH).zip
APTOS_CLI_URL=https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v$(APTOS_CLI_VERSION)/$(APTOS_CLI_ZIP)
APTOS?=./aptos

all: compile test

# See: https://github.com/aptos-labs/aptos-python-sdk
python-deps:
	pip3 install --user --break-system-packages -r requirements.txt

test: aptos
	$(APTOS) move test --package-dir contracts

build compile: aptos
	$(APTOS) move compile --package-dir contracts

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
