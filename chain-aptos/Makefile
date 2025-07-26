# See: https://aptos.dev/build/cli/install-cli/install-cli-linux
APTOS_CLI_VERSION?=7.6.1
APTOS_CLI_ARCH?=Linux-x86_64
APTOS_CLI_ZIP=aptos-cli-$(APTOS_CLI_VERSION)-$(APTOS_CLI_ARCH).zip
APTOS_CLI_URL=https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v$(APTOS_CLI_VERSION)/$(APTOS_CLI_ZIP)

all: compile test

python-deps:
	pip3 install --user --break-system-packages -r requirements.txt

test: aptos
	./aptos move test --package-dir contracts

build compile: aptos
	./aptos move compile --package-dir contracts

download: $(APTOS_CLI_ZIP)

aptos: $(APTOS_CLI_ZIP)
	unzip $<
	touch $@
	chmod +x $@

$(APTOS_CLI_ZIP):
	wget -O "$@" "$(APTOS_CLI_URL)"
