SUI_VERSION?=1.51.5
SUI_ARCH?=ubuntu-x86_64
SUI_TAR=sui-mainnet-v$(SUI_VERSION)-$(SUI_ARCH).tgz
SUI_URL=https://github.com/MystenLabs/sui/releases/download/mainnet-v$(SUI_VERSION)/$(SUI_TAR)

SUI?=./sui-bin/sui

all:
	@echo you need to run: $(MAKE) download sui-bin build test

build:
	$(SUI) move build -p contracts

test:
	$(SUI) move test -p contracts

clean:
	$(SUI) move clean

download: $(SUI_TAR)

$(SUI_TAR):
	wget -O "$@" "$(SUI_URL)"

sui-bin: $(SUI_TAR)
	mkdir -p "$@"
	tar -C "$@" -xvf "$<"
