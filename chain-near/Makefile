NEAR_ACCOUNT?=harryr.testnet

all:
	@echo ...

build:
	cargo near build non-reproducible-wasm

build-release:
	cargo near build reproducible-wasm

# See: https://docs.near.org/smart-contracts/quickstart?code-tabs=rust#create-a-testnet-account
near-create-account:
	near account create-account sponsor-by-faucet-service $(NEAR_ACCOUNT) autogenerate-new-keypair save-to-legacy-keychain network-config testnet create

testnet-account-status:
	near account view-account-summary harryr.testnet network-config testnet now

testnet-deploy:
	near contract deploy $(NEAR_ACCOUNT) use-file ./target/near/contract_rs.wasm without-init-call network-config testnet sign-with-keychain send

testnet-interact-view:
	near contract call-function as-read-only $(NEAR_ACCOUNT) get_greeting json-args {} network-config testnet now

testnet-interact-write:
	near contract call-function as-transaction $(NEAR_ACCOUNT) set_greeting json-args '{"greeting": "Hola"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as $(NEAR_ACCOUNT) network-config testnet sign-with-keychain send
