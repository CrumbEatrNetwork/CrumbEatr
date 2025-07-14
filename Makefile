start:
	dfx start --background -qqqq

staging_deploy:
	NODE_ENV=production DFX_NETWORK=staging make fe
	FEATURES=staging dfx build
	FEATURES=staging dfx --identity prod deploy --network staging crumbeatr

local_deploy:
	FEATURES=dev dfx deploy

dev_build:
	FEATURES=dev ./build.sh bucket
	FEATURES=dev ./build.sh crumbeatr
	FEATURES=dev dfx build

local_reinstall:
	make fe
	FEATURES=dev dfx deploy --mode=reinstall crumbeatr -y

build:
	NODE_ENV=production make fe
	./build.sh bucket
	./build.sh crumbeatr

test:
	make e2e_build
	make local_deploy
	cargo clippy --tests --benches -- -D clippy::all
	POCKET_IC_MUTE_SERVER=true cargo test
	npm run test:e2e

pocket_ic:
	cd tests && ./download-pocket-ic.sh

fe:
	npm run build --quiet

e2e_build:
	NODE_ENV=production DFX_NETWORK=local npm run build
	FEATURES=dev ./build.sh bucket
	FEATURES=dev ./build.sh crumbeatr

e2e_test:
	npm run install:e2e
	dfx canister create --all
	make e2e_build
	make start || true # don't fail if DFX is already running
	npm run test:e2e
	dfx stop

release:
	docker build -t crumbeatr .
	docker run --rm -v $(shell pwd)/release-artifacts:/target/wasm32-unknown-unknown/release crumbeatr
	make hashes

hashes:
	git rev-parse HEAD
	shasum -a 256 ./release-artifacts/crumbeatr.wasm.gz  | cut -d ' ' -f 1
