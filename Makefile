IMAGE_NAME = node-dev-lts

all: docker-shell

docker-build:
	docker build -t $(IMAGE_NAME) .

docker-shell:
	docker run --rm -ti \
		--network=host \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(PWD):/src \
		-e HISTFILE=/dev/null \
		-e HOME=/src \
		-e CARGO_HOME=/src/.cargo \
		-e RUSTUP_HOME=/src/.rustup \
		-u `id -u`:`id -g` \
		$(IMAGE_NAME)

docker-clean:
	docker rmi $(IMAGE_NAME)

docker-dev: build run

docker-prune:
	docker image prune -f
	docker system prune -f
	docker system prune -f --volumes
	docker system df

