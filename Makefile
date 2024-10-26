.PHONY: clean vault all run
ENV ?= development

clean:
	rm -Rf build/

vault:
	mkdir -p build
	cp .env.production build
	go build -o build/vault .

all: clean vault

docker:
	docker buildx build --progress plain --platform=linux/amd64,linux/arm64 -t ghcr.io/grexie/signchain-vault:latest .

docker-push: docker
	docker push ghcr.io/grexie/signchain-vault:latest

docker-run: docker
	docker run -it --rm -p 443:443 ghcr.io/grexie/signchain-vault
	
docker-deploy: docker-push
	docker stack deploy -c docker-compose.yml signchain-vault --with-registry-auth

run: clean vault
	NODE_ENV=production
	cd build && ./vault

test:
	go run github.com/smartystreets/goconvey