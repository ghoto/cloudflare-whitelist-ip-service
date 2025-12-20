.PHONY: build run stop

build:
	docker build -t cloudflare-whitelist-ip-service .

run:
	docker run -d --name cloudflare-whitelist-ip-service -p 8080:8080 cloudflare-whitelist-ip-service

stop:
	-docker stop cloudflare-whitelist-ip-service
	-docker rm cloudflare-whitelist-ip-service
