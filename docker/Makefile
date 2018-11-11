.PHONY:all
all:
	@echo 'Available make targets:'
	@grep '^[^#[:space:]^\.PHONY.*].*:' Makefile

.PHONY: build
build: build
	cd rekall && docker build --no-cache . -t threatresponse/rekall:latest

.PHONY: push
push: build
	cd rekall
	docker push threatresponse/rekall:latest
