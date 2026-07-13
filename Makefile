.PHONY: run test vet build check

run:
	go run ./cmd/mercutio

test:
	go test ./...

vet:
	go vet ./...

build:
	go build -o bin/mercutio ./cmd/mercutio

check: test vet build
	node --check public/app.js
