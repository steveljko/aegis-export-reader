BINARY_NAME=aer

GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
GOFILES=$(wildcard *.go)

MAKEFLAGS += --silent

build:
	@echo "Building..."
	@go build -o $(GOBIN)/$(BINARY_NAME) .

run: build
	@echo "Running..."
	@$(GOBIN)/$(BINARY_NAME)

clean:
	@echo "Cleaning..."
	@go clean
	@rm -f $(GOBIN)/$(BINARY_NAME)

test:
	@echo "Running tests..."
	@go test -v ./...

deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

install:
	@echo "Installing..."
	@go install .

.PHONY: build run clean test deps install
