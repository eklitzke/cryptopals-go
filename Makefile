.PHONY: check
check:
	go test -v

.PHONY: lint
lint:
	golangci-lint run
