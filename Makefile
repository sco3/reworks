.PHONY: build clean run test

build:
	go build -o rewrk2 main.go

clean:
	rm -f rewrk2

run: build
	./rewrk2

test:
	go test -v ./...

install: build
	cp rewrk2 /usr/local/bin/

help:
	@echo "Available targets:"
	@echo "  build   - Build the rewrk2 binary"
	@echo "  clean   - Remove built binary"
	@echo "  run     - Build and run rewrk2"
	@echo "  test    - Run tests"
	@echo "  install - Install rewrk2 to /usr/local/bin"
	@echo "  help    - Show this help message"