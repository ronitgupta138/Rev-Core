.PHONY: all build test clean run check fmt clippy install package

CARGO := cargo

all: build test

build:
	$(CARGO) build --release

test:
	$(CARGO) test --verbose

check:
	$(CARGO) check --all-targets

fmt:
	$(CARGO) fmt --check

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

install:
	$(CARGO) install --path . --force

package:
	$(CARGO) package --verbose

clean:
	$(CARGO) clean
