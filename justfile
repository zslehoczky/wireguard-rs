build:
    cargo build --release

test:
    cargo test --verbose

fmt:
    cargo fmt

check-fmt:
    cargo fmt --check

check-clippy:
    cargo clippy --all-targets --all-features -- -D warnings

check-build:
    cargo hack check --feature-powerset

integration: build
    #!/usr/bin/env bash
    if [[ "$OSTYPE" == "darwin"* ]]; then
        cd docker && ./run-tests-macos.sh ../target/release/wireguard-rs
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        cd docker && ./run-tests-linux.sh ../target/release/wireguard-rs
    else
        echo "Unsupported OS: $OSTYPE"
        exit 1
    fi

ci: build check-fmt check-clippy test integration
