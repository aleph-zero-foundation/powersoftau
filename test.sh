#!/bin/bash

set -euo pipefail

cargo build --release --bin new_constrained
cargo build --release --bin compute_constrained
cargo build --release --bin verify_transform_constrained

rm -rf challenge
rm -rf response
rm -rf new_challenge

cargo run --release --bin new_constrained
cargo run --release --bin compute_constrained
cargo run --release --bin verify_transform_constrained
