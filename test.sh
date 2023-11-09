#!/bin/sh

rm challenge
rm response
rm new_challenge
rm challenge_old
rm response_old

cargo run --release --bin new_constrained
cargo run --release --bin compute_constrained
RUST_BACKTRACE=1 cargo run --release --bin verify_transform_constrained

