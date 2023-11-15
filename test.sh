#!/bin/bash

set -euo pipefail

cargo build --release --bin new_constrained
cargo build --release --bin compute_constrained
cargo build --release --bin verify_transform_constrained

rm -rf challenge
rm -rf response
rm -rf new_challenge

echo Starting experiment at $(date)

./target/release/new_constrained > new_constrained.out
echo new-constrained finished at $(date)

echo "\n" | ./target/release/compute_constrained > compute_constrained.out
echo compute-constrained finished at $(date)

./target/release/verify_transform_constrained > verify_transform_constrained.out
echo Experiment finished at $(date)
