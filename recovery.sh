#!/bin/bash

set -euo pipefail

rm -rf response

cargo build --release --bin compute_constrained
cargo build --release --bin verify_transform_constrained

echo Returning back to the experiment at $(date)

echo "\n" | ./target/release/compute_constrained > compute_constrained.out
echo compute-constrained finished at $(date)

./target/release/verify_transform_constrained > verify_transform_constrained.out
echo Experiment finished at $(date)
