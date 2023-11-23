extern crate memmap;

use memmap::*;
use std::env;
use std::fs::{File, OpenOptions};
use std::path::Path;

use bellman::pairing::bn256::{Bn256, Fr};
use bellman::pairing::ff::{Field, ScalarEngine};
use bellman::pairing::{CurveAffine, CurveProjective, Engine};
use powersoftau::batched_accumulator::BachedAccumulator;
use powersoftau::parameters::{CheckForCorrectness, PowersOfTauParameters, UseCompression};
use powersoftau::small_bn256::Bn256CeremonyParameters;

const RESPONSE_COMPRESSION: UseCompression = UseCompression::Yes;

fn check_challenge_hash(reader: &Mmap) {
    println!("Checking challenge hash...");

    let challenge_hash = reader.get(0..64).expect("must read point data from file");

    assert_eq!(challenge_hash.len(), 64, "must read 64 bytes");
    println!("✅ Challenge hash has 64 bytes");

    assert!(challenge_hash.iter().all(|&x| x == 0), "must be zeroed out");
    println!("✅ Challenge hash is zeroed out correctly!");
}

fn read_chunk(
    reader: &Mmap,
    start: usize,
    size: usize,
) -> BachedAccumulator<Bn256, Bn256CeremonyParameters> {
    let mut accumulator = BachedAccumulator::empty();
    accumulator
        .read_chunk(
            start,
            size,
            RESPONSE_COMPRESSION,
            CheckForCorrectness::Yes,
            reader,
        )
        .expect("must read chunk");

    assert!(
        accumulator.tau_powers_g1.len() == size && accumulator.tau_powers_g2.len() == size,
        "accumulator must have powers: {start}..{}",
        start + size
    );

    accumulator
}

fn check_powers(
    accumulator: &BachedAccumulator<Bn256, Bn256CeremonyParameters>,
    tau: &Fr,
    lowest_power: u64,
) {
    assert_eq!(
        accumulator.tau_powers_g1.len(),
        accumulator.tau_powers_g2.len()
    );

    for i in 0..accumulator.tau_powers_g1.len() {
        let g1 = accumulator.tau_powers_g1[i];
        let expected_g1 =
            <Bn256 as Engine>::G1Affine::one().mul(tau.pow(&[lowest_power + i as u64]));
        assert_eq!(g1, expected_g1.into_affine(), "G1 {i} power is incorrect");

        let g2 = accumulator.tau_powers_g2[i];
        let expected_g2 =
            <Bn256 as Engine>::G2Affine::one().mul(tau.pow(&[lowest_power + i as u64]));
        assert_eq!(g2, expected_g2.into_affine(), "G2 {i} power is incorrect");
    }
}

fn check_first_few_powers<const FEW: usize>(reader: &Mmap, tau: &Fr) {
    let accumulator = read_chunk(reader, 0, FEW);
    check_powers(&accumulator, tau, 0);
    println!("✅ First {FEW} powers are correct");
}

fn check_last_few_powers<const FEW: usize>(reader: &Mmap, tau: &Fr, all_powers: usize) {
    let start = all_powers - FEW;
    let accumulator = read_chunk(reader, start, FEW);
    check_powers(&accumulator, tau, start as u64);
    println!("✅ Last {FEW} powers are correct",);
}

fn count_powers(reader: &File, path: &Path) -> usize {
    let metadata = reader.metadata().unwrap();
    let all_bytes = filesize::file_real_size_fast(path, &metadata).unwrap() as usize;

    println!("File size: {}", all_bytes);
    println!("Full size: {}", FULL_SIZE);

    const FULL_SIZE: usize = Bn256CeremonyParameters::CONTRIBUTION_BYTE_SIZE;
    const BYTES_PER_POWER: usize = Bn256CeremonyParameters::G1_COMPRESSED_BYTE_SIZE
        + Bn256CeremonyParameters::G2_COMPRESSED_BYTE_SIZE;

    let powers = if all_bytes >= FULL_SIZE {
        println!("✅ Response file is of full size");

        let powers_bytes = all_bytes.saturating_sub(
            Bn256CeremonyParameters::HASH_SIZE + Bn256CeremonyParameters::PUBLIC_KEY_SIZE,
        );
        powers_bytes / BYTES_PER_POWER
    } else {
        println!("🔴 WARNING: response file is not full size");

        let powers_bytes = all_bytes.saturating_sub(Bn256CeremonyParameters::HASH_SIZE);
        let full_chunks_saved =
            powers_bytes / (Bn256CeremonyParameters::EMPIRICAL_BATCH_SIZE * BYTES_PER_POWER);
        let reliable_power_bytes =
            full_chunks_saved * Bn256CeremonyParameters::EMPIRICAL_BATCH_SIZE * BYTES_PER_POWER;
        reliable_power_bytes / BYTES_PER_POWER
    };

    let powers = powers.min(Bn256CeremonyParameters::TAU_POWERS_LENGTH);

    println!(
        "There are {} powers present, which is {}% of the expected output.",
        powers,
        (powers as f64 / Bn256CeremonyParameters::TAU_POWERS_LENGTH as f64) * 100.0
    );
    powers
}

fn main() {
    let tau = <Bn256 as ScalarEngine>::Fr::from_hex(
        "0x1f8cd6a3d6ef1026a9b58c087935c9b5516c438fe5aaee2d8668b6baba96c605",
    )
    .unwrap();

    let response_file = env::var("RESPONSE_FILE").unwrap_or("response".to_string());

    let mut reader = OpenOptions::new()
        .read(true)
        .open(response_file.clone())
        .expect(&format!("unable open response file ({response_file})"));

    println!("======================================================");
    let powers = count_powers(&mut reader, &Path::new(&response_file));

    let readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    println!("======================================================");
    check_challenge_hash(&readable_map);
    println!("======================================================");
    check_first_few_powers::<128>(&readable_map, &tau);
    println!("======================================================");
    check_last_few_powers::<128>(&readable_map, &tau, powers);
    println!("======================================================");
    println!("✅ All checks passed!");
}
