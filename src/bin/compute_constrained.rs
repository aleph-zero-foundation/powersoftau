extern crate bellman;
extern crate blake2;
extern crate byteorder;
extern crate memmap;
extern crate powersoftau;
extern crate rand;

use std::env;
// use powersoftau::bn256::{Bn256CeremonyParameters};
use powersoftau::batched_accumulator::BachedAccumulator;
use powersoftau::keypair::keypair;
use powersoftau::parameters::{CheckForCorrectness, UseCompression};
use powersoftau::small_bn256::Bn256CeremonyParameters;

use bellman::pairing::bn256::Bn256;
use memmap::*;
use std::fs::OpenOptions;

use bellman::pairing::ff::ScalarEngine;
use std::io::{Read, Write};

use powersoftau::parameters::PowersOfTauParameters;

const INPUT_IS_COMPRESSED: UseCompression = UseCompression::No;
const COMPRESS_THE_OUTPUT: UseCompression = UseCompression::Yes;
const CHECK_INPUT_CORRECTNESS: CheckForCorrectness = CheckForCorrectness::No;

fn main() {
    let checkpoint = env::var("CHECKPOINT")
        .ok()
        .map(|s| s.parse::<u64>().unwrap());

    match checkpoint {
        None => println!("Running procedure from the scratch"),
        Some(checkpoint) => println!("Running procedure from checkpoint {}", checkpoint),
    }

    // println!(
    //     "Will contribute to accumulator for 2^{} powers of tau",
    //     Bn256CeremonyParameters::REQUIRED_POWER
    // );

    println!(
        "In total will generate up to {} powers",
        Bn256CeremonyParameters::TAU_POWERS_LENGTH
    );

    // Create an RNG based on a mixture of system randomness and user provided randomness
    let mut rng = {
        use blake2::{Blake2b, Digest};
        use byteorder::{BigEndian, ReadBytesExt};
        use rand::chacha::ChaChaRng;
        use rand::{OsRng, Rng, SeedableRng};

        let h = {
            let mut system_rng = OsRng::new().unwrap();
            let mut h = Blake2b::default();

            // Gather 1024 bytes of entropy from the system
            for _ in 0..1024 {
                let r: u8 = system_rng.gen();
                h.input(&[r]);
            }

            // Ask the user to provide some information for additional entropy
            let mut user_input = String::new();
            println!("Type some random text and press [ENTER] to provide additional entropy...");
            std::io::stdin()
                .read_line(&mut user_input)
                .expect("expected to read some random text from the user");

            // Hash it all up to make a seed
            h.input(&user_input.as_bytes());
            h.result()
        };

        let mut digest = &h[..];

        // Interpret the first 32 bytes of the digest as 8 32-bit words
        let mut seed = [0u32; 8];
        for i in 0..8 {
            seed[i] = digest
                .read_u32::<BigEndian>()
                .expect("digest is large enough for this to work");
        }

        ChaChaRng::from_seed(&seed)
    };

    // Try to load `./challenge` from disk.
    let reader = OpenOptions::new()
        .read(true)
        .open("challenge")
        .expect("unable open `./challenge` in this directory");

    {
        let metadata = reader
            .metadata()
            .expect("unable to get filesystem metadata for `./challenge`");
        let expected_challenge_length = match INPUT_IS_COMPRESSED {
            UseCompression::Yes => Bn256CeremonyParameters::CONTRIBUTION_BYTE_SIZE,
            UseCompression::No => Bn256CeremonyParameters::ACCUMULATOR_BYTE_SIZE,
        };

        if metadata.len() != (expected_challenge_length as u64) {
            panic!(
                "The size of `./challenge` should be {}, but it's {}, so something isn't right.",
                expected_challenge_length,
                metadata.len()
            );
        }
    }

    let readable_map = unsafe {
        MmapOptions::new()
            .map(&reader)
            .expect("unable to create a memory map for input")
    };

    if checkpoint.is_none() {
        // Create `./response` in this directory
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open("response")
            .expect("unable to create `./response` in this directory");

        let required_output_length = match COMPRESS_THE_OUTPUT {
            UseCompression::Yes => Bn256CeremonyParameters::CONTRIBUTION_BYTE_SIZE,
            UseCompression::No => {
                Bn256CeremonyParameters::ACCUMULATOR_BYTE_SIZE
                    + Bn256CeremonyParameters::PUBLIC_KEY_SIZE
            }
        };

        writer
            .set_len(required_output_length as u64)
            .expect("must make output file large enough");

        let mut writable_map = unsafe {
            MmapOptions::new()
                .map_mut(&writer)
                .expect("unable to create a memory map for output")
        };

        {
            let mut challenge_hash = [0; 64];
            let memory_slice = readable_map
                .get(0..64)
                .expect("must read point data from file");
            memory_slice
                .clone()
                .read_exact(&mut challenge_hash)
                .expect("couldn't read hash of challenge file from response file");

            println!("`challenge` file claims (!!! Must not be blindly trusted) that it was based on the original contribution with a hash:");
            for line in challenge_hash.chunks(16) {
                print!("\t");
                for section in line.chunks(4) {
                    for b in section {
                        print!("{:02x}", b);
                    }
                    print!(" ");
                }
                println!("");
            }
        }

        // Construct our keypair using the RNG we created above

        // tau is a conribution to the "powers of tau", in a set of points of the form "tau^i * G"
        let tau = <Bn256 as ScalarEngine>::Fr::from_hex("0x1f8cd6a3d6ef1026a9b58c087935c9b5516c438fe5aaee2d8668b6baba96c605").unwrap();
        let (pubkey, privkey) = keypair(&mut rng, &[41u8; 64], tau);
        println!("tau is:{}", privkey.tau);
        // Perform the transformation
        println!("Computing and writing your contribution, this could take a while...");

        // this computes a transformation and writes it
        BachedAccumulator::<Bn256, Bn256CeremonyParameters>::transform(
            &readable_map,
            &mut writable_map,
            INPUT_IS_COMPRESSED,
            COMPRESS_THE_OUTPUT,
            CHECK_INPUT_CORRECTNESS,
            &privkey,
        )
            .expect("must transform with the key");

        println!("Finihsing writing your contribution to `./response`...");

        // Write the public key
        pubkey
            .write::<Bn256CeremonyParameters>(&mut writable_map, COMPRESS_THE_OUTPUT)
            .expect("unable to write public key");

        writable_map.flush().expect("must flush a memory map");

        print!(
            "Done!\n\n\
              Your contribution has been written to `./response`\n\n"
        );

        println!("Thank you for your participation, much appreciated! :)");
    } else {
    }
}
