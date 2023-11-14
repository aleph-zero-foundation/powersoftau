extern crate bellman;
extern crate blake2;
extern crate byteorder;
extern crate crossbeam;
extern crate generic_array;
extern crate itertools;
extern crate memmap;
extern crate num_cpus;
/// Memory constrained accumulator that checks parts of the initial information in parts that fit to memory
/// and then contributes to entropy in parts as well
extern crate rand;
extern crate typenum;

use bellman::pairing::bn256::Bn256;
use bellman::pairing::ff::{Field, PrimeField};
use bellman::pairing::*;
use blake2::{Blake2b, Digest};
use byteorder::{BigEndian, ReadBytesExt};
use generic_array::GenericArray;
use itertools::{Itertools, MinMaxResult};
use memmap::{Mmap, MmapMut};
use rand::chacha::ChaChaRng;
use rand::{Rand, Rng, SeedableRng};
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use typenum::consts::U64;

use super::keypair::*;
use super::parameters::*;
use super::utils::*;

pub enum AccumulatorState {
    Empty,
    NonEmpty,
    Transformed,
}

/// The `Accumulator` is an object that participants of the ceremony contribute
/// randomness to. This object contains powers of trapdoor `tau` in G1 and in G2 over
/// fixed generators, and additionally in G1 over two other generators of exponents
/// `alpha` and `beta` over those fixed generators. In other words:
///
/// * (τ, τ<sup>2</sup>, ..., τ<sup>2<sup>22</sup> - 2</sup>, α, ατ, ατ<sup>2</sup>, ..., ατ<sup>2<sup>21</sup> - 1</sup>, β, βτ, βτ<sup>2</sup>, ..., βτ<sup>2<sup>21</sup> - 1</sup>)<sub>1</sub>
/// * (β, τ, τ<sup>2</sup>, ..., τ<sup>2<sup>21</sup> - 1</sup>)<sub>2</sub>
pub struct BachedAccumulator<E: Engine, P: PowersOfTauParameters> {
    /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_G1_LENGTH - 1}
    pub tau_powers_g1: Vec<E::G1Affine>,
    /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_LENGTH - 1}
    pub tau_powers_g2: Vec<E::G2Affine>,
    /// Hash chain hash
    pub hash: GenericArray<u8, U64>,
    /// Keep parameters here as a marker
    marker: std::marker::PhantomData<P>,
}

impl<E: Engine, P: PowersOfTauParameters> BachedAccumulator<E, P> {
    /// Calcualte the contibution hash from the resulting file. Original powers of tau implementaiton
    /// used a specially formed writer to write to the file and calculate a hash on the fly, but memory-constrained
    /// implementation now writes without a particular order, so plain recalculation at the end
    /// of the procedure is more efficient
    pub fn calculate_hash(input_map: &Mmap) -> GenericArray<u8, U64> {
        let chunk_size = 1 << 30; // read by 1GB from map
        let mut hasher = Blake2b::default();
        for chunk in input_map.chunks(chunk_size) {
            hasher.input(&chunk);
        }

        hasher.result()
    }
}

impl<E: Engine, P: PowersOfTauParameters> BachedAccumulator<E, P> {
    pub fn empty() -> Self {
        Self {
            tau_powers_g1: vec![],
            tau_powers_g2: vec![],
            hash: blank_hash(),
            marker: std::marker::PhantomData::<P> {},
        }
    }
}

impl<E: Engine, P: PowersOfTauParameters> BachedAccumulator<E, P> {
    fn g1_size(compression: UseCompression) -> usize {
        match compression {
            UseCompression::Yes => {
                return P::G1_COMPRESSED_BYTE_SIZE;
            }
            UseCompression::No => {
                return P::G1_UNCOMPRESSED_BYTE_SIZE;
            }
        }
    }

    fn g2_size(compression: UseCompression) -> usize {
        match compression {
            UseCompression::Yes => {
                return P::G2_COMPRESSED_BYTE_SIZE;
            }
            UseCompression::No => {
                return P::G2_UNCOMPRESSED_BYTE_SIZE;
            }
        }
    }

    fn get_size(element_type: ElementType, compression: UseCompression) -> usize {
        let size = match element_type {
            ElementType::TauG1 => Self::g1_size(compression),
            ElementType::TauG2 => Self::g2_size(compression),
        };

        size
    }

    /// File expected structure
    /// HASH_SIZE bytes for the hash of the contribution
    /// TAU_POWERS_G1_LENGTH of G1 points
    /// TAU_POWERS_LENGTH of G2 points
    /// Public key appended to the end of file, but it's irrelevant for an accumulator itself

    fn calculate_mmap_position(
        index: usize,
        element_type: ElementType,
        compression: UseCompression,
    ) -> usize {
        let g1_size = Self::g1_size(compression);
        let g2_size = Self::g2_size(compression);
        let required_power = P::TAU_POWERS_LENGTH;
        let position = match element_type {
            ElementType::TauG1 => {
                let mut position = 0;
                position += g1_size * index;
                assert!(
                    index < P::TAU_POWERS_LENGTH,
                    "Index of TauG1 element written must not exceed {}, while it's {}",
                    P::TAU_POWERS_LENGTH,
                    index
                );

                position
            }
            ElementType::TauG2 => {
                let mut position = 0;
                position += g1_size * required_power;
                assert!(
                    index < P::TAU_POWERS_LENGTH,
                    "Index of TauG2 element written must not exceed {}, while it's {}",
                    P::TAU_POWERS_LENGTH,
                    index
                );
                position += g2_size * index;

                position
            }
        };

        position + P::HASH_SIZE
    }
}

impl<E: Engine, P: PowersOfTauParameters> BachedAccumulator<E, P> {
    /// Verifies a transformation of the `Accumulator` with the `PublicKey`, given a 64-byte transcript `digest`.
    pub fn verify_transformation(
        input_map: &Mmap,
        output_map: &Mmap,
        key: &PublicKey<E>,
        digest: &[u8],
        input_is_compressed: UseCompression,
        output_is_compressed: UseCompression,
        check_input_for_correctness: CheckForCorrectness,
        check_output_for_correctness: CheckForCorrectness,
    ) -> bool {
        use itertools::MinMaxResult::MinMax;
        assert_eq!(digest.len(), 64);

        let tau_g2_s = compute_g2_s::<E>(&digest, &key.tau_g1.0, &key.tau_g1.1, 0);

        // Check the proofs-of-knowledge for tau/alpha/beta

        // g1^s / g1^(s*x) = g2^s / g2^(s*x)
        if !same_ratio(key.tau_g1, (tau_g2_s, key.tau_g2)) {
            println!("Invalid ratio key.tau_g1, (tau_g2_s, key.tau_g2)");
            return false;
        }

        // Load accumulators AND perform computations

        let mut before = Self::empty();
        let mut after = Self::empty();

        // these checks only touch a part of the accumulator, so read two elements

        {
            let chunk_size = 2;
            before
                .read_chunk(
                    0,
                    chunk_size,
                    input_is_compressed,
                    check_input_for_correctness,
                    &input_map,
                )
                .expect("must read a first chunk from `challenge`");
            after
                .read_chunk(
                    0,
                    chunk_size,
                    output_is_compressed,
                    check_output_for_correctness,
                    &output_map,
                )
                .expect("must read a first chunk from `response`");

            // Check the correctness of the generators for tau powers
            if after.tau_powers_g1[0] != E::G1Affine::one() {
                println!("tau_powers_g1[0] != 1");
                return false;
            }
            if after.tau_powers_g2[0] != E::G2Affine::one() {
                println!("tau_powers_g2[0] != 1");
                return false;
            }

            // Did the participant multiply the previous tau by the new one?
            if !same_ratio(
                (before.tau_powers_g1[1], after.tau_powers_g1[1]),
                (tau_g2_s, key.tau_g2),
            ) {
                println!("Invalid ratio (before.tau_powers_g1[1], after.tau_powers_g1[1]), (tau_g2_s, key.tau_g2)");
                return false;
            }
        }

        let tau_powers_g2_0 = after.tau_powers_g2[0].clone();
        let tau_powers_g2_1 = after.tau_powers_g2[1].clone();
        let tau_powers_g1_0 = after.tau_powers_g1[0].clone();
        let tau_powers_g1_1 = after.tau_powers_g1[1].clone();

        // Read by parts and just verify same ratios. Cause of two fixed variables above with tau_powers_g2_1 = tau_powers_g2_0 ^ s
        // one does not need to care about some overlapping

        // let mut tau_powers_last_first_chunks = vec![E::G1Affine::zero(); 2];
        for chunk in &(0..P::TAU_POWERS_LENGTH)
            .into_iter()
            .chunks(P::EMPIRICAL_BATCH_SIZE)
        {
            let (start, end) = match chunk.minmax() {
                MinMaxResult::NoElements => unreachable!(),
                MinMaxResult::OneElement(last) => (last, last),
                MinMax(start, end) => {
                    (start, end)
                }
            };

            // extra 1 to ensure intersection between chunks and ensure we don't overflow
            let size = end - start
                + 1
                + if end == P::TAU_POWERS_LENGTH - 1 {
                0
            } else {
                1
            };
            before
                .read_chunk(
                    start,
                    size,
                    input_is_compressed,
                    check_input_for_correctness,
                    &input_map,
                )
                .expect(&format!(
                    "must read a chunk from {} to {} from `challenge`",
                    start, end
                ));
            after
                .read_chunk(
                    start,
                    size,
                    output_is_compressed,
                    check_output_for_correctness,
                    &output_map,
                )
                .expect(&format!(
                    "must read a chunk from {} to {} from `response`",
                    start, end
                ));

            // Are the powers of tau correct?
            if !same_ratio(
                power_pairs(&after.tau_powers_g1),
                (tau_powers_g2_0, tau_powers_g2_1),
            ) {
                println!("Invalid ratio power_pairs(&after.tau_powers_g1), (tau_powers_g2_0, tau_powers_g2_1)");
                return false;
            }
            if !same_ratio(
                power_pairs(&after.tau_powers_g2),
                (tau_powers_g1_0, tau_powers_g1_1),
            ) {
                println!("Invalid ratio power_pairs(&after.tau_powers_g2), (tau_powers_g1_0, tau_powers_g1_1)");
                return false;
            }
            // if end == P::TAU_POWERS_LENGTH - 1 {
            //     tau_powers_last_first_chunks[0] = after.tau_powers_g1[size - 1];
            // }
            println!("Done processing {} powers of tau", end);
        }

        true
    }

    pub fn decompress(
        input_map: &Mmap,
        output_map: &mut MmapMut,
        check_input_for_correctness: CheckForCorrectness,
    ) -> io::Result<()> {
        use itertools::MinMaxResult::MinMax;

        let mut accumulator = Self::empty();

        for chunk in &(0..P::TAU_POWERS_LENGTH)
            .into_iter()
            .chunks(P::EMPIRICAL_BATCH_SIZE)
        {
            let (start, end) = match chunk.minmax() {
                MinMaxResult::NoElements => unreachable!(),
                MinMaxResult::OneElement(last) => (last, last),
                MinMax(start, end) => {
                    (start, end)
                }
            };

            let size = end - start + 1;
            accumulator
                .read_chunk(
                    start,
                    size,
                    UseCompression::Yes,
                    check_input_for_correctness,
                    &input_map,
                )
                .expect(&format!(
                    "must read a chunk from {} to {} from source of decompression",
                    start, end
                ));
            accumulator.write_chunk(start, UseCompression::No, output_map)?;
        }

        Ok(())
    }
}

impl<E: Engine, P: PowersOfTauParameters> BachedAccumulator<E, P> {
    pub fn read_chunk(
        &mut self,
        from: usize,
        size: usize,
        compression: UseCompression,
        checked: CheckForCorrectness,
        input_map: &Mmap,
    ) -> Result<(), DeserializationError> {
        self.tau_powers_g1 = match compression {
            UseCompression::Yes => self
                .read_points_chunk::<<E::G1Affine as CurveAffine>::Compressed>(
                    from,
                    size,
                    ElementType::TauG1,
                    compression,
                    checked,
                    &input_map,
                )?,
            UseCompression::No => self
                .read_points_chunk::<<E::G1Affine as CurveAffine>::Uncompressed>(
                    from,
                    size,
                    ElementType::TauG1,
                    compression,
                    checked,
                    &input_map,
                )?,
        };

        self.tau_powers_g2 = match compression {
            UseCompression::Yes => self
                .read_points_chunk::<<E::G2Affine as CurveAffine>::Compressed>(
                    from,
                    size,
                    ElementType::TauG2,
                    compression,
                    checked,
                    &input_map,
                )?,
            UseCompression::No => self
                .read_points_chunk::<<E::G2Affine as CurveAffine>::Uncompressed>(
                    from,
                    size,
                    ElementType::TauG2,
                    compression,
                    checked,
                    &input_map,
                )?,
        };

        Ok(())
    }

    fn read_points_chunk<ENC: EncodedPoint>(
        &mut self,
        from: usize,
        size: usize,
        element_type: ElementType,
        compression: UseCompression,
        checked: CheckForCorrectness,
        input_map: &Mmap,
    ) -> Result<Vec<ENC::Affine>, DeserializationError> {
        // Read the encoded elements
        let mut res = vec![ENC::empty(); size];

        for (i, encoded) in res.iter_mut().enumerate() {
            let index = from + i;
            match element_type {
                ElementType::TauG1 => {
                    if index >= P::TAU_POWERS_LENGTH {
                        return Ok(vec![]);
                    }
                }
                ElementType::TauG2 => {
                    if index >= P::TAU_POWERS_LENGTH {
                        return Ok(vec![]);
                    }
                }
            };
            let position = Self::calculate_mmap_position(index, element_type, compression);
            let element_size = Self::get_size(element_type, compression);
            let memory_slice = input_map
                .get(position..position + element_size)
                .expect("must read point data from file");
            memory_slice.clone().read_exact(encoded.as_mut())?;
        }

        // Allocate space for the deserialized elements
        let mut res_affine = vec![ENC::Affine::zero(); size];

        let mut chunk_size = res.len() / num_cpus::get();
        if chunk_size == 0 {
            chunk_size = 1;
        }

        // If any of our threads encounter a deserialization/IO error, catch
        // it with this.
        let decoding_error = Arc::new(Mutex::new(None));

        crossbeam::scope(|scope| {
            for (source, target) in res
                .chunks(chunk_size)
                .zip(res_affine.chunks_mut(chunk_size))
            {
                let decoding_error = decoding_error.clone();

                scope.spawn(move || {
                    assert_eq!(source.len(), target.len());
                    for (source, target) in source.iter().zip(target.iter_mut()) {
                        match {
                            // If we're a participant, we don't need to check all of the
                            // elements in the accumulator, which saves a lot of time.
                            // The hash chain prevents this from being a problem: the
                            // transcript guarantees that the accumulator was properly
                            // formed.
                            match checked {
                                CheckForCorrectness::Yes => {
                                    // Points at infinity are never expected in the accumulator
                                    source
                                        .into_affine()
                                        .map_err(|e| e.into())
                                        .and_then(|source| {
                                            if source.is_zero() {
                                                Err(DeserializationError::PointAtInfinity)
                                            } else {
                                                Ok(source)
                                            }
                                        })
                                }
                                CheckForCorrectness::No => {
                                    source.into_affine_unchecked().map_err(|e| e.into())
                                }
                            }
                        } {
                            Ok(source) => {
                                *target = source;
                            }
                            Err(e) => {
                                *decoding_error.lock().unwrap() = Some(e);
                            }
                        }
                    }
                });
            }
        });

        // extra check that during the decompression all the the initially initialized infinitu points
        // were replaced with something
        for decoded in res_affine.iter() {
            if decoded.is_zero() {
                return Err(DeserializationError::PointAtInfinity);
            }
        }

        match Arc::try_unwrap(decoding_error)
            .unwrap()
            .into_inner()
            .unwrap()
        {
            Some(e) => Err(e),
            None => Ok(res_affine),
        }
    }
}

impl<E: Engine, P: PowersOfTauParameters> BachedAccumulator<E, P> {
    fn write_all(
        &mut self,
        chunk_start: usize,
        compression: UseCompression,
        element_type: ElementType,
        output_map: &mut MmapMut,
    ) -> io::Result<()> {
        match element_type {
            ElementType::TauG1 => {
                for (i, c) in self.tau_powers_g1.clone().iter().enumerate() {
                    let index = chunk_start + i;
                    self.write_point(index, c, compression, element_type.clone(), output_map)?;
                }
            }
            ElementType::TauG2 => {
                for (i, c) in self.tau_powers_g2.clone().iter().enumerate() {
                    let index = chunk_start + i;
                    self.write_point(index, c, compression, element_type.clone(), output_map)?;
                }
            }
        };

        output_map.flush()?;

        Ok(())
    }

    fn write_point<C>(
        &mut self,
        index: usize,
        p: &C,
        compression: UseCompression,
        element_type: ElementType,
        output_map: &mut MmapMut,
    ) -> io::Result<()>
        where
            C: CurveAffine<Engine=E, Scalar=E::Fr>,
    {
        if index >= P::TAU_POWERS_LENGTH {
            return Ok(());
        }

        match compression {
            UseCompression::Yes => {
                let position = Self::calculate_mmap_position(index, element_type, compression);
                // let size = self.get_size(element_type, compression);
                (&mut output_map[position..]).write(p.into_compressed().as_ref())?;
            }
            UseCompression::No => {
                let position = Self::calculate_mmap_position(index, element_type, compression);
                // let size = self.get_size(element_type, compression);
                (&mut output_map[position..]).write(p.into_uncompressed().as_ref())?;
            }
        };

        Ok(())
    }

    /// Write the accumulator with some compression behavior.
    pub fn write_chunk(
        &mut self,
        chunk_start: usize,
        compression: UseCompression,
        output_map: &mut MmapMut,
    ) -> io::Result<()> {
        self.write_all(chunk_start, compression, ElementType::TauG1, output_map)?;
        if chunk_start < P::TAU_POWERS_LENGTH {
            self.write_all(chunk_start, compression, ElementType::TauG2, output_map)?;
        }

        Ok(())
    }
}

impl<E: Engine, P: PowersOfTauParameters> BachedAccumulator<E, P> {
    /// Transforms the accumulator with a private key.
    /// Due to large amount of data in a previous accumulator even in the compressed form
    /// this function can now work on compressed input. Output can be made in any form
    /// WARNING: Contributor does not have to check that values from challenge file were serialized
    /// corrently, but we may want to enforce it if a ceremony coordinator does not recompress the previous
    /// contribution into the new challenge file
    pub fn transform(
        input_map: &Mmap,
        output_map: &mut MmapMut,
        input_is_compressed: UseCompression,
        compress_the_output: UseCompression,
        check_input_for_correctness: CheckForCorrectness,
        key: &PrivateKey<E>,
    ) -> io::Result<()> {
        /// Exponentiate a large number of points, with an optional coefficient to be applied to the
        /// exponent.
        fn batch_exp<EE: Engine, C: CurveAffine<Engine=EE, Scalar=EE::Fr>>(
            bases: &mut [C],
            exp: &[C::Scalar],
            coeff: Option<&C::Scalar>,
        ) {
            assert_eq!(bases.len(), exp.len());
            let mut projective = vec![C::Projective::zero(); bases.len()];
            let chunk_size = if bases.len() < num_cpus::get() {
                bases.len()
            } else {
                bases.len() / num_cpus::get()
            };

            // Perform wNAF over multiple cores, placing results into `projective`.
            crossbeam::scope(|scope| {
                for ((bases, exp), projective) in bases
                    .chunks_mut(chunk_size)
                    .zip(exp.chunks(chunk_size))
                    .zip(projective.chunks_mut(chunk_size))
                {
                    scope.spawn(move || {
                        let mut wnaf = Wnaf::new();

                        for ((base, exp), projective) in
                        bases.iter_mut().zip(exp.iter()).zip(projective.iter_mut())
                        {
                            let mut exp = *exp;
                            if let Some(coeff) = coeff {
                                exp.mul_assign(coeff);
                            }

                            *projective =
                                wnaf.base(base.into_projective(), 1).scalar(exp.into_repr());
                        }
                    });
                }
            });

            // Perform batch normalization
            crossbeam::scope(|scope| {
                for projective in projective.chunks_mut(chunk_size) {
                    scope.spawn(move || {
                        C::Projective::batch_normalization(projective);
                    });
                }
            });

            // Turn it all back into affine points
            for (projective, affine) in projective.iter().zip(bases.iter_mut()) {
                *affine = projective.into_affine();
                assert!(
                    !affine.is_zero(),
                    "your contribution happed to produce a point at infinity, please re-run"
                );
            }
        }

        let mut accumulator = Self::empty();

        use itertools::MinMaxResult::MinMax;

        for chunk in &(0..P::TAU_POWERS_LENGTH)
            .into_iter()
            .chunks(P::EMPIRICAL_BATCH_SIZE)
        {
            let (start, end) = match chunk.minmax() {
                MinMaxResult::NoElements => unreachable!(),
                MinMaxResult::OneElement(last) => (last, last),
                MinMax(start, end) => {
                    (start, end)
                }
            };

            let size = end - start + 1;
            accumulator
                .read_chunk(
                    start,
                    size,
                    input_is_compressed,
                    check_input_for_correctness,
                    &input_map,
                )
                .expect("must read a first chunk");

            // Construct the powers of tau
            let mut taupowers = vec![E::Fr::zero(); size];
            let chunk_size = if size < num_cpus::get() {
                size
            } else {
                size / num_cpus::get()
            };

            // Construct exponents in parallel
            crossbeam::scope(|scope| {
                for (i, taupowers) in taupowers.chunks_mut(chunk_size).enumerate() {
                    scope.spawn(move || {
                        let mut acc = key.tau.pow(&[(start + i * chunk_size) as u64]);

                        for t in taupowers {
                            *t = acc;
                            acc.mul_assign(&key.tau);
                        }
                    });
                }
            });

            batch_exp::<E, _>(&mut accumulator.tau_powers_g1, &taupowers[0..], None);
            batch_exp::<E, _>(&mut accumulator.tau_powers_g2, &taupowers[0..], None);
            accumulator.write_chunk(start, compress_the_output, output_map)?;

            println!("Done processing {} powers of tau", end);
        }

        Ok(())
    }
}

impl<E: Engine, P: PowersOfTauParameters> BachedAccumulator<E, P> {
    /// Transforms the accumulator with a private key.
    pub fn generate_initial(
        output_map: &mut MmapMut,
        compress_the_output: UseCompression,
    ) -> io::Result<()> {
        use itertools::MinMaxResult::MinMax;

        for chunk in &(0..P::TAU_POWERS_LENGTH)
            .into_iter()
            .chunks(P::EMPIRICAL_BATCH_SIZE)
        {
            let (start, end) = match chunk.minmax() {
                MinMaxResult::NoElements => unreachable!(),
                MinMaxResult::OneElement(last) => (last, last),
                MinMax(start, end) => {
                    (start, end)
                }
            };
            let size = end - start + 1;
            let mut accumulator = Self {
                tau_powers_g1: vec![E::G1Affine::one(); size],
                tau_powers_g2: vec![E::G2Affine::one(); size],
                hash: blank_hash(),
                marker: std::marker::PhantomData::<P> {},
            };

            accumulator.write_chunk(start, compress_the_output, output_map)?;
            println!("Done processing {} powers of tau", end);
        }

        Ok(())
    }
}
