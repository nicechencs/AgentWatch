//! One-shot XXH3-64 (seed 0, default secret), for [`super::proc`] only.
//!
//! ADR-0007 names `xxh3_64` as the process-identity hash. This is the public
//! one-shot function (`XXH3_64bits`), not a seeded or custom-secret variant, so
//! the same bytes hash the same on every platform. No host entropy is mixed in.
//!
//! The algorithm follows the XXH3 specification (xxHash spec 0.2.0, Adrien Wu /
//! Yann Collet, BSD-2-Clause reference description). The long-input path (> 240
//! bytes) is not implemented: process identity hashes a boot id plus two
//! integers, which is far below that. A longer input returns [`None`] rather
//! than a wrong digest.

/// Default XXH3 secret, 192 bytes. Read little-endian wherever the spec says so.
const SECRET: [u8; 192] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME_MX1: u64 = 0x1656_6791_9E37_79F9;
const PRIME_MX2: u64 = 0x9FB2_1C65_1E98_DF25;

/// Longest input this one-shot covers. The 129–240 byte path is the last one
/// implemented; the striped accumulator path is intentionally absent.
const MIDSIZE_MAX: usize = 240;

/// `XXH3_64bits(input, len)` with seed 0 and the default secret.
///
/// Returns `None` when `input.len() > 240`. Process-identity inputs never reach
/// that; refusing is safer than emitting a digest that is not XXH3.
pub(crate) fn xxh3_64(input: &[u8]) -> Option<u64> {
    let len = input.len();
    if len > MIDSIZE_MAX {
        return None;
    }
    Some(hash_short(input))
}

fn hash_short(input: &[u8]) -> u64 {
    let len = input.len();
    if len <= 16 {
        hash_0_to_16(input)
    } else if len <= 128 {
        hash_17_to_128(input)
    } else {
        hash_129_to_240(input)
    }
}

fn hash_0_to_16(input: &[u8]) -> u64 {
    let len = input.len();
    if len > 8 {
        hash_9_to_16(input)
    } else if len >= 4 {
        hash_4_to_8(input)
    } else if len != 0 {
        hash_1_to_3(input)
    } else {
        // Empty: avalanche_XXH64 is the *XXH64* mixer, not the XXH3 one.
        // secret[56:72] as two little-endian u64, seed 0.
        avalanche_xxh64(read64(56) ^ read64(64))
    }
}

fn hash_1_to_3(input: &[u8]) -> u64 {
    let len = input.len();
    let combined = u32::from(input[len - 1])
        | ((len as u32) << 8)
        | (u32::from(input[0]) << 16)
        | (u32::from(input[len >> 1]) << 24);
    let secret_words = read32(0) ^ read32(4);
    // Seed is 0, so it drops out of `(secret_xor as u64) + seed`.
    avalanche_xxh64(u64::from(secret_words) ^ u64::from(combined))
}

fn hash_4_to_8(input: &[u8]) -> u64 {
    let len = input.len();
    let input_first = read32_at(input, 0);
    let input_last = read32_at(input, len - 4);
    let combined = u64::from(input_last) | (u64::from(input_first) << 32);
    // Seed 0 => modifiedSeed 0, so the secret term is not subtracted from.
    let mut value = (read64(8) ^ read64(16)) ^ combined;
    value ^= value.rotate_left(49) ^ value.rotate_left(24);
    value = value.wrapping_mul(PRIME_MX2);
    value ^= (value >> 35).wrapping_add(len as u64);
    value = value.wrapping_mul(PRIME_MX2);
    value ^ (value >> 28)
}

fn hash_9_to_16(input: &[u8]) -> u64 {
    let len = input.len();
    let low = read64(24) ^ read64(32) ^ read64_at(input, 0);
    let high = read64(40) ^ read64(48) ^ read64_at(input, len - 8);
    let folded = mul128_fold64(low, high);
    let value = (len as u64)
        .wrapping_add(low.swap_bytes())
        .wrapping_add(high)
        .wrapping_add(folded);
    avalanche(value)
}

fn hash_17_to_128(input: &[u8]) -> u64 {
    let len = input.len();
    let mut acc = (len as u64).wrapping_mul(PRIME64_1);
    // `num_rounds` is at least 1 for len >= 17, so the `i >= 0` loop is the
    // reverse of `0..num_rounds` and does not wrap.
    let num_rounds = ((len - 1) / 32) + 1;
    for i in (0..num_rounds).rev() {
        acc = acc.wrapping_add(mix16(input, i * 16, i * 32));
        let end = len - (i * 16) - 16;
        acc = acc.wrapping_add(mix16(input, end, (i * 32) + 16));
    }
    avalanche(acc)
}

fn hash_129_to_240(input: &[u8]) -> u64 {
    let len = input.len();
    let mut acc = (len as u64).wrapping_mul(PRIME64_1);
    for i in 0..8 {
        acc = acc.wrapping_add(mix16(input, i * 16, i * 16));
    }
    acc = avalanche(acc);
    let num_chunks = len / 16;
    for i in 8..num_chunks {
        acc = acc.wrapping_add(mix16(input, i * 16, (i - 8) * 16 + 3));
    }
    // Last 16 bytes, secret offset 136 - 17 = 119.
    acc = acc.wrapping_add(mix16(input, len - 16, 119));
    avalanche(acc)
}

/// 16 input bytes mixed with 16 secret bytes. Seed is 0, so it cancels.
fn mix16(input: &[u8], input_off: usize, secret_off: usize) -> u64 {
    let lhs = read64_at(input, input_off) ^ read64(secret_off);
    let rhs = read64_at(input, input_off + 8) ^ read64(secret_off + 8);
    mul128_fold64(lhs, rhs)
}

fn avalanche(mut x: u64) -> u64 {
    x ^= x >> 37;
    x = x.wrapping_mul(PRIME_MX1);
    x ^ (x >> 32)
}

fn avalanche_xxh64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    x ^= x >> 29;
    x = x.wrapping_mul(0x1656_67B1_9E37_79F9);
    x ^ (x >> 32)
}

/// Low 64 bits XOR high 64 bits of a full 64×64 → 128 multiply.
fn mul128_fold64(lhs: u64, rhs: u64) -> u64 {
    let wide = u128::from(lhs).wrapping_mul(u128::from(rhs));
    (wide as u64) ^ ((wide >> 64) as u64)
}

fn read32(offset: usize) -> u32 {
    read32_at(&SECRET, offset)
}

fn read64(offset: usize) -> u64 {
    read64_at(&SECRET, offset)
}

fn read32_at(bytes: &[u8], offset: usize) -> u32 {
    let raw = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    u32::from_le_bytes(raw)
}

fn read64_at(bytes: &[u8], offset: usize) -> u64 {
    let raw = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ];
    u64::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
    use super::xxh3_64;

    /// `PRIME32` from the xxhsum sanity check. The buffer fill starts here.
    const PRIME32: u64 = 2_654_435_761;
    /// `PRIME64` from the same file. Also the non-zero seed in the table below.
    const PRIME64: u64 = 11_400_714_785_074_694_797;

    fn fill(len: usize) -> Vec<u8> {
        let mut byte_gen = PRIME32;
        let mut out = vec![0_u8; len];
        for slot in &mut out {
            *slot = (byte_gen >> 56) as u8;
            byte_gen = byte_gen.wrapping_mul(PRIME64);
        }
        out
    }

    /// Official `XSUM_XXH3_testdata` rows with seed 0, from xxHash
    /// `cli/xsum_sanity_check.c` (`XXH3_64bits` on `XSUM_fillTestBuffer`).
    /// Seeded rows are omitted: identity hashing does not take a seed, and a
    /// seeded short input is a different function.
    #[test]
    fn xxh3_matches_official_seed0_vectors() {
        let samples: &[(usize, u64)] = &[
            (0, 0x2D06_8005_38D3_94C2),
            (1, 0xC44B_DFF4_074E_ECDB),
            (6, 0x27B5_6A84_CD2D_7325),
            (12, 0xA713_DAF0_DFBB_77E7),
            (24, 0xA3FE_70BF_9D35_10EB),
            (48, 0x397D_A259_ECBA_1F11),
            (80, 0xBCDE_FBBB_2C47_C90A),
            (195, 0xCD94_217E_E362_EC3A),
        ];
        for &(len, expected) in samples {
            let digest = xxh3_64(&fill(len));
            assert_eq!(digest, Some(expected), "len {len}");
        }
    }

    #[test]
    fn xxh3_refuses_the_long_path_it_does_not_implement() {
        assert_eq!(xxh3_64(&fill(241)), None);
    }
}
