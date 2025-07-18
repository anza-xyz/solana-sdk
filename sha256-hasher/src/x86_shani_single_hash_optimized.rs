/*
Adapted from the RustCrypto hasher/sha2 x86 shani source code. Optimized for single 32-byte block hashing.

MIT License

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT 
OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE.

*/
use core::arch::x86_64::*;

/// Swapped round constants for SHA-256 family of digests
pub const K32X4: [[u32; 4]; 16] = {
    let mut res = [[0u32; 4]; 16];
    let mut i = 0;
    while i < 16 {
        res[i] = [K32[4 * i + 3], K32[4 * i + 2], K32[4 * i + 1], K32[4 * i]];
        i += 1;
    }
    res
};

/// Round constants for SHA-256 family of digests
pub const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline(always)]
unsafe fn schedule(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i) -> __m128i {
    let t1 = _mm_sha256msg1_epu32(v0, v1);
    let t2 = _mm_alignr_epi8(v3, v2, 4);
    let t3 = _mm_add_epi32(t1, t2);
    _mm_sha256msg2_epu32(t3, v3)
}

macro_rules! rounds4 {
    ($abef:ident, $cdgh:ident, $rest:expr, $i:expr) => {{
        let k = K32X4[$i];
        let kv = _mm_set_epi32(k[0] as i32, k[1] as i32, k[2] as i32, k[3] as i32);
        let t1 = _mm_add_epi32($rest, kv);
        $cdgh = _mm_sha256rnds2_epu32($cdgh, $abef, t1);
        let t2 = _mm_shuffle_epi32(t1, 0x0E);
        $abef = _mm_sha256rnds2_epu32($abef, $cdgh, t2);
    }};
}

macro_rules! schedule_rounds4 {
    (
        $abef:ident, $cdgh:ident,
        $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr,
        $i: expr
    ) => {{
        $w4 = schedule($w0, $w1, $w2, $w3);
        rounds4!($abef, $cdgh, $w4, $i);
    }};
}

#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn digest_block_32_initial(block: &[u8; 32]) -> [u8; 32] {

    let mut abef = _mm_set_epi64x(0x6A09E667BB67AE85, 0x510E527F9B05688C);
    let mut cdgh = _mm_set_epi64x(0x3C6EF372A54FF53A, 0x1F83D9AB5BE0CD19);
    
    let mask: __m128i = _mm_set_epi64x(
        0x0C0D_0E0F_0809_0A0Bu64 as i64,
        0x0405_0607_0001_0203u64 as i64,
    );

    let block_ptr: *const __m128i = block.as_ptr().cast();
    let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(0)), mask);
    let mut w1 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(1)), mask);
    
    let mut w2 = _mm_set_epi64x(0, 0x80000000);
    let mut w3 = _mm_set_epi64x(0x10000000000, 0);
    let mut w4;

    rounds4!(abef, cdgh, w0, 0);
    rounds4!(abef, cdgh, w1, 1);
    rounds4!(abef, cdgh, w2, 2);
    rounds4!(abef, cdgh, w3, 3);


    schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 4);
    schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 5);
    schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 6);
    schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 7);
    schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 8);
    schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 9);
    schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 10);
    schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 11);
    schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 12);
    schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 13);
    schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 14);
    schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 15);

    let abef_save = _mm_set_epi64x(0x6A09E667BB67AE85, 0x510E527F9B05688C);
    let cdgh_save = _mm_set_epi64x(0x3C6EF372A54FF53A, 0x1F83D9AB5BE0CD19);

    abef = _mm_add_epi32(abef, abef_save);
    cdgh = _mm_add_epi32(cdgh, cdgh_save);

    let feba = _mm_shuffle_epi32(abef, 0x1B);
    let dchg = _mm_shuffle_epi32(cdgh, 0xB1);
    let dcba = _mm_blend_epi16(feba, dchg, 0xF0);
    let hgef = _mm_alignr_epi8(dchg, feba, 8);

    let rev_mask = _mm_setr_epi8(
         3,  2,  1,  0,
         7,  6,  5,  4,
        11, 10,  9,  8,
        15, 14, 13, 12,
    );

    // Shuffle each lane to big-endian order:
    let dcba_be = _mm_shuffle_epi8(dcba, rev_mask);
    let hgef_be = _mm_shuffle_epi8(hgef, rev_mask);

    let mut out = [0u8; 32];
    let out_ptr = out.as_mut_ptr().cast::<__m128i>();
    _mm_storeu_si128(out_ptr.add(0), dcba_be);
    _mm_storeu_si128(out_ptr.add(1), hgef_be);

    out

}

#[inline(always)]
pub fn single_hash_32(input: &[u8; 32]) -> [u8; 32] {

    unsafe { digest_block_32_initial(&input) }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_hash_32() {

        let inputs  = vec![
            rand::random::<[u8; 32]>(),
        ];

        const ITERS: usize = 100_000;

        // Run the sha2 implementation
        let before = std::time::Instant::now();
        let mut sw_final = vec![];
        for _ in 0..ITERS {
            let mut sw = <sha2::Sha256 as sha2::Digest>::new(); 
            sha2::Digest::update(&mut sw, inputs[0]);
            sw_final = sha2::Digest::finalize(sw).to_vec();
        }
        let sw_duration = before.elapsed();

        // Run our implementation
        let before = std::time::Instant::now();
        let mut my_final = vec![];
        for _ in 0..ITERS {
            my_final = single_hash_32(&inputs[0]).to_vec();
        }
        let my_duration = before.elapsed();

        assert_eq!(my_final.len(), sw_final.len());

        assert_eq!(my_final, sw_final, "Mismatch in hash results");

        println!("Bench {ITERS} hashes: sha2 {:?} vs our {:?}", sw_duration, my_duration);
    }

}