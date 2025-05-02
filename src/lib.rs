use hex;
use itoa; // For fast integer->bytes conversion
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use serde::{Deserialize, Serialize};

/// Rules for the Anubis challenge (difficulty specifies leading zero nibbles).
/// Other JSON fields like 'report_as', 'algorithm' are ignored.
#[derive(Debug, Deserialize, Clone)]
pub struct AnubisChallengeRules {
    #[serde(rename = "difficulty")]
    pub difficulty: usize,
}

/// Anubis challenge data: a prefix string and difficulty rules.
#[derive(Debug, Deserialize, Clone)]
pub struct AnubisChallenge {
    #[serde(rename = "challenge")]
    pub challenge: String,
    #[serde(rename = "rules")]
    pub rules: AnubisChallengeRules,
}

/// Result of successfully solving the challenge.
#[derive(Debug, Serialize, Clone)]
pub struct SolverResult {
    #[serde(rename = "hash")]
    pub hash: String,
    #[serde(rename = "data")]
    pub data: String,
    #[serde(rename = "difficulty")]
    pub difficulty: usize,
    #[serde(rename = "nonce")]
    pub nonce: u64,
}

/// Optimized check for hash difficulty (leading zero nibbles).
fn check_difficulty_fast(hash: &[u8], difficulty: usize) -> bool {
    let full_bytes = difficulty / 2;
    if hash.len() < full_bytes { return false; }

    if hash[..full_bytes].iter().any(|&byte| byte != 0) {
        return false;
    }

    if difficulty % 2 != 0 {
        if hash.len() <= full_bytes { return false; }
        if (hash[full_bytes] >> 4) != 0 {
            return false;
        }
    }
    true
}


/// Solves the Proof-of-Work challenge using parallel SHA256 hashing.
///
/// Iterates nonces across threads, hashing `challenge_data + nonce`
/// until a hash meeting the `difficulty` is found. Uses efficient
/// buffer reuse to avoid allocations during hashing.
///
/// # Arguments
/// * `challenge` - Challenge prefix string and difficulty rules.
/// * `progress_callback` - Optional function called periodically with the current nonce.
///
/// # Returns
/// * `Ok(SolverResult)` on success.
/// * `Err(String)` if no solution found or other error.
pub fn solve_challenge_native<F>(
    challenge: &AnubisChallenge,
    progress_callback: Option<F>,
) -> Result<SolverResult, String>
where
    F: Fn(u64) + Send + Sync + 'static,
{
    let num_threads = rayon::current_num_threads();
    let difficulty = challenge.rules.difficulty;
    let data_bytes = challenge.challenge.as_bytes();
    // Base data length + max decimal digits for u64
    let initial_capacity = data_bytes.len() + 20;

    let found_solution = Arc::new(AtomicBool::new(false));
    let result_nonce = Arc::new(AtomicU64::new(0));
    let progress_callback = progress_callback.map(Arc::new);

    let result = (0..num_threads)
        .into_par_iter()
        .map(|thread_id| {
            let mut nonce = thread_id as u64;
            let mut hasher = Sha256::new();
            let local_found = found_solution.clone();
            let local_progress_callback = progress_callback.clone();

            // Thread-local buffer for efficient hashing without allocation per hash
            let mut buffer = Vec::with_capacity(initial_capacity);
            buffer.extend_from_slice(data_bytes);
            let data_len = data_bytes.len();
            let mut itoa_buf = itoa::Buffer::new();

            // Main hashing loop for this thread
            while !local_found.load(Ordering::Relaxed) {
                let nonce_str_bytes = itoa_buf.format(nonce).as_bytes();
                buffer.truncate(data_len);
                buffer.extend_from_slice(nonce_str_bytes);

                hasher.update(&buffer);
                let hash_result = hasher.finalize_reset();

                if check_difficulty_fast(&hash_result, difficulty) {
                    if !local_found.swap(true, Ordering::SeqCst) {
                        // First thread to find the solution
                        result_nonce.store(nonce, Ordering::Relaxed);
                        return Some(SolverResult {
                            hash: hex::encode(hash_result),
                            data: challenge.challenge.clone(), // Clone original data for result
                            difficulty,
                            nonce,
                        });
                    } else {
                        // Another thread found it first
                        return None;
                    }
                }

                // Optional progress reporting (approx every 16k attempts per thread)
                if nonce % (1024 * 16) == thread_id as u64 {
                    if let Some(ref cb_arc) = local_progress_callback {
                        cb_arc(nonce);
                    }
                }

                // Advance nonce for this thread, checking for overflow
                match nonce.checked_add(num_threads as u64) {
                    Some(next_nonce) => nonce = next_nonce,
                    None => break, // Nonce overflowed u64::MAX
                }
            }
            None // Thread finished its range or was preempted
        })
        .find_any(|res| res.is_some()) // Get the first successful result from any thread
        .flatten(); // Unwrap Option<Option<SolverResult>>

    match result {
        Some(res) => Ok(res),
        None => {
            // If no result was returned directly, check if any thread stored a winning nonce
            if found_solution.load(Ordering::Relaxed) {
                 // Reconstruct result using the globally stored winning nonce (requires re-hashing)
                 let winning_nonce = result_nonce.load(Ordering::Relaxed);

                 let mut buffer = Vec::with_capacity(initial_capacity);
                 buffer.extend_from_slice(data_bytes);
                 let data_len = data_bytes.len();
                 let mut itoa_buf = itoa::Buffer::new();
                 let nonce_str_bytes = itoa_buf.format(winning_nonce).as_bytes();
                 buffer.truncate(data_len);
                 buffer.extend_from_slice(nonce_str_bytes);
                 let hash_result = Sha256::digest(&buffer);

                 Ok(SolverResult {
                    hash: hex::encode(hash_result),
                    data: challenge.challenge.clone(),
                    difficulty,
                    nonce: winning_nonce,
                 })
            } else {
                // No solution found across all threads within the u64 range
                Err("Solver finished without finding a solution.".to_string())
            }
        }
    }
}