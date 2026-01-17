use hex;
use itoa;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Deserialize, Clone)]
pub struct AnubisChallengeRules {
    #[serde(rename = "difficulty")]
    pub difficulty: usize,
    #[serde(rename = "algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChallengeData {
    pub id: String,
    #[serde(rename = "randomData")]
    pub random_data: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AnubisChallenge {
    #[serde(rename = "challenge")]
    pub challenge: ChallengeData,
    #[serde(rename = "rules")]
    pub rules: AnubisChallengeRules,
}

#[derive(Debug, Serialize, Clone)]
pub struct SolverResult {
    pub hash: String,
    pub data: String,
    pub difficulty: usize,
    pub nonce: Option<u64>,
}

/// Preact: SHA256(randomData), server enforces difficulty * 80ms wait.
pub fn solve_preact_challenge(challenge: &AnubisChallenge) -> SolverResult {
    let hash = Sha256::digest(challenge.challenge.random_data.as_bytes());
    SolverResult {
        hash: hex::encode(hash),
        data: challenge.challenge.random_data.clone(),
        difficulty: challenge.rules.difficulty,
        nonce: None,
    }
}

/// Metarefresh: echo raw randomData, server enforces difficulty * 800ms wait.
pub fn solve_metarefresh_challenge(challenge: &AnubisChallenge) -> SolverResult {
    SolverResult {
        hash: challenge.challenge.random_data.clone(),
        data: challenge.challenge.random_data.clone(),
        difficulty: challenge.rules.difficulty,
        nonce: None,
    }
}

/// Check if hash has required leading zero nibbles.
fn check_difficulty_fast(hash: &[u8], difficulty: usize) -> bool {
    let full_bytes = difficulty / 2;
    if hash.len() < full_bytes {
        return false;
    }

    if hash[..full_bytes].iter().any(|&byte| byte != 0) {
        return false;
    }

    if difficulty % 2 != 0 {
        if hash.len() <= full_bytes {
            return false;
        }
        if (hash[full_bytes] >> 4) != 0 {
            return false;
        }
    }
    true
}

/// PoW solver: find nonce where SHA256(randomData + nonce) has `difficulty` leading zero nibbles.
pub fn solve_challenge_native<F>(
    challenge: &AnubisChallenge,
    progress_callback: Option<F>,
) -> Result<SolverResult, String>
where
    F: Fn(u64) + Send + Sync + 'static,
{
    let num_threads = rayon::current_num_threads();
    let difficulty = challenge.rules.difficulty;
    let data_bytes = challenge.challenge.random_data.as_bytes();
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

            let mut buffer = Vec::with_capacity(initial_capacity);
            buffer.extend_from_slice(data_bytes);
            let data_len = data_bytes.len();
            let mut itoa_buf = itoa::Buffer::new();

            while !local_found.load(Ordering::Relaxed) {
                let nonce_str_bytes = itoa_buf.format(nonce).as_bytes();
                buffer.truncate(data_len);
                buffer.extend_from_slice(nonce_str_bytes);

                hasher.update(&buffer);
                let hash_result = hasher.finalize_reset();

                if check_difficulty_fast(&hash_result, difficulty) {
                    if !local_found.swap(true, Ordering::SeqCst) {
                        result_nonce.store(nonce, Ordering::Relaxed);
                        return Some(SolverResult {
                            hash: hex::encode(hash_result),
                            data: challenge.challenge.random_data.clone(),
                            difficulty,
                            nonce: Some(nonce),
                        });
                    } else {
                        return None;
                    }
                }

                if nonce % (1024 * 16) == thread_id as u64 {
                    if let Some(ref cb_arc) = local_progress_callback {
                        cb_arc(nonce);
                    }
                }

                match nonce.checked_add(num_threads as u64) {
                    Some(next_nonce) => nonce = next_nonce,
                    None => break,
                }
            }
            None
        })
        .find_any(|res| res.is_some())
        .flatten();

    match result {
        Some(res) => Ok(res),
        None => {
            if found_solution.load(Ordering::Relaxed) {
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
                    data: challenge.challenge.random_data.clone(),
                    difficulty,
                    nonce: Some(winning_nonce),
                })
            } else {
                Err("Solver finished without finding a solution.".to_string())
            }
        }
    }
}
