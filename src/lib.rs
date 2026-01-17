use hex;
use itoa;
use rayon::prelude::*;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const SUBMISSION_PATH: &str = ".within.website/x/cmd/anubis/api/pass-challenge";

#[derive(Debug, Deserialize, Clone)]
pub struct AnubisChallengeRules {
    #[serde(rename = "difficulty")]
    pub difficulty: usize,
    #[serde(rename = "algorithm", default)]
    pub algorithm: String,
}

/// New format (Aug 2025+): challenge is an object with id, randomData, etc.
#[derive(Debug, Deserialize, Clone)]
pub struct ChallengeDataNew {
    pub id: String,
    #[serde(rename = "randomData")]
    pub random_data: String,
}

/// Handles both old format (plain string) and new format (object)
#[derive(Debug, Clone)]
pub struct ChallengeData {
    pub id: Option<String>,
    pub random_data: String,
}

impl<'de> Deserialize<'de> for ChallengeData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct ChallengeDataVisitor;

        impl<'de> Visitor<'de> for ChallengeDataVisitor {
            type Value = ChallengeData;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or an object with id and randomData")
            }

            // Old format: challenge is a plain hex string
            fn visit_str<E>(self, value: &str) -> Result<ChallengeData, E>
            where
                E: de::Error,
            {
                Ok(ChallengeData {
                    id: None,
                    random_data: value.to_string(),
                })
            }

            // New format: challenge is an object
            fn visit_map<M>(self, mut map: M) -> Result<ChallengeData, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut id: Option<String> = None;
                let mut random_data: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "id" => id = Some(map.next_value()?),
                        "randomData" => random_data = Some(map.next_value()?),
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                let random_data =
                    random_data.ok_or_else(|| de::Error::missing_field("randomData"))?;

                Ok(ChallengeData { id, random_data })
            }
        }

        deserializer.deserialize_any(ChallengeDataVisitor)
    }
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
impl AnubisChallenge {
    /// Returns the effective algorithm, defaulting to "fast" for old versions.
    pub fn algorithm(&self) -> &str {
        if self.rules.algorithm.is_empty() {
            "fast"
        } else {
            &self.rules.algorithm
        }
    }

    /// Returns the minimum wait duration for time-based challenges.
    pub fn min_wait(&self) -> Option<Duration> {
        match self.algorithm() {
            "preact" => Some(Duration::from_millis((self.rules.difficulty as u64) * 80)),
            "metarefresh" => Some(Duration::from_millis((self.rules.difficulty as u64) * 800)),
            _ => None,
        }
    }

    /// Builds the id query parameter if present.
    pub fn id_param(&self) -> String {
        self.challenge
            .id
            .as_ref()
            .map(|id| format!("&id={}", id))
            .unwrap_or_default()
    }
}

/// Parsed challenge with optional version info.
pub struct ParsedChallenge {
    pub challenge: AnubisChallenge,
    pub version: String,
}

/// Parse Anubis challenge from HTML response body.
pub fn parse_challenge_from_html(html: &str) -> Option<ParsedChallenge> {
    if !html.contains("anubis_challenge") {
        return None;
    }

    let document = Html::parse_document(html);

    let challenge_selector = Selector::parse("#anubis_challenge").ok()?;
    let challenge_element = document.select(&challenge_selector).next()?;
    let challenge_json = challenge_element.text().collect::<String>();

    if challenge_json.trim() == "null" || challenge_json.is_empty() {
        return None;
    }

    let challenge: AnubisChallenge = serde_json::from_str(&challenge_json).ok()?;

    let version = Selector::parse("#anubis_version")
        .ok()
        .and_then(|sel| document.select(&sel).next())
        .and_then(|el| {
            let json = el.text().collect::<String>();
            serde_json::from_str::<String>(&json).ok()
        })
        .unwrap_or_else(|| "unknown".to_string());

    Some(ParsedChallenge { challenge, version })
}

/// Build submission URL for the solved challenge.
pub fn build_submission_url(
    scheme: &str,
    host: &str,
    challenge: &AnubisChallenge,
    result: &SolverResult,
    redir_url: &str,
    elapsed_ms: u128,
) -> String {
    let id_param = challenge.id_param();
    let encoded_redir = urlencoding::encode(redir_url);

    match challenge.algorithm() {
        "preact" => format!(
            "{}://{}/{}?result={}&redir={}&elapsedTime={}{}",
            scheme, host, SUBMISSION_PATH, result.hash, encoded_redir, elapsed_ms, id_param
        ),
        "metarefresh" => format!(
            "{}://{}/{}?challenge={}&redir={}&elapsedTime={}{}",
            scheme, host, SUBMISSION_PATH, result.hash, encoded_redir, elapsed_ms, id_param
        ),
        _ => format!(
            "{}://{}/{}?response={}&nonce={}&redir={}&elapsedTime={}{}",
            scheme,
            host,
            SUBMISSION_PATH,
            result.hash,
            result.nonce.unwrap_or(0),
            encoded_redir,
            elapsed_ms,
            id_param
        ),
    }
}

/// Solve the challenge based on its algorithm type.
pub fn solve_challenge<F>(
    challenge: &AnubisChallenge,
    progress_callback: Option<F>,
) -> Result<SolverResult, String>
where
    F: Fn(u64) + Send + Sync + 'static,
{
    match challenge.algorithm() {
        "preact" => Ok(solve_preact_challenge(challenge)),
        "metarefresh" => Ok(solve_metarefresh_challenge(challenge)),
        _ => solve_challenge_native(challenge, progress_callback),
    }
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
