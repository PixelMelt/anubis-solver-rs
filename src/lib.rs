use argon2::Argon2;
use hashx::HashX;
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

/// Difficulty Anubis validates against when a rule's difficulty is 0 or unset, and so
/// left out of the challenge page. The server falls back to its global `DIFFICULTY`,
/// which the page does not expose; this is that setting's default.
pub const DEFAULT_DIFFICULTY: usize = 4;

fn default_difficulty() -> usize {
    DEFAULT_DIFFICULTY
}

#[derive(Debug, Deserialize, Clone)]
pub struct AnubisChallengeRules {
    /// Missing from the page when the rule's difficulty is 0 or unset; then
    /// [`DEFAULT_DIFFICULTY`].
    #[serde(rename = "difficulty", default = "default_difficulty")]
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

/// Preact: SHA256(randomData), server enforces a difficulty-scaled wait (see [`AnubisChallenge::min_wait`]).
pub fn solve_preact_challenge(challenge: &AnubisChallenge) -> SolverResult {
    let hash = Sha256::digest(challenge.challenge.random_data.as_bytes());
    SolverResult {
        hash: hex::encode(hash),
        data: challenge.challenge.random_data.clone(),
        difficulty: challenge.rules.difficulty,
        nonce: None,
    }
}

/// Metarefresh: echo raw randomData, server enforces a difficulty-scaled wait (see [`AnubisChallenge::min_wait`]).
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
    ///
    /// These are the official clients' own waits: preact 125 ms and metarefresh
    /// (difficulty + 1) s. They cover every server version's check, the strictest
    /// being v1.22's 95 ms and 950 ms per difficulty (v1.23+ check 80 ms and 800 ms).
    pub fn min_wait(&self) -> Option<Duration> {
        let difficulty = self.rules.difficulty as u64;
        match self.algorithm() {
            "preact" => Some(Duration::from_millis(difficulty * 125)),
            "metarefresh" => Some(Duration::from_millis((difficulty + 1) * 1000)),
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

/// Parse the path prefix Anubis is served under (its `BASE_PREFIX`, e.g. `/myapp`)
/// from a challenge page. Empty when Anubis is served at the site root.
pub fn parse_base_prefix(html: &str) -> String {
    let document = Html::parse_document(html);
    Selector::parse("#anubis_base_prefix")
        .ok()
        .and_then(|sel| document.select(&sel).next())
        .and_then(|el| serde_json::from_str::<String>(&el.text().collect::<String>()).ok())
        .map(|prefix| prefix.trim_end_matches('/').to_string())
        .unwrap_or_default()
}

/// URLs a browser fetches while rendering the challenge page that the server checks
/// were fetched before it accepts a solution: the `@import`s in the page's `<style>`
/// elements, such as the `css-load` challenge extension's.
///
/// They are returned as written, usually as absolute paths, so resolve them against
/// the challenge page's URL. Fetch each with the same cookie jar before submitting.
pub fn parse_prefetch_urls(html: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let Ok(selector) = Selector::parse("style") else {
        return Vec::new();
    };

    let mut urls = Vec::new();
    for style in document.select(&selector) {
        let css = style.text().collect::<String>();
        for rule in css.split("@import").skip(1) {
            let rule = rule.trim_start();
            let rule = rule.strip_prefix("url(").unwrap_or(rule).trim_start();
            let url = match rule.chars().next() {
                Some(quote @ ('"' | '\'')) => rule[1..].split(quote).next(),
                _ => rule.split([')', ';', ' ']).next(),
            };
            if let Some(url) = url.map(str::trim).filter(|url| !url.is_empty()) {
                if !urls.iter().any(|u| u == url) {
                    urls.push(url.to_string());
                }
            }
        }
    }
    urls
}

/// Build submission URL for the solved challenge, for Anubis served at the site root.
///
/// Equivalent to [`build_submission_url_with_prefix`] with an empty base prefix.
pub fn build_submission_url(
    scheme: &str,
    host: &str,
    challenge: &AnubisChallenge,
    result: &SolverResult,
    redir_url: &str,
    elapsed_ms: u128,
) -> String {
    build_submission_url_with_prefix(scheme, host, "", challenge, result, redir_url, elapsed_ms)
}

/// Build submission URL for the solved challenge, for Anubis served under
/// `base_prefix` (from [`parse_base_prefix`]; empty for the site root).
pub fn build_submission_url_with_prefix(
    scheme: &str,
    host: &str,
    base_prefix: &str,
    challenge: &AnubisChallenge,
    result: &SolverResult,
    redir_url: &str,
    elapsed_ms: u128,
) -> String {
    let id_param = challenge.id_param();
    let encoded_redir = urlencoding::encode(redir_url);
    // Insert the separator ourselves so a malformed prefix (e.g. "@evil.com") stays in
    // the path and can never change the host.
    let base = match base_prefix.trim_matches('/') {
        "" => format!("{}://{}", scheme, host),
        prefix => format!("{}://{}/{}", scheme, host, prefix),
    };

    match challenge.algorithm() {
        "preact" => format!(
            "{}/{}?result={}&redir={}&elapsedTime={}{}",
            base, SUBMISSION_PATH, result.hash, encoded_redir, elapsed_ms, id_param
        ),
        "metarefresh" => format!(
            "{}/{}?challenge={}&redir={}&elapsedTime={}{}",
            base, SUBMISSION_PATH, result.hash, encoded_redir, elapsed_ms, id_param
        ),
        _ => format!(
            "{}/{}?response={}&nonce={}&redir={}&elapsedTime={}{}",
            base,
            SUBMISSION_PATH,
            result.hash,
            result.nonce.unwrap_or(0),
            encoded_redir,
            elapsed_ms,
            id_param
        ),
    }
}

/// Error returned by [`solve_challenge_with_cancel`] when the solve was cancelled.
pub const CANCELLED: &str = "solve cancelled";

/// Solve the challenge based on its algorithm type.
pub fn solve_challenge<F>(
    challenge: &AnubisChallenge,
    progress_callback: Option<F>,
) -> Result<SolverResult, String>
where
    F: Fn(u64) + Send + Sync + 'static,
{
    solve_challenge_with_cancel(challenge, progress_callback, &AtomicBool::new(false))
}

/// Like [`solve_challenge`], but gives up once `cancel` is set, returning
/// `Err(CANCELLED)`. Every search loop checks the flag, so a high-difficulty solve
/// stops promptly; set it from another thread, e.g. on a timeout.
pub fn solve_challenge_with_cancel<F>(
    challenge: &AnubisChallenge,
    progress_callback: Option<F>,
    cancel: &AtomicBool,
) -> Result<SolverResult, String>
where
    F: Fn(u64) + Send + Sync + 'static,
{
    if cancel.load(Ordering::Relaxed) {
        return Err(CANCELLED.to_string());
    }

    // The WASM algorithms hash the raw bytes of randomData, not its hex string.
    let random_data = || {
        hex::decode(&challenge.challenge.random_data)
            .map_err(|e| format!("invalid randomData: {}", e))
    };

    match challenge.algorithm() {
        "preact" => Ok(solve_preact_challenge(challenge)),
        "metarefresh" => Ok(solve_metarefresh_challenge(challenge)),
        "fast" | "slow" => solve_native(challenge, progress_callback, cancel),
        "sha256" => {
            let data = random_data()?;
            solve_wasm_pow(challenge, progress_callback, cancel, |nonce| {
                compute_hash_sha256(&data, nonce)
            })
        }
        "hashx" => {
            let h = make_hashx(&random_data()?, cancel).ok_or(CANCELLED)?;
            solve_wasm_pow(challenge, progress_callback, cancel, |nonce| {
                h.hash_to_bytes(nonce as u64)
            })
        }
        "argon2id" => {
            let data = random_data()?;
            solve_wasm_pow(challenge, progress_callback, cancel, |nonce| {
                compute_hash_argon2id(&data, nonce)
            })
        }
        other => Err(format!("unsupported algorithm: {}", other)),
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
    solve_native(challenge, progress_callback, &AtomicBool::new(false))
}

fn solve_native<F>(
    challenge: &AnubisChallenge,
    progress_callback: Option<F>,
    cancel: &AtomicBool,
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

            while !local_found.load(Ordering::Relaxed) && !cancel.load(Ordering::Relaxed) {
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
            } else if cancel.load(Ordering::Relaxed) {
                Err(CANCELLED.to_string())
            } else {
                Err("Solver finished without finding a solution.".to_string())
            }
        }
    }
}

/// Check if hash has `difficulty` leading zero bits.
///
/// Port of `validate` in Anubis wasm/pow/{sha256,hashx,argon2id}/src/lib.rs.
fn check_difficulty_bits(hash: &[u8], difficulty: u32) -> bool {
    let mut remaining = difficulty;
    for &byte in hash {
        if remaining == 0 {
            break;
        }

        if remaining >= 8 {
            if byte != 0 {
                return false;
            }
            remaining -= 8;
        } else {
            let mask = 0xFF << (8 - remaining);
            if (byte & mask) != 0 {
                return false;
            }
            remaining = 0;
        }
    }
    true
}

/// SHA256(data + nonce bytes), nonce little-endian if the last data byte is >= 128, else big-endian.
///
/// Port of `compute_hash` in Anubis wasm/pow/sha256/src/lib.rs.
fn compute_hash_sha256(data_slice: &[u8], nonce: u32) -> [u8; 32] {
    let use_le = data_slice.last().copied().unwrap_or(0) >= 128;

    let mut hasher = Sha256::new();
    hasher.update(data_slice);
    hasher.update(if use_le {
        nonce.to_le_bytes()
    } else {
        nonce.to_be_bytes()
    });
    hasher.finalize().into()
}

/// Argon2id with data as the password and the nonce as a u64 salt, same endianness rule as sha256.
///
/// Port of `compute_hash` in Anubis wasm/pow/argon2id/src/lib.rs.
fn compute_hash_argon2id(data_slice: &[u8], nonce: u32) -> [u8; 32] {
    let use_le = data_slice.last().copied().unwrap_or(0) >= 128;
    let mut result = [0u8; 32];

    let nonce = nonce as u64;

    let nonce = if use_le {
        nonce.to_le_bytes()
    } else {
        nonce.to_be_bytes()
    };

    let argon2 = Argon2::default();
    argon2
        .hash_password_into(data_slice, &nonce, &mut result)
        .unwrap();
    result
}

/// HashX seeded with data. If HashX rejects the seed, retry with data + u32 LE counter.
/// Returns `None` if `cancel` is set during the retries.
///
/// Port of `make_hashx` in Anubis wasm/pow/hashx/src/lib.rs, plus the cancel check.
fn make_hashx(data_slice: &[u8], cancel: &AtomicBool) -> Option<HashX> {
    if let Ok(h) = HashX::new(data_slice) {
        return Some(h);
    }

    let mut seed = Vec::with_capacity(data_slice.len() + 4);
    let mut counter: u32 = 0;
    while !cancel.load(Ordering::Relaxed) {
        seed.clear();
        seed.extend_from_slice(data_slice);
        seed.extend_from_slice(&counter.to_le_bytes());
        if let Ok(h) = HashX::new(&seed) {
            return Some(h);
        }
        counter = counter.wrapping_add(1);
    }
    None
}

/// PoW solver for the WASM algorithms (sha256, hashx, argon2id): find a u32 nonce where
/// `compute_hash(nonce)` has `difficulty` leading zero bits.
fn solve_wasm_pow<H, F>(
    challenge: &AnubisChallenge,
    progress_callback: Option<F>,
    cancel: &AtomicBool,
    compute_hash: H,
) -> Result<SolverResult, String>
where
    H: Fn(u32) -> [u8; 32] + Sync,
    F: Fn(u64) + Send + Sync + 'static,
{
    let num_threads = rayon::current_num_threads() as u32;
    let difficulty = challenge.rules.difficulty;
    let difficulty_bits = u32::try_from(difficulty)
        .map_err(|_| format!("difficulty {} out of range", difficulty))?;

    let found_solution = AtomicBool::new(false);

    let result = (0..num_threads)
        .into_par_iter()
        .find_map_any(|thread_id| {
            let mut nonce = thread_id;

            while !found_solution.load(Ordering::Relaxed) && !cancel.load(Ordering::Relaxed) {
                let hash = compute_hash(nonce);

                if check_difficulty_bits(&hash, difficulty_bits) {
                    if !found_solution.swap(true, Ordering::SeqCst) {
                        return Some(SolverResult {
                            hash: hex::encode(hash),
                            data: challenge.challenge.random_data.clone(),
                            difficulty,
                            nonce: Some(nonce as u64),
                        });
                    } else {
                        return None;
                    }
                }

                if nonce % (1024 * 16) == thread_id {
                    if let Some(ref cb) = progress_callback {
                        cb(nonce as u64);
                    }
                }

                match nonce.checked_add(num_threads) {
                    Some(next_nonce) => nonce = next_nonce,
                    None => break,
                }
            }
            None
        });

    match result {
        Some(result) => Ok(result),
        None if cancel.load(Ordering::Relaxed) => Err(CANCELLED.to_string()),
        None => Err("Solver finished without finding a solution.".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vectors below were produced by the reference Anubis v1.28.2 code
    // (wasm/pow/{sha256,hashx,argon2id}/src/lib.rs, compiled natively), not by this port.

    /// Last byte 0x40 < 128: nonce encoded big-endian.
    const DATA_BE: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";
    /// Last byte 0xbf >= 128: nonce encoded little-endian.
    const DATA_LE: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    /// A seed HashX::new rejects (ProgramConstraints), so make_hashx takes the retry path.
    const DATA_HASHX_REJECTED: &str = "2ce8a45f1bd7934f0ac6823efab5712de9a5601cd894500cc7833ffbb7722eeaa6621dd995510dc88440fcb8732feba7631eda96520ec98541fdb97430eca864";

    fn bytes(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn challenge(algorithm: &str, random_data: &str, difficulty: usize) -> AnubisChallenge {
        AnubisChallenge {
            challenge: ChallengeData {
                id: Some("test".to_string()),
                random_data: random_data.to_string(),
            },
            rules: AnubisChallengeRules {
                difficulty,
                algorithm: algorithm.to_string(),
            },
        }
    }

    /// First nonce from 0 that passes, like the reference `anubis_work(difficulty, 0, 1)`.
    fn first_nonce(difficulty: u32, compute_hash: impl Fn(u32) -> [u8; 32]) -> u32 {
        (0..=u32::MAX)
            .find(|&n| check_difficulty_bits(&compute_hash(n), difficulty))
            .unwrap()
    }

    /// Mirrors the reference `anubis_validate` the server runs.
    fn anubis_validate(algorithm: &str, data: &[u8], nonce: u32, difficulty: u32, hash: &[u8]) -> bool {
        let computed = match algorithm {
            "sha256" => compute_hash_sha256(data, nonce),
            "hashx" => make_hashx(data, &AtomicBool::new(false)).unwrap().hash_to_bytes(nonce as u64),
            "argon2id" => compute_hash_argon2id(data, nonce),
            _ => unreachable!(),
        };
        check_difficulty_bits(&computed, difficulty) && computed[..] == *hash
    }

    #[test]
    fn sha256_known_answers() {
        let cases: [(&str, [(u32, &str); 4]); 2] = [
            (DATA_BE, [
                (0, "97a84d279f57b43a45d8d6607ca908bb8efa33ead1a6e75085c77098b2dbfe59"),
                (1, "578176c7e1ad5421e4eb203a52b1dd2a76070b0bd4f4eeae6cbca6f504faa1f1"),
                (305419896, "badfbdaf6349f15f92fcce7c971d3d847ba3f36c57a5e266bebaeafbd3483e95"),
                (4294967295, "283edd1d95d9f8155b91ae638a2bd8af17356d30a790f27358e2bc52ac03e341"),
            ]),
            (DATA_LE, [
                (0, "b13a7a0bd9be70d6bf1b336bb3164eb3a438f33d4b1997936ced72247aba3c8a"),
                (1, "a4490c9d5af698bd2a4bc08efc6564e6315dedd92a7df007a2a6c2b4e72629e0"),
                (305419896, "3a5276c398e74ffd7d775b7726db8cb77a9aeb24431621fc7af4c52147b8743a"),
                (4294967295, "bbaf3b0e3bd1df4b89b5fe4e4ec22aa44207d9203a80c1634c93c9b4d43aa7b3"),
            ]),
        ];
        for (data, vectors) in cases {
            let data = bytes(data);
            for (nonce, hash) in vectors {
                assert_eq!(hex::encode(compute_hash_sha256(&data, nonce)), hash, "nonce {}", nonce);
            }
        }

        // reference anubis_work(12, 0, 1)
        for (data, nonce, hash) in [
            (DATA_BE, 2087, "00017fbbef075f5fce9a99e3c58a3de677bfc4cf675f4a49ce6170afd5475763"),
            (DATA_LE, 157, "0000637b3fbb8daddd22841685fa9f4ac55e0110d0a22247d2963efdb2489bbb"),
        ] {
            let data = bytes(data);
            assert_eq!(first_nonce(12, |n| compute_hash_sha256(&data, n)), nonce);
            assert_eq!(hex::encode(compute_hash_sha256(&data, nonce)), hash);
        }
    }

    #[test]
    fn hashx_known_answers() {
        let cases: [(&str, &[(u32, &str)]); 3] = [
            (DATA_BE, &[
                (0, "687df854eb934c16d614864d32c358b2dfbaa3bcbd13b2fd44017c8710ff55ab"),
                (1, "931cd056e2f595eca749459552990ab59807d402950597dc54b5b3337bb84938"),
                (305419896, "f4e728fcd506248c91cedeb1e2643a4a3760f83d6fd01b083c51fa411fa7f38d"),
                (4294967295, "230b5563bcf3690a6ed69e1ec743167520bb8baa57232b90e83e3d23a19de3b7"),
            ]),
            (DATA_LE, &[
                (0, "c3422a63c7e120b20d9d490d8f1f7046ac5e0f08c25d8e3f1364df8dc4a8ebaa"),
                (1, "9b65c8f829068a3d9530f7d9c0d8d2f40fe3ba7815b4deefe430ed924f72cb16"),
                (305419896, "cf725fae2db7d87cc610a07e323bbe845ecefaccd19673de8ae3bb1cae18ecaa"),
                (4294967295, "70997f785427e2e4bf7f58263946a00e7357a9f772d1776b0219da1d973c4f30"),
            ]),
            (DATA_HASHX_REJECTED, &[
                (0, "cd7fc3fabc41fd55b299289a3d438d0e4350d1593bb64f96eff268b98f328fdf"),
                (1, "8b421db04242814e76ce2dfb45cebec9623e460aa9dd5c2aa07fabfd45620146"),
                (305419896, "ec88fbeee613cc858c9e5410bb15400ad722376ca9524bedbc957073249d0583"),
            ]),
        ];
        assert!(HashX::new(&bytes(DATA_HASHX_REJECTED)).is_err());
        for (data, vectors) in cases {
            let h = make_hashx(&bytes(data), &AtomicBool::new(false)).unwrap();
            for &(nonce, hash) in vectors {
                assert_eq!(hex::encode(h.hash_to_bytes(nonce as u64)), hash, "nonce {}", nonce);
            }
        }

        // reference anubis_work(10, 0, 1)
        for (data, nonce, hash) in [
            (DATA_BE, 210, "00146040106972509735532a264d165a35bc01b004aa9b200d1a5ad67e960897"),
            (DATA_LE, 1469, "003a4f342a71c6286088b1920bd9bab0af10fe60643714b20c1f2deb1505155c"),
            (DATA_HASHX_REJECTED, 210, "001d85269497eba8b9ce49ae6d69c63c404462e19e520564e3b665df0d93838e"),
        ] {
            let h = make_hashx(&bytes(data), &AtomicBool::new(false)).unwrap();
            assert_eq!(first_nonce(10, |n| h.hash_to_bytes(n as u64)), nonce);
            assert_eq!(hex::encode(h.hash_to_bytes(nonce as u64)), hash);
        }
    }

    #[test]
    fn argon2id_known_answers() {
        let cases: [(&str, [(u32, &str); 4]); 2] = [
            (DATA_BE, [
                (0, "0ae44efd62d52faf82632e3e360e90bf506314f3fc8e7b5357ef9fc6eee3c786"),
                (1, "ea50cd1d425ed6c58f92cb1b77abf1bb5c6752f9acf791710579b5cd46878393"),
                (305419896, "1ce128474e77291aac166a69f5ae22b5231490057edb31cd67ecd5ca29f1b168"),
                (4294967295, "297f1f0fe28814905ec83dacd1b9f92fc1961b397e2b0c1ecc7cc4edbb26d9d2"),
            ]),
            (DATA_LE, [
                (0, "19973df98d7363cb92c4e82e079531f4add46e22bcc3bde48b3a588c2caac771"),
                (1, "0782ad1d48ef0b1767fc4cdd89c6dfb642fde7eb4ed7d70317de2037f06534d4"),
                (305419896, "9bf55704ac09c272cb110cbaa4f2af0e59919150c85f92521aa5a7fa925a979c"),
                (4294967295, "04e4d23922d6664e8b31e76327ad821bbf2002bf3f052be5e73efaace7d780b8"),
            ]),
        ];
        for (data, vectors) in cases {
            let data = bytes(data);
            for (nonce, hash) in vectors {
                assert_eq!(hex::encode(compute_hash_argon2id(&data, nonce)), hash, "nonce {}", nonce);
            }
        }

        // reference anubis_work(6, 0, 1); argon2id is slow unoptimized, so check the
        // winning nonce and its predecessor rather than the whole range.
        for (data, nonce, hash) in [
            (DATA_BE, 41, "020be1e82c40a012e027f1e465005c744763b5520033fe2d6d9eaa6e7239d227"),
            (DATA_LE, 103, "01842c3a72b8ebfe83ea008b3d6891cc2269d6b4c35ac3bf6ce249aa03d43948"),
        ] {
            let data = bytes(data);
            let found = compute_hash_argon2id(&data, nonce);
            assert_eq!(hex::encode(found), hash);
            assert!(check_difficulty_bits(&found, 6));
            assert!(!check_difficulty_bits(&compute_hash_argon2id(&data, nonce - 1), 6));
        }
    }

    #[test]
    fn wasm_solvers_round_trip() {
        for (algorithm, data, difficulty) in [
            ("sha256", DATA_BE, 16),
            ("sha256", DATA_LE, 16),
            ("hashx", DATA_BE, 12),
            ("hashx", DATA_HASHX_REJECTED, 12),
            ("argon2id", DATA_BE, 2),
            ("argon2id", DATA_LE, 2),
        ] {
            let c = challenge(algorithm, data, difficulty);
            let result = solve_challenge::<fn(u64)>(&c, None).unwrap();
            let nonce = u32::try_from(result.nonce.unwrap()).unwrap();
            assert!(
                anubis_validate(algorithm, &bytes(data), nonce, difficulty as u32, &bytes(&result.hash)),
                "{} {} nonce {}",
                algorithm,
                data,
                nonce
            );
        }
    }

    /// Trimmed from a v1.28.2 page served with BASE_PREFIX=/myapp and the css-load extension.
    const PAGE_PREFIX_CSS_LOAD: &str = r#"<!doctype html><html lang="en"><head><title>Making sure you&#39;re not a bot!</title><link rel="stylesheet" href="/myapp/.within.website/x/xess/xess.min.css?cachebuster=v1.28.2"><style>
        body { height: 100%; }
    </style><script id="anubis_version" type="application/json">"v1.28.2"</script><script id="anubis_challenge" type="application/json">{"rules":{"algorithm":"fast","difficulty":2,"extensions":["css-load"]},"challenge":{"id":"01a1eb04-1bc5-7ab5-a68e-d1b1514dd9ea","method":"fast","randomData":"abcd","difficulty":2}}</script><script id="anubis_base_prefix" type="application/json">"/myapp"</script><script id="anubis_public_url" type="application/json">""</script></head><body id="top"><main><h1 id="title" class="centered-div">Making sure you&#39;re not a bot!</h1><style>@import url("/myapp/.within.website/x/cmd/anubis/ext/css-load/01a1eb04-1bc5-7ab5-a68e-d1b1514dd9ea");</style><div class="centered-div"></div></main></body></html>"#;

    /// A page from Anubis at the site root with no extensions.
    fn page(rules: &str) -> String {
        format!(
            r#"<html><head><style>body {{ margin: 0; }}</style><script id="anubis_version" type="application/json">"v1.28.2"</script><script id="anubis_challenge" type="application/json">{{"rules":{},"challenge":{{"id":"x","randomData":"abcd"}}}}</script><script id="anubis_base_prefix" type="application/json">""</script></head><body></body></html>"#,
            rules
        )
    }

    #[test]
    fn base_prefix_submission_url() {
        assert_eq!(parse_base_prefix(PAGE_PREFIX_CSS_LOAD), "/myapp");
        assert_eq!(parse_base_prefix(&page(r#"{"algorithm":"fast","difficulty":4}"#)), "");
        // Versions before 1.17 have no element.
        assert_eq!(parse_base_prefix("<html><body></body></html>"), "");

        let c = challenge("fast", "abcd", 4);
        let result = SolverResult {
            hash: "00ff".to_string(),
            data: "abcd".to_string(),
            difficulty: 4,
            nonce: Some(7),
        };
        let tail = ".within.website/x/cmd/anubis/api/pass-challenge?response=00ff&nonce=7\
                    &redir=https%3A%2F%2Fh%2Fmyapp%2F&elapsedTime=5&id=test";
        assert_eq!(
            build_submission_url_with_prefix("https", "h", "@evil.com", &c, &result, "https://h/myapp/", 5),
            format!("https://h/@evil.com/{}", tail)
        );
        for prefix in ["/myapp", "/myapp/", "myapp"] {
            assert_eq!(
                build_submission_url_with_prefix("https", "h", prefix, &c, &result, "https://h/myapp/", 5),
                format!("https://h/myapp/{}", tail)
            );
        }
        assert_eq!(
            build_submission_url("https", "h", &c, &result, "https://h/myapp/", 5),
            format!("https://h/{}", tail)
        );
        assert_eq!(
            build_submission_url_with_prefix("https", "h", "", &c, &result, "https://h/myapp/", 5),
            format!("https://h/{}", tail)
        );
    }

    #[test]
    fn prefetch_urls() {
        assert_eq!(
            parse_prefetch_urls(PAGE_PREFIX_CSS_LOAD),
            ["/myapp/.within.website/x/cmd/anubis/ext/css-load/01a1eb04-1bc5-7ab5-a68e-d1b1514dd9ea"]
        );
        assert!(parse_prefetch_urls(&page(r#"{"algorithm":"fast","difficulty":4}"#)).is_empty());
        assert_eq!(
            parse_prefetch_urls(
                r#"<style>@import url('/a'); @import url(/b);</style><style>@import "/c";@import url("/a");</style>"#
            ),
            ["/a", "/b", "/c"]
        );
    }

    #[test]
    fn missing_difficulty_uses_server_default() {
        // Anubis omits a difficulty of 0 (or an unset one) from the page and then
        // validates against its global DIFFICULTY, 4 by default.
        for rules in [r#"{"algorithm":"metarefresh"}"#, r#"{"algorithm":"metarefresh","extensions":["css-load"]}"#] {
            let parsed = parse_challenge_from_html(&page(rules)).expect(rules);
            assert_eq!(parsed.challenge.rules.difficulty, DEFAULT_DIFFICULTY);
            assert_eq!(parsed.challenge.min_wait(), Some(Duration::from_secs(5)));
        }
        let parsed = parse_challenge_from_html(&page(r#"{"algorithm":"fast","difficulty":2}"#)).unwrap();
        assert_eq!(parsed.challenge.rules.difficulty, 2);
        // Old pages have no algorithm either.
        let parsed = parse_challenge_from_html(&page("{}")).unwrap();
        assert_eq!((parsed.challenge.algorithm(), parsed.challenge.rules.difficulty), ("fast", 4));
    }

    #[test]
    fn wait_times_cover_every_version() {
        assert_eq!(challenge("preact", "abcd", 4).min_wait(), Some(Duration::from_millis(500)));
        assert_eq!(challenge("metarefresh", "abcd", 4).min_wait(), Some(Duration::from_millis(5000)));
        assert_eq!(challenge("fast", "abcd", 4).min_wait(), None);
        // Server checks: v1.22 95 ms / 950 ms per difficulty, v1.23+ 80 ms / 800 ms.
        for difficulty in 0..=64 {
            let d = difficulty as u64;
            let preact = challenge("preact", "abcd", difficulty).min_wait().unwrap();
            let metarefresh = challenge("metarefresh", "abcd", difficulty).min_wait().unwrap();
            assert!(preact >= Duration::from_millis(d * 95), "preact {}", difficulty);
            assert!(metarefresh >= Duration::from_millis(d * 950), "metarefresh {}", difficulty);
        }
    }

    #[test]
    fn cancelled_solve_returns_promptly() {
        // A pool of its own, so other tests' solves on the global pool don't delay this one.
        let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap();
        for (algorithm, difficulty) in [("fast", 30), ("slow", 30), ("sha256", 128), ("hashx", 128), ("argon2id", 128)] {
            let c = challenge(algorithm, DATA_BE, difficulty);
            let cancel = AtomicBool::new(false);
            let start = std::time::Instant::now();
            let result = std::thread::scope(|scope| {
                scope.spawn(|| {
                    std::thread::sleep(Duration::from_millis(100));
                    cancel.store(true, Ordering::Relaxed);
                });
                pool.install(|| solve_challenge_with_cancel::<fn(u64)>(&c, None, &cancel))
            });
            assert_eq!(result.unwrap_err(), CANCELLED, "{}", algorithm);
            assert!(start.elapsed() < Duration::from_secs(3), "{} took {:?}", algorithm, start.elapsed());
        }

        // Already cancelled: no work at all.
        let cancel = AtomicBool::new(true);
        for algorithm in ["fast", "preact", "metarefresh", "hashx"] {
            let c = challenge(algorithm, DATA_BE, 4);
            assert_eq!(solve_challenge_with_cancel::<fn(u64)>(&c, None, &cancel).unwrap_err(), CANCELLED);
        }
    }

    #[test]
    fn unknown_algorithm_is_an_error() {
        let c = challenge("blake3", DATA_BE, 4);
        assert_eq!(
            solve_challenge::<fn(u64)>(&c, None).unwrap_err(),
            "unsupported algorithm: blake3"
        );
        // Empty means an old Anubis version and still uses the fast solver.
        let c = challenge("", DATA_BE, 1);
        assert!(solve_challenge::<fn(u64)>(&c, None).unwrap().nonce.is_some());
    }
}
