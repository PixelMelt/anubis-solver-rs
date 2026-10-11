//! End-to-end check against a live Anubis instance.
//!
//! Usage: cargo run --example check -- <url> [expected-algorithm] [expected-body-text]
//!
//! Fetches <url>, solves the challenge it serves, submits the solution and
//! confirms the original page is reachable afterwards. Exits non-zero on failure.

use std::time::{Duration, Instant};

use anubis_solver::{build_submission_url, parse_challenge_from_html, solve_challenge};
use fake_user_agent::get_chrome_rua;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let Some(url) = args.next() else {
        eprintln!("Usage: check <url> [expected-algorithm] [expected-body-text]");
        std::process::exit(2);
    };
    let expected = args.next();
    let expected_body = args.next();

    if let Err(e) = run(&url, expected.as_deref(), expected_body.as_deref()).await {
        eprintln!("FAIL: {}", e);
        std::process::exit(1);
    }
    println!("OK");
}

async fn run(
    url: &str,
    expected: Option<&str>,
    expected_body: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let parsed_url = reqwest::Url::parse(url)?;
    let host = match parsed_url.port() {
        Some(port) => format!("{}:{}", parsed_url.host_str().ok_or("URL has no host")?, port),
        None => parsed_url.host_str().ok_or("URL has no host")?.to_string(),
    };

    let user_agent = get_chrome_rua();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let resp = client.get(url).header("User-Agent", user_agent).send().await?;
    let status = resp.status();
    let html = resp.text().await?;
    let parsed = parse_challenge_from_html(&html)
        .ok_or_else(|| format!("no challenge found in response ({})", status))?;
    let challenge = &parsed.challenge;

    println!(
        "Anubis {} challenge: algorithm={}, difficulty={}",
        parsed.version,
        challenge.algorithm(),
        challenge.rules.difficulty
    );

    if let Some(expected) = expected {
        if challenge.algorithm() != expected {
            return Err(format!(
                "expected a {} challenge, server issued {}",
                expected,
                challenge.algorithm()
            )
            .into());
        }
    }

    let start_time = Instant::now();
    let result = solve_challenge::<fn(u64)>(challenge, None)?;

    if let Some(min_wait) = challenge.min_wait() {
        let elapsed = start_time.elapsed();
        if elapsed < min_wait {
            tokio::time::sleep(min_wait - elapsed).await;
        }
    }

    let elapsed_time = start_time.elapsed();
    println!("Solved in {:?}", elapsed_time);

    let submit_url = build_submission_url(
        parsed_url.scheme(),
        &host,
        challenge,
        &result,
        url,
        elapsed_time.as_millis(),
    );

    let submit_resp = client
        .get(&submit_url)
        .header("User-Agent", user_agent)
        .send()
        .await?;
    let submit_status = submit_resp.status();
    if submit_status != reqwest::StatusCode::FOUND {
        return Err(format!("submission returned {} instead of 302", submit_status).into());
    }

    let resp = client.get(url).header("User-Agent", user_agent).send().await?;
    let status = resp.status();
    let body = resp.text().await?;
    if parse_challenge_from_html(&body).is_some() {
        return Err("challenged again after a successful submission".into());
    }
    if !status.is_success() {
        return Err(format!("page returned {} after passing the challenge", status).into());
    }
    if let Some(expected_body) = expected_body {
        if !body.contains(expected_body) {
            return Err(format!(
                "page after passing the challenge does not contain {:?}",
                expected_body
            )
            .into());
        }
    }

    Ok(())
}
