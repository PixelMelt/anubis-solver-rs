//! End-to-end check against a live Anubis instance.
//!
//! Usage: cargo run --example check -- <url> [expected-algorithm] [expected-body-text]
//!
//! Fetches <url>, following redirects to the challenge (in forward-auth mode it is
//! on Anubis's public URL), solves it, submits the solution and follows the redirects
//! back to <url>, confirming the page is reachable. Exits non-zero on failure.

use std::time::{Duration, Instant};

use anubis_solver::{
    build_submission_url_for_page, is_auth_cookie, parse_challenge_from_html,
    parse_prefetch_urls, parse_redirect_target, solve_challenge,
};
use fake_user_agent::get_chrome_rua;
use reqwest::header::{LOCATION, SET_COOKIE};
use reqwest::{Client, Response, StatusCode, Url};

const MAX_REDIRECTS: usize = 10;

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
    let parsed_url = Url::parse(url)?;

    let user_agent = get_chrome_rua();
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let resp = client.get(url).header("User-Agent", user_agent).send().await?;
    let (page_url, status, html) = follow_redirects(&client, user_agent, resp).await?;
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

    for prefetch in parse_prefetch_urls(&html) {
        let prefetch_url = page_url.join(&prefetch)?;
        if prefetch_url.origin() != page_url.origin() {
            return Err(format!("challenge page imports cross-origin {}", prefetch_url).into());
        }
        let resp = client
            .get(prefetch_url.clone())
            .header("User-Agent", user_agent)
            .send()
            .await?;
        println!("Fetched {} ({})", prefetch_url.path(), resp.status());
        if !resp.status().is_success() {
            return Err(format!("fetching {} returned {}", prefetch_url, resp.status()).into());
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

    let redir = parse_redirect_target(page_url.as_str(), &html, url);
    let submit_url = build_submission_url_for_page(
        page_url.as_str(),
        &html,
        challenge,
        &result,
        &redir,
        elapsed_time.as_millis(),
    )
    .ok_or_else(|| format!("cannot submit to challenge page {}", page_url))?;

    let submit_resp = client
        .get(&submit_url)
        .header("User-Agent", user_agent)
        .send()
        .await?;
    let submit_status = submit_resp.status();
    if submit_status != StatusCode::FOUND {
        return Err(format!("submission returned {} instead of 302", submit_status).into());
    }
    // Anubis also answers 302 when it is missing the verification cookie, sending us
    // back for a fresh challenge; only the auth cookie means the solution was accepted.
    let passed = submit_resp
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .any(|value| value.to_str().is_ok_and(is_auth_cookie));
    if !passed {
        return Err("submission redirected without setting the auth cookie".into());
    }

    let (final_url, status, body) = follow_redirects(&client, user_agent, submit_resp).await?;
    if parse_challenge_from_html(&body).is_some() {
        return Err("challenged again after a successful submission".into());
    }
    if final_url != parsed_url {
        return Err(format!("ended up at {} instead of {}", final_url, parsed_url).into());
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

/// Follows the redirects starting at `resp`, returning the final URL, status and body.
async fn follow_redirects(
    client: &Client,
    user_agent: &str,
    mut resp: Response,
) -> Result<(Url, StatusCode, String), Box<dyn std::error::Error>> {
    let is_redirect = |status: StatusCode| matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308);
    for _ in 0..MAX_REDIRECTS {
        if !is_redirect(resp.status()) {
            break;
        }
        let location = resp
            .headers()
            .get(LOCATION)
            .ok_or_else(|| format!("{} from {} has no Location", resp.status(), resp.url()))?
            .to_str()?;
        let next = resp.url().join(location)?;
        println!("{} redirected to {}", resp.status(), next);
        resp = client.get(next).header("User-Agent", user_agent).send().await?;
    }
    if is_redirect(resp.status()) {
        return Err(format!("more than {} redirects", MAX_REDIRECTS).into());
    }
    let url = resp.url().clone();
    let status = resp.status();
    Ok((url, status, resp.text().await?))
}
