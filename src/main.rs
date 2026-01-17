use clap::Parser;
use fake_user_agent::get_chrome_rua;
use rust_solver::{
    solve_challenge_native, solve_metarefresh_challenge, solve_preact_challenge, AnubisChallenge,
    SolverResult,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CONNECTION, UPGRADE_INSECURE_REQUESTS,
    USER_AGENT,
};
use scraper::{Html, Selector};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Solves Anubis challenges and retrieves protected content"
)]
struct Args {
    #[arg(short, long)]
    url: String,

    #[arg(short, long, default_value_t = false)]
    progress: bool,

    #[arg(long, default_value_t = false)]
    print_html: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let base_url = &args.url;
    let user_agent = get_chrome_rua();

    println!("Starting solver for {}...", base_url);

    let mut headers = HeaderMap::new();
    let parsed_url = reqwest::Url::parse(base_url)?;
    let host = parsed_url.host_str().ok_or("Invalid URL: Missing host")?;
    headers.insert("host", HeaderValue::from_str(host)?);
    headers.insert(
        "sec-ch-ua",
        HeaderValue::from_static(
            r#""Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126""#,
        ),
    );
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Linux\""));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
    headers.insert(USER_AGENT, HeaderValue::from_str(user_agent)?);
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    headers.insert("priority", HeaderValue::from_static("u=0, i"));
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

    // Shared cookie jar persists cookies across requests, including the JWT after solving
    let cookie_jar = Arc::new(reqwest::cookie::Jar::default());

    let client = reqwest::Client::builder()
        .default_headers(headers.clone())
        .cookie_provider(cookie_jar.clone())
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    println!("Fetching challenge...");
    let res = client.get(base_url).send().await?;
    if !res.status().is_success() {
        return Err(format!("Failed to fetch challenge page: Status {}", res.status()).into());
    }
    let html_content = res.text().await?;

    let document = Html::parse_document(&html_content);
    let selector =
        Selector::parse("#anubis_challenge").map_err(|e| format!("Invalid selector: {:?}", e))?;
    let challenge_element = document
        .select(&selector)
        .next()
        .ok_or("Could not find #anubis_challenge element")?;
    let challenge_json = challenge_element.text().collect::<String>();
    if challenge_json.is_empty() {
        return Err("Found #anubis_challenge element but it was empty".into());
    }

    let challenge_data: AnubisChallenge = serde_json::from_str(&challenge_json)?;
    println!(
        "Challenge: algorithm={}, difficulty={}, id={}",
        challenge_data.rules.algorithm,
        challenge_data.rules.difficulty,
        challenge_data.challenge.id
    );

    let start_time = Instant::now();
    let algorithm = challenge_data.rules.algorithm.as_str();

    // Anubis supports multiple challenge algorithms:
    //
    // TIME-BASED CHALLENGES (anti-bot timing verification):
    //   - "preact": Compute SHA256(randomData), wait 80ms × difficulty, submit as 'result'
    //   - "metarefresh": Echo back raw randomData, wait 800ms × difficulty, submit as 'challenge'
    //
    // PROOF-OF-WORK CHALLENGES (CPU-bound computation):
    //   - "fast"/"slow": Find nonce where SHA256(randomData + nonce) has N leading zero nibbles,
    //                    where N = difficulty. Submit hash as 'response' with 'nonce' parameter.

    let (solver_result, elapsed_time): (SolverResult, Duration) = match algorithm {
        "preact" => {
            let min_wait = Duration::from_millis((challenge_data.rules.difficulty as u64) * 80);
            println!("Solving 'preact' (SHA256 + {:?} wait)...", min_wait);

            let result = solve_preact_challenge(&challenge_data);
            let elapsed = start_time.elapsed();

            if elapsed < min_wait {
                let remaining = min_wait - elapsed;
                println!("Waiting {:?}...", remaining);
                tokio::time::sleep(remaining).await;
            }

            let total_elapsed = start_time.elapsed();
            println!("Solved in {:.2?}, hash: {}", total_elapsed, result.hash);
            (result, total_elapsed)
        }
        "metarefresh" => {
            let min_wait = Duration::from_millis((challenge_data.rules.difficulty as u64) * 800);
            println!("Solving 'metarefresh' (echo + {:?} wait)...", min_wait);

            let result = solve_metarefresh_challenge(&challenge_data);
            let elapsed = start_time.elapsed();

            if elapsed < min_wait {
                let remaining = min_wait - elapsed;
                println!("Waiting {:?}...", remaining);
                tokio::time::sleep(remaining).await;
            }

            let total_elapsed = start_time.elapsed();
            println!(
                "Solved in {:.2?}, result: {}...",
                total_elapsed,
                &result.hash[..32.min(result.hash.len())]
            );
            (result, total_elapsed)
        }
        "fast" | "slow" => {
            println!(
                "Solving '{}' PoW (difficulty={}, find leading zeros)...",
                algorithm, challenge_data.rules.difficulty
            );
            let progress_counter = Arc::new(AtomicU64::new(0));

            let result = if args.progress {
                let progress_clone = progress_counter.clone();
                let callback = move |nonce: u64| {
                    let count = progress_clone.fetch_add(1, Ordering::Relaxed);
                    if count % 100 == 0 {
                        print!("\rProgress: nonce={}", nonce);
                        use std::io::{self, Write};
                        io::stdout().flush().unwrap_or_default();
                    }
                };
                solve_challenge_native(&challenge_data, Some(callback))
            } else {
                solve_challenge_native::<fn(u64)>(&challenge_data, None)
            }?;

            let elapsed = start_time.elapsed();
            if args.progress {
                println!();
            }

            println!(
                "Solved in {:.2?}, nonce={:?}, hash={}",
                elapsed, result.nonce, result.hash
            );
            (result, elapsed)
        }
        _ => {
            return Err(format!("Unsupported algorithm: {}", algorithm).into());
        }
    };

    let submission_path = ".within.website/x/cmd/anubis/api/pass-challenge";

    let submission_url_str = match algorithm {
        "preact" => format!(
            "{}://{}/{}?result={}&redir={}&elapsedTime={}&id={}",
            parsed_url.scheme(),
            host,
            submission_path,
            solver_result.hash,
            base_url,
            elapsed_time.as_millis(),
            challenge_data.challenge.id
        ),
        "metarefresh" => format!(
            "{}://{}/{}?challenge={}&redir={}&elapsedTime={}&id={}",
            parsed_url.scheme(),
            host,
            submission_path,
            solver_result.hash,
            base_url,
            elapsed_time.as_millis(),
            challenge_data.challenge.id
        ),
        _ => format!(
            "{}://{}/{}?response={}&nonce={}&redir={}&elapsedTime={}&id={}",
            parsed_url.scheme(),
            host,
            submission_path,
            solver_result.hash,
            solver_result.nonce.unwrap_or(0),
            base_url,
            elapsed_time.as_millis(),
            challenge_data.challenge.id
        ),
    };

    let submission_url = reqwest::Url::parse(&submission_url_str)?;
    println!("Submitting to: {}", submission_url);

    // Disable redirects to check for 302 response directly; cookie jar captures the JWT
    let no_redirect_client = reqwest::Client::builder()
        .default_headers(headers)
        .cookie_provider(cookie_jar)
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let submit_res = no_redirect_client.get(submission_url).send().await?;
    let submit_status = submit_res.status();

    if submit_status != reqwest::StatusCode::FOUND {
        eprintln!("Submission failed: expected 302, got {}", submit_status);
        if let Ok(body) = submit_res.text().await {
            eprintln!("{}", body);
        }
        return Err(format!("Unexpected submission status: {}", submit_status).into());
    }

    println!("Success! Server responded with 302 Found.");

    if args.print_html {
        println!("Fetching protected content...");
        let final_res = client.get(base_url).send().await?;
        let final_status = final_res.status();

        if !final_status.is_success() {
            eprintln!("Failed to fetch content: {}", final_status);
            if let Ok(body) = final_res.text().await {
                eprintln!("{}", body);
            }
            return Err(format!("Unexpected status: {}", final_status).into());
        }

        let final_html = final_res.text().await?;
        println!("\n--- Content ---\n{}\n--- End ---", final_html);
    }

    Ok(())
}
