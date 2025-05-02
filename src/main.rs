use clap::Parser;
use rust_solver::{solve_challenge_native, AnubisChallenge};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CONNECTION, UPGRADE_INSECURE_REQUESTS, USER_AGENT};
use scraper::{Html, Selector};

/// Fetches, solves, submits Anubis PoW challenges from a given URL, and returns the final HTML.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // The URL of the Anubis challenge page
    #[arg(short, long)]
    url: String,

    // Show progress updates during solving
    #[arg(short, long, default_value_t = false)]
    progress: bool,

    // Print the final HTML content to stdout after successful submission
    #[arg(long, default_value_t = false)]
    print_html: bool,
}

// Mimics a common browser User-Agent.
const FAKE_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let base_url = &args.url;

    println!("Starting solver for {}...", base_url);

    // --- 1. Prepare HTTP Client and Headers ---
    let mut headers = HeaderMap::new();
    let parsed_url = reqwest::Url::parse(base_url)?;
    let host = parsed_url.host_str().ok_or("Invalid URL: Missing host")?;
    headers.insert("host", HeaderValue::from_str(host)?);
    // Common browser headers
    headers.insert("sec-ch-ua", HeaderValue::from_static(r#""Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126""#));
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Linux\""));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
    headers.insert(USER_AGENT, HeaderValue::from_static(FAKE_USER_AGENT));
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    headers.insert("priority", HeaderValue::from_static("u=0, i"));
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

    let cookie_jar = Arc::new(reqwest::cookie::Jar::default());

    // Main client: Uses shared cookies and follows redirects.
    let client = reqwest::Client::builder()
        .default_headers(headers.clone())
        .cookie_provider(cookie_jar.clone())
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // --- 2. Fetch Initial Page & Extract Challenge ---
    println!("Fetching challenge...");
    let res = client.get(base_url).send().await?;
    if !res.status().is_success() {
        return Err(format!("Failed to fetch challenge page: Status {}", res.status()).into());
    }
    let html_content = res.text().await?;
    println!("Successfully fetched page.");

    println!("Parsing challenge...");
    let document = Html::parse_document(&html_content);
    let selector = Selector::parse("#anubis_challenge").map_err(|e| format!("Invalid selector: {:?}", e))?;
    let challenge_element = document.select(&selector).next().ok_or("Could not find #anubis_challenge element")?;
    let challenge_json = challenge_element.text().collect::<String>();
    if challenge_json.is_empty() {
         return Err("Found #anubis_challenge element but it was empty".into());
    }

    let challenge_data: AnubisChallenge = serde_json::from_str(&challenge_json)?;
    println!("Successfully deserialized challenge: Difficulty {}", challenge_data.rules.difficulty);

    // --- 3. Solve the PoW Challenge ---
    println!("Solving challenge natively...");
    let start_time = Instant::now();
    let progress_counter = Arc::new(AtomicU64::new(0));

    let solver_result = if args.progress {
        let progress_clone = progress_counter.clone(); // Clone for the closure
        let callback = move |nonce: u64| {
            let count = progress_clone.fetch_add(1, Ordering::Relaxed);
            // Reduce console update frequency for performance
            if count % 100 == 0 {
                print!("\rSolver progress: Nonce {} ({} updates)", nonce, count + 1);
                use std::io::{self, Write};
                io::stdout().flush().unwrap_or_default();
            }
        };
        solve_challenge_native(&challenge_data, Some(callback))
    } else {
        // Pass None or a dummy function type if no callback is needed
        solve_challenge_native::<fn(u64)>(&challenge_data, None)
    }?;

    let elapsed_time = start_time.elapsed();
    if args.progress { println!(); } // Ensure newline after progress indicator

    println!(
        "\nChallenge solved in {:.2?}! Nonce: {}, Hash: {}",
        elapsed_time,
        solver_result.nonce,
        solver_result.hash
    );

    // --- 4. Construct Submission URL ---
    // The submission path and query params format is specific to the Anubis challenge system.
    // Example target: https://{host}/.within.website/x/cmd/anubis/api/pass-challenge?response={hash}&nonce={nonce}&redir={base_url}&elapsedTime={ms}
    let submission_path = ".within.website/x/cmd/anubis/api/pass-challenge";
    let submission_url_str = format!(
        "{}://{}/{}?response={}&nonce={}&redir={}&elapsedTime={}",
        parsed_url.scheme(),
        host,
        submission_path,
        solver_result.hash,
        solver_result.nonce,
        base_url, // The 'redir' parameter uses the original full challenge URL.
        elapsed_time.as_millis()
    );
    let submission_url = reqwest::Url::parse(&submission_url_str)?;
    println!("Constructed submission URL: {}", submission_url);

    // --- 5. Submit Solution ---
    println!("Submitting solution...");
    // Use a separate client configured NOT to follow redirects for the submission step.
    // This allows checking for the expected 302 status code directly.
     let no_redirect_client = reqwest::Client::builder()
        .default_headers(headers) // Reuse original headers
        .cookie_provider(cookie_jar) // CRITICAL: Use the same cookie jar to send session cookies if any were set previously, and capture new ones.
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none()) // Do not follow redirects automatically.
        .build()?;

    let submit_res = no_redirect_client.get(submission_url).send().await?;
    let submit_status = submit_res.status();
    println!("Submission response status: {}", submit_status);

    // --- 6. Verify Submission Response ---
    // The challenge system typically responds with 302 Found on successful PoW submission.
    if submit_status != reqwest::StatusCode::FOUND {
         eprintln!(
            "Submission failed! Expected status 302 Found, but got {}. Server response body:",
            submit_status
        );
        // Attempt to print body for debugging info from the server.
        match submit_res.text().await {
            Ok(body) => eprintln!("{}", body),
            Err(e) => eprintln!("Could not read response body: {}", e),
        }
        return Err(format!("Unexpected submission status: {}", submit_status).into());
    }

    println!("Successfully submitted solution! Server responded with 302 Found.");
    // The necessary session cookies should now be stored in the shared `cookie_jar`.

    // --- 7. Optionally Fetch Final Content ---
    // Only fetch the final page if requested, using the original client which now has the session cookie.
    if args.print_html {
        println!("Fetching final page content with session cookie...");
        // Use the original client which follows redirects and has the updated cookie jar.
        let final_res = client.get(base_url).send().await?;
        let final_status = final_res.status(); // Check status before consuming body.

        if !final_status.is_success() {
            eprintln!("Failed to fetch final page content: Status {}", final_status);
            // Attempt to print body for debugging.
            match final_res.text().await {
                Ok(body) => eprintln!("Response body: {}", body),
                Err(e) => eprintln!("Could not read response body: {}", e),
            }
            return Err(format!("Unexpected status code on final fetch: {}", final_status).into());
        }

        let final_html = final_res.text().await?;
        println!("Successfully fetched final page content.");

        println!("\n--- Final HTML Content ---");
        println!("{}", final_html);
        println!("--- End HTML Content ---");
    } else {
        println!("Final submission successful. Run with --print-html to fetch and display the final page content.");
    }

    Ok(())
}