use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use fake_user_agent::get_chrome_rua;
use reqwest::header::HeaderMap;
use anubis_solver::{build_submission_url, parse_challenge_from_html, solve_challenge};
use std::time::Duration;

type CookieJarCache = Arc<DashMap<String, Arc<reqwest::cookie::Jar>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8192".into())
        .parse()
        .unwrap_or(8192);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    println!("Anubis proxy listening on http://{}", addr);
    println!("Usage: GET /proxy/<host>/<path>");

    let jars: CookieJarCache = Arc::new(DashMap::new());

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let jars = jars.clone();

        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service_fn(|req| handle_request(req, jars.clone())))
                .await
            {
                eprintln!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    jars: CookieJarCache,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();

    if path == "/health" {
        return Ok(Response::new(Full::new(Bytes::from("ok"))));
    }

    if !path.starts_with("/proxy/") {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from(
                "Usage: /proxy/<host>/<path>\nExample: /proxy/clew.se/search?q=test",
            )))
            .unwrap());
    }

    let rest = &path[7..];
    let (host, target_path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    if host.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("Missing host in path")))
            .unwrap());
    }

    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let target_url = format!("https://{}{}{}", host, target_path, query);

    println!("Proxying: {} {}", req.method(), target_url);

    match proxy_request(req.method().clone(), &target_url, host, jars).await {
        Ok((status, headers, body)) => {
            let mut builder = Response::builder().status(status);
            for (key, value) in headers {
                if let Some(name) = key {
                    let name_str = name.as_str().to_lowercase();
                    if name_str != "transfer-encoding" && name_str != "connection" {
                        builder = builder.header(name, value);
                    }
                }
            }
            Ok(builder.body(Full::new(Bytes::from(body))).unwrap())
        }
        Err(e) => {
            eprintln!("Proxy error: {}", e);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(format!("Proxy error: {}", e))))
                .unwrap())
        }
    }
}

fn get_or_create_jar(jars: &CookieJarCache, host: &str) -> Arc<reqwest::cookie::Jar> {
    jars.entry(host.to_string())
        .or_insert_with(|| Arc::new(reqwest::cookie::Jar::default()))
        .clone()
}

async fn proxy_request(
    _method: Method,
    url: &str,
    host: &str,
    jars: CookieJarCache,
) -> Result<(StatusCode, HeaderMap, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let user_agent = get_chrome_rua();
    let jar = get_or_create_jar(&jars, host);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .cookie_provider(jar.clone())
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let resp = client
        .get(url)
        .header("User-Agent", user_agent)
        .send()
        .await?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.bytes().await?.to_vec();

    let html = String::from_utf8_lossy(&body);
    if let Some(parsed) = parse_challenge_from_html(&html) {
        println!(
            "Detected Anubis {} challenge for {} (algorithm={}, difficulty={})",
            parsed.version,
            host,
            parsed.challenge.algorithm(),
            parsed.challenge.rules.difficulty
        );
        return solve_and_retry(&client, url, host, &user_agent, parsed).await;
    }

    Ok((status, headers, body))
}

async fn solve_and_retry(
    client: &reqwest::Client,
    original_url: &str,
    host: &str,
    user_agent: &str,
    parsed: anubis_solver::ParsedChallenge,
) -> Result<(StatusCode, HeaderMap, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let challenge = &parsed.challenge;
    let start_time = Instant::now();

    let result = solve_challenge::<fn(u64)>(challenge, None)?;

    if let Some(min_wait) = challenge.min_wait() {
        let elapsed = start_time.elapsed();
        if elapsed < min_wait {
            tokio::time::sleep(min_wait - elapsed).await;
        }
    }

    let elapsed_time = start_time.elapsed();
    println!(
        "Solved {} challenge in {:?}",
        challenge.algorithm(),
        elapsed_time
    );

    let submit_url = build_submission_url(
        "https",
        host,
        challenge,
        &result,
        original_url,
        elapsed_time.as_millis(),
    );

    let submit_resp = client
        .get(&submit_url)
        .header("User-Agent", user_agent)
        .send()
        .await?;

    let submit_status = submit_resp.status();
    let submit_headers = submit_resp.headers().clone();

    if submit_status != reqwest::StatusCode::FOUND {
        let body = submit_resp.bytes().await?.to_vec();
        eprintln!(
            "Challenge submission returned {} instead of 302 (server-side issue)",
            submit_status
        );
        return Ok((submit_status, submit_headers, body));
    }

    println!("Challenge passed, fetching content...");

    let resp = client
        .get(original_url)
        .header("User-Agent", user_agent)
        .send()
        .await?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.bytes().await?.to_vec();

    Ok((status, headers, body))
}
