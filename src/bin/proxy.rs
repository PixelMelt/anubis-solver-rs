use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
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
use anubis_solver::{
    build_submission_url_for_page, is_auth_cookie, parse_challenge_from_html,
    parse_prefetch_urls, parse_redirect_target, solve_challenge_with_cancel,
};
use std::time::Duration;

type CookieJarCache = Arc<DashMap<String, Arc<reqwest::cookie::Jar>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8192".into())
        .parse()
        .unwrap_or(8192);

    let solve_timeout = Duration::from_secs(
        std::env::var("SOLVE_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60),
    );

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    println!("Anubis proxy listening on http://{}", addr);
    println!("Usage: GET /proxy/<host>/<path>");
    println!("Solve timeout: {:?}", solve_timeout);

    let jars: CookieJarCache = Arc::new(DashMap::new());

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let jars = jars.clone();

        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(|req| handle_request(req, jars.clone(), solve_timeout)),
                )
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
    solve_timeout: Duration,
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

    match proxy_request(req.method().clone(), &target_url, host, jars, solve_timeout).await {
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

/// The cookie jar for requests to `host`. Every hop of a request uses it, including
/// redirects to other hosts such as a forward-auth Anubis's public URL; the jar's
/// domain matching decides which cookies each hop gets.
fn get_or_create_jar(jars: &CookieJarCache, host: &str) -> Arc<reqwest::cookie::Jar> {
    jars.entry(host.to_string())
        .or_insert_with(|| Arc::new(reqwest::cookie::Jar::default()))
        .clone()
}

/// Redirects followed before giving up, per chain.
const MAX_REDIRECTS: usize = 10;
/// Solves per request before giving up. Anubis sends a client that lost its
/// verification cookie back for one fresh challenge.
const MAX_SOLVES: usize = 2;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Upstream = (StatusCode, HeaderMap, Vec<u8>);

/// A response at the end of a redirect chain.
struct Fetched {
    url: reqwest::Url,
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn proxy_request(
    _method: Method,
    url: &str,
    host: &str,
    jars: CookieJarCache,
    solve_timeout: Duration,
) -> Result<Upstream, BoxError> {
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
    let mut fetched = follow_redirects(&client, user_agent, resp).await?;

    let mut solves = 0;
    loop {
        let html = String::from_utf8_lossy(&fetched.body).into_owned();
        let Some(parsed) = parse_challenge_from_html(&html) else {
            return Ok((fetched.status, fetched.headers, fetched.body));
        };
        if solves == MAX_SOLVES {
            return Err(format!(
                "still challenged at {} after solving {} times",
                fetched.url, MAX_SOLVES
            )
            .into());
        }
        println!(
            "Detected Anubis {} challenge at {} (algorithm={}, difficulty={})",
            parsed.version,
            fetched.url,
            parsed.challenge.algorithm(),
            parsed.challenge.rules.difficulty
        );
        solves += 1;
        match solve_and_submit(&client, url, &fetched.url, user_agent, parsed, &html, solve_timeout)
            .await?
        {
            Ok(next) => fetched = next,
            Err(response) => return Ok(response),
        }
    }
}

/// Follows the redirects starting at `resp`, to https URLs only, like the proxy's own
/// upstream requests. A redirect without a Location is returned as received.
async fn follow_redirects(
    client: &reqwest::Client,
    user_agent: &str,
    mut resp: reqwest::Response,
) -> Result<Fetched, BoxError> {
    let is_redirect = |resp: &reqwest::Response| {
        matches!(resp.status().as_u16(), 301 | 302 | 303 | 307 | 308)
            && resp.headers().contains_key(reqwest::header::LOCATION)
    };
    for _ in 0..MAX_REDIRECTS {
        if !is_redirect(&resp) {
            break;
        }
        let location = resp.headers()[reqwest::header::LOCATION].to_str()?;
        let next = resp.url().join(location)?;
        if next.scheme() != "https" {
            return Err(format!("refusing to follow non-https redirect to {}", next).into());
        }
        println!("{} redirected to {}", resp.status(), next);
        resp = client
            .get(next)
            .header("User-Agent", user_agent)
            .send()
            .await?;
    }
    if is_redirect(&resp) {
        return Err(format!("more than {} redirects from {}", MAX_REDIRECTS, resp.url()).into());
    }
    Ok(Fetched {
        url: resp.url().clone(),
        status: resp.status(),
        headers: resp.headers().clone(),
        body: resp.bytes().await?.to_vec(),
    })
}

/// Solves the challenge on `page_url`, reached while requesting `original_url`, and
/// submits the solution. Returns where the submission's redirects led, or `Err` with
/// a response to hand back as-is: a solve timeout, or a submission Anubis refused.
async fn solve_and_submit(
    client: &reqwest::Client,
    original_url: &str,
    page_url: &reqwest::Url,
    user_agent: &str,
    parsed: anubis_solver::ParsedChallenge,
    html: &str,
    solve_timeout: Duration,
) -> Result<Result<Fetched, Upstream>, BoxError> {
    let challenge = &parsed.challenge;
    let start_time = Instant::now();

    // Resources the page loads that the server checks for, e.g. the css-load extension's.
    for prefetch in parse_prefetch_urls(html) {
        let prefetch_url = page_url.join(&prefetch)?;
        // Anubis only serves these from its own origin; never let the page aim us elsewhere.
        if prefetch_url.origin() != page_url.origin() {
            eprintln!("Skipping cross-origin prefetch {}", prefetch_url);
            continue;
        }
        let resp = client
            .get(prefetch_url.clone())
            .header("User-Agent", user_agent)
            .send()
            .await?;
        // Anubis rejects the solution if this fetch was not recorded, so don't bother solving.
        if !resp.status().is_success() {
            return Err(format!("fetching {} returned {}", prefetch_url, resp.status()).into());
        }
    }

    // Solve off the async runtime, giving up after the timeout. The guard also stops
    // the solve if this request is dropped, e.g. when the client disconnects.
    let cancel = CancelOnDrop(Arc::new(AtomicBool::new(false)));
    let solve = {
        let challenge = challenge.clone();
        let cancel = cancel.0.clone();
        tokio::task::spawn_blocking(move || {
            solve_challenge_with_cancel::<fn(u64)>(&challenge, None, &cancel)
        })
    };
    let result = match tokio::time::timeout(solve_timeout, solve).await {
        Ok(joined) => joined??,
        Err(_) => {
            eprintln!(
                "Gave up solving {} challenge (difficulty {}) at {} after {:?}",
                challenge.algorithm(),
                challenge.rules.difficulty,
                page_url,
                solve_timeout
            );
            return Ok(Err((
                StatusCode::GATEWAY_TIMEOUT,
                HeaderMap::new(),
                format!(
                    "Proxy error: gave up solving the Anubis challenge after {}s \
                     (algorithm {}, difficulty {}); raise SOLVE_TIMEOUT_SECS to allow longer\n",
                    solve_timeout.as_secs(),
                    challenge.algorithm(),
                    challenge.rules.difficulty
                )
                .into_bytes(),
            )));
        }
    };

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

    // Submit to the page's own origin, which in forward-auth mode is Anubis's public
    // URL rather than the requested host, and return to where the page says.
    let redir = parse_redirect_target(page_url.as_str(), html, original_url);
    let submit_url = build_submission_url_for_page(
        page_url.as_str(),
        html,
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
    if submit_status != reqwest::StatusCode::FOUND {
        let submit_headers = submit_resp.headers().clone();
        let body = submit_resp.bytes().await?.to_vec();
        eprintln!(
            "Challenge submission returned {} instead of 302 (server-side issue)",
            submit_status
        );
        return Ok(Err((submit_status, submit_headers, body)));
    }

    // Anubis also redirects when the verification cookie is missing, sending the
    // client back for a fresh challenge; only the auth cookie means it passed.
    let passed = submit_resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .any(|value| value.to_str().is_ok_and(is_auth_cookie));
    if passed {
        println!("Challenge passed, following redirect to {}", redir);
    } else {
        println!("Submission redirected without the auth cookie, checking whether it passed");
    }

    let next = follow_redirects(client, user_agent, submit_resp).await?;
    // Without the auth cookie, only a fresh challenge (Anubis's retry) is expected here;
    // anything else is an error page, not the content.
    if !passed && parse_challenge_from_html(&String::from_utf8_lossy(&next.body)).is_none() {
        return Err(format!("Anubis did not accept the solution at {}", page_url).into());
    }
    Ok(Ok(next))
}

/// Sets the solve's cancel flag when dropped.
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}
