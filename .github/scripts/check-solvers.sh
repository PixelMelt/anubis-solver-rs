#!/usr/bin/env bash
# Runs every solver against a local Anubis container and records the results.
#
# Usage: check-solvers.sh [output-dir]
#
# Writes to the output dir:
#   <algorithm>.json  shields.io endpoint badge
#   summary.md        results tables, plus logs for anything that failed
#   failed            space-separated list of failing algorithms and cases (empty if none)
#
# Exits 0 if the checks ran; read `failed` for the outcome. Exits non-zero
# without writing results if the test environment itself could not be set up.
set -uo pipefail

ALGORITHMS=(fast slow preact metarefresh sha256 hashx argon2id)
# The WASM algorithms count leading zero bits, not nibbles. These are the values
# Anubis's docs list as equivalent to `fast` at 4; everything else uses 4.
declare -A DIFFICULTY=([sha256]=16 [hashx]=15 [argon2id]=4)
IMAGE="${ANUBIS_IMAGE:-ghcr.io/techarohq/anubis:latest}"
# Used by the anubis-v1.22 cases.
OLD_IMAGE="ghcr.io/techarohq/anubis:v1.22.0"
# Used by the forward-auth case.
TRAEFIK_IMAGE="traefik:v3.7.19"
PORT="${ANUBIS_PORT:-8923}"
# The forward-auth case publishes the app (Traefik) and Anubis's public URL here.
APP_PORT=$((PORT + 1))
PUBLIC_PORT=$((PORT + 2))
OUT="${1:-solver-status}"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECK="$ROOT/target/debug/examples/check"
NETWORK="anubis-check"
BACKEND_MARKER="Welcome to nginx"

die() {
    echo "error: $*" >&2
    exit 1
}

cargo build --manifest-path "$ROOT/Cargo.toml" --example check || die "build failed"

mkdir -p "$OUT"
POLICY="$(mktemp)"
TRAEFIK_CONFIG="$(mktemp)"
chmod 644 "$POLICY" "$TRAEFIK_CONFIG"

cleanup() {
    docker rm -f anubis-check anubis-check-backend anubis-check-traefik >/dev/null 2>&1
    docker network rm "$NETWORK" >/dev/null 2>&1
}
trap 'cleanup; rm -f "$POLICY" "$TRAEFIK_CONFIG"' EXIT
cleanup

for image in "$IMAGE" "$OLD_IMAGE" "$TRAEFIK_IMAGE"; do
    docker pull -q "$image" >/dev/null || die "could not pull $image"
done
docker network create "$NETWORK" >/dev/null || die "could not create docker network"
docker run -d --name anubis-check-backend --network "$NETWORK" nginx:alpine >/dev/null ||
    die "could not start backend"

failed=()
version="unknown"
logs=""

# run_check <name> <algorithm> <image> <path> <challenge> [VAR=value ...]
#
# Starts Anubis from <image> with a policy that challenges every request with
# <challenge> (a YAML mapping for the rule's `challenge:` key), plus the given
# extra environment. Then runs the checker against <path> on Anubis (or against
# <path> itself if it is a full URL), expecting an <algorithm> challenge. Sets
# $status (0 when the check passed) and $row (the summary table row), and
# records failures in $failed and $logs.
run_check() {
    local name=$1 algorithm=$2 image=$3 path=$4 challenge=$5
    shift 5
    local env=() var
    for var in "$@"; do
        env+=(-e "$var")
    done

    echo "=== $name"
    cat >"$POLICY" <<POLICY_EOF
bots:
  - name: challenge-everything
    path_regex: .*
    action: CHALLENGE
    challenge: $challenge
dnsbl: false
POLICY_EOF

    docker rm -f anubis-check >/dev/null 2>&1
    docker run -d --name anubis-check --network "$NETWORK" -p "127.0.0.1:$PORT:8923" \
        -v "$POLICY:/policy.yaml:ro" \
        -e BIND=:8923 \
        -e TARGET=http://anubis-check-backend:80 \
        -e POLICY_FNAME=/policy.yaml \
        -e COOKIE_SECURE=false \
        -e SERVE_ROBOTS_TXT=false \
        -e USE_REMOTE_ADDRESS=true \
        "${env[@]}" \
        "$image" >/dev/null || die "could not start Anubis"

    local ready=""
    for _ in $(seq 1 40); do
        if curl -s -o /dev/null "http://127.0.0.1:$PORT/"; then
            ready=1
            break
        fi
        sleep 0.5
    done
    if [ -z "$ready" ]; then
        docker logs --tail 20 anubis-check >&2
        die "Anubis did not come up for $name"
    fi

    local url="http://127.0.0.1:$PORT$path"
    [[ $path == http* ]] && url=$path

    local output
    output="$("$CHECK" "$url" "$algorithm" "$BACKEND_MARKER" 2>&1)"
    status=$?
    echo "$output"

    if [ "$image" = "$IMAGE" ]; then
        local found
        found="$(sed -n 's/^Anubis \(.*\) challenge: .*/\1/p' <<<"$output" | head -n1)"
        [ -n "$found" ] && version="$found"
    fi

    if [ $status -eq 0 ]; then
        row="| \`$name\` | ✅ passing |"
    else
        failed+=("$name")
        row="| \`$name\` | ❌ failing |"
        logs+=$'\n'"### \`$name\`"$'\n\n```\n'"$output"$'\n'"(exit status $status)"$'\n```\n\n'
        logs+=$'<details><summary>Anubis log</summary>\n\n```\n'
        logs+="$(docker logs --tail 20 anubis-check 2>&1 | cut -c1-1000)"$'\n```\n\n</details>\n'
    fi
}

solver_rows=""
for algorithm in "${ALGORITHMS[@]}"; do
    run_check "$algorithm" "$algorithm" "$IMAGE" / \
        "{algorithm: $algorithm, difficulty: ${DIFFICULTY[$algorithm]:-4}}"
    solver_rows+="$row"$'\n'

    if [ $status -eq 0 ]; then
        message="passing"
        color="brightgreen"
    else
        message="failing"
        color="red"
    fi
    printf '{"schemaVersion":1,"label":"%s","message":"%s","color":"%s"}\n' \
        "$algorithm" "$message" "$color" >"$OUT/$algorithm.json"
done

# Cases: deployment setups beyond the per-algorithm checks. They go into
# summary.md and `failed` like the algorithms, but get no badge.
case_rows=""
case_check() {
    run_check "$@"
    case_rows+="$row"$'\n'
}
# Anubis served under a path prefix; the backend sees the stripped path.
case_check base-prefix fast "$IMAGE" /myapp/ "{algorithm: fast, difficulty: 4}" \
    BASE_PREFIX=/myapp STRIP_BASE_PREFIX=true
# Submission is refused unless the page's CSS @import was fetched first.
case_check css-load fast "$IMAGE" / "{algorithm: fast, difficulty: 2, extensions: [css-load]}"
# Difficulty 0 or missing is left out of the page; the server falls back to DIFFICULTY (4).
case_check difficulty-0 fast "$IMAGE" / "{algorithm: fast, difficulty: 0}"
case_check no-difficulty metarefresh "$IMAGE" / "{algorithm: metarefresh}"
# v1.22 enforced longer waits (950 ms and 95 ms per difficulty) than later versions.
case_check anubis-v1.22-metarefresh metarefresh "$OLD_IMAGE" / "{algorithm: metarefresh, difficulty: 4}"
case_check anubis-v1.22-preact preact "$OLD_IMAGE" / "{algorithm: preact, difficulty: 4}"

# Forward-auth (subrequest) mode: Traefik asks Anubis's check endpoint about every
# request to the app, and Anubis answers 307 to the challenge on its public URL,
# a different port. Cookies ignore ports, so COOKIE_DOMAIN shares them. Anubis is
# reached through Traefik too and takes the client IP from its X-Real-Ip header.
cat >"$TRAEFIK_CONFIG" <<'TRAEFIK_EOF'
http:
  middlewares:
    anubis:
      forwardAuth:
        address: http://anubis-check:8923/.within.website/x/cmd/anubis/api/check
  routers:
    app:
      entryPoints: [app]
      rule: PathPrefix(`/`)
      middlewares: [anubis]
      service: backend
    anubis:
      entryPoints: [anubis]
      rule: PathPrefix(`/`)
      service: anubis
  services:
    backend:
      loadBalancer:
        servers: [{url: "http://anubis-check-backend:80"}]
    anubis:
      loadBalancer:
        servers: [{url: "http://anubis-check:8923"}]
TRAEFIK_EOF
docker run -d --name anubis-check-traefik --network "$NETWORK" \
    -p "127.0.0.1:$APP_PORT:8080" -p "127.0.0.1:$PUBLIC_PORT:8081" \
    -v "$TRAEFIK_CONFIG:/dynamic.yml:ro" \
    "$TRAEFIK_IMAGE" \
    --entrypoints.app.address=:8080 --entrypoints.anubis.address=:8081 \
    --providers.file.filename=/dynamic.yml >/dev/null || die "could not start Traefik"
traefik_ready=""
for _ in $(seq 1 40); do
    # 404 until the file provider has loaded the routers.
    case "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PUBLIC_PORT/")" in
    000 | 404) sleep 0.5 ;;
    *)
        traefik_ready=1
        break
        ;;
    esac
done
[ -n "$traefik_ready" ] || die "Traefik did not come up"
# REDIRECT_DOMAINS is a glob: Anubis v1.28 refuses to start on "127.0.0.1:<port>",
# which url.Parse rejects.
case_check forward-auth fast "$IMAGE" "http://127.0.0.1:$APP_PORT/" "{algorithm: fast, difficulty: 4}" \
    "TARGET= " USE_REMOTE_ADDRESS=false "PUBLIC_URL=http://127.0.0.1:$PUBLIC_PORT" \
    COOKIE_DOMAIN=127.0.0.1 "REDIRECT_DOMAINS=127.0.0.1*"
docker rm -f anubis-check-traefik >/dev/null 2>&1

{
    echo "Tested against Anubis \`$version\` (\`$IMAGE\`)."
    echo
    echo "| Solver | Status |"
    echo "|--------|--------|"
    printf '%s' "$solver_rows"
    echo
    echo "| Case | Status |"
    echo "|------|--------|"
    printf '%s' "$case_rows"
    printf '%s' "$logs"
} >"$OUT/summary.md"

echo "${failed[*]}" >"$OUT/failed"
