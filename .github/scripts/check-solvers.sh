#!/usr/bin/env bash
# Runs every solver against a local Anubis container and records the results.
#
# Usage: check-solvers.sh [output-dir]
#
# Writes to the output dir:
#   <algorithm>.json  shields.io endpoint badge
#   summary.md        results table, plus logs for anything that failed
#   failed            space-separated list of failing algorithms (empty if none)
#
# Exits 0 if the checks ran; read `failed` for the outcome. Exits non-zero
# without writing results if the test environment itself could not be set up.
set -uo pipefail

ALGORITHMS=(fast slow preact metarefresh)
IMAGE="${ANUBIS_IMAGE:-ghcr.io/techarohq/anubis:latest}"
PORT="${ANUBIS_PORT:-8923}"
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
chmod 644 "$POLICY"

cleanup() {
    docker rm -f anubis-check anubis-check-backend >/dev/null 2>&1
    docker network rm "$NETWORK" >/dev/null 2>&1
}
trap 'cleanup; rm -f "$POLICY"' EXIT
cleanup

docker pull -q "$IMAGE" >/dev/null || die "could not pull $IMAGE"
docker network create "$NETWORK" >/dev/null || die "could not create docker network"
docker run -d --name anubis-check-backend --network "$NETWORK" nginx:alpine >/dev/null ||
    die "could not start backend"

failed=()
version="unknown"
rows=""
logs=""

for algorithm in "${ALGORITHMS[@]}"; do
    echo "=== $algorithm"
    cat >"$POLICY" <<POLICY_EOF
bots:
  - name: challenge-everything
    path_regex: .*
    action: CHALLENGE
    challenge:
      algorithm: $algorithm
      difficulty: 4
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
        "$IMAGE" >/dev/null || die "could not start Anubis"

    ready=""
    for _ in $(seq 1 40); do
        if curl -s -o /dev/null "http://127.0.0.1:$PORT/"; then
            ready=1
            break
        fi
        sleep 0.5
    done
    if [ -z "$ready" ]; then
        docker logs --tail 20 anubis-check >&2
        die "Anubis did not come up with the $algorithm policy"
    fi

    output="$("$CHECK" "http://127.0.0.1:$PORT/" "$algorithm" "$BACKEND_MARKER" 2>&1)"
    status=$?
    echo "$output"

    found="$(sed -n 's/^Anubis \(.*\) challenge: .*/\1/p' <<<"$output" | head -n1)"
    [ -n "$found" ] && version="$found"

    if [ $status -eq 0 ]; then
        rows+="| \`$algorithm\` | ✅ passing |"$'\n'
        message="passing"
        color="brightgreen"
    else
        failed+=("$algorithm")
        rows+="| \`$algorithm\` | ❌ failing |"$'\n'
        message="failing"
        color="red"
        logs+=$'\n'"### \`$algorithm\`"$'\n\n```\n'"$output"$'\n```\n\n'
        logs+=$'<details><summary>Anubis log</summary>\n\n```\n'
        logs+="$(docker logs --tail 20 anubis-check 2>&1 | cut -c1-1000)"$'\n```\n\n</details>\n'
    fi

    printf '{"schemaVersion":1,"label":"%s","message":"%s","color":"%s"}\n' \
        "$algorithm" "$message" "$color" >"$OUT/$algorithm.json"
done

{
    echo "Tested against Anubis \`$version\` (\`$IMAGE\`)."
    echo
    echo "| Solver | Status |"
    echo "|--------|--------|"
    printf '%s' "$rows"
    printf '%s' "$logs"
} >"$OUT/summary.md"

echo "${failed[*]}" >"$OUT/failed"
