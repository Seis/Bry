#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$project_root"

shopt -s nullglob
jars=(target/*.jar)
if (( ${#jars[@]} != 1 )); then
  echo "Expected exactly one executable JAR in target; run clean verify first." >&2
  exit 1
fi

rm -rf -- target/distribution
mkdir -p target/distribution
cp "${jars[0]}" target/distribution/bry.jar
cat > target/distribution/RUNNING.txt <<'EOF'
BRy backend Java challenge

Requires JDK 17.0.21 or a newer Java 17 update.

Run:
  java -jar bry.jar

Open http://localhost:8080/ for the test page.
If port 8080 is occupied:
  java -jar bry.jar --server.port=8081

Verify downloaded file checksums (Linux):
  sha256sum -c SHA256SUMS

Date checks are advisory under this application's verification policy.
Read the separately supplied activity report for decisions and limitations.
EOF

(
  cd target/distribution
  sha256sum bry.jar RUNNING.txt > SHA256SUMS
)
