#!/usr/bin/env bash
#
# End-to-end verification of the whole stack.
#
#   ./scripts/verify-e2e.sh
#
# Starts the packaged application, pushes the demo captures through the real
# REST API, and asserts the persisted results. Nothing is mocked: the Java half
# runs the actual Python engine as a subprocess, exactly as it does in
# production, so this is the check that proves the two halves agree about the
# JSON contract between them.
#
# Exits non-zero on the first failed assertion.
#
# Environment:
#   SMS_JAVA     java binary            (default: java on PATH)
#   SMS_PYTHON   python interpreter     (default: python3)
#   SMS_PORT     port to bind           (default: 18099)

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAVA="${SMS_JAVA:-java}"
PYTHON="${SMS_PYTHON:-python3}"
PORT="${SMS_PORT:-18099}"
JAR="$ROOT/backend/target/securemailscope-1.0.0.jar"
WORK="$(mktemp -d)"
BASE="http://localhost:$PORT"

pass=0
fail=0

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; fail=$((fail+1)); }
info() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
  [[ -n "${APP_PID:-}" ]] && kill "$APP_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

# --------------------------------------------------------------------------

if [[ ! -f "$JAR" ]]; then
  echo "No application jar at $JAR"
  echo "Build it first:  mvn -f backend/pom.xml -DskipTests package"
  exit 2
fi

info "Starting the application on port $PORT"
mkdir -p "$WORK/uploads"
(cd "$WORK" && "$JAVA" -jar "$JAR" \
  --server.port="$PORT" \
  --spring.datasource.url="jdbc:h2:mem:smsverify;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1" \
  --sms.engine.python="$PYTHON" \
  --sms.engine.demo-dir="$ROOT/demo-pcaps" \
  --sms.engine.upload-dir="$WORK/uploads" \
  --sms.engine.ml-enabled=false \
  --logging.level.root=WARN > "$WORK/app.log" 2>&1) &
APP_PID=$!

for _ in $(seq 1 60); do
  curl -sf --max-time 2 "$BASE/api/health" >/dev/null 2>&1 && break
  sleep 0.5
done

health="$(curl -s --max-time 5 "$BASE/api/health" || true)"
if [[ "$health" == *'"status":"UP"'* ]]; then
  ok "application is up and can reach the analysis engine"
elif [[ "$health" == *'"status":"DEGRADED"'* ]]; then
  # The service is running; it just cannot run the engine. That is a different
  # problem from a failed boot and deserves a different message — the health
  # body already says exactly what is wrong and how to fix it.
  bad "the API started but cannot run the analysis engine"
  echo
  echo "$health" | "$PYTHON" -c 'import json,sys; h=json.load(sys.stdin); print("  error:", h.get("error")); print("  hint: ", (h.get("hint") or "").replace("\n", "\n         "))'
  exit 1
else
  bad "application did not start — see $WORK/app.log"
  tail -30 "$WORK/app.log"
  exit 1
fi

info "Uploading the demo captures"
for f in smtp.pcap pop-ssl.pcapng sample-imf.pcap.gz imap.cap smtp-ssl.pcapng synthetic-imaps-tls13.pcap; do
  src="$ROOT/demo-pcaps/$f"
  [[ -f "$src" ]] || { echo "  (skipping $f — not present)"; continue; }
  curl -s --max-time 120 -F "file=@$src" "$BASE/api/captures/sync" \
       -o "$WORK/$f.json" && ok "uploaded and analysed $f" || bad "upload failed: $f"
done

info "Checking the persisted results"
"$PYTHON" - "$WORK" "$BASE" <<'PY'
import json, os, sys, urllib.error, urllib.parse, urllib.request

work, base = sys.argv[1], sys.argv[2]
failures = []

def check(name, cond, detail=""):
    mark = "\033[32m✓\033[0m" if cond else "\033[31m✗\033[0m"
    print(f"  {mark} {name}" + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        failures.append(name)

def get(path):
    return json.load(urllib.request.urlopen(base + path))

def load(f):
    p = os.path.join(work, f + ".json")
    return json.load(open(p)) if os.path.exists(p) else None

# --- smtp.pcap: server offered STARTTLS, client ignored it, creds in clear ---
d = load("smtp.pcap")
if d:
    check("smtp.pcap completed", d["status"] == "COMPLETED", d.get("errorMessage"))
    check("smtp.pcap grades F", d["overallGrade"] == "F", d["overallGrade"])
    check("smtp.pcap reports exposed credentials",
          d["counts"]["credentialsExposed"] == 1)
    check("smtp.pcap hash recorded", len(d["sha256"]) == 64)
    det = get(f"/api/captures/{d['id']}")
    s = det["sessions"][0]
    check("smtp.pcap classified as MTA relay", s["role"] == "mta_relay", s["role"])
    check("smtp.pcap saw STARTTLS offered but unused",
          s["starttlsOffered"] is True and s["starttlsRequested"] is False)
    rules = {f["ruleId"] for f in get(
        f"/api/captures/{d['id']}/sessions/{s['id']}")["findings"]}
    check("SMS-STRIP-002 fired (offered but unused)", "SMS-STRIP-002" in rules, rules)
    check("SMS-AUTH-001 fired (cleartext credentials)", "SMS-AUTH-001" in rules, rules)

# --- pop-ssl.pcapng: clean STARTTLS upgrade, self-signed certificate ---------
d = load("pop-ssl.pcapng")
if d:
    check("pop-ssl.pcapng completed", d["status"] == "COMPLETED", d.get("errorMessage"))
    check("pop-ssl.pcapng grades C", d["overallGrade"] == "C", d["overallGrade"])
    det = get(f"/api/captures/{d['id']}")
    s = det["sessions"][0]
    check("pop-ssl negotiated TLS 1.2", s["tlsVersion"] == "1.2", s["tlsVersion"])
    check("pop-ssl capped by the self-signed rule",
          s["cappedBy"] == "SMS-CERT-003", s["cappedBy"])
    # The defining property: valid when captured in 2015, expired since.
    check("certificate NOT reported as expired at capture time",
          s["certExpiredAtCapture"] is False, s["certExpiredAtCapture"])
    raw = get(f"/api/captures/{d['id']}/report.json")
    ids = {f["rule_id"] for sess in raw["sessions"] for f in sess["findings"]}
    check("no false expiry finding (SMS-CERT-001 absent)", "SMS-CERT-001" not in ids)

# --- sample-imf.pcap.gz: gzip, submission port, cleartext auth ---------------
d = load("sample-imf.pcap.gz")
if d:
    check("gzip capture read transparently", d["format"] == "pcap.gz", d["format"])
    check("sample-imf grades F", d["overallGrade"] == "F", d["overallGrade"])
    det = get(f"/api/captures/{d['id']}")
    check("port 587 graded as submission",
          det["sessions"][0]["role"] == "submission_access")

# --- imap.cap: two DCE/RPC streams share the file and must be excluded -------
d = load("imap.cap")
if d:
    check("imap.cap completed", d["status"] == "COMPLETED", d.get("errorMessage"))
    check("non-email streams excluded (1 session, not 3)",
          d["counts"]["sessions"] == 1, d["counts"]["sessions"])
    raw = get(f"/api/captures/{d['id']}/report.json")
    ids = {f["rule_id"] for sess in raw["sessions"] for f in sess["findings"]}
    check("LITERAL+ not misread as a stripped keyword",
          "SMS-STRIP-001" not in ids, ids)

# --- synthetic-imaps-tls13.pcap: the good end of the scale -------------------
d = load("synthetic-imaps-tls13.pcap")
if d:
    check("TLS 1.3 capture completed", d["status"] == "COMPLETED", d.get("errorMessage"))
    check("a well-configured session earns A+", d["overallGrade"] == "A+", d["overallGrade"])
    det = get(f"/api/captures/{d['id']}")
    s = det["sessions"][0]
    check("TLS 1.3 negotiated", s["tlsVersion"] == "1.3", s["tlsVersion"])
    # The regression this file exists for: with the ServerHello key_share
    # extension unparsed, the key exchange scored 0 and this graded F.
    check("TLS 1.3 key exchange strength was read",
          s["rawScore"] == 97.0, s.get("rawScore"))
    check("nothing at medium or worse", d["counts"]["critical"] == 0
          and d["counts"]["high"] == 0 and d["counts"]["medium"] == 0, d["counts"])

# --- exports: HTML and PDF are real downloads, not instructions --------------
d = load("pop-ssl.pcapng")
if d:
    html = urllib.request.urlopen(base + f"/api/captures/{d['id']}/report.html")
    body = html.read().decode("utf-8", "replace")
    check("report.html serves HTML",
          html.headers.get_content_type() == "text/html", html.headers.get_content_type())
    check("report.html is the self-contained report",
          body.lstrip().startswith("<!DOCTYPE html>") and "</html>" in body)
    check("report.html is about this evidence", d["sha256"] in body)
    check("report.html leaks no password",
          "punjab@123" not in body and "cHVuamFiQDEyMw==" not in body)

    # "Save as PDF" is this same report opened with ?print=1, printed by the
    # browser. There is no server-side PDF endpoint to fail.
    printable = urllib.request.urlopen(
        base + f"/api/captures/{d['id']}/report.html?print=1")
    ptext = printable.read().decode("utf-8", "replace")
    check("the printable report serves HTML",
          printable.headers.get_content_type() == "text/html")
    check("the printable report carries the print hook", "window.print()" in ptext)
    check("and the page-break rules it prints with", "@page" in ptext)

    # The removed endpoint must be gone, not merely broken.
    try:
        urllib.request.urlopen(base + f"/api/captures/{d['id']}/report.pdf")
        check("the server-side PDF endpoint is gone", False, "it still answers")
    except urllib.error.HTTPError as e:
        check("the server-side PDF endpoint is gone", e.code == 404, e.code)

# --- static routing: the SPA fallback must not swallow real files -----------
# A view-controller fallback used to forward every dotless path to index.html,
# so /samples/smtp.json came back as HTTP 200 + HTML and the dashboard reported
# "Unexpected token '<'". A missing file has to 404 honestly.
try:
    r = urllib.request.urlopen(base + "/samples/definitely-not-here.json")
    body = r.read(200).decode("utf-8", "replace")
    check("a missing .json 404s instead of returning index.html",
          False, f"HTTP {r.status}: {body[:80]!r}")
except urllib.error.HTTPError as e:
    check("a missing .json 404s instead of returning index.html", e.code == 404, e.code)

# A real application route must still reach the SPA when one is bundled.
try:
    r = urllib.request.urlopen(base + "/report/sample")
    ctype = r.headers.get_content_type()
    check("an app route reaches the dashboard", ctype == "text/html", ctype)
except urllib.error.HTTPError as e:
    check("an app route reaches the dashboard (no frontend bundled — skipped)",
          e.code == 404, e.code)

# --- the bundled captures go through the same pipeline as an upload ----------
# The dashboard used to render pre-generated JSON for these. Now it asks the
# backend to analyse them, so a demo exercises the production path.
demos = get("/api/demo-captures")
names = [d["name"] for d in demos]
grades = [d["grade"] for d in demos]

check("the API offers exactly five bundled captures", len(demos) == 5, names)
# Two failures, two partial passes, one clean result. A demo that only ever
# shows failures gives a viewer no way to judge the grader.
check("the demo set spans the scale (2 F, 2 C, 1 A+)",
      sorted(grades) == ["A+", "C", "C", "F", "F"], grades)
check("worst first", grades == ["F", "F", "C", "C", "A+"], grades)
check("every demo carries a title and a note",
      all(d["title"] and d["note"] for d in demos), demos)

# The grade on each button is a claim about what the engine will do. Analyse
# every one of them and hold the claim to it — otherwise the buttons drift away
# from the analysis behind them and the demo starts lying.
for d in demos:
    req = urllib.request.Request(
        base + "/api/captures/demo/" + urllib.parse.quote(d["name"]), method="POST")
    got = json.load(urllib.request.urlopen(req))
    check(f"{d['name']} analyses and grades {d['grade']} as advertised",
          got["status"] == "COMPLETED" and got["overallGrade"] == d["grade"],
          f"{got.get('overallGrade')} / {got.get('errorMessage')}")
    check(f"{d['name']} is hashed like any other evidence", len(got["sha256"]) == 64)

# Same file, same bytes, so the same digest as the upload of it earlier.
uploaded = load("synthetic-imaps-tls13.pcap")
demo_a_plus = [d for d in demos if d["grade"] == "A+"]
if uploaded and demo_a_plus:
    req = urllib.request.Request(
        base + "/api/captures/demo/" + urllib.parse.quote(demo_a_plus[0]["name"]),
        method="POST")
    again = json.load(urllib.request.urlopen(req))
    check("demo and upload of the same file agree on the hash",
          again["sha256"] == uploaded["sha256"], (again["sha256"], uploaded["sha256"]))

# A name that escapes the demo directory must be refused.
try:
    urllib.request.urlopen(urllib.request.Request(
        base + "/api/captures/demo/..%2F..%2Fetc%2Fpasswd", method="POST"))
    check("path traversal in a demo name is refused", False, "it was accepted")
except urllib.error.HTTPError as e:
    check("path traversal in a demo name is refused", e.code in (400, 404), e.code)

# --- cross-cutting -----------------------------------------------------------
listing = get("/api/captures")
check("all captures persisted and listable", len(listing) >= 3, len(listing))

raw_any = None
for f in ("smtp.pcap", "pop-ssl.pcapng"):
    d = load(f)
    if d and d.get("id"):
        raw_any = get(f"/api/captures/{d['id']}/report.json")
        break
if raw_any:
    check("engine document round-trips intact",
          raw_any["schema_version"] and raw_any["capture"]["sha256"])
    body = json.dumps(raw_any)
    check("no plaintext password in stored report",
          "punjab@123" not in body and "cHVuamFiQDEyMw==" not in body)

print()
if failures:
    print(f"\033[31m{len(failures)} check(s) failed\033[0m")
    sys.exit(1)
print("\033[32mall checks passed\033[0m")
PY
rc=$?

info "Summary"
echo "  shell checks: $pass passed, $fail failed"
if [[ $rc -ne 0 || $fail -ne 0 ]]; then
  echo "  application log: $WORK/app.log"
  exit 1
fi
echo "  end-to-end verification passed"
