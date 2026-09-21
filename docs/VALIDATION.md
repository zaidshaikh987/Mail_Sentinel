# Validation record

This records the checks performed for the investigation architecture update.

- Python engine suite: **157 tests passed** (149 existing plus 8 assessment/history/dataset tests).
- Java backend suite: **14 tests passed**, with no skips. Includes real-engine upload tests,
  investigation scoping, cancellation/retry lineage, interrupted-run recovery,
  persisted stage visibility, comparison wording, remediation persistence,
  output/progress separation and subprocess timeout/cancellation checks.
- React production build: passed.
- Packaged-app end-to-end script: passed using an isolated local server and database.
  It exercised bundled PCAP ingestion, expected grades, persisted analysis, exports,
  static routing, and credential redaction.
- Browser: created an investigation, selected its capture destination, launched samples
  asynchronously, observed the queued job page and completion navigation, inspected full
  session evidence/coverage/model explanations, compared captures and saved analyst status.
- `git diff --check`: passed.
- Lab Python syntax: valid. Docker Compose capture lab **not executed**, because the
  Docker daemon was unavailable. No new training accuracy or captured-corpus performance
  result is claimed.

Browser and packaged-application checks used an isolated H2 database and upload
directory, leaving the default application database unchanged.

These checks do not constitute a production security review, a benchmark on 2 GB files,
a distributed-worker test, or real-world validation of the historical anomaly thresholds.
The captured-dataset loader is tested, but a new four-class model has not been trained
from the supplied two-class seed lab.

## Presentation fixtures and clean Docker workspace

- Nine synthetic presentation captures have independently asserted grades, rule IDs,
  session counts and SHA-256 hashes; all nine fixture tests passed.
- Docker image builds explicitly skip Java tests and sample capture analysis.
- `compose.demo.yml` uses separate database/upload volumes; existing regular
  investigation data is preserved when switching to presentation mode.

## Multi-session comparison captures

- Added two matched snapshots, each with six IMAPS sessions across three servers.
  Verified server identities, chronological ordering, F-to-A+ overall improvement,
  certificate trust and disappearance of the earlier non-informational findings.
- Fixed SNI decoding so valid hostnames survive ClientHello parsing; malformed
  names no longer discard the remaining handshake metadata.
- Full Python suite after this change: **172 tests passed**.
