# Presentation captures

This pack contains **eleven synthetic PCAPs**: nine single-session scenarios and
a matched before/after pair with six sessions per capture. Upload them manually
from this folder; generating or building them does not create investigation records.
Their filenames describe the scenario, and `manifest.json` records verified grades,
evidence hashes and expected findings.

| Grade | Capture scenario |
|---|---|
| A+ | Normal TLS 1.3 IMAPS; normal TLS 1.2 with a trusted public certificate |
| A | Strong encryption, but certificate renewal due in ten days |
| B | TLS 1.2 using AES-128-CBC; TLS 1.2 using AES-256-CBC |
| C | Self-signed certificate; deprecated TLS 1.0 |
| F | STARTTLS stripping simulation with dummy credentials; expired certificate |

**D and E:** the current scoring implementation lists these bands, but the
combination of component scores and security caps does not produce them for
meaningful complete sessions. Cleartext sessions already score zero (F), even
where a rule's ceiling is D. No finding currently imposes E. These fixtures do not
alter grading rules or fake results to fill those bands.

**Suggested order:** normal TLS 1.2 → CBC → self-signed → STARTTLS stripping.
Show the session evidence and remediation, then export HTML/PDF. Use TLS 1.3 to
explain that a strong observed negotiation does not prove certificate validity:
the certificate is encrypted and unavailable to the passive analyser.

## Synthetic evidence boundaries

Traffic uses documentation IP ranges and dummy credentials. Negotiations are
constructed packets, not recordings of completed live TLS connections; signatures
and ciphertext are placeholders. The stripping fixture simulates the suspicious
`XXXXXXXX` capability replacement. Detection is an indicator, not proof of an
attack on an actual system.

The TLS 1.2 fixtures embed a frozen **public** example.com certificate chain and
use its hostname for validation. They do not claim example.com runs these email
services or has these weaknesses. No private key is included. Packet dates are
chosen around certificate validity so expiry demonstrations stay stable over time.
Trust-store changes can still affect chain validation.

## Regenerate and verify

From the repository root after installing the engine:

```bash
.venv/bin/python scripts/make_judge_captures.py
```

The generator verifies the nine individual grades and key findings using the real engine.
It runs offline using the included public chain. It never contacts the API or
writes to the application database. ML predictions are advisory and are not used
to select grades.

## Start with clean investigation history

```bash
docker compose -f docker-compose.yml -f compose.demo.yml up -d --build
```

This switches the application to separate presentation database/upload volumes.
On their first use the investigation history is empty. Your existing regular
volumes remain intact. Subsequent presentation starts retain presentation uploads;
rebuilding an image intentionally does not erase evidence.

Return to your regular data with `docker compose up -d`. Do not use `down -v` to
switch profiles: that deletes volumes. Docker builds skip Java tests and sample
analysis; tests use isolated databases when run explicitly.

## Before and after: multi-session remediation demo

Upload these two files into the **same investigation**, before first:

1. **Before - Weak mail servers - 6 sessions.pcap** — overall F.
2. **After - Remediated mail servers - 6 sessions.pcap** — overall A+.

Both contain the same three IMAPS server identities (port 993, SNI `example.com`),
with two client sessions per server. The after snapshot is dated one day later.
These are distinct observations of the same environment, not an edited historical
capture. The addresses and negotiations are synthetic, as described above.

| Server | Before (two sessions) | After (two sessions) |
|---|---|---|
| `203.0.113.40` | B: TLS 1.2 with CBC | A+: TLS 1.2 with AEAD |
| `203.0.113.41` | C: deprecated TLS 1.0 | A+: TLS 1.2 with AEAD |
| `203.0.113.42` | F: expired self-signed certificate | A+: valid publicly trusted certificate |

Open the investigation, select the two runs under **Compare captures**, and show
how the matched servers' TLS, cipher and certificate observations change. Earlier
weaknesses should be **not observed in the later capture**; the UI intentionally
does not treat absence alone as verified remediation. This two-capture demo does
not supply enough prior evidence to establish an historical ML baseline.

Regenerate the pair without changing the other captures:

```bash
.venv/bin/python scripts/make_comparison_captures.py
```
