# Captured-traffic validation lab

This is a seed corpus generator using actual Postfix and Dovecot TCP/TLS sessions,
not randomly generated feature vectors. The disposable container has **no network
interface except loopback**, no published ports, no real mail and no real credentials.
The app itself remains entirely passive. Image construction needs package downloads.

From this directory, run `docker compose build` then `docker compose run --rm capture-lab`.
This creates 27 captures: SMTP/IMAP/POP3 × cleartext/TLS 1.2/TLS 1.3 × 3 batches,
8 sessions each, plus a configuration-labelled manifest and tcpdump diagnostics.
TLS fixtures deliberately use a self-signed certificate, so encrypted profiles are
labelled **weak**, including TLS 1.3 where the certificate is not visible to the parser.
The isolated fixture client alone accepts that certificate; this does not change app validation.

From the project root:

```
.venv/bin/python -m mailsentinel.ml.captured_dataset lab/output/manifest.json lab/output/dataset.jsonl
.venv/bin/python -m mailsentinel.ml.train --dataset lab/output/dataset.jsonl --artifacts lab/output/candidate
```

The second command intentionally **refuses this starter dataset**: it contains only
critical and weak classes. Extend the manifest with independently configured secure
and vulnerable profiles, and diversify servers, clients, ciphers and certificates
before training a four-class candidate. Use configuration IDs shared by all captures
of a configuration, not a new ID per packet/session/batch. Reused capture hashes across
groups are rejected. Labels must be independently justified in `ground_truth`.

An externally captured PCAP can be added by supplying `path`, `configuration_id`,
`label` (critical/vulnerable/weak/secure), and `ground_truth`. Do not label from the
engine's findings. Use a separate held-out server family for final validation.

Training writes grouped cross-validation metrics and a rules-only baseline to the
candidate directory. It does not overwrite the application model. Inspect critical
false negatives and the certificate-masked slice before manually promoting a model.
The starter lab and grouped CV do not establish production accuracy.

To exercise historical baselines, upload batches 0, 1 and 2 into one investigation in
chronological order. The third TLS batch can use the earlier two as its baseline;
cleartext sessions without a hostname remain provisional endpoint observations.
