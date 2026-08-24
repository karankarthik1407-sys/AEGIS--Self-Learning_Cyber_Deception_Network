# AEGIS Evidence Gateway Guide

Version 0.7.0 · offline sensor normalization checkpoint · 20 August 2026

## Purpose

The Evidence Gateway is the first implemented boundary between external security
sensor records and the AEGIS resident telemetry spool. It is deliberately an
**offline, analyst-initiated importer**, not a live packet collector or a remote
sensor controller.

It currently accepts selected fields from:

- Suricata EVE JSON records; and
- Zeek JSON `conn.log` records.

The gateway previews every transformation before persistence. Committing an
import stores only normalized `TelemetryObservation` records. It does not create
an investigation case, assign an attacker label, train a model, trigger a decoy,
contact a sensor or transmit data outward.

## Why the airlock exists

Sensor logs may contain addresses, hostnames, domains, flow identifiers, paths,
packet content, file metadata and application data. Copying all of that into an
ML system would increase privacy, security and poisoning risk. AEGIS therefore
uses a three-stage airlock:

1. **Validate in memory.** Enforce connector, record-count, record-size,
   timestamp and field constraints.
2. **Minimize and pseudonymize.** Convert endpoints and sensitive linkage values
   to stable local HMAC references; bucket selected quantities; discard content.
3. **Preview and commit.** Show the safe output and rejection reasons, then
   require a separate explicit commit.

The per-install HMAC key never leaves the local data directory. A raw address is
also scanned for in the normalized output; any privacy-invariant failure rejects
the record.

## Connector contracts

### Suricata EVE JSON

Supported `event_type` values are `alert`, `anomaly`, `dns`, `flow`, `http`,
`ssh` and `tls`. The current adapter retains bounded timestamps, event type,
protocol/application identifiers, ports, selected alert/flow state and
pseudonymous endpoint, flow, domain and fingerprint references.

It discards packet/PCAP payload, HTTP paths/bodies/headers, file content, raw
domain/SNI values, raw addresses and arbitrary nested application data. Alert
category text is reduced to a pseudonymous category reference rather than copied
verbatim.

Suricata documents EVE as a JSON facility for alerts, anomalies, metadata,
file information and protocol records. The adapter implements a strict subset;
it does not claim complete EVE coverage or Suricata certification:
<https://docs.suricata.io/en/latest/output/eve/eve-json-format.html>

### Zeek `conn.log` JSON

The adapter retains timestamp, protocol/service, bounded ports, coarse duration,
byte buckets, connection state/history, local-direction flags and pseudonymous
endpoint/flow references. It discards raw addresses, raw UID/community ID,
hostnames, packet content and application content.

Zeek describes `conn.log` as its core connection log for TCP, UDP and ICMP flow
semantics, and documents JSON as a pipeline-friendly format:
<https://docs.zeek.org/en/current/reference/logs/conn.html> and
<https://docs.zeek.org/en/current/tutorial/logs.html>.

## Input format and limits

The UI accepts a JSON array or newline-delimited JSON. Comment lines beginning
with `#` are ignored only by the browser parser. The API requires:

- one to 256 JSON objects;
- no more than 64,000 canonical bytes per record; and
- a complete HTTP request below 1 MiB.

Traditional tab-separated Zeek logs are not accepted in v0.7. Export JSON first
or add a separately tested adapter. Unsupported Suricata event types are rejected
rather than partially copied.

## Safe-output examples

| Raw input | Persisted representation |
| --- | --- |
| `src_ip: 198.51.100.27` | `source_ref: source-<local HMAC prefix>` |
| `dest_ip: 192.0.2.40` | `destination_ref: destination-<local HMAC prefix>` |
| Suricata `flow_id` or Zeek `uid` | `flow_ref: flow-<local HMAC prefix>` |
| TLS SNI or DNS name | `domain_cluster_ref: domain-<local HMAC prefix>` |
| `orig_bytes: 821` | `origin_bytes_bucket: lt-1024` |
| packet payload or HTTP body | discarded |

The examples use RFC 5737 documentation ranges and never contact them.

## Provenance and deduplication

Every preview and commit reports:

- SHA-256 of the canonical input batch;
- connector contract and mode;
- accepted/rejected disposition per record;
- safe payloads only;
- received, accepted, rejected, inserted and deduplicated counts;
- explicit privacy assertions; and
- a manifest SHA-256 over the safe descriptor.

Committed normalized observations reuse the telemetry digest uniqueness
constraint. Re-importing the same records does not multiply observations. The
import ledger stores the safe report, not the original records.

## Use from the console

1. Open **Evidence Gateway**.
2. Select the exact connector contract.
3. Load the built-in documentation-range sample or choose a local JSON/JSONL
   file.
4. Run **privacy preview**.
5. Review all rejected records and retained references.
6. Commit only if the connector, authorization and minimization are correct.
7. Inspect the normalized observations in **Telemetry Nexus**.

The browser does not upload automatically when a file is selected. Commit stays
disabled until an accepted preview exists.

## Security and research limitations

- The Research Edition has no authenticated multi-user upload boundary.
- Connector correctness is fixture-tested, not certified by Suricata or Zeek.
- HMAC pseudonyms preserve local linkability and may still be sensitive.
- Input digests can support provenance but are not digital signatures or trusted
  timestamps.
- A compromised local host can tamper with the runtime, database or key.
- No malware sandbox, decompression or file-content parser is present.
- No automatic sensor-to-case promotion exists; a future governed promotion
  protocol needs separate authorization, label provenance and audit controls.
- Live tailing, message-bus ingestion and enterprise backpressure are deferred
  until authentication, transport security and deployment testing exist.

## Reproduce v0.7

```bash
python -m unittest tests.test_sensor_gateway -v
python -m unittest discover -s tests -v
```

The complete v0.7 suite contains 45 tests. The gateway tests cover minimization,
pseudonymization, content discard, limits, refusal, persistence, deduplication,
manifesting and the no-case-promotion invariant.
