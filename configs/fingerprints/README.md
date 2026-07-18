# MiBee Fingerprint Library

Language-agnostic, data-driven identification rules consumed by the scannerv2
`RuleClassifier`. The full format specification lives in
`docs/fingerprint-spec.md`; this README is the quick reference.

## Why data, not code

The identification rule library is the project's moat — its breadth and
accuracy are what make the scanner useful. Keeping rules as **data** (not Go
code) lowers the contribution barrier: a new device signature is one YAML
entry, not a new classifier struct + test. Any language (Go, Zig, Rust) can
load the same files via the adapter spec.

## File layout

| File | Covers | Replaces (code classifier) |
|---|---|---|
| `banner.yaml` | TCP banner greetings (SSH/HTTP/RTSP/FTP/SMTP/POP3/IMAP) | BannerClassifier, HTTPClassifier, MailClassifier |
| `http-tls.yaml` | kind-presence services (RTSP/ONVIF/Web/TLS/Prometheus) | RTSPClassifier, ONVIFClassifier, WebClassifier, TLSClassifier, PrometheusClassifier |
| `ports.yaml` | port-shape-only fallbacks (LDAP/SMB/DNS-TCP/…) | MiscClassifier |
| `snmp-data.yaml` | SNMP OID-prefix table + sysDescr keyword tables (data asset) | data tables of SNMPClassifier (bitmask heuristic stays in code) |

## License & provenance

**The fingerprint corpus is licensed under
[CC-BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).** Anyone is
free to use and adapt it, but derivative fingerprint corpora must be released
under the same (CC-BY-SA) license — the copyleft applies to the data itself,
separately from the AGPLv3 that covers the MiBee Steward source code.

Every rule carries a `source` field for attribution:

- `builtin` — authored for MiBee (CC-BY-SA 4.0 within this corpus).
- `recog` — converted from [Rapid7 Recog](https://github.com/rapid7/recog)
  (upstream Apache-2.0; redistributed here under CC-BY-SA, which Apache-2.0
  permits because CC-BY-SA is at least as restrictive for the resulting
  derivative work).
- `ieee-oui` — IEEE OUI assignment list (factual registry; cite IEEE).
- `iana-pen` — IANA Private Enterprise Numbers (factual registry; cite IANA).

**nmap-service-probes is NOT imported.** It is NPSL-licensed (GPL-derived +
OEM/redistribution restrictions, not OSI-free). nmap's match patterns may be
read for format-design reference only (clean-room); its data file is never
copied into this corpus.

## Two rule shapes

**1. Match/emit rules** (`banner.yaml`, `http-tls.yaml`, `ports.yaml`):
each rule matches evidence and emits a `ServiceIdentity`.

**2. Data tables** (`snmp-data.yaml`): lookup tables (OID prefix → brand+type,
keyword → type/os/brand) loaded by the logic-retained `SNMPClassifier`. The
bitmask + numeric-compare device-type heuristic cannot be expressed as a single
declarative rule, so it stays as Go code (see spec §"Logic plugins").
