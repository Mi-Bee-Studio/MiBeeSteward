# MiBee Fingerprint Library — Adapter Specification

**Version:** 1 · **Status:** Stable · **License:** Apache-2.0 (corpus) + factual registries (IEEE/IANA, cited)

This document is the normative specification for the MiBee fingerprint library:
a language-agnostic, data-driven identification rule format. Any runtime (Go,
Zig, Rust, …) that loads these rule files and implements the contract below
produces identical classification output.

## 1. Why a spec

The identification rule library is the project's core value. Keeping it as
**data** (not code) means a new device signature is one YAML entry, not a new
classifier struct. The spec exists so that:

- Contributions stay low-friction (a rule is data, reviewable in a PR diff).
- Any language can consume the same corpus without re-implementing heuristics.
- Confidence and matching semantics are identical across implementations.

## 2. The contract: Evidence → ServiceIdentity

A fingerprint rule consumes `Evidence` and emits `ServiceIdentity`. Both are
plain JSON structures (defined in `internal/service/scannerv2/evidence.go`):

### Evidence (input)

```json
{
  "source": "active:tcp",
  "kind": "banner",
  "ip": "192.168.1.5",
  "port": 22,
  "protocol": "tcp",
  "raw_data": { "banner": "SSH-2.0-OpenSSH_9.0" },
  "confidence": 0.9,
  "observed_at": "2026-07-09T12:00:00Z"
}
```

| Field | Type | Meaning |
|---|---|---|
| `source` | string | probe that produced this (e.g. `active:snmp`, `passive:ebpf:tc`) |
| `kind` | string | evidence shape: `port_open`, `banner`, `snmp`, `http`, `tls`, `rtsp_banner`, `onvif_response`, `metric`, `echo` |
| `ip` | string | target host |
| `port` | int | L4 port (0 when N/A, e.g. ICMP) |
| `protocol` | string | `tcp` / `udp` / `` (icmp) |
| `raw_data` | map<string,string> | protocol-specific payload (banner text, SNMP varbinds, headers, …) |
| `confidence` | float | this evidence's standalone reliability, ∈ [0,1] |
| `observed_at` | timestamp | when gathered |

### ServiceIdentity (output)

```json
{
  "service": "ssh",
  "port": 22,
  "protocol": "tcp",
  "confidence": 0.995,
  "evidence": [ /* the Evidence pieces that backed this */ ],
  "metadata": { "banner": "SSH-2.0-OpenSSH_9.0", "version": "OpenSSH_9.0" }
}
```

A classifier receives the full evidence set for one host and emits zero or more
identities. **Classifiers must be pure**: same evidence → same identities, no
side effects, no I/O.

## 3. Rule file format

A rule file is YAML with `version: 1` and a `rules:` list. Each rule has:

```yaml
- id: banner-ssh              # unique, stable identifier
  source: builtin             # provenance: builtin|recog|ieee-oui|iana-pen
  match: { ... }              # when to fire (see §4)
  service: ssh                # ServiceIdentity.service to emit
  protocol: tcp               # ServiceIdentity.protocol
  confidence: 0.95            # base confidence (fused at runtime, see §5)
  literal_confidence: false   # if true, confidence is NOT fused (port fallbacks)
  priority: 10                # higher = evaluated first (default 0)
  exclusive_group: ssh        # rules sharing a group: only highest-priority match fires per evidence
  extract: { ... }            # metadata derivation (see §6)
```

### SNMP data tables (separate shape)

`snmp-data.yaml` uses a different top-level shape (lookup tables, not
match/emit rules) — see §7. It is consumed by the logic-retained
`SNMPClassifier`, not the rule evaluator.

## 4. Match operations (`match:`)

A `match` node has an `op` (operation). Leaf ops test one field; composite ops
combine sub-matches.

### Leaf ops

| op | fields | semantics |
|---|---|---|
| `kind_presence` | `kind` | fires if any evidence has `Kind == kind` |
| `port` | `value` (int) | **host-scoped**: fires once per host if port N is open (attaches `idx.byPort[N]`, literal confidence) |
| `port_eq` | `value` (int) | fires if `evidence.port == N` (used as a disambiguating AND-condition) |
| `prefix` | `field`, `value` (str\|str[]) | `field` starts with value (case-sensitive) |
| `prefix_ci` | `field`, `value` (str\|str[]) | `field` starts with any value (case-insensitive) |
| `contains` | `field`, `value`, `ci` | `field` contains value |
| `contains_any` | `field`, `value` (str[]), `ci` | `field` contains any of values |
| `equals` | `field`, `value`, `ci` | `field` equals value |
| `regex` | `field`, `value` | `field` matches the regexp |

`field` defaults to `"banner"`. `trim: true` trims the field value before
testing (mail rules trim the banner; banner rules do not).

### Composite ops

| op | field | semantics |
|---|---|---|
| `compound` | `and: [match…]` | ALL sub-matches must be true |
| `or` | `any: [match…]` | ANY sub-match must be true |

Composites nest arbitrarily: `compound` can contain `or`, which can contain
`port_eq`, etc. Example (POP3: `+OK` prefix AND (`pop3` contains OR port==110)):

```yaml
match:
  kind: banner
  field: banner
  trim: true
  op: compound
  and:
    - { op: prefix, value: "+OK" }
    - op: or
      any:
        - { op: contains, value: "pop3", ci: true }
        - { op: port_eq, value: 110 }
```

### Evaluation modes

- **Per-evidence rules** (all ops except `port`): the rule is tested against
  each evidence piece and fires once per match, attaching `[e]`.
- **Host-scoped rules** (`op: port`): fire once per host when the port is open,
  attaching `idx.byPort[port]` with literal confidence (no fusion). Mirrors a
  port→service lookup table.

### `exclusive_group`

Rules sharing an `exclusive_group` use first-match-wins semantics: once the
highest-priority rule in a group fires on an evidence piece, lower-priority
siblings in that group are suppressed for that evidence. This mirrors a Go
`switch` (e.g. Prometheus: `node_exporter` before `prometheus_`).

## 5. Confidence model

Two flavors coexist. Implementations MUST compute these identically or
cross-language results diverge.

### Fused (default)

`confidence = 1 - Π(1 - c_i)` over `{evidence.confidence, rule.confidence}`.
Independent evidence reinforces: a single 0.9 source stays 0.9; two 0.9 sources
yield ~0.99.

```
fused = 1 - (1 - evidence.conf) * (1 - rule.conf)
```

Example: evidence confidence 0.9, rule base 0.95 → `1 - 0.1*0.05 = 0.995`.

### Literal (`literal_confidence: true`)

The rule's `confidence` is used verbatim — no fusion. Used by port-shape-only
fallbacks (e.g. `0.5`) where there's no meaningful evidence confidence to fuse.

## 6. Extract operations (`extract:`)

After a rule matches, `extract` builds the `metadata` map.

### `metadata_all: true`

Passthrough every `raw_data` key into metadata (WebClassifier / TLSClassifier
copy all headers/cert fields).

### Per-key extractors

Each `metadata:` key maps to one extractor:

| extractor | example | semantics |
|---|---|---|
| `const` | `{ const: "node_exporter" }` | fixed string |
| `passthrough` | `{ passthrough: server }` | copy `raw_data[server]` |
| `split` | `{ split: { delim: "-", index: 2 } }` | `SplitN(banner, delim, index+1)[index]` — SSH version |
| `substring_after` | `{ substring_after: { field: server, delim: "/", until: [" ", "("] } }` | after first `delim`, until first char in `until` — HTTP server version |
| `keyword_map` | see below | ordered CI-contains → enum (brand/OS tables) |
| `when_equals` | `{ when_equals: { field: auth_required, value: "true", set: "true" } }` | set value iff `raw_data[field] == value` |

### `keyword_map` (ordered contains → enum)

```yaml
inferred_brand:
  keyword_map:
    field: subject_cn
    ci: true
    entries:
      - { contains_any: ["hikvision", "hik"], set: "Hikvision" }
      - { contains: "dahua", set: "Dahua" }
      # first match wins; empty result if none match
```

## 7. Logic plugins (NOT expressible as rules)

Some identification logic cannot be a single declarative rule. These stay as
code in each runtime (Go now; optional for Zig/Rust). The spec documents their
input/output contract so implementations are interoperable.

### SNMP device-type heuristic (`SNMPClassifier` stage 3)

**Input:** `sys_services` (bitmask), `sys_descr` (string), `sys_object_id`
(OID), `if_number` (int).

**Logic** (4-stage cascade, first non-empty wins):
1. OID prefix → type (data table: `snmp-data.yaml` `oid_prefixes`)
2. sysDescr keyword → type (data table: `sysdescr_types`)
3. **bitmask + numeric** (THIS is the logic plugin):
   - `hasL2 = sys_services & 1`, `hasL3 = sys_services & 2`, `ifNum = int(if_number)`
   - `hasL3 && !hasL2 && ifNum <= 2` → router
   - `hasL2 && hasL3 && ifNum > 4` → switch
   - `hasL2 && hasL3` → router
   - `hasL2 && !hasL3 && ifNum > 4` → switch
   - `sys_services >= 72` → server
4. none → ""

**Why not a rule:** requires bitmask bit-tests, integer parsing, numeric
comparisons (`>`, `<=`, `>=`), and ordered multi-condition fallthrough. A DSL
for this would raise the contribution barrier; keeping it as a small, well-tested
function preserves the "rules are easy data" property.

### Camera cross-evidence fusion (`CameraClassifier`)

**Input:** all `rtsp_banner` + `onvif_response` evidence for a host.

**Logic:** if either is present, emit one host-level `camera` identity. Port =
first RTSP port, else first ONVIF port. Confidence = `fuseConfidence` over ALL
rtsp+onvif evidence confidences (variable-arity). Brand from RTSP `server`
header, falling back to ONVIF `server` (priority-ordered cross-evidence field
selection).

**Why not a rule:** aggregates multiple evidence pieces into one identity with
variable-arity fusion and cross-source field selection — inherently multi-evidence.

## 8. Provenance & license

Every rule carries a `source` field for attribution:

| source | origin | license | importable? |
|---|---|---|---|
| `builtin` | authored for MiBee | Apache-2.0 | yes (project's own) |
| `recog` | Rapid7 Recog | Apache-2.0 | yes — convert via `fpimport recog` |
| `ieee-oui` | IEEE OUI registry | factual registry | yes — cite IEEE |
| `iana-pen` | IANA Private Enterprise Numbers | factual registry | yes — cite IANA |

### nmap-service-probes: NOT imported

nmap's `nmap-service-probes` is **NPSL**-licensed (GPL-derived + OEM/
redistribution restrictions; not OSI-free). Its match patterns may be read for
**format-design reference only** (clean-room). Its data file is never copied
into this corpus. The corpus stays Apache-clean.

### Data vs code distinction

Importing a *database* of facts (MAC→vendor, OID→vendor) does not force the
importing project to the source's license when the data is factual (not a
creative expression). IEEE OUI and IANA PEN are factual registries. Recog's
regex fingerprints are a creative expression → Apache-2.0 attribution is
retained on every converted rule (`source: recog`).

## 9. Reference implementation

The Go `RuleClassifier` (`internal/service/scannerv2/classify/rule_classifier.go`)
is the reference. A Zig/Rust implementation is considered conforming iff, given
the same rule files and evidence, it emits byte-identical `ServiceIdentity`
output (service, port, protocol, confidence within 1e-9, metadata). The parity
tests in `rule_classifier_test.go` are the conformance suite.
