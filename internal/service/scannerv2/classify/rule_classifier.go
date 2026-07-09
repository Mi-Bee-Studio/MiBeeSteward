// Package classify — data-driven rule classifier.
//
// RuleClassifier loads identification rules from YAML files (see
// configs/fingerprints/*.yaml + docs/fingerprint-spec.md) and evaluates them
// against Evidence, emitting ServiceIdentities exactly as the hand-written
// classifiers did. The goal is behavioral parity: a rule set authored to
// mirror an existing classifier produces byte-identical ServiceIdentity output
// (service, port, protocol, confidence, metadata).
//
// This is the "data" half of the fingerprint library. Logic that cannot be
// expressed as declarative rules (SNMP bitmask+numeric device-type heuristic,
// CameraClassifier cross-evidence fusion) stays as Go code — see
// docs/fingerprint-spec.md §"Logic plugins".
//
// Loading mirrors vendor/oui.go: a missing directory is silent degradation
// (empty rule set, never blocks engine startup); a malformed file is a hard
// error (the engine should not start with corrupt fingerprints).

package classify

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"mibee-steward/internal/service/scannerv2"
)

// ── YAML schema ──────────────────────────────────────────────────────────

// ruleFile is one YAML fingerprint file. `version` gates format evolution.
type ruleFile struct {
	Version int      `yaml:"version"`
	Rules   []rule   `yaml:"rules"`
	// SNMP data-table fields (only snmp-data.yaml uses these; rule files leave
	// them nil). Loaded by SNMPClassifier via LoadSNMPTables, not by the rule
	// evaluator.
	OIDPrefixes    []oidPrefixEntry  `yaml:"oid_prefixes"`
	SysDescrTypes  []sysDescrKwEntry `yaml:"sysdescr_types"`
	SysDescrBrands []sysDescrKwEntry `yaml:"sysdescr_brands"`
	SysDescrOS     []sysDescrKwEntry `yaml:"sysdescr_os"`
}

type rule struct {
	ID             string      `yaml:"id"`
	Source         string      `yaml:"source"`
	Match          matchSpec   `yaml:"match"`
	Service        string      `yaml:"service"`
	Protocol       string      `yaml:"protocol"`
	Confidence     float64     `yaml:"confidence"`
	LiteralConf    bool        `yaml:"literal_confidence"`
	Priority       int         `yaml:"priority"`
	ExclusiveGroup string      `yaml:"exclusive_group"` // rules sharing a group: only the highest-priority match fires per evidence piece (switch first-match)
	Extract        extractSpec `yaml:"extract"`
}

// matchSpec is a recursive matcher. Exactly one of the leaf fields (or
// `compound`/`or` for composites) is set per node.
type matchSpec struct {
	Kind      string     `yaml:"kind"`      // evidence Kind to scope to (advisory; op may ignore)
	Field     string     `yaml:"field"`     // RawData key to test (default "banner")
	Op        string     `yaml:"op"`        // prefix_ci|prefix|contains|contains_any|equals|regex|kind_presence|port|port_eq|compound|or
	Value     any        `yaml:"value"`     // string | []string | int (port)
	CI        bool       `yaml:"ci"`        // case-insensitive (for contains/equals)
	Trim      bool       `yaml:"trim"`      // trim the field value before testing (mail rules)
	Transform string     `yaml:"transform"` // strip_ssh_prefix|strip_resp_code — transform field before matching
	And       []matchSpec `yaml:"and"`      // compound: ALL must match
	Any       []matchSpec `yaml:"any"`      // or: ANY must match
}

type extractSpec struct {
	MetadataAll bool                  `yaml:"metadata_all"`
	Metadata    map[string]extractor  `yaml:"metadata"`
}

// extractor: exactly one variant set. `const` emits a fixed string;
// `passthrough` copies RawData[field]; `split`/`substring_after`/`keyword_map`
// /`when_equals` derive a value.
type extractor struct {
	Const         string           `yaml:"const"`
	Passthrough   string           `yaml:"passthrough"`
	Split         *splitExtract    `yaml:"split"`
	SubstringAfter *substringExtract `yaml:"substring_after"`
	KeywordMap    *keywordMap      `yaml:"keyword_map"`
	WhenEquals    *whenEquals      `yaml:"when_equals"`
}

type splitExtract struct {
	Delim string `yaml:"delim"`
	Index int    `yaml:"index"`
}

type substringExtract struct {
	Field string   `yaml:"field"`
	Delim string   `yaml:"delim"`
	Until []string `yaml:"until"`
}

type keywordMap struct {
	Field   string         `yaml:"field"`
	CI      bool           `yaml:"ci"`
	Entries []keywordEntry `yaml:"entries"`
}

type keywordEntry struct {
	Contains   string   `yaml:"contains"`
	ContainsAny []string `yaml:"contains_any"`
	Set        string   `yaml:"set"`
}

type whenEquals struct {
	Field string `yaml:"field"`
	Value string `yaml:"value"`
	Set   string `yaml:"set"`
}

// SNMP data-table entry types (snmp-data.yaml).
type oidPrefixEntry struct {
	Prefix string `yaml:"prefix"`
	Brand  string `yaml:"brand"`
	Type   string `yaml:"type"`
}

type sysDescrKwEntry struct {
	Keywords []string `yaml:"keywords"`
	Keyword  string   `yaml:"keyword"`
	Type     string   `yaml:"type"`
	Brand    string   `yaml:"brand"`
	OS       string   `yaml:"os"`
}

// ── Compiled forms ───────────────────────────────────────────────────────

// compiledRule is a rule with its matchSpec turned into a matcher closure.
type compiledRule struct {
	id         string
	service    string
	protocol   string
	conf       float64
	literal    bool
	priority   int
	group      string // exclusive_group: only the highest-priority matching rule fires per evidence
	hostScoped bool   // op:port — fires once per host (not per evidence), attaches idx.byPort[port]
	port       int    // the port this host-scoped rule asserts (0 for per-evidence rules)
	matcher    matcher
	extract    extractSpec
}

// matcher tests one evidence piece + the host's evidence index. Returns true
// if the rule fires on this evidence. The index is needed for port_eq (cross-
// evidence port lookups) and compound/ or combinators that may reference it.
type matcher func(e scannerv2.Evidence, idx evidenceIndex) bool

// ── RuleClassifier ───────────────────────────────────────────────────────

// RuleClassifier is a data-driven ServiceClassifier. LoadFromDir populates it
// from a directory of YAML files; an empty/unloaded classifier emits nothing.
type RuleClassifier struct {
	rules []compiledRule
	loaded bool
}

// Service returns the nominal classifier name. Rules emit diverse service
// names (ssh, http, …); this name is only for registry enumeration.
func (r *RuleClassifier) Service() string { return "rule-based" }

// Loaded reports whether a non-empty rule set is in memory.
func (r *RuleClassifier) Loaded() bool { return r != nil && r.loaded }

// RuleCount returns the number of compiled rules (for startup logging).
func (r *RuleClassifier) RuleCount() int {
	if r == nil {
		return 0
	}
	return len(r.rules)
}

// Classify evaluates all rules against the host evidence set. Two evaluation
// modes coexist:
//   - Per-evidence rules (banner/rtsp/onvif/web/tls/metric): fire once per
//     matching evidence piece, attaching [e] and fusing e.Confidence.
//   - Host-scoped rules (op:port): fire once per HOST when the port is open,
//     attaching idx.byPort[port] with a literal confidence (no fusion). This
//     mirrors MiscClassifier, which iterates a port table and emits one identity
//     per open port with all that port's evidence attached.
//
// Within an exclusive_group, only the highest-priority matching rule fires per
// evidence piece (mirrors a Go `switch` first-match-wins). Rules are pre-sorted
// by descending priority.
func (r *RuleClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	if r == nil || len(r.rules) == 0 {
		return nil
	}
	idx := indexEvidence(ev)
	var out []scannerv2.ServiceIdentity

	// Host-scoped rules: one emit per host when the port is open. Mirrors
	// MiscClassifier's port-table iteration. Confidence is literal (0.5) and
	// evidence is idx.byPort[port] (all evidence for that port).
	for _, rl := range r.rules {
		if !rl.hostScoped {
			continue
		}
		if !portHasOpen(idx, rl.port) {
			continue
		}
		out = append(out, scannerv2.ServiceIdentity{
			Service:    rl.service,
			Port:       rl.port,
			Protocol:   rl.protocol,
			Confidence: rl.conf, // literal — port-shape only, no evidence to fuse
			Evidence:   idx.byPort[rl.port],
		})
	}

	// Per-evidence rules: fire once per matching evidence piece.
	for _, e := range ev {
		// Track which exclusive groups already fired on this evidence piece so
		// lower-priority siblings skip. Empty-group rules are always independent.
		firedGroups := map[string]bool{}
		for _, rl := range r.rules {
			if rl.hostScoped {
				continue
			}
			if rl.group != "" && firedGroups[rl.group] {
				continue
			}
			if !rl.matcher(e, idx) {
				continue
			}
			conf := rl.conf
			if !rl.literal {
				conf = fuseConfidence(e.Confidence, rl.conf)
			}
			md := applyExtract(rl.extract, e)
			out = append(out, scannerv2.ServiceIdentity{
				Service:    rl.service,
				Port:       e.Port,
				Protocol:   rl.protocol,
				Confidence: conf,
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   md,
			})
			if rl.group != "" {
				firedGroups[rl.group] = true
			}
		}
	}
	return out
}

// LoadFromDir reads all *.yaml files in dir, compiles their rules, and stores
// them sorted by descending priority (stable on id for ties). A missing
// directory is silent: returns nil with loaded=false (the classifier becomes a
// no-op, mirroring vendor/oui.go). A present-but-malformed file is a hard error.
func (r *RuleClassifier) LoadFromDir(dir string) error {
	if r == nil {
		return nil
	}
	r.rules = nil
	r.loaded = false
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // silent degradation
		}
		return err
	}
	var loaded []compiledRule
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, ent.Name())
		var rf ruleFile
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("fingerprint %s: %w", ent.Name(), err)
		}
		if err := yaml.Unmarshal(b, &rf); err != nil {
			return fmt.Errorf("fingerprint %s: %w", ent.Name(), err)
		}
		if rf.Version != 1 {
			return fmt.Errorf("fingerprint %s: unsupported version %d", ent.Name(), rf.Version)
		}
		for _, rl := range rf.Rules {
			m, hostScoped, port, err := compileMatch(rl.Match)
			if err != nil {
				return fmt.Errorf("fingerprint %s rule %q: %w", ent.Name(), rl.ID, err)
			}
			loaded = append(loaded, compiledRule{
				id: rl.ID, service: rl.Service, protocol: rl.Protocol,
				conf: rl.Confidence, literal: rl.LiteralConf, priority: rl.Priority,
				group: rl.ExclusiveGroup, hostScoped: hostScoped, port: port,
				matcher: m, extract: rl.Extract,
			})
		}
	}
	// Descending priority, stable on id for deterministic ties. Higher-priority
	// rules evaluate first so first-match-wins ordering (Prometheus
	// node_exporter before prometheus_) is respected.
	sort.SliceStable(loaded, func(i, j int) bool {
		if loaded[i].priority != loaded[j].priority {
			return loaded[i].priority > loaded[j].priority
		}
		return loaded[i].id < loaded[j].id
	})
	r.rules = loaded
	r.loaded = len(loaded) > 0
	return nil
}

// ── matcher compilation ──────────────────────────────────────────────────

func compileMatch(s matchSpec) (matcher, bool, int, error) {
	switch s.Op {
	case "kind_presence":
		kind := s.Kind
		return func(e scannerv2.Evidence, _ evidenceIndex) bool { return e.Kind == kind }, false, 0, nil
	case "port":
		// Host-scoped: fires once per host (not per evidence piece). The caller
		// (Classify) attaches idx.byPort[port] and uses `port` as the identity
		// port. The matcher itself is a no-op placeholder — host-scoped rules
		// are handled outside the per-evidence loop.
		port, err := toInt(s.Value)
		if err != nil {
			return nil, false, 0, fmt.Errorf("port value: %w", err)
		}
		return func(_ scannerv2.Evidence, _ evidenceIndex) bool { return true }, true, port, nil
	case "port_eq":
		port, err := toInt(s.Value)
		if err != nil {
			return nil, false, 0, fmt.Errorf("port_eq value: %w", err)
		}
		return func(e scannerv2.Evidence, _ evidenceIndex) bool { return e.Port == port }, false, 0, nil
	case "prefix", "prefix_ci":
		vals := toStrings(s.Value)
		ci := s.Op == "prefix_ci"
		return func(e scannerv2.Evidence, _ evidenceIndex) bool {
			b := fieldOf(e, s.Field, s.Trim)
			if ci {
				return hasPrefix(b, vals...)
			}
			up := strings.ToUpper(b)
			for _, v := range vals {
				if strings.HasPrefix(up, strings.ToUpper(v)) {
					return true
				}
			}
			return false
		}, false, 0, nil
	case "contains", "contains_any":
		vals := toStrings(s.Value)
		ci := s.CI
		return func(e scannerv2.Evidence, _ evidenceIndex) bool {
			b := fieldOf(e, s.Field, s.Trim)
			if ci {
				lb := strings.ToLower(b)
				for _, v := range vals {
					if strings.Contains(lb, strings.ToLower(v)) {
						return true
					}
				}
			} else {
				for _, v := range vals {
					if strings.Contains(b, v) {
						return true
					}
				}
			}
			return false
		}, false, 0, nil
	case "equals":
		val, _ := s.Value.(string)
		return func(e scannerv2.Evidence, _ evidenceIndex) bool {
			b := fieldOf(e, s.Field, s.Trim)
			if s.CI {
				return strings.EqualFold(b, val)
			}
			return b == val
		}, false, 0, nil
	case "regex":
		pat, _ := s.Value.(string)
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, false, 0, fmt.Errorf("regex %q: %w", pat, err)
		}
		return func(e scannerv2.Evidence, _ evidenceIndex) bool {
			return re.MatchString(fieldOfTransformed(e, s.Field, s.Transform))
		}, false, 0, nil
	case "compound":
		subs := make([]matcher, 0, len(s.And))
		for _, c := range s.And {
			m, _, _, err := compileMatch(c)
			if err != nil {
				return nil, false, 0, err
			}
			subs = append(subs, m)
		}
		return func(e scannerv2.Evidence, idx evidenceIndex) bool {
			for _, m := range subs {
				if !m(e, idx) {
					return false
				}
			}
			return true
		}, false, 0, nil
	case "or":
		subs := make([]matcher, 0, len(s.Any))
		for _, c := range s.Any {
			m, _, _, err := compileMatch(c)
			if err != nil {
				return nil, false, 0, err
			}
			subs = append(subs, m)
		}
		return func(e scannerv2.Evidence, idx evidenceIndex) bool {
			for _, m := range subs {
				if m(e, idx) {
					return true
				}
			}
			return false
		}, false, 0, nil
	default:
		return nil, false, 0, fmt.Errorf("unknown op %q", s.Op)
	}
}

// fieldOf reads RawData[field] (default "banner"), optionally trimmed.
func fieldOf(e scannerv2.Evidence, field string, trim bool) string {
	if field == "" {
		field = "banner"
	}
	if e.RawData == nil {
		return ""
	}
	v := e.RawData[field]
	if trim {
		v = strings.TrimSpace(v)
	}
	return v
}

// applyTransform applies a named transform to a field value before matching.
// Used by Recog-imported rules whose patterns expect pre-stripped input:
//   - strip_ssh_prefix: "SSH-2.0-OpenSSH_9.0 Debian-7" → "OpenSSH_9.0 Debian-7"
//     (removes the "SSH-x.y-" protocol prefix, leaving the software string that
//     Recog's ssh.banner patterns match against).
//   - strip_resp_code: "220 foo.bar ESMTP Postfix" → "foo.bar ESMTP Postfix"
//     (removes the leading "NNN " response code that FTP/SMTP/POP3/IMAP banners
//     start with, leaving the greeting text Recog patterns match against).
func applyTransform(v, transform string) string {
	switch transform {
	case "strip_ssh_prefix":
		// "SSH-2.0-..." → strip through the 2nd "-" (SplitN(s,"-",3)[2]).
		parts := strings.SplitN(v, "-", 3)
		if len(parts) >= 3 {
			return parts[2]
		}
		return v
	case "strip_resp_code":
		// "220 foo bar" → "foo bar" (strip leading "NNN " response code).
		if len(v) > 4 && v[3] == ' ' && v[0] >= '0' && v[0] <= '9' &&
			v[1] >= '0' && v[1] <= '9' && v[2] >= '0' && v[2] <= '9' {
			return v[4:]
		}
		return v
	}
	return v
}

// fieldOfTransformed reads RawData[field] and applies a transform. Used by
// matchers that need pre-stripped input (Recog banner rules).
func fieldOfTransformed(e scannerv2.Evidence, field, transform string) string {
	v := fieldOf(e, field, false)
	if transform != "" {
		v = applyTransform(v, transform)
	}
	return v
}

func toStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func toInt(v any) (int, error) {
	switch t := v.(type) {
	case int:
		return t, nil
	case int64:
		return int(t), nil
	case string:
		return strconv.Atoi(t)
	}
	return 0, fmt.Errorf("not an int: %T", v)
}

// ── extraction ───────────────────────────────────────────────────────────

// applyExtract builds the metadata map for a fired rule. Mirrors each original
// classifier's metadata construction exactly.
func applyExtract(spec extractSpec, e scannerv2.Evidence) map[string]string {
	md := map[string]string{}
	// metadata_all: passthrough every RawData key (WebClassifier / TLSClassifier).
	if spec.MetadataAll && e.RawData != nil {
		for k, v := range e.RawData {
			md[k] = v
		}
	}
	for key, ex := range spec.Metadata {
		if v := evalExtractor(ex, e); v != "" {
			md[key] = v
		} else if ex.WhenEquals != nil {
			// when_equals sets a flag value (may be "true" even when the field
			// value itself is the set target); handle separately below.
		}
	}
	// when_equals: emits Set iff RawData[Field]==Value. Unlike the extractors
	// above (which skip on ""), it can set "true". Handle in the same loop via
	// a second pass to keep the map iteration order-independent.
	for key, ex := range spec.Metadata {
		if ex.WhenEquals != nil {
			we := ex.WhenEquals
			if e.RawData != nil && e.RawData[we.Field] == we.Value {
				md[key] = we.Set
			}
		}
	}
	return md
}

// evalExtractor evaluates one non-when_equals extractor. Returns "" when no
// value is derivable (caller skips empty — mirrors original classifiers which
// only set a metadata key when non-empty).
func evalExtractor(ex extractor, e scannerv2.Evidence) string {
	if ex.WhenEquals != nil {
		return "" // handled by the when_equals pass in applyExtract
	}
	// const wins regardless of evidence (e.g. content_kind: "node_exporter").
	if ex.Const != "" {
		return ex.Const
	}
	if ex.Passthrough != "" {
		if e.RawData != nil {
			return e.RawData[ex.Passthrough]
		}
		return ""
	}
	if ex.Split != nil {
		// extractSSHVersion: SplitN(banner, delim, delim-count) then take [index].
		// The original uses SplitN(b, "-", 3) → 3 parts, returns parts[2].
		b := fieldOf(e, "banner", false)
		parts := strings.SplitN(b, ex.Split.Delim, ex.Split.Index+1)
		if len(parts) > ex.Split.Index {
			return parts[ex.Split.Index]
		}
		return ""
	}
	if ex.SubstringAfter != nil {
		// serverVersion: find first delim in RawData[field], take substring
		// after it, stop at first char in `until` set.
		s := ""
		if e.RawData != nil {
			s = e.RawData[ex.SubstringAfter.Field]
		}
		i := strings.IndexByte(s, ex.SubstringAfter.Delim[0])
		if i < 0 {
			return ""
		}
		rest := s[i+1:]
		for j := 0; j < len(rest); j++ {
			for _, stop := range ex.SubstringAfter.Until {
				if rest[j] == stop[0] {
					return rest[:j]
				}
			}
		}
		return rest
	}
	if ex.KeywordMap != nil {
		// brandFromServerHeader / vendorFromCertCN: ordered CI-contains → enum.
		s := ""
		if e.RawData != nil {
			s = e.RawData[ex.KeywordMap.Field]
		}
		if ex.KeywordMap.CI {
			s = strings.ToLower(s)
		}
		for _, ent := range ex.KeywordMap.Entries {
			if len(ent.ContainsAny) > 0 {
				for _, kw := range ent.ContainsAny {
					needle := kw
					if ex.KeywordMap.CI {
						needle = strings.ToLower(kw)
					}
					if strings.Contains(s, needle) {
						return ent.Set
					}
				}
			} else {
				needle := ent.Contains
				if ex.KeywordMap.CI {
					needle = strings.ToLower(ent.Contains)
				}
				if strings.Contains(s, needle) {
					return ent.Set
				}
			}
		}
		return ""
	}
	return ""
}
