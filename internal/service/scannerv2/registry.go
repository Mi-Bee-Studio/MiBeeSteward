package scannerv2

import (
	"fmt"
	"sort"
	"sync"
)

// Registry holds the registered ProbeSources, Classifiers, and ServiceHandlers
// for the orchestrator. Registration is open (any package may register at
// construction time); lookup is read-only after construction.
//
// The registry is the single extension point for new protocols: to add support
// for a new service, construct its Classifier + Handler and Register them — no
// orchestrator changes needed.
type Registry struct {
	mu          sync.RWMutex
	probes      map[string]ProbeSource
	classifiers map[string]ServiceClassifier // keyed by Service()
	handlers    map[string]ServiceHandler    // keyed by Service()
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		probes:      make(map[string]ProbeSource),
		classifiers: make(map[string]ServiceClassifier),
		handlers:    make(map[string]ServiceHandler),
	}
}

// RegisterProbe adds a ProbeSource. Re-registering a name replaces it (useful
// for tests). Returns the registry for chaining.
func (r *Registry) RegisterProbe(p ProbeSource) *Registry {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.probes[p.Name()] = p
	return r
}

// RegisterClassifier adds a ServiceClassifier keyed by its Service(). A later
// registration for the same service overrides the earlier (last-wins).
func (r *Registry) RegisterClassifier(c ServiceClassifier) *Registry {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.classifiers[c.Service()] = c
	return r
}

// RegisterHandler adds a ServiceHandler keyed by its Service(). Last-wins.
func (r *Registry) RegisterHandler(h ServiceHandler) *Registry {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[h.Service()] = h
	return r
}

// Probes returns the registered probe sources in a deterministic (name-sorted)
// order. Determinism matters so scan results are reproducible.
func (r *Registry) Probes() []ProbeSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProbeSource, 0, len(r.probes))
	names := make([]string, 0, len(r.probes))
	for n := range r.probes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, r.probes[n])
	}
	return out
}

// Classifiers returns all registered classifiers (service-sorted).
func (r *Registry) Classifiers() []ServiceClassifier {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ServiceClassifier, 0, len(r.classifiers))
	names := make([]string, 0, len(r.classifiers))
	for n := range r.classifiers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, r.classifiers[n])
	}
	return out
}

// Handlers returns all registered handlers (service-sorted).
func (r *Registry) Handlers() []ServiceHandler {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ServiceHandler, 0, len(r.handlers))
	names := make([]string, 0, len(r.handlers))
	for n := range r.handlers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, r.handlers[n])
	}
	return out
}

// HandlerFor returns the handler registered for a service, or nil.
func (r *Registry) HandlerFor(service string) ServiceHandler {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.handlers[service]
}

// String summarizes the registry contents for startup logs / debugging.
func (r *Registry) String() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return fmt.Sprintf("registry{probes=%d classifiers=%d handlers=%d}",
		len(r.probes), len(r.classifiers), len(r.handlers))
}
