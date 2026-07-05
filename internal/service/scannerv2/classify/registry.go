package classify

import "mibee-steward/internal/service/scannerv2"

// DefaultClassifiers returns the standard set of ServiceClassifiers, ready to
// register into a scannerv2.Registry. Order is the registration order; since
// classifiers are pure and emit disjoint service names, order does not affect
// correctness (only deterministic enumeration).
func DefaultClassifiers() []scannerv2.ServiceClassifier {
	return []scannerv2.ServiceClassifier{
		BannerClassifier{},
		HTTPClassifier{},
		RTSPClassifier{},
		ONVIFClassifier{},
		PrometheusClassifier{},
		SNMPClassifier{},
		CameraClassifier{},
	}
}
