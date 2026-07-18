package probe

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
)

// publicKeyBits reports the strength of a certificate's public key in bits.
//   - RSA: modulus bit length (e.g. 2048, 4096).
//   - ECDSA: curve order bit size (e.g. P-256 → 256, P-384 → 384, P-521 → 521).
//   - Ed25519: 256 (fixed by the spec).
//
// Returns 0 for unknown key types so callers can omit the field rather than
// show a misleading "0".
func publicKeyBits(cert *x509.Certificate) int {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			return 0
		}
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil {
			return 0
		}
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	}
	return 0
}
