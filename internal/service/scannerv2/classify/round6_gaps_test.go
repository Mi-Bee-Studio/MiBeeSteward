// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package classify

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestClassifierServiceNames pins every classifier's Service() identity, the
// name that lands in host_services.service and drives server-class data
// tables. A silent rename here desyncs the UI's service filters.
func TestClassifierServiceNames(t *testing.T) {
	names := map[string]scService{
		"banner":     BannerClassifier{}.Service(),
		"database":   DatabaseClassifier{}.Service(),
		"mail":       MailClassifier{}.Service(),
		"remote":     RemoteAccessClassifier{}.Service(),
		"misc":       MiscClassifier{}.Service(),
		"onvif":      ONVIFClassifier{}.Service(),
		"prometheus": PrometheusClassifier{}.Service(),
		"rtsp":       RTSPClassifier{}.Service(),
		"camera":     CameraClassifier{}.Service(),
		"http":       HTTPClassifier{}.Service(),
		"snmp":       SNMPClassifier{}.Service(),
		"web":        WebClassifier{}.Service(),
		"tls":        TLSClassifier{}.Service(),
	}
	for want, got := range names {
		require.Equal(t, want, got)
	}
}

type scService = string

func TestAtoiSafe(t *testing.T) {
	require.Equal(t, 42, atoiSafe("42"))
	require.Equal(t, 42, atoiSafe("42 x"))
	require.Equal(t, 7, atoiSafe("Linux 7.3"))
	require.Equal(t, 0, atoiSafe("no digits"))
	require.Equal(t, 0, atoiSafe(""))
}
