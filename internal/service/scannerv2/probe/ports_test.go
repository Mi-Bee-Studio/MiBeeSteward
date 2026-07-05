package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// --- port spec + priority ordering (pure logic) ---

func TestParsePortSpec(t *testing.T) {
	cases := []struct {
		in      string
		want    []int
		wantErr bool
	}{
		{"22,80,443", []int{22, 80, 443}, false},
		{"80,22,80", []int{22, 80}, false}, // dedup + sort
		{"100-103", []int{100, 101, 102, 103}, false},
		{"22,100-102,80", []int{22, 80, 100, 101, 102}, false},
		{"0", nil, true},       // out of range
		{"70000", nil, true},   // out of range
		{"1-70000", nil, true}, // range too big
		{"abc", nil, true},     // not a number
		{"", []int{}, false},   // empty → empty
		{" 22 , 80 ", []int{22, 80}, false},
	}
	for _, c := range cases {
		got, err := parsePortSpec(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parsePortSpec(%q) expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePortSpec(%q) unexpected error: %v", c.in, err)
			continue
		}
		if !sliceEq(got, c.want) {
			t.Errorf("parsePortSpec(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPriorityPortList_FingerprintFirst(t *testing.T) {
	// 22 and 80 are fingerprint ports; they must come first, in fingerprint
	// order, then the rest ascending.
	got, err := priorityPortList("1-5,22,80,100", []int{80, 22})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{80, 22, 1, 2, 3, 4, 5, 100}
	if !sliceEq(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestPriorityPortList_Dedup(t *testing.T) {
	got, err := priorityPortList("22,22,80", []int{22, 80})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 80}
	if !sliceEq(got, want) {
		t.Errorf("got %v want %v (should dedup)", got, want)
	}
}

// --- PortSpecProbe: real open-port + banner detection ---

func TestPortSpecProbe_OpenPortAndBanner(t *testing.T) {
	// Start a TCP listener that sends an SSH banner.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Proactively send the SSH banner (server-volunteers style), then read
		// until the probe closes (keep conn alive while the probe reads).
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
		ioReadUntilClosed(conn)
	}()

	p := NewPortSpecProbe(itoa(port), nil)
	evs, err := p.Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) < 1 {
		t.Fatalf("expected at least 1 evidence (port_open), got %d", len(evs))
	}
	var foundOpen, foundBanner bool
	for _, e := range evs {
		if e.Kind == "port_open" && e.Port == port {
			foundOpen = true
		}
		if e.Kind == "banner" && strings.HasPrefix(e.RawData["banner"], "SSH-2.0") {
			foundBanner = true
		}
	}
	if !foundOpen {
		t.Error("no port_open evidence for the listener port")
	}
	if !foundBanner {
		t.Error("no banner evidence capturing SSH greeting")
	}
}

func TestPortSpecProbe_ClosedPortNoEvidence(t *testing.T) {
	// A port nothing is listening on.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	p := NewPortSpecProbe(itoa(port), nil)
	evs, err := p.Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{Timeout: 1 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Errorf("closed port should yield no evidence, got %d", len(evs))
	}
}

// --- RTSPProbe: mock RTSP server ---

func TestRTSPProbe_DetectsRTSPServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read the OPTIONS request, then respond with RTSP reply + Server header.
		buf := make([]byte, 256)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hikvision\r\n\r\n"))
		ioReadUntilClosed(conn)
	}()

	p := NewRTSPProbe()
	// Override default ports so the probe targets the mock port.
	p.defaultPorts = []int{port}
	evs, err := p.Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{
		Ports:   []int{port},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Kind != "rtsp_banner" {
		t.Fatalf("expected 1 rtsp_banner evidence, got %#v", evs)
	}
	if evs[0].RawData["server"] != "Hikvision" {
		t.Errorf("server header = %q, want Hikvision", evs[0].RawData["server"])
	}
}

func TestRTSPProbe_RejectsNonRTSP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		ioReadUntilClosed(conn)
	}()

	p := NewRTSPProbe()
	p.defaultPorts = []int{port}
	evs, _ := p.Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{Ports: []int{port}, Timeout: time.Second})
	if len(evs) != 0 {
		t.Errorf("non-RTSP server should yield no evidence, got %d", len(evs))
	}
}

// --- ONVIFProbe: mock ONVIF device vs nginx ---

func TestONVIFProbe_DetectsGenuineONVIF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/onvif/device_service" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Server", "Hikvision-ONVIF/1.0")
		w.WriteHeader(200)
		w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><td:GetSystemDateAndTimeResponse xmlns:td="http://www.onvif.org/ver10/device/wsdl"></td:GetSystemDateAndTimeResponse></s:Body></s:Envelope>`))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	p := NewONVIFProbe()
	evs, _ := p.Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{Ports: []int{port}, Timeout: 2 * time.Second})
	if len(evs) != 1 || evs[0].Kind != "onvif_response" {
		t.Fatalf("expected onvif_response, got %#v", evs)
	}
	if evs[0].RawData["server"] != "Hikvision-ONVIF/1.0" {
		t.Errorf("server = %q", evs[0].RawData["server"])
	}
}

func TestONVIFProbe_RejectsNonONVIFBody(t *testing.T) {
	// nginx-style 200 with HTML body — must NOT match.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>Welcome to nginx</body></html>`))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	p := NewONVIFProbe()
	evs, _ := p.Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{Ports: []int{port}, Timeout: 2 * time.Second})
	if len(evs) != 0 {
		t.Errorf("non-ONVIF HTML body should yield no evidence, got %d", len(evs))
	}
}

func TestONVIFProbe_Accepts401WithONVIFBody(t *testing.T) {
	// ONVIF devices often require auth; the body still carries the namespace.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Digest realm="ONVIF"`)
		w.WriteHeader(401)
		w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><td:NotAuthorized xmlns:td="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>`))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	p := NewONVIFProbe()
	evs, _ := p.Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{Ports: []int{port}, Timeout: 2 * time.Second})
	if len(evs) != 1 {
		t.Fatalf("expected 1 onvif evidence for 401+ONVIF body, got %d", len(evs))
	}
	if evs[0].RawData["auth_required"] != "true" {
		t.Error("401 should set auth_required")
	}
}

// --- HTTPMetricsProbe ---

func TestHTTPMetricsProbe_PrometheusContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("# HELP prometheus_build_info\nprometheus_build_info{version=\"2.45.0\"} 1\n# HELP go_goroutines\ngo_goroutines 42\n"))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	p := NewHTTPMetricsProbe()
	evs, _ := p.Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{Ports: []int{port}, Timeout: 2 * time.Second})
	if len(evs) != 1 || evs[0].Kind != "metric" {
		t.Fatalf("expected 1 metric evidence, got %#v", evs)
	}
	if !strings.Contains(evs[0].RawData["content_sample"], "prometheus_build_info") {
		t.Error("metric sample should contain prometheus_build_info")
	}
}

func TestHTTPMetricsProbe_NodeExporterContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("# HELP node_exporter_build_info\nnode_exporter_build_info{version=\"1.6.1\"} 1\nnode_cpu_seconds_total{cpu=\"0\"} 1.23\nnode_memory_MemTotal_bytes 8.59e+09\n"))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	p := NewHTTPMetricsProbe()
	evs, _ := p.Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{Ports: []int{port}, Timeout: 2 * time.Second})
	if len(evs) != 1 {
		t.Fatalf("expected metric evidence, got %d", len(evs))
	}
	sample := evs[0].RawData["content_sample"]
	if !strings.Contains(sample, "node_exporter_build_info") || !strings.Contains(sample, "node_memory_MemTotal_bytes") {
		t.Error("sample should contain node_exporter + node_memory metrics")
	}
}

func TestHTTPMetricsProbe_NoMetricsEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404) // no /metrics
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	p := NewHTTPMetricsProbe()
	evs, _ := p.Probe(context.Background(), "127.0.0.1", scannerv2.ProbeHint{Ports: []int{port}, Timeout: 2 * time.Second})
	if len(evs) != 0 {
		t.Errorf("non-metrics endpoint should yield no evidence, got %d", len(evs))
	}
}

// --- helpers ---

func sliceEq(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ioReadUntilClosed blocks the goroutine reading from conn until conn is
// closed by the peer (probe finishes). Keeps mock servers alive long enough
// for the probe to complete its read. Returns on read error or deadline.
func ioReadUntilClosed(conn net.Conn) {
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}
