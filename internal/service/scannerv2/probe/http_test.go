package probe

import "testing"

func TestExtractHTMLTitle(t *testing.T) {
	cases := []struct{ in, want string }{
		{`<html><head><TITLE>Welcome</TITLE></head>`, "Welcome"},
		{`<title lang="en">Foo Bar</title>`, "Foo Bar"},
		{`<title>  Multi
		Line  </title>`, "Multi Line"},
		{`<html><body>no title</body></html>`, ""},
		{`<title>`, ""},
	}
	for _, c := range cases {
		if got := extractHTMLTitle(c.in); got != c.want {
			t.Errorf("extractHTMLTitle() = %q, want %q", got, c.want)
		}
	}
}

func TestProbeForPort(t *testing.T) {
	if got := probeForPort(80); string(got) != "GET / HTTP/1.0\r\n\r\n" {
		t.Errorf("port 80 should have HTTP probe, got %q", got)
	}
	if got := probeForPort(22); got != nil {
		t.Errorf("port 22 (SSH) should have no active probe, got %q", got)
	}
}
