package scannerv2

import "testing"

// The interface/route extractors (#528/#529): kind-gated, shape-validated.
func TestExtractInterfacesAndRoutes(t *testing.T) {
	evs := []Evidence{
		{Kind: "interface", RawData: map[string]string{"if_index": "3", "if_name": "eth3", "mac": "aa:bb:cc:dd:ee:03", "ip": "10.0.0.3", "speed_mbps": "100"}},
		{Kind: "interface", RawData: map[string]string{"if_index": "x"}}, // bad index: skipped
		{Kind: "interface", RawData: nil}, // no payload
		{Kind: "route", RawData: map[string]string{"dest": "172.16.0.0/12", "next_hop": "10.0.0.254", "if_index": "2", "proto": "ospf"}},
		{Kind: "route", RawData: map[string]string{"dest": "10.0.0.0/8"}}, // no next hop: skipped
		{Kind: "neighbor", RawData: map[string]string{"if_index": "9"}},   // other kind
	}
	faces := ExtractInterfaces(evs)
	if len(faces) != 1 || faces[0].IfIndex != 3 || faces[0].Speed != 100 || faces[0].IP != "10.0.0.3" {
		t.Fatalf("interfaces = %+v", faces)
	}
	routes := ExtractRoutes(evs)
	if len(routes) != 1 || routes[0].DestCIDR != "172.16.0.0/12" || routes[0].IfIndex != 2 {
		t.Fatalf("routes = %+v", routes)
	}
	if got := ExtractInterfaces(nil); got != nil {
		t.Fatalf("nil input = %+v", got)
	}
	if got := ExtractRoutes(nil); got != nil {
		t.Fatalf("nil input = %+v", got)
	}
}
