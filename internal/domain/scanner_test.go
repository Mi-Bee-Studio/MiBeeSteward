package domain

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanHost_SNMPFields_JSONTags(t *testing.T) {
	host := ScanHost{
		IP:           "192.168.1.1",
		Alive:        true,
		RTTMs:        5,
		SNMPName:     "router1",
		SNMPDescr:    "Cisco Router",
		SNMPSuccess:  true,
		SNMPObjID:    "1.3.6.1.4.1.9",
		SNMPLocation: "DC-A Rack 12",
		SNMPContact:  "admin@example.com",
		SNMPUptime:   123456789,
		SNMPServices: 72,
		SNMPIfCount:  24,
	}

	data, err := json.Marshal(host)
	if err != nil {
		t.Fatalf("failed to marshal ScanHost: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal ScanHost: %v", err)
	}

	// Check existing fields
	existingFields := []string{"ip", "alive", "rtt_ms", "snmp_name", "snmp_descr", "snmp_success"}
	for _, field := range existingFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing existing JSON field %q in ScanHost", field)
		}
	}

	// Check new SNMP fields
	newFields := []string{"snmp_obj_id", "snmp_location", "snmp_contact", "snmp_uptime", "snmp_services", "snmp_if_count"}
	for _, field := range newFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing new SNMP JSON field %q in ScanHost", field)
		}
	}
}

func TestScanHost_SNMPFields_OmitEmpty(t *testing.T) {
	// Host with all SNMP fields empty — should omit omitempty fields
	host := ScanHost{
		IP:    "192.168.1.1",
		Alive: false,
		RTTMs: 0,
	}

	data, err := json.Marshal(host)
	if err != nil {
		t.Fatalf("failed to marshal ScanHost: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal ScanHost: %v", err)
	}

	// snmp_name, snmp_descr, snmp_obj_id, snmp_location, snmp_contact should be omitted
	omitFields := []string{"snmp_name", "snmp_descr", "snmp_obj_id", "snmp_location", "snmp_contact"}
	for _, field := range omitFields {
		if _, ok := decoded[field]; ok {
			t.Errorf("expected JSON field %q to be omitted (omitempty), but it was present", field)
		}
	}

	// snmp_success, snmp_uptime, snmp_services, snmp_if_count should be present (no omitempty or zero values)
	// snmp_success is bool, will default to false
	if _, ok := decoded["snmp_success"]; !ok {
		t.Error("missing JSON field \"snmp_success\" in ScanHost (should always be present)")
	}
}

func TestScanHost_SNMPFields_RoundTrip(t *testing.T) {
	host := ScanHost{
		IP:           "10.0.0.1",
		Alive:        true,
		RTTMs:        1,
		SNMPName:     "switch-a",
		SNMPDescr:    "Managed Switch",
		SNMPSuccess:  true,
		SNMPObjID:    "1.3.6.1.4.1.2636",
		SNMPLocation: "Floor 2 IDF",
		SNMPContact:  "noc@company.com",
		SNMPUptime:   987654321,
		SNMPServices: 76,
		SNMPIfCount:  48,
	}

	data, err := json.Marshal(host)
	if err != nil {
		t.Fatalf("failed to marshal ScanHost: %v", err)
	}

	var decoded ScanHost
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal ScanHost: %v", err)
	}

	if decoded.SNMPObjID != host.SNMPObjID {
		t.Errorf("SNMPObjID = %q, want %q", decoded.SNMPObjID, host.SNMPObjID)
	}
	if decoded.SNMPLocation != host.SNMPLocation {
		t.Errorf("SNMPLocation = %q, want %q", decoded.SNMPLocation, host.SNMPLocation)
	}
	if decoded.SNMPContact != host.SNMPContact {
		t.Errorf("SNMPContact = %q, want %q", decoded.SNMPContact, host.SNMPContact)
	}
	if decoded.SNMPUptime != host.SNMPUptime {
		t.Errorf("SNMPUptime = %d, want %d", decoded.SNMPUptime, host.SNMPUptime)
	}
	if decoded.SNMPServices != host.SNMPServices {
		t.Errorf("SNMPServices = %d, want %d", decoded.SNMPServices, host.SNMPServices)
	}
	if decoded.SNMPIfCount != host.SNMPIfCount {
		t.Errorf("SNMPIfCount = %d, want %d", decoded.SNMPIfCount, host.SNMPIfCount)
	}
}

func TestAddDeviceItem_NewFields_JSONTags(t *testing.T) {
	snmpData := map[string]interface{}{
		"obj_id":   "1.3.6.1.4.1.9",
		"location": "DC-A",
		"contact":  "admin@example.com",
	}
	item := AddDeviceItem{
		IP:          "10.0.0.1",
		Name:        "core-switch",
		Type:        "switch",
		Description: "Core network switch",
		Brand:       "Cisco",
		Model:       "Catalyst 9300",
		Location:    "DC-A Rack 12",
		SNMPData:    snmpData,
	}

	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("failed to marshal AddDeviceItem: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal AddDeviceItem: %v", err)
	}

	// Check existing fields
	existingFields := []string{"ip", "name", "type"}
	for _, field := range existingFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing existing JSON field %q in AddDeviceItem", field)
		}
	}

	// Check new fields
	newFields := []string{"description", "brand", "model", "location", "snmp_data"}
	for _, field := range newFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing new JSON field %q in AddDeviceItem", field)
		}
	}
}

func TestAddDeviceItem_NewFields_OmitEmpty(t *testing.T) {
	item := AddDeviceItem{
		IP:   "10.0.0.1",
		Name: "test-device",
		Type: "other",
	}

	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("failed to marshal AddDeviceItem: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal AddDeviceItem: %v", err)
	}

	// New fields should be omitted when empty
	omitFields := []string{"description", "brand", "model", "location", "snmp_data"}
	for _, field := range omitFields {
		if _, ok := decoded[field]; ok {
			t.Errorf("expected JSON field %q to be omitted (omitempty), but it was present", field)
		}
	}
}

func TestAddDeviceItem_RoundTrip(t *testing.T) {
	snmpData := map[string]interface{}{
		"obj_id":    "1.3.6.1.4.1.9.1.123",
		"uptime":    123456,
		"if_count":  48,
		"services":  72,
		"contact":   "noc@company.com",
		"location":  "Floor 1",
	}
	item := AddDeviceItem{
		IP:          "192.168.1.100",
		Name:        "access-point-01",
		Type:        "iot",
		Description: "WiFi Access Point",
		Brand:       "Aruba",
		Model:       "AP-515",
		Location:    "Building A, Floor 3",
		SNMPData:    snmpData,
	}

	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("failed to marshal AddDeviceItem: %v", err)
	}

	var decoded AddDeviceItem
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal AddDeviceItem: %v", err)
	}

	if decoded.Description != item.Description {
		t.Errorf("Description = %q, want %q", decoded.Description, item.Description)
	}
	if decoded.Brand != item.Brand {
		t.Errorf("Brand = %q, want %q", decoded.Brand, item.Brand)
	}
	if decoded.Model != item.Model {
		t.Errorf("Model = %q, want %q", decoded.Model, item.Model)
	}
	if decoded.Location != item.Location {
		t.Errorf("Location = %q, want %q", decoded.Location, item.Location)
	}
	if decoded.SNMPData == nil {
		t.Fatal("SNMPData is nil after round-trip")
	}
	if decoded.SNMPData["obj_id"] != snmpData["obj_id"] {
		t.Errorf("SNMPData.obj_id = %v, want %v", decoded.SNMPData["obj_id"], snmpData["obj_id"])
	}
}

func TestScanResultResponse_JSONTags(t *testing.T) {
	// Verify ScanResultResponse has the expected enriched fields
	resp := ScanResultResponse{
		ID:                   1,
		TaskID:               1,
		RunID:                42,
		IP:                   "192.168.1.1",
		Alive:                true,
		RTTMs:                5,
		Ports:                "80,443",
		Services:             "HTTP,HTTPS",
		SNMPData:             `{"obj_id":"1.3.6.1.4.1.9"}`,
		PrometheusDetected:   true,
		PrometheusURL:        "http://192.168.1.1:9090",
		NodeExporterDetected: true,
		NodeExporterURL:      "http://192.168.1.1:9100",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal ScanResultResponse: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal ScanResultResponse: %v", err)
	}

	// All fields should use snake_case
	expectedFields := []string{
		"id", "task_id", "run_id", "ip", "alive", "rtt_ms",
		"ports", "services", "snmp_data",
		"prometheus_detected", "prometheus_url",
		"node_exporter_detected", "node_exporter_url",
	}
	for _, field := range expectedFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q in ScanResultResponse", field)
		}
	}
}

func TestAddDeviceItemJSONRoundTrip(t *testing.T) {
	item := AddDeviceItem{
		IP:          "10.0.0.1",
		Name:        "core-switch",
		Type:        "switch",
		Description: "Core network switch",
		Brand:       "Cisco",
		Model:       "Catalyst 9300",
		Location:    "DC-A Rack 12",
		SNMPData:    map[string]interface{}{"obj_id": "1.3.6.1.4.1.9"},
		Ports: []PortInfo{
			{Port: 80, State: "open", Service: "HTTP"},
			{Port: 443, State: "open", Service: "HTTPS"},
		},
		Services: []ServiceInfo{
			{Port: 80, Name: "HTTP", Version: "1.1"},
			{Port: 9090, Name: "prometheus", Version: "2.45"},
		},
		PromURL: "http://10.0.0.1:9090",
		NEURL:   "http://10.0.0.1:9100",
		RTTMs:   5,
	}

	data, err := json.Marshal(item)
	require.NoError(t, err)

	var decoded AddDeviceItem
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Equal(t, item.IP, decoded.IP)
	require.Equal(t, item.Name, decoded.Name)
	require.Equal(t, item.Type, decoded.Type)
	require.Equal(t, item.Description, decoded.Description)
	require.Equal(t, item.Brand, decoded.Brand)
	require.Equal(t, item.Model, decoded.Model)
	require.Equal(t, item.Location, decoded.Location)
	require.Equal(t, item.SNMPData, decoded.SNMPData)
	require.Equal(t, item.PromURL, decoded.PromURL)
	require.Equal(t, item.NEURL, decoded.NEURL)
	require.Equal(t, item.RTTMs, decoded.RTTMs)
	require.Equal(t, item.Ports, decoded.Ports)
	require.Equal(t, item.Services, decoded.Services)
}

func TestAddDeviceItemBackwardCompat(t *testing.T) {
	// Old JSON without new fields should still deserialize correctly
	oldJSON := `{"ip":"1.2.3.4","name":"test","type":"other","snmp_data":{}}`

	var item AddDeviceItem
	err := json.Unmarshal([]byte(oldJSON), &item)
	require.NoError(t, err)
	require.Equal(t, "1.2.3.4", item.IP)
	require.Equal(t, "test", item.Name)
	require.Equal(t, "other", item.Type)
	require.NotNil(t, item.SNMPData)

	// New fields should be zero-valued
	require.Nil(t, item.Ports, "Ports should be nil for old JSON")
	require.Nil(t, item.Services, "Services should be nil for old JSON")
	require.Empty(t, item.PromURL, "PromURL should be empty for old JSON")
	require.Empty(t, item.NEURL, "NEURL should be empty for old JSON")
	require.Zero(t, item.RTTMs, "RTTMs should be zero for old JSON")
}
