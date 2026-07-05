package domain

import (
	"testing"
)

// validScanTaskRequest returns a baseline valid request.
func validScanTaskRequest() ScanTaskRequest {
	return ScanTaskRequest{
		Name:            "test-scan",
		Targets:         "192.168.1.0/24",
		CronExpr:        "0 */6 * * *",
		PipelineConfig:  DefaultPipelineConfig(),
		Timeout:         300,
		ConcurrentHosts: 50,
	}
}

func TestValidateScanTaskRequest_NameRequired(t *testing.T) {
	req := validScanTaskRequest()
	req.Name = ""
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if err.Error() != "name is required" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestValidateScanTaskRequest_TargetsRequired(t *testing.T) {
	req := validScanTaskRequest()
	req.Targets = ""
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for empty targets")
	}
	if err.Error() != "targets is required" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestValidateScanTaskRequest_CronRequired(t *testing.T) {
	req := validScanTaskRequest()
	req.CronExpr = ""
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for empty cron_expr")
	}
	if err.Error() != "cron_expr is required" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestValidateScanTaskRequest_CronInvalid(t *testing.T) {
	req := validScanTaskRequest()
	req.CronExpr = "not-a-cron"
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for invalid cron expression")
	}
	if err.Error() != "cron_expr: invalid cron expression: not-a-cron" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestValidateScanTaskRequest_CronValid(t *testing.T) {
	req := validScanTaskRequest()
	req.CronExpr = "*/5 * * * *"
	err := ValidateScanTaskRequest(req)
	if err != nil {
		t.Fatalf("unexpected error for valid cron: %v", err)
	}
}

func TestValidateScanTaskRequest_TimeoutTooLow(t *testing.T) {
	req := validScanTaskRequest()
	req.Timeout = 0
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for timeout=0")
	}
}

func TestValidateScanTaskRequest_TimeoutTooHigh(t *testing.T) {
	req := validScanTaskRequest()
	req.Timeout = 601
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for timeout=601")
	}
}

func TestValidateScanTaskRequest_TimeoutBoundaries(t *testing.T) {
	// Minimum valid
	req := validScanTaskRequest()
	req.Timeout = 1
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("unexpected error for timeout=1: %v", err)
	}
	// Maximum valid
	req.Timeout = 600
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("unexpected error for timeout=600: %v", err)
	}
}

func TestValidateScanTaskRequest_ConcurrentHostsTooLow(t *testing.T) {
	req := validScanTaskRequest()
	req.ConcurrentHosts = 0
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for concurrent_hosts=0")
	}
}

func TestValidateScanTaskRequest_ConcurrentHostsTooHigh(t *testing.T) {
	req := validScanTaskRequest()
	req.ConcurrentHosts = 201
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for concurrent_hosts=201")
	}
}

func TestValidateScanTaskRequest_ConcurrentHostsBoundaries(t *testing.T) {
	// Minimum valid
	req := validScanTaskRequest()
	req.ConcurrentHosts = 1
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("unexpected error for concurrent_hosts=1: %v", err)
	}
	// Maximum valid
	req.ConcurrentHosts = 200
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("unexpected error for concurrent_hosts=200: %v", err)
	}
}

func TestValidateScanTaskRequest_InvalidTarget(t *testing.T) {
	req := validScanTaskRequest()
	req.Targets = "not-an-ip-or-cidr"
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
}

func TestValidateScanTaskRequest_TooManyIPs(t *testing.T) {
	req := validScanTaskRequest()
	// /16 = 65536 IPs, way over 4096 limit
	req.Targets = "10.0.0.0/16"
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for too many IPs in /16")
	}
}

func TestValidateScanTaskRequest_MaxCIDRAllowed(t *testing.T) {
	req := validScanTaskRequest()
	// /20 = 4096 IPs, exactly at limit (not > 4096)
	req.Targets = "10.0.0.0/20"
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("unexpected error for /20 CIDR: %v", err)
	}
}

func TestValidateScanTaskRequest_OverLimitCIDR(t *testing.T) {
	req := validScanTaskRequest()
	// /19 = 8192 IPs, over the 4096 limit
	req.Targets = "10.0.0.0/19"
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for too many IPs in /19")
	}
}

func TestValidateScanTaskRequest_ValidSingleIP(t *testing.T) {
	req := validScanTaskRequest()
	req.Targets = "192.168.1.1"
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("unexpected error for single IP target: %v", err)
	}
}

func TestValidateScanTaskRequest_ValidCIDR(t *testing.T) {
	req := validScanTaskRequest()
	req.Targets = "10.0.0.0/24"
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("unexpected error for valid CIDR: %v", err)
	}
}

func TestValidateScanTaskRequest_CommaSeparatedTargets(t *testing.T) {
	req := validScanTaskRequest()
	req.Targets = "192.168.1.1,10.0.0.0/24,172.16.0.1"
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("unexpected error for comma-separated targets: %v", err)
	}
}

func TestValidateScanTaskRequest_CommaSeparatedOverLimit(t *testing.T) {
	req := validScanTaskRequest()
	// /24 (256) + /24 (256) + /24 (256) + /24 (256) + /24 (256) = 1280, still under 4096
	req.Targets = "10.0.0.0/24,10.0.1.0/24,10.0.2.0/24,10.0.3.0/24,10.0.4.0/24"
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("expected valid for 5x /24 (1280 IPs): %v", err)
	}
}

func TestValidateScanTaskRequest_IPRange(t *testing.T) {
	req := validScanTaskRequest()
	req.Targets = "192.168.1.1-10"
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("unexpected error for IP range: %v", err)
	}
}

func TestValidateScanTaskRequest_IPRangeFullEnd(t *testing.T) {
	req := validScanTaskRequest()
	req.Targets = "192.168.1.1-192.168.1.10"
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("unexpected error for IP range with full end IP: %v", err)
	}
}

func TestValidateScanTaskRequest_InvalidIPRangeReversed(t *testing.T) {
	req := validScanTaskRequest()
	req.Targets = "192.168.1.10-5"
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for reversed IP range")
	}
}

func TestValidateScanTaskRequest_InvalidIPRangeFormat(t *testing.T) {
	req := validScanTaskRequest()
	req.Targets = "192.168.1.1-"
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for malformed IP range")
	}
}

func TestValidateScanTaskRequest_ValidAll(t *testing.T) {
	req := validScanTaskRequest()
	if err := ValidateScanTaskRequest(req); err != nil {
		t.Fatalf("unexpected error for valid request: %v", err)
	}
}

func TestValidateScanTaskRequest_CronWithSeconds(t *testing.T) {
	// 6-field cron (with seconds) should be rejected by 5-field parser
	req := validScanTaskRequest()
	req.CronExpr = "0 */5 * * * *"
	err := ValidateScanTaskRequest(req)
	if err == nil {
		t.Fatal("expected error for 6-field cron expression")
	}
}

// Test helpers for countTargetIPs and validateCronExpr

func TestCountTargetIPs_SingleIP(t *testing.T) {
	count, err := countTargetIPs("192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 IP, got %d", count)
	}
}

func TestCountTargetIPs_CIDR(t *testing.T) {
	count, err := countTargetIPs("10.0.0.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 256 {
		t.Errorf("expected 256 IPs for /24, got %d", count)
	}
}

func TestCountTargetIPs_Range(t *testing.T) {
	count, err := countTargetIPs("192.168.1.1-10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 10 {
		t.Errorf("expected 10 IPs for range 1-10, got %d", count)
	}
}

func TestCountTargetIPs_CommaSeparated(t *testing.T) {
	count, err := countTargetIPs("192.168.1.1,10.0.0.0/24,192.168.2.1-5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 1 + 256 + 5 = 262
	if count != 262 {
		t.Errorf("expected 262 IPs, got %d", count)
	}
}

func TestCountTargetIPs_InvalidCIDR(t *testing.T) {
	_, err := countTargetIPs("10.0.0.0/33")
	if err == nil {
		t.Fatal("expected error for invalid CIDR /33")
	}
}

func TestValidateCronExpr_Valid(t *testing.T) {
	if err := validateCronExpr("0 */6 * * *"); err != nil {
		t.Fatalf("unexpected error for valid cron: %v", err)
	}
}

func TestValidateCronExpr_Invalid(t *testing.T) {
	if err := validateCronExpr("not-a-cron"); err == nil {
		t.Fatal("expected error for invalid cron expression")
	}
}

func TestValidateCronExpr_Empty(t *testing.T) {
	if err := validateCronExpr(""); err == nil {
		t.Fatal("expected error for empty cron expression")
	}
}
