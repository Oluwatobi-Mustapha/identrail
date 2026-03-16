package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/aurelius/internal/config"
)

func TestExecuteScan(t *testing.T) {
	cfg := config.Config{ServiceName: "aurelius-test", Provider: "aws"}
	var out bytes.Buffer

	err := Execute(cfg, []string{"scan"}, &out)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !strings.Contains(out.String(), "Starting scan with service aurelius-test on aws") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestExecuteFindings(t *testing.T) {
	cfg := config.Config{ServiceName: "aurelius-test", Provider: "aws"}
	var out bytes.Buffer

	err := Execute(cfg, []string{"findings"}, &out)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !strings.Contains(out.String(), "No findings available yet") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestExecuteUnknownCommand(t *testing.T) {
	cfg := config.Config{ServiceName: "aurelius-test", Provider: "aws"}
	var out bytes.Buffer

	err := Execute(cfg, []string{"unknown"}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(out.String(), "unknown command") {
		t.Fatalf("expected unknown command output, got: %q", out.String())
	}
}
