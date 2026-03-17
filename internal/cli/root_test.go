package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
)

func TestExecuteScanAndFindingsTable(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	stateFile := filepath.Join(t.TempDir(), "state.json")
	fixtureA := repoFixturePath(t, "role_with_policies.json")
	fixtureB := repoFixturePath(t, "role_with_urlencoded_trust.json")

	var scanOut bytes.Buffer
	err := Execute(cfg, []string{
		"--state-file", stateFile,
		"scan",
		"--fixture", fixtureA,
		"--fixture", fixtureB,
		"--output", "table",
	}, &scanOut)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !strings.Contains(scanOut.String(), "Scan completed:") {
		t.Fatalf("expected scan summary, got: %q", scanOut.String())
	}
	if !strings.Contains(strings.ToLower(scanOut.String()), "risky trust policy") {
		t.Fatalf("expected risky trust finding in output, got: %q", scanOut.String())
	}

	var findingsOut bytes.Buffer
	err = Execute(cfg, []string{"--state-file", stateFile, "findings"}, &findingsOut)
	if err != nil {
		t.Fatalf("findings failed: %v", err)
	}
	if !strings.Contains(findingsOut.String(), "Last scan:") {
		t.Fatalf("expected findings header, got: %q", findingsOut.String())
	}
}

func TestExecuteScanJSONNoSave(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	fixtureA := repoFixturePath(t, "role_with_policies.json")

	var out bytes.Buffer
	err := Execute(cfg, []string{
		"scan",
		"--fixture", fixtureA,
		"--output", "json",
		"--no-save",
	}, &out)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !strings.Contains(out.String(), "\"generated_at\"") {
		t.Fatalf("expected json output, got: %q", out.String())
	}
	if strings.Contains(out.String(), "Saved findings state") {
		t.Fatalf("did not expect save confirmation when --no-save is set")
	}
}

func TestExecuteFindingsMissingState(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	missingState := filepath.Join(t.TempDir(), "missing.json")

	var out bytes.Buffer
	err := Execute(cfg, []string{"--state-file", missingState, "findings"}, &out)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !strings.Contains(out.String(), "No findings state found") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestExecuteInvalidOutputFormat(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	fixtureA := repoFixturePath(t, "role_with_policies.json")

	var out bytes.Buffer
	err := Execute(cfg, []string{"scan", "--fixture", fixtureA, "--output", "xml"}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteUnsupportedProvider(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "azure"}

	var out bytes.Buffer
	err := Execute(cfg, []string{"scan"}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported provider") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteKubernetesScan(t *testing.T) {
	cfg := config.Config{
		ServiceName: "identrail-test",
		Provider:    "kubernetes",
	}
	stateFile := filepath.Join(t.TempDir(), "k8s-state.json")
	sa := repoFixturePathForProvider(t, "kubernetes", "service_account_payments.json")
	rb := repoFixturePathForProvider(t, "kubernetes", "role_binding_cluster_admin.json")
	role := repoFixturePathForProvider(t, "kubernetes", "cluster_role_cluster_admin.json")
	pod := repoFixturePathForProvider(t, "kubernetes", "pod_payments.json")

	var out bytes.Buffer
	err := Execute(cfg, []string{
		"--state-file", stateFile,
		"scan",
		"--fixture", sa,
		"--fixture", role,
		"--fixture", rb,
		"--fixture", pod,
		"--output", "table",
	}, &out)
	if err != nil {
		t.Fatalf("kubernetes scan failed: %v", err)
	}
	lower := strings.ToLower(out.String())
	if !strings.Contains(lower, "broadly privileged") {
		t.Fatalf("expected overprivileged finding in output, got %q", out.String())
	}
}

func TestExecuteRepoScan(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	repo := initCLITestRepoWithSecret(t)

	var out bytes.Buffer
	err := Execute(cfg, []string{
		"repo-scan",
		"--repo", repo,
		"--history-limit", "50",
		"--max-findings", "20",
		"--output", "json",
	}, &out)
	if err != nil {
		t.Fatalf("repo scan failed: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "\"secret_exposure\"") {
		t.Fatalf("expected secret finding output, got %q", body)
	}
	if strings.Contains(body, "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234") {
		t.Fatalf("expected redacted output, got %q", body)
	}
}

func TestExecuteRepoScanValidationErrors(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	var out bytes.Buffer

	if err := Execute(cfg, []string{"repo-scan"}, &out); err == nil {
		t.Fatal("expected --repo validation error")
	}
	if err := Execute(cfg, []string{"repo-scan", "--repo", ".", "--history-limit", "0"}, &out); err == nil {
		t.Fatal("expected history-limit validation error")
	}
	if err := Execute(cfg, []string{"repo-scan", "--repo", ".", "--max-findings", "0"}, &out); err == nil {
		t.Fatal("expected max-findings validation error")
	}
	if err := Execute(cfg, []string{"repo-scan", "--repo", ".", "--output", "xml"}, &out); err == nil {
		t.Fatal("expected output validation error")
	}
}

func initCLITestRepoWithSecret(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	runCLITestGit(t, repo, "init", "-q")

	if err := os.WriteFile(filepath.Join(repo, "app.env"), []byte("AWS_SECRET_ACCESS_KEY=ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234\n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	runCLITestGit(t, repo, "add", "app.env")
	runCLITestGit(t, repo, "commit", "-q", "-m", "add secret")
	return repo
}

func runCLITestGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=identrail-test",
		"GIT_AUTHOR_EMAIL=identrail-test@example.com",
		"GIT_COMMITTER_NAME=identrail-test",
		"GIT_COMMITTER_EMAIL=identrail-test@example.com",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
	}
}

func TestExecuteKubernetesUnsupportedSource(t *testing.T) {
	cfg := config.Config{
		ServiceName:      "identrail-test",
		Provider:         "kubernetes",
		KubernetesSource: "unknown",
	}
	var out bytes.Buffer
	err := Execute(cfg, []string{"scan", "--no-save"}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported kubernetes source") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteAWSUnsupportedSource(t *testing.T) {
	cfg := config.Config{
		ServiceName: "identrail-test",
		Provider:    "aws",
		AWSSource:   "unknown",
	}
	var out bytes.Buffer
	err := Execute(cfg, []string{"scan"}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported aws source") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteUnknownCommand(t *testing.T) {
	cfg := config.Config{ServiceName: "identrail-test", Provider: "aws"}
	var out bytes.Buffer

	err := Execute(cfg, []string{"unknown"}, &out)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(out.String(), "unknown command") {
		t.Fatalf("expected unknown command output, got: %q", out.String())
	}
}

func repoFixturePath(t *testing.T, name string) string {
	return repoFixturePathForProvider(t, "aws", name)
}

func repoFixturePathForProvider(t *testing.T, provider string, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve caller path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return filepath.Join(root, "testdata", provider, name)
}
