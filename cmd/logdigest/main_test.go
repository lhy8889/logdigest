package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const sample = "../../testdata/app.log"

func runWith(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := run(args, strings.NewReader(""), &stdout, &stderr)
	return stdout.String(), err
}

func TestRunPrintsTable(t *testing.T) {
	out, err := runWith(t, "-top", "3", sample)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	for _, want := range []string{
		"1 file, 20 records, 7 patterns",
		"COUNT",
		"INFO GET /health <n> <n>ms",
		"ERROR redis: connection refused <ip>:<n>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "slow query") {
		t.Errorf("-top 3 printed a fourth pattern\n---\n%s", out)
	}
	if !strings.Contains(out, "4 more patterns not shown") {
		t.Errorf("missing the truncation hint\n---\n%s", out)
	}
}

func TestRunShowsAllWithZeroTop(t *testing.T) {
	out, err := runWith(t, "-top", "0", sample)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "more patterns not shown") {
		t.Error("-top 0 truncated the table")
	}
	if !strings.Contains(out, "slow query") {
		t.Error("-top 0 dropped a pattern")
	}
}

func TestRunJSON(t *testing.T) {
	out, err := runWith(t, "-json", "-top", "2", sample)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	var got struct {
		Sources  []string `json:"sources"`
		Records  int      `json:"records"`
		Patterns int      `json:"patterns"`
		Groups   []struct {
			Pattern string `json:"pattern"`
			Count   int    `json:"count"`
			Level   string `json:"level"`
			Last    string `json:"last"`
			Sample  string `json:"sample"`
		} `json:"groups"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if got.Records != 20 || got.Patterns != 7 || len(got.Groups) != 2 {
		t.Fatalf("records=%d patterns=%d groups=%d", got.Records, got.Patterns, len(got.Groups))
	}
	if len(got.Sources) != 1 {
		t.Errorf("sources = %v, want the single test log", got.Sources)
	}
	if got.Groups[0].Count != 5 {
		t.Errorf("top group count = %d, want 5", got.Groups[0].Count)
	}
	if got.Groups[0].Level != "info" {
		t.Errorf("top group level = %q, want info", got.Groups[0].Level)
	}
	if got.Groups[0].Last == "" {
		t.Error("last seen timestamp is missing from the JSON")
	}
	if strings.Contains(out, "10.4.19.7") {
		t.Errorf("an IP address survived masking\n%s", out)
	}
	if !strings.Contains(out, "<ip>") {
		t.Errorf("expected a masked IP placeholder\n%s", out)
	}
}

func TestRunMaskFalseKeepsTheRawLine(t *testing.T) {
	out, err := runWith(t, "-json", "-mask=false", sample)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "10.4.19.7") {
		t.Errorf("-mask=false still masked the sample\n%s", out)
	}
}

func TestRunReadsStandardInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	stdin := strings.NewReader("2026-11-05 09:00:01 ERROR boom\n2026-11-05 09:00:02 ERROR boom\n")
	if err := run(nil, stdin, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(stdout.String(), "2 records, 1 pattern") {
		t.Errorf("unexpected output:\n%s", stdout.String())
	}
}

func TestRunFiltersByLevel(t *testing.T) {
	out, err := runWith(t, "-level", "error", "-top", "0", sample)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "GET /health") {
		t.Errorf("-level error kept an info pattern\n%s", out)
	}
	if !strings.Contains(out, "redis") {
		t.Errorf("-level error dropped an error pattern\n%s", out)
	}
}

func TestRunRejectsBadSince(t *testing.T) {
	_, err := runWith(t, "-since", "yesterday", sample)
	if err == nil || !strings.Contains(err.Error(), "-since") {
		t.Fatalf("err = %v, want a -since hint", err)
	}
}

func TestRunMissingFile(t *testing.T) {
	_, err := runWith(t, "does-not-exist.log")
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestComma(t *testing.T) {
	cases := map[int]string{0: "0", 7: "7", 1234: "1,234", 1234567: "1,234,567", -1234: "-1,234"}
	for n, want := range cases {
		if got := comma(n); got != want {
			t.Errorf("comma(%d) = %q, want %q", n, got, want)
		}
	}
}
