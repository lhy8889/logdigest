package digest

import (
	"strings"
	"testing"
	"time"
)

// fixedNow keeps the syslog year stable across machines and years.
var fixedNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.Local)

func split(t *testing.T, log string) []Record {
	t.Helper()
	recs, err := Split(strings.NewReader(log), "app.log", fixedNow)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	return recs
}

func TestSplitKeepsStackTraceWithItsLine(t *testing.T) {
	recs := split(t, `2026-11-05 09:00:11 ERROR upstream timeout
    at payment.Client.Charge (/srv/app/payment/client.go:214)
    at orders.(*Service).Create (/srv/app/orders/service.go:88)
2026-11-05 09:00:12 INFO recovered
`)

	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if got := len(recs[0].Lines); got != 3 {
		t.Fatalf("first record has %d lines, want 3", got)
	}
	if recs[0].Body != "ERROR upstream timeout" {
		t.Errorf("body = %q", recs[0].Body)
	}
	if !recs[0].HasTime {
		t.Error("first record lost its timestamp")
	}
	want := time.Date(2026, 11, 5, 9, 0, 11, 0, time.Local)
	if !recs[0].Time.Equal(want) {
		t.Errorf("time = %v, want %v", recs[0].Time, want)
	}
}

func TestSplitWithoutTimestampsTreatsLinesAsRecords(t *testing.T) {
	recs := split(t, "cache miss for key a\ncache miss for key b\n")

	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (one per line)", len(recs))
	}
	if recs[0].HasTime {
		t.Error("record without a timestamp was marked as having one")
	}
	if recs[1].Body != "cache miss for key b" {
		t.Errorf("second body = %q", recs[1].Body)
	}
}

func TestSplitRecognisesCommonTimestampFormats(t *testing.T) {
	cases := []struct {
		name string
		line string
		want time.Time
	}{
		{"iso space", "2026-11-05 09:00:11 hello", time.Date(2026, 11, 5, 9, 0, 11, 0, time.Local)},
		{"slash", "2026/11/05 09:00:11 hello", time.Date(2026, 11, 5, 9, 0, 11, 0, time.Local)},
		{"bracketed", "[2026-11-05 09:00:11] hello", time.Date(2026, 11, 5, 9, 0, 11, 0, time.Local)},
		{"rfc3339 utc", "2026-11-05T09:00:11Z hello", time.Date(2026, 11, 5, 9, 0, 11, 0, time.UTC)},
		{"fraction", "2026-11-05 09:00:11.250 hello", time.Date(2026, 11, 5, 9, 0, 11, 250_000_000, time.Local)},
		{"syslog", "Nov  5 09:00:11 host app[7]: hello", time.Date(2026, 11, 5, 9, 0, 11, 0, time.Local)},
		{"apache", `[05/Nov/2026:09:00:11 +0800] "GET / HTTP/1.1"`, time.Date(2026, 11, 5, 1, 0, 11, 0, time.UTC)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recs := split(t, tc.line+"\n")
			if len(recs) != 1 {
				t.Fatalf("got %d records, want 1", len(recs))
			}
			if !recs[0].HasTime {
				t.Fatalf("no timestamp parsed from %q", tc.line)
			}
			if got := recs[0].Time.UTC(); !got.Equal(tc.want.UTC()) {
				t.Errorf("time = %v, want %v", recs[0].Time.UTC(), tc.want.UTC())
			}
			if strings.ContainsAny(recs[0].Body[:1], "[]") {
				t.Errorf("body still carries the timestamp punctuation: %q", recs[0].Body)
			}
		})
	}
}

func TestFingerprintCollapsesVolatileParts(t *testing.T) {
	a := Record{Lines: []string{"GET /orders/8812 failed after 312ms from 10.4.19.7"}}
	b := Record{Lines: []string{"GET /orders/99031 failed after 1204ms from 10.4.19.8"}}

	fa, fb := Fingerprint(a), Fingerprint(b)
	if fa != fb {
		t.Fatalf("fingerprints differ:\n  %q\n  %q", fa, fb)
	}
	if want := "GET /orders/<n> failed after <n>ms from <ip>"; fa != want {
		t.Errorf("fingerprint = %q, want %q", fa, want)
	}
}

func TestFingerprintKeepsDifferentEventsApart(t *testing.T) {
	a := Record{Lines: []string{"ERROR redis: connection refused 127.0.0.1:6379"}}
	b := Record{Lines: []string{"ERROR postgres: connection refused 127.0.0.1:5432"}}

	if Fingerprint(a) == Fingerprint(b) {
		t.Error("two different errors share a fingerprint")
	}
}

func TestFingerprintIncludesContinuationLines(t *testing.T) {
	a := Record{Lines: []string{"ERROR boom", "  at a (x.go:1)"}}
	b := Record{Lines: []string{"ERROR boom", "  at b (x.go:2)"}}
	c := Record{Lines: []string{"ERROR boom", "  at a (x.go:1)"}}

	if Fingerprint(a) == Fingerprint(b) {
		t.Error("stack traces from different call sites share a fingerprint")
	}
	if Fingerprint(a) != Fingerprint(c) {
		t.Error("identical stack traces got different fingerprints")
	}
}

func TestTemplateSummarisesContinuationLines(t *testing.T) {
	rec := Record{Lines: []string{"ERROR boom", "  at a (x.go:1)", "  at b (x.go:2)"}}
	if got, want := Template(Fingerprint(rec)), "ERROR boom (+2 lines)"; got != want {
		t.Errorf("template = %q, want %q", got, want)
	}
}

func TestMaskTextKeepsNumbers(t *testing.T) {
	got := MaskText("timeout after 3001ms from 10.4.19.7 for user 4f1c8e22-7d3b-4c1a-9e55-1c2b3a4d5e6f")
	want := "timeout after 3001ms from <ip> for user <uuid>"
	if got != want {
		t.Errorf("MaskText = %q, want %q", got, want)
	}
}

func TestBuildOrdersByCount(t *testing.T) {
	recs := concat(
		record("ERROR rare", 3),
		record("INFO common", 1),
		record("WARN middling", 2),
	)
	rep := Build(recs, Options{Mask: true})

	if len(rep.Groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(rep.Groups))
	}
	want := []int{3, 2, 1}
	for i, count := range want {
		if rep.Groups[i].Count != count {
			t.Errorf("group %d count = %d, want %d", i, rep.Groups[i].Count, count)
		}
	}
	if rep.Records != 6 {
		t.Errorf("records = %d, want 6", rep.Records)
	}
}

func TestBuildBreaksTiesByMostRecent(t *testing.T) {
	older := record("ERROR older", 2)
	for i := range older {
		older[i].Time = time.Date(2026, 11, 5, 9, 0, i, 0, time.Local)
		older[i].HasTime = true
	}
	newer := record("ERROR newer", 2)
	for i := range newer {
		newer[i].Time = time.Date(2026, 11, 5, 10, 0, i, 0, time.Local)
		newer[i].HasTime = true
	}

	rep := Build(concat(older, newer), Options{})
	if rep.Groups[0].Sample != "ERROR newer" {
		t.Errorf("first row = %q, want the most recent event", rep.Groups[0].Sample)
	}
	if !rep.Groups[0].Last.After(rep.Groups[1].Last) {
		t.Error("last-seen ordering is wrong")
	}
}

func TestBuildRecordsFirstAndLastSeen(t *testing.T) {
	recs := []Record{
		{Body: "ERROR boom", Lines: []string{"ERROR boom"}, HasTime: true, Time: time.Date(2026, 11, 5, 9, 0, 0, 0, time.Local)},
		{Body: "ERROR boom", Lines: []string{"ERROR boom"}, HasTime: true, Time: time.Date(2026, 11, 5, 9, 30, 0, 0, time.Local)},
		{Body: "ERROR boom", Lines: []string{"ERROR boom"}, HasTime: true, Time: time.Date(2026, 11, 5, 9, 15, 0, 0, time.Local)},
	}
	rep := Build(recs, Options{})
	group := rep.Groups[0]

	if !group.First.Equal(time.Date(2026, 11, 5, 9, 0, 0, 0, time.Local)) {
		t.Errorf("first = %v", group.First)
	}
	if !group.Last.Equal(time.Date(2026, 11, 5, 9, 30, 0, 0, time.Local)) {
		t.Errorf("last = %v", group.Last)
	}
}

func TestBuildFiltersBySinceButKeepsUntimedRecords(t *testing.T) {
	timed := []Record{
		{Body: "ERROR old", Lines: []string{"ERROR old"}, HasTime: true, Time: time.Date(2026, 11, 5, 8, 0, 0, 0, time.Local)},
		{Body: "ERROR new", Lines: []string{"ERROR new"}, HasTime: true, Time: time.Date(2026, 11, 5, 11, 0, 0, 0, time.Local)},
		{Body: "ERROR no timestamp", Lines: []string{"ERROR no timestamp"}},
	}
	cutoff := time.Date(2026, 11, 5, 10, 0, 0, 0, time.Local)
	rep := Build(timed, Options{Since: cutoff})

	if len(rep.Groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(rep.Groups))
	}
	for _, group := range rep.Groups {
		if group.Sample == "ERROR old" {
			t.Error("-since kept a record older than the cutoff")
		}
	}
}

func TestBuildFiltersByLevel(t *testing.T) {
	recs := concat(
		record("INFO all good", 1),
		record("WARN slow query", 1),
		record("ERROR boom", 1),
		record("panic: nil map", 1),
	)
	rep := Build(recs, Options{Level: "error"})

	if len(rep.Groups) != 2 {
		t.Fatalf("got %d groups, want the error and panic ones", len(rep.Groups))
	}
	for _, group := range rep.Groups {
		if group.Level != "ERROR" && group.Level != "PANIC" {
			t.Errorf("kept %q (%s)", group.Sample, group.Level)
		}
	}
}

func TestBuildDetectsLevelFromMessage(t *testing.T) {
	cases := map[string]string{
		"ERROR boom":                 "ERROR",
		"warning: retrying":          "WARN",
		"Traceback (most recent)":    "",
		"panic: assignment to entry": "PANIC",
	}
	for body, want := range cases {
		rep := Build(record(body, 1), Options{})
		if got := rep.Groups[0].Level; got != want {
			t.Errorf("%q detected as %q, want %q", body, got, want)
		}
	}
}

func TestBuildMinCountAndTop(t *testing.T) {
	recs := append(record("ERROR often", 5), record("ERROR once", 1)...)
	rep := Build(recs, Options{MinCount: 2})
	if len(rep.Groups) != 1 {
		t.Fatalf("min count kept %d groups, want 1", len(rep.Groups))
	}

	recs = append(record("ERROR a", 3), record("ERROR b", 2)...)
	rep = Build(recs, Options{Top: 1})
	if len(rep.Groups) != 1 {
		t.Fatalf("top kept %d groups, want 1", len(rep.Groups))
	}
	if rep.Patterns != 2 {
		t.Errorf("patterns = %d, want 2 (top truncates the view, not the count)", rep.Patterns)
	}
}

func TestBuildSampleHonoursMasking(t *testing.T) {
	recs := []Record{{Body: "ERROR timeout from 10.4.19.7 after 3001ms", Lines: []string{"ERROR timeout from 10.4.19.7 after 3001ms"}}}

	masked := Build(recs, Options{Mask: true}).Groups[0].Sample
	if masked != "ERROR timeout from <ip> after 3001ms" {
		t.Errorf("masked sample = %q", masked)
	}

	raw := Build(recs, Options{Mask: false}).Groups[0].Sample
	if raw != "ERROR timeout from 10.4.19.7 after 3001ms" {
		t.Errorf("raw sample = %q", raw)
	}
}

func TestBuildCollectsSources(t *testing.T) {
	a := record("ERROR boom", 1)
	a[0].Source = "app.log"
	b := record("ERROR boom", 1)
	b[0].Source = "app.log.1"
	c := record("INFO ok", 1)
	c[0].Source = "app.log"

	rep := Build(concat(a, b, c), Options{})
	if len(rep.Sources) != 2 {
		t.Errorf("sources = %v, want 2 unique files", rep.Sources)
	}
	for _, group := range rep.Groups {
		if group.Sample == "ERROR boom" && len(group.Sources) != 2 {
			t.Errorf("group sources = %v, want both files", group.Sources)
		}
	}
}

// record builds n copies of the same event, so counting tests do not have to
// repeat themselves.
func record(body string, n int) []Record {
	recs := make([]Record, n)
	for i := range recs {
		recs[i] = Record{Body: body, Lines: []string{body}}
	}
	return recs
}

// concat keeps the counting tests readable when they need several groups.
func concat(groups ...[]Record) []Record {
	var all []Record
	for _, g := range groups {
		all = append(all, g...)
	}
	return all
}
