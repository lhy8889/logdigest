// Package digest turns a noisy log file into a small table: one row per
// distinct event, with how often it happened and when it was last seen.
//
// The two halves are deliberately separate. Split turns lines into records
// (a timestamped line plus the stack trace that belongs to it), and Build
// groups those records by a normalised fingerprint, so that
//
//	GET /orders/8812 failed after 312ms
//	GET /orders/99031 failed after 1204ms
//
// become one row: GET /orders/<n> failed after <n>ms.
package digest

import (
	"bufio"
	"io"
	"regexp"
	"strings"
	"time"
)

// maxRecordLines caps how many continuation lines a single record may absorb.
// A log that loses its newlines should not turn into one record holding the
// whole file.
const maxRecordLines = 200

// Record is one log event: a timestamped line plus any continuation lines that
// belong to it, such as a stack trace.
type Record struct {
	// Time is the parsed timestamp, valid only when HasTime is true.
	Time    time.Time
	HasTime bool
	// Body is the first line with the timestamp stripped.
	Body string
	// Lines holds every line of the event, the first one already stripped.
	Lines []string
	// Source is the file the record came from, or "-" for standard input.
	Source string
}

// Text joins the record's lines, which is what the fingerprint is built from.
func (r Record) Text() string {
	if len(r.Lines) == 1 {
		return r.Lines[0]
	}
	return strings.Join(r.Lines, "\n")
}

var (
	// 2026-11-05 12:00:01, 2026-11-05T12:00:01.123Z, 2026/11/05 12:00:01+08:00
	stampRe = regexp.MustCompile(`^\s*[\[\(]?(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)`)
	// Nov  5 12:00:01 (syslog, no year)
	syslogRe = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})`)
	// [05/Nov/2026:12:00:01 +0800 (Apache)
	apacheRe = regexp.MustCompile(`^\s*\[?(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})`)
)

var stampLayouts = []string{
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006/01/02 15:04:05.999999999",
	"2006/01/02 15:04:05",
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
}

// Split reads r and returns its records. now supplies the year for timestamp
// formats that leave it out; pass time.Now() in production and a fixed value in
// tests.
func Split(r io.Reader, source string, now time.Time) ([]Record, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var lines []string
	for sc.Scan() {
		lines = append(lines, strings.TrimRight(sc.Text(), "\r"))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return splitLines(lines, source, now), nil
}

func splitLines(lines []string, source string, now time.Time) []Record {
	// A file whose lines never carry a timestamp is the simple case: one line,
	// one record. Deciding this up front keeps a bare `docker logs` dump from
	// collapsing into a single blob.
	sawStamp := false
	for _, line := range lines {
		if _, _, ok := parseStamp(line, now); ok {
			sawStamp = true
			break
		}
	}

	var recs []Record
	for _, line := range lines {
		stamp, body, ok := parseStamp(line, now)
		if ok || !sawStamp {
			if !ok {
				body = strings.TrimSpace(line)
			}
			if body == "" && !ok {
				continue
			}
			rec := Record{Source: source, Body: body, Lines: []string{body}}
			if ok {
				rec.Time, rec.HasTime = stamp, true
			}
			recs = append(recs, rec)
			continue
		}

		if len(recs) == 0 {
			body := strings.TrimSpace(line)
			recs = append(recs, Record{Source: source, Body: body, Lines: []string{body}})
			continue
		}
		last := &recs[len(recs)-1]
		if len(last.Lines) < maxRecordLines {
			last.Lines = append(last.Lines, strings.TrimRight(line, " \t"))
		}
	}
	return recs
}

// parseStamp returns the timestamp of a line and the line with that timestamp
// removed. ok is false when the line does not start with a timestamp.
func parseStamp(line string, now time.Time) (time.Time, string, bool) {
	for i, re := range []*regexp.Regexp{stampRe, apacheRe, syslogRe} {
		m := re.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		raw := line[m[2]:m[3]]
		var t time.Time
		var err error
		switch i {
		case 1:
			t, err = time.Parse("02/Jan/2006:15:04:05 -0700", raw)
		case 2:
			t, err = time.ParseInLocation("Jan _2 15:04:05", raw, time.Local)
			if err == nil {
				t = t.AddDate(now.Year(), 0, 0)
			}
		default:
			t, err = parseLayouts(raw)
		}
		if err != nil {
			continue
		}
		return t, cleanBody(line[m[1]:]), true
	}
	return time.Time{}, "", false
}

func parseLayouts(raw string) (time.Time, error) {
	candidate := strings.Replace(raw, ",", ".", 1)
	var firstErr error
	// ParseInLocation rather than Parse: a log line without an offset is almost
	// always local time, and treating it as UTC would shift every row by the
	// machine's offset. Layouts that do carry an offset keep it.
	for _, layout := range stampLayouts {
		t, err := time.ParseInLocation(layout, candidate, time.Local)
		if err == nil {
			return t, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	// 2026-11-05T12:00:01+0800 uses the offset without a colon.
	if t, err := time.ParseInLocation("2006-01-02T15:04:05Z0700", candidate, time.Local); err == nil {
		return t, nil
	}
	return time.Time{}, firstErr
}

// cleanBody strips the punctuation that usually separates a timestamp from the
// message: "] ", "- ", "| " and the like.
func cleanBody(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "]|-:>\t ")
	return strings.TrimSpace(s)
}
