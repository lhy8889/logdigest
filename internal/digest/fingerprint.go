package digest

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	// maxFingerprintBytes caps the text a fingerprint is computed from, so a
	// huge stack trace still groups with its shorter siblings.
	maxFingerprintBytes = 2000
	// maxTemplateRunes caps the one-line label shown in the table.
	maxTemplateRunes = 150
)

// Volatile tokens, in the order they are replaced. Each entry collapses one
// thing that differs between two occurrences of the same event.
var replacers = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`), "<uuid>"},
	{regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), "<ip>"},
	{regexp.MustCompile(`\b[0-9A-Za-z._%+\-]+@[0-9A-Za-z.\-]+\.[A-Za-z]{2,}\b`), "<email>"},
	{regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`), "<hex>"},
	{regexp.MustCompile(`\d+(?:[.,]\d+)?`), "<n>"},
	{regexp.MustCompile(`\s+`), " "},
}

// Fingerprint is the identity of an event: its text with the volatile parts
// replaced by placeholders. Two records with the same fingerprint are counted
// as one row.
func Fingerprint(rec Record) string {
	text := rec.Text()
	if len(text) > maxFingerprintBytes {
		text = text[:maxFingerprintBytes]
	}
	// Truncating bytes can split a multi-byte rune; drop the remainder.
	text = strings.ToValidUTF8(text, "")
	return normalize(text)
}

// Template is the readable one-line form of a fingerprint, used as the row
// label. Continuation lines are summarised rather than printed.
func Template(fingerprint string) string {
	line := fingerprint
	extra := 0
	if i := strings.IndexByte(fingerprint, '\n'); i >= 0 {
		line = fingerprint[:i]
		extra = strings.Count(fingerprint[i+1:], "\n") + 1
	}
	line = truncate(line, maxTemplateRunes)
	if extra > 0 {
		line += " (+" + strconv.Itoa(extra) + " lines)"
	}
	return line
}

// MaskText replaces the identifying parts of a raw line: IPs, emails, UUIDs and
// long hex ids. Numbers are kept, so a sample still shows the real timeout.
func MaskText(s string) string {
	for _, r := range replacers[:4] {
		s = r.re.ReplaceAllString(s, r.with)
	}
	return strings.TrimSpace(s)
}

// normalize collapses the volatile parts of every line but keeps the line
// breaks: a stack trace and the message it belongs to are one event, and
// Template counts the continuation lines from the separators.
func normalize(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		for _, r := range replacers {
			line = r.re.ReplaceAllString(line, r.with)
		}
		lines[i] = strings.TrimSpace(line)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return strings.TrimRight(string(runes[:max]), " ") + " …"
}
