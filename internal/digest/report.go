package digest

import (
	"regexp"
	"sort"
	"strings"
	"time"
)

// Options controls how records are filtered and folded into a report. The zero
// value means "everything, in the order it happened, with masking on".
type Options struct {
	// Top keeps only the first N groups after sorting. Zero or negative keeps all.
	Top int
	// MinCount drops groups seen fewer times. Zero keeps all.
	MinCount int
	// Since drops records older than this. Records without a timestamp are
	// always kept, because they cannot be placed on the timeline.
	Since time.Time
	// Level keeps groups at or above this level (error, warn, info, ...).
	Level string
	// Mask replaces IPs, emails and ids in the sample line.
	Mask bool
}

// Group is one row: an event, how often it happened, and its first/last
// occurrence.
type Group struct {
	Template string
	Count    int
	First    time.Time
	Last     time.Time
	Level    string
	Sample   string
	Sources  []string
}

// Report is the whole table.
type Report struct {
	Sources  []string
	Records  int
	Patterns int
	Groups   []Group
}

var levelRank = map[string]int{
	"critical": 4,
	"fatal":    4,
	"panic":    4,
	"error":    3,
	"warn":     2,
	"warning":  2,
	"info":     1,
	"debug":    0,
	"trace":    0,
}

var levelRe = regexp.MustCompile(`(?i)\b(fatal|critical|panic|error|warn|warning|info|debug|trace)\b`)

// detectLevel reads the severity out of the message itself. It looks at the
// first line only: a stack trace below an INFO line mentions plenty of errors.
func detectLevel(body string) string {
	m := levelRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	level := strings.ToLower(m[1])
	if level == "warning" {
		level = "warn"
	}
	return strings.ToUpper(level)
}

func rank(level string) int {
	if level == "" {
		return -1
	}
	return levelRank[strings.ToLower(level)]
}

// Build groups records by fingerprint and returns them ordered by how often
// they happened, most frequent first.
func Build(recs []Record, opts Options) Report {
	var rep Report
	byFingerprint := make(map[string]*Group, len(recs))
	seenSource := make(map[string]bool)
	minRank := -1
	if opts.Level != "" {
		minRank = rank(opts.Level)
	}

	for _, rec := range recs {
		if !opts.Since.IsZero() && rec.HasTime && rec.Time.Before(opts.Since) {
			continue
		}
		level := detectLevel(rec.Body)
		if rank(level) < minRank {
			continue
		}
		fingerprint := Fingerprint(rec)
		if fingerprint == "" {
			continue
		}

		group, ok := byFingerprint[fingerprint]
		if !ok {
			sample := strings.TrimSpace(rec.Body)
			if opts.Mask {
				sample = MaskText(sample)
			}
			group = &Group{Template: Template(fingerprint), Sample: sample}
			byFingerprint[fingerprint] = group
		}

		group.Count++
		rep.Records++
		if group.Level == "" {
			// The severity word lives in the message, so it is part of the
			// fingerprint and every member of a group agrees on it.
			group.Level = level
		}
		if rec.HasTime {
			if group.First.IsZero() || rec.Time.Before(group.First) {
				group.First = rec.Time
			}
			if rec.Time.After(group.Last) {
				group.Last = rec.Time
			}
		}
		if rec.Source != "" && !contains(group.Sources, rec.Source) {
			group.Sources = append(group.Sources, rec.Source)
		}
		if rec.Source != "" && !seenSource[rec.Source] {
			seenSource[rec.Source] = true
			rep.Sources = append(rep.Sources, rec.Source)
		}
	}

	for _, group := range byFingerprint {
		rep.Groups = append(rep.Groups, *group)
	}
	rep.Patterns = len(rep.Groups)

	if opts.MinCount > 1 {
		kept := rep.Groups[:0]
		for _, group := range rep.Groups {
			if group.Count >= opts.MinCount {
				kept = append(kept, group)
			}
		}
		rep.Groups = kept
	}

	sort.Slice(rep.Groups, func(i, j int) bool {
		a, b := rep.Groups[i], rep.Groups[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if !a.Last.Equal(b.Last) {
			return a.Last.After(b.Last)
		}
		return a.Template < b.Template
	})

	if opts.Top > 0 && len(rep.Groups) > opts.Top {
		rep.Groups = rep.Groups[:opts.Top]
	}
	return rep
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
