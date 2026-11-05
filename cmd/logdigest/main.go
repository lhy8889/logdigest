// Command logdigest folds a noisy log into one row per distinct event.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lhy8889/logdigest/internal/digest"
)

const usageText = `logdigest - collapse a noisy log into one row per distinct event

  logdigest [flags] [file...]        read the files, or standard input if none
  tail -n 20000 app.log | logdigest -top 10

Flags:
`

// version is replaced at build time, e.g. -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "logdigest: %v\n", err)
		os.Exit(2)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("logdigest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	top := fs.Int("top", 20, "show at most N patterns (0 shows all)")
	minCount := fs.Int("min", 1, "drop patterns seen fewer times than N")
	since := fs.String("since", "", "only records newer than this: 2h, 90m, 2026-11-01 or an RFC3339 time")
	level := fs.String("level", "", "keep patterns at or above this level: error, warn, info, debug")
	jsonOut := fs.Bool("json", false, "print JSON instead of a table")
	mask := fs.Bool("mask", true, "mask IPs, emails and long ids in the sample line")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprint(stderr, usageText)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	now := time.Now()
	if *showVersion {
		fmt.Fprintf(stdout, "logdigest %s\n", version)
		return nil
	}

	cutoff, err := parseSince(*since, now)
	if err != nil {
		return err
	}

	sources := fs.Args()
	if len(sources) == 0 {
		sources = []string{"-"}
	}

	var recs []digest.Record
	for _, name := range sources {
		if name == "-" {
			part, err := digest.Split(stdin, "-", now)
			if err != nil {
				return fmt.Errorf("standard input: %w", err)
			}
			recs = append(recs, part...)
			continue
		}
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		part, err := digest.Split(file, name, now)
		file.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		recs = append(recs, part...)
	}

	report := digest.Build(recs, digest.Options{
		Top:      *top,
		MinCount: *minCount,
		Since:    cutoff,
		Level:    *level,
		Mask:     *mask,
	})

	if *jsonOut {
		return writeJSON(stdout, report)
	}
	writeTable(stdout, report)
	return nil
}

func parseSince(value string, now time.Time) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(value); err == nil {
		return now.Add(-d), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot read -since %q: use 2h, 90m, 2026-11-01 or 2026-11-01T09:00:00Z", value)
}

func writeTable(w io.Writer, report digest.Report) {
	if report.Records == 0 {
		fmt.Fprintln(w, "no records")
		return
	}

	fmt.Fprintf(w, "%s, %s, %s\n\n",
		plural(len(report.Sources), "file"),
		plural(report.Records, "record"),
		plural(report.Patterns, "pattern"))

	countWidth := len("count")
	for _, group := range report.Groups {
		if n := len(comma(group.Count)); n > countWidth {
			countWidth = n
		}
	}

	fmt.Fprintf(w, "%*s  %-5s  %-19s  %s\n", countWidth, "COUNT", "LEVEL", "LAST SEEN", "PATTERN")
	for _, group := range report.Groups {
		level := group.Level
		if level == "" {
			level = "-"
		}
		last := "-"
		if !group.Last.IsZero() {
			last = group.Last.Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(w, "%*s  %-5s  %-19s  %s\n", countWidth, comma(group.Count), strings.ToLower(level), last, group.Template)
	}
	if len(report.Groups) < report.Patterns {
		fmt.Fprintf(w, "\n%d more patterns not shown, use -top 0 to see them all\n", report.Patterns-len(report.Groups))
	}
}

type jsonGroup struct {
	Pattern string   `json:"pattern"`
	Count   int      `json:"count"`
	Level   string   `json:"level,omitempty"`
	First   string   `json:"first,omitempty"`
	Last    string   `json:"last,omitempty"`
	Sources []string `json:"sources,omitempty"`
	Sample  string   `json:"sample"`
}

type jsonReport struct {
	Sources  []string    `json:"sources"`
	Records  int         `json:"records"`
	Patterns int         `json:"patterns"`
	Groups   []jsonGroup `json:"groups"`
}

func writeJSON(w io.Writer, report digest.Report) error {
	out := jsonReport{Sources: report.Sources, Records: report.Records, Patterns: report.Patterns}
	for _, group := range report.Groups {
		item := jsonGroup{
			Pattern: group.Template,
			Count:   group.Count,
			Level:   strings.ToLower(group.Level),
			Sources: group.Sources,
			Sample:  group.Sample,
		}
		if !group.First.IsZero() {
			item.First = group.First.Format(time.RFC3339)
		}
		if !group.Last.IsZero() {
			item.Last = group.Last.Format(time.RFC3339)
		}
		out.Groups = append(out.Groups, item)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Placeholders like <ip> are meant to be read, not escaped to \u003cip.
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

func comma(n int) string {
	sign := ""
	if n < 0 {
		sign, n = "-", -n
	}
	digits := strconv.Itoa(n)
	var b strings.Builder
	for i, digit := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(digit)
	}
	return sign + b.String()
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return comma(n) + " " + word + "s"
}
