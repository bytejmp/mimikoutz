package main

import (
	"fmt"
	"io"
	"os"

	"github.com/bytejmp/mimikoutz/internal/formatter"
	"github.com/bytejmp/mimikoutz/internal/parser"
)

var stderr = os.Stderr

func main() {
	cfg := parseFlags()

	if cfg.NoColor {
		formatter.DisableColor()
	}
	if !cfg.NoBanner {
		printBanner()
	}

	credentials, err := parseInputs(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "parse error: %v\n", err)
		os.Exit(1)
	}

	credentials = parser.Deduplicate(credentials)

	if cfg.DiffFile != "" {
		baseline, err := parseFile(cfg.DiffFile)
		if err != nil {
			fmt.Fprintf(stderr, "diff baseline error: %v\n", err)
			os.Exit(1)
		}
		baseline = parser.Deduplicate(baseline)
		credentials = parser.Diff(baseline, credentials)
		fmt.Fprintf(stderr, "[*] diff mode: comparing against %s\n", cfg.DiffFile)
	}

	parser.TagCredentials(credentials)
	credentials = parser.ApplyFilters(credentials, cfg.Filter)
	parser.Sort(credentials)

	var output io.Writer
	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		output = f
	} else {
		output = os.Stdout
	}

	if err := formatOutput(output, cfg.Format, credentials); err != nil {
		fmt.Fprintf(stderr, "format error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(stderr, "\n[*] %d unique credentials found\n", len(credentials))

	if cfg.ShowStats {
		stats := parser.ComputeStats(credentials)
		parser.PrintStats(stderr, stats)

		paths := parser.DetectPathToDA(credentials)
		if len(paths) > 0 {
			parser.PrintPathToDA(stderr, paths)
		}

		reuse := parser.DetectPasswordReuse(credentials)
		if len(reuse) > 0 {
			parser.PrintPasswordReuse(stderr, reuse)
		}

		krbTargets := parser.DetectKerberoastable(credentials)
		if len(krbTargets) > 0 {
			parser.PrintKerberoastable(stderr, krbTargets)
		}
	}

	if cfg.ShowNXC {
		parser.PrintNXCCommands(stderr, credentials)
	}
}

func parseInputs(cfg Config) ([]parser.Credential, error) {
	if len(cfg.InputFiles) > 0 {
		var all []parser.Credential
		for _, path := range cfg.InputFiles {
			creds, err := parseFile(path)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			all = append(all, creds...)
		}
		return all, nil
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		printUsage()
		os.Exit(1)
	}
	return parser.ParseAuto(os.Stdin)
}

func parseFile(path string) ([]parser.Credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parser.ParseAuto(f)
}

func formatOutput(w io.Writer, format string, creds []parser.Credential) error {
	switch format {
	case "csv":
		return formatter.CSV(w, creds)
	case "json":
		return formatter.JSON(w, creds)
	case "grep":
		return formatter.Grep(w, creds)
	case "hashcat":
		return formatter.Hashcat(w, creds)
	case "john":
		return formatter.John(w, creds)
	case "secretsdump":
		return formatter.SecretsDump(w, creds)
	default:
		return formatter.Table(w, creds)
	}
}
