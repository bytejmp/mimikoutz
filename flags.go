package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bytejmp/mimikoutz/internal/parser"
)

type multiString []string

func (m *multiString) String() string { return strings.Join(*m, ", ") }
func (m *multiString) Set(val string) error {
	*m = append(*m, val)
	return nil
}

type Config struct {
	InputFiles multiString
	OutputFile string
	Format     string
	NoColor    bool
	NoBanner   bool
	Filter     parser.Filter
	ShowStats  bool
	ShowNXC    bool
	DiffFile   string
}

func parseFlags() Config {
	var cfg Config
	flag.Var(&cfg.InputFiles, "i", "input file(s), can be repeated (default: stdin)")
	flag.StringVar(&cfg.OutputFile, "o", "", "output file (default: stdout)")
	flag.StringVar(&cfg.Format, "f", "table", "output format: table, csv, json, grep, hashcat, john, secretsdump")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "disable colored output")
	flag.BoolVar(&cfg.NoBanner, "no-banner", false, "suppress banner")
	flag.BoolVar(&cfg.NoBanner, "s", false, "suppress banner (alias for --no-banner)")
	flag.BoolVar(&cfg.NoBanner, "silent", false, "suppress banner (alias for --no-banner)")
	flag.BoolVar(&cfg.ShowStats, "stats", false, "show credential statistics")
	flag.BoolVar(&cfg.ShowNXC, "nxc", false, "show nxc/netexec lateral movement commands")
	flag.StringVar(&cfg.DiffFile, "diff", "", "diff against another dump file (show new creds only)")

	flag.StringVar(&cfg.Filter.Username, "u", "", "filter by username")
	flag.StringVar(&cfg.Filter.Domain, "d", "", "filter by domain")
	flag.BoolVar(&cfg.Filter.HasPassword, "has-password", false, "only show entries with plaintext password")
	flag.BoolVar(&cfg.Filter.HasHash, "has-hash", false, "only show entries with hash")
	flag.BoolVar(&cfg.Filter.NoMachine, "no-machine", false, "exclude machine accounts ($)")

	flag.Usage = func() { printUsage() }
	flag.Parse()

	if len(cfg.InputFiles) == 0 && flag.NArg() > 0 {
		for _, arg := range flag.Args() {
			if _, err := os.Stat(arg); err == nil {
				cfg.InputFiles = append(cfg.InputFiles, arg)
			}
		}
	}

	return cfg
}

func printUsage() {
	fmt.Fprintln(stderr, "usage: mimikoutz [-i file [-i file2]] [-f format] [-o output] [filters]")
	fmt.Fprintln(stderr, "       cat mimikatz.log | mimikoutz")
	fmt.Fprintln(stderr, "       mimikoutz -i dump1.txt -i dump2.txt --stats")
	fmt.Fprintln(stderr, "       nxc smb 10.0.0.0/24 --sam | mimikoutz --nxc")
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "input formats auto-detected: mimikatz, secretsdump, pypykatz, nxc/netexec")
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "output formats: table (default), csv, json, grep, hashcat, john, secretsdump")
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "filters:")
	fmt.Fprintln(stderr, "  -u <user>       filter by username")
	fmt.Fprintln(stderr, "  -d <domain>     filter by domain")
	fmt.Fprintln(stderr, "  --has-password  only plaintext passwords")
	fmt.Fprintln(stderr, "  --has-hash      only entries with hash")
	fmt.Fprintln(stderr, "  --no-machine    exclude machine accounts ($)")
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "diff:")
	fmt.Fprintln(stderr, "  --diff <file>   compare against baseline, show only new credentials")
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "AD analysis (auto):")
	fmt.Fprintln(stderr, "  privilege tagging     [DA] [EA] [PRIV] [SVC] [MACHINE] [KRBAST]")
	fmt.Fprintln(stderr, "  path-to-DA detection  alerts when DA/EA creds captured")
	fmt.Fprintln(stderr, "  password reuse        groups users sharing same hash/password")
	fmt.Fprintln(stderr, "  kerberoastable        flags service accounts for offline cracking")
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "options:")
	fmt.Fprintln(stderr, "  --stats         show credential statistics")
	fmt.Fprintln(stderr, "  --nxc           show nxc/netexec quick commands")
	fmt.Fprintln(stderr, "  --no-color      disable colors")
	fmt.Fprintln(stderr, "  -s, --silent    suppress banner")
}
