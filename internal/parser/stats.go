package parser

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

type Stats struct {
	Total         int
	UniqueUsers   int
	WithPlaintext int
	WithHash      int
	MachineAccts  int
	ServiceAccts  int
	EmptyHashes   int
	PrivAccts     int
	DAAccts       int
	Kerberoastable int
	Domains       map[string]int
	Sources       map[string]int
	Hosts         map[string]int
}

func ComputeStats(creds []Credential) Stats {
	s := Stats{
		Total:   len(creds),
		Domains: make(map[string]int),
		Sources: make(map[string]int),
		Hosts:   make(map[string]int),
	}

	users := make(map[string]struct{})
	for _, c := range creds {
		key := strings.ToLower(c.Domain + "\\" + c.Username)
		users[key] = struct{}{}

		if c.HasPlaintext() {
			s.WithPlaintext++
		}
		if c.HasHash() {
			s.WithHash++
		}
		if c.IsMachine() {
			s.MachineAccts++
		}
		if c.IsService() {
			s.ServiceAccts++
		}
		if c.IsEmptyHash() {
			s.EmptyHashes++
		}
		if c.HasTag(TagDA) || c.HasTag(TagEA) {
			s.DAAccts++
		} else if c.HasTag(TagPRIV) || c.HasTag(TagSA) {
			s.PrivAccts++
		}
		if c.HasTag(TagKRBAST) {
			s.Kerberoastable++
		}

		if c.Domain != "" {
			s.Domains[c.Domain]++
		}
		if c.Source != "" {
			s.Sources[c.Source]++
		}
		if c.Host != "" {
			s.Hosts[c.Host]++
		}
	}
	s.UniqueUsers = len(users)
	return s
}

func PrintStats(w io.Writer, s Stats) {
	fmt.Fprintf(w, "\n╔══════════════════════════════════════╗\n")
	fmt.Fprintf(w, "║           CREDENTIAL STATS           ║\n")
	fmt.Fprintf(w, "╠══════════════════════════════════════╣\n")
	fmt.Fprintf(w, "║  Total entries     : %-15d ║\n", s.Total)
	fmt.Fprintf(w, "║  Unique users      : %-15d ║\n", s.UniqueUsers)
	fmt.Fprintf(w, "║  With plaintext    : %-15d ║\n", s.WithPlaintext)
	fmt.Fprintf(w, "║  With hash         : %-15d ║\n", s.WithHash)
	fmt.Fprintf(w, "║  DA/EA accounts    : %-15d ║\n", s.DAAccts)
	fmt.Fprintf(w, "║  Privileged accts  : %-15d ║\n", s.PrivAccts)
	fmt.Fprintf(w, "║  Service accounts  : %-15d ║\n", s.ServiceAccts)
	fmt.Fprintf(w, "║  Machine accounts  : %-15d ║\n", s.MachineAccts)
	fmt.Fprintf(w, "║  Kerberoastable    : %-15d ║\n", s.Kerberoastable)
	fmt.Fprintf(w, "║  Empty/known hash  : %-15d ║\n", s.EmptyHashes)
	fmt.Fprintf(w, "╠══════════════════════════════════════╣\n")

	fmt.Fprintf(w, "║  Domains:                            ║\n")
	for _, kv := range sortedMap(s.Domains) {
		fmt.Fprintf(w, "║    %-20s : %-10d ║\n", truncStat(kv.Key, 20), kv.Val)
	}

	fmt.Fprintf(w, "╠══════════════════════════════════════╣\n")
	fmt.Fprintf(w, "║  Sources:                            ║\n")
	for _, kv := range sortedMap(s.Sources) {
		fmt.Fprintf(w, "║    %-20s : %-10d ║\n", truncStat(kv.Key, 20), kv.Val)
	}

	if len(s.Hosts) > 0 {
		fmt.Fprintf(w, "╠══════════════════════════════════════╣\n")
		fmt.Fprintf(w, "║  Hosts:                              ║\n")
		for _, kv := range sortedMap(s.Hosts) {
			fmt.Fprintf(w, "║    %-20s : %-10d ║\n", truncStat(kv.Key, 20), kv.Val)
		}
	}

	fmt.Fprintf(w, "╚══════════════════════════════════════╝\n")
}

type kv struct {
	Key string
	Val int
}

func sortedMap(m map[string]int) []kv {
	var pairs []kv
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Val > pairs[j].Val
	})
	return pairs
}

func truncStat(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
