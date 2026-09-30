package parser

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

var knownPrivRIDs = map[string]PrivTag{
	"500": TagPRIV,
	"512": TagDA,
	"518": TagSA,
	"519": TagEA,
}

var adminPatterns = []string{
	"admin", "adm_", "adm-", "domainadmin", "enterpriseadmin",
	"schemaadmin", "serveradmin", "root",
}

func TagCredentials(creds []Credential) {
	for i := range creds {
		creds[i].Tags = computeTags(creds[i])
	}
}

func computeTags(c Credential) []PrivTag {
	var tags []PrivTag
	seen := make(map[PrivTag]bool)

	add := func(t PrivTag) {
		if !seen[t] {
			seen[t] = true
			tags = append(tags, t)
		}
	}

	if c.SID != "" {
		rid := extractRID(c.SID)
		if tag, ok := knownPrivRIDs[rid]; ok {
			add(tag)
		}
	}

	lower := strings.ToLower(c.Username)

	if !seen[TagDA] && !seen[TagEA] && !seen[TagSA] {
		for _, pattern := range adminPatterns {
			if strings.Contains(lower, pattern) {
				add(TagPRIV)
				break
			}
		}
	}

	if c.IsMachine() {
		add(TagMACHINE)
	} else if isServiceName(lower) {
		add(TagSVC)
		if !c.HasPlaintext() && c.HasHash() {
			add(TagKRBAST)
		}
	}

	return tags
}

func extractRID(sid string) string {
	parts := strings.Split(sid, "-")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

type PasswordReuse struct {
	Type  string
	Value string
	Users []string
}

func DetectPasswordReuse(creds []Credential) []PasswordReuse {
	hashUsers := make(map[string]map[string]struct{})
	passUsers := make(map[string]map[string]struct{})

	for _, c := range creds {
		identity := c.Domain + "\\" + c.Username

		if c.NTLM != "" && !c.IsEmptyHash() {
			if hashUsers[c.NTLM] == nil {
				hashUsers[c.NTLM] = make(map[string]struct{})
			}
			hashUsers[c.NTLM][identity] = struct{}{}
		}

		if c.HasPlaintext() {
			if passUsers[c.Password] == nil {
				passUsers[c.Password] = make(map[string]struct{})
			}
			passUsers[c.Password][identity] = struct{}{}
		}
	}

	var results []PasswordReuse

	for hash, users := range hashUsers {
		if len(users) < 2 {
			continue
		}
		var names []string
		for u := range users {
			names = append(names, u)
		}
		sort.Strings(names)
		display := hash[:16] + "..."
		results = append(results, PasswordReuse{Type: "hash", Value: display, Users: names})
	}

	for pass, users := range passUsers {
		if len(users) < 2 {
			continue
		}
		var names []string
		for u := range users {
			names = append(names, u)
		}
		sort.Strings(names)
		results = append(results, PasswordReuse{Type: "password", Value: pass, Users: names})
	}

	sort.Slice(results, func(i, j int) bool {
		return len(results[i].Users) > len(results[j].Users)
	})

	return results
}

func PrintPasswordReuse(w io.Writer, reuse []PasswordReuse) {
	if len(reuse) == 0 {
		return
	}

	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "╔══════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(w, "║          ⚠  PASSWORD REUSE DETECTED                    ║\n")
	fmt.Fprintf(w, "╠══════════════════════════════════════════════════════════╣\n")

	for _, r := range reuse {
		label := "Hash"
		if r.Type == "password" {
			label = "Password"
		}
		fmt.Fprintf(w, "║  %-10s: %-43s ║\n", label, truncStat(r.Value, 43))
		fmt.Fprintf(w, "║  Shared by: %-43s ║\n", truncStat(strings.Join(r.Users, ", "), 43))
		fmt.Fprintf(w, "║  Count    : %-43d ║\n", len(r.Users))
		fmt.Fprintf(w, "╠══════════════════════════════════════════════════════════╣\n")
	}

	fmt.Fprintf(w, "║  Total reuse groups: %-34d ║\n", len(reuse))
	fmt.Fprintf(w, "╚══════════════════════════════════════════════════════════╝\n")
}

type PathToDA struct {
	Credential Credential
	Reason     string
}

func DetectPathToDA(creds []Credential) []PathToDA {
	var paths []PathToDA
	seen := make(map[string]struct{})

	for _, c := range creds {
		key := c.Domain + "\\" + c.Username
		if _, exists := seen[key]; exists {
			continue
		}

		for _, tag := range c.Tags {
			switch tag {
			case TagDA:
				seen[key] = struct{}{}
				paths = append(paths, PathToDA{
					Credential: c,
					Reason:     "Domain Admin credential captured",
				})
			case TagEA:
				seen[key] = struct{}{}
				paths = append(paths, PathToDA{
					Credential: c,
					Reason:     "Enterprise Admin credential captured",
				})
			case TagSA:
				seen[key] = struct{}{}
				paths = append(paths, PathToDA{
					Credential: c,
					Reason:     "Schema Admin credential captured",
				})
			}
		}

		if _, exists := seen[key]; exists {
			continue
		}

		if c.HasTag(TagSVC) && c.HasHash() {
			lowerHost := strings.ToLower(c.Host)
			if strings.Contains(lowerHost, "dc") || strings.Contains(lowerHost, "domain") {
				seen[key] = struct{}{}
				paths = append(paths, PathToDA{
					Credential: c,
					Reason:     fmt.Sprintf("Service account with hash found on DC-like host (%s)", c.Host),
				})
			}
		}

		if c.HasTag(TagSVC) && c.HasPlaintext() {
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				paths = append(paths, PathToDA{
					Credential: c,
					Reason:     "Service account with plaintext — try lateral movement to DC",
				})
			}
		}
	}

	return paths
}

func PrintPathToDA(w io.Writer, paths []PathToDA) {
	if len(paths) == 0 {
		return
	}

	hasDirect := false
	for _, p := range paths {
		if p.Credential.HasTag(TagDA) || p.Credential.HasTag(TagEA) {
			hasDirect = true
			break
		}
	}

	fmt.Fprintf(w, "\n")
	if hasDirect {
		fmt.Fprintf(w, "╔══════════════════════════════════════════════════════════╗\n")
		fmt.Fprintf(w, "║     💀  DOMAIN ADMIN CREDENTIAL CAPTURED  💀            ║\n")
		fmt.Fprintf(w, "╠══════════════════════════════════════════════════════════╣\n")
	} else {
		fmt.Fprintf(w, "╔══════════════════════════════════════════════════════════╗\n")
		fmt.Fprintf(w, "║     🔑  POTENTIAL PATH TO DA                            ║\n")
		fmt.Fprintf(w, "╠══════════════════════════════════════════════════════════╣\n")
	}

	for _, p := range paths {
		identity := p.Credential.Domain + "\\" + p.Credential.Username
		fmt.Fprintf(w, "║  Account: %-45s ║\n", truncStat(identity, 45))
		fmt.Fprintf(w, "║  Reason : %-45s ║\n", truncStat(p.Reason, 45))
		if p.Credential.HasPlaintext() {
			fmt.Fprintf(w, "║  Type   : %-45s ║\n", "PLAINTEXT")
		} else if p.Credential.HasHash() {
			fmt.Fprintf(w, "║  Type   : %-45s ║\n", "HASH (pass-the-hash / crack)")
		}
		fmt.Fprintf(w, "╠══════════════════════════════════════════════════════════╣\n")
	}

	fmt.Fprintf(w, "╚══════════════════════════════════════════════════════════╝\n")
}

func DetectKerberoastable(creds []Credential) []Credential {
	var targets []Credential
	seen := make(map[string]struct{})

	for _, c := range creds {
		if !c.HasTag(TagKRBAST) {
			continue
		}
		key := c.Domain + "\\" + c.Username
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, c)
	}
	return targets
}

func PrintKerberoastable(w io.Writer, targets []Credential) {
	if len(targets) == 0 {
		return
	}

	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "╔══════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(w, "║     🎯  KERBEROASTABLE CANDIDATES                      ║\n")
	fmt.Fprintf(w, "╠══════════════════════════════════════════════════════════╣\n")

	for _, c := range targets {
		identity := c.Domain + "\\" + c.Username
		fmt.Fprintf(w, "║  %-55s ║\n", truncStat(identity, 55))
		if c.NTLM != "" {
			fmt.Fprintf(w, "║    NTLM: %-46s ║\n", c.NTLM)
		}
		fmt.Fprintf(w, "║    Suggestion: request TGS, crack offline              ║\n")
		fmt.Fprintf(w, "╠══════════════════════════════════════════════════════════╣\n")
	}

	fmt.Fprintf(w, "║  nxc: nxc ldap <DC> -u <user> -p <pass> --kerberoasting ║\n")
	fmt.Fprintf(w, "╚══════════════════════════════════════════════════════════╝\n")
}

func PrintNXCCommands(w io.Writer, creds []Credential) {
	if len(creds) == 0 {
		return
	}

	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "╔══════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(w, "║     🔫  NXC QUICK COMMANDS                             ║\n")
	fmt.Fprintf(w, "╠══════════════════════════════════════════════════════════╣\n")

	var bestPlain, bestHash *Credential
	for i := range creds {
		c := &creds[i]
		if c.IsMachine() {
			continue
		}
		if c.HasPlaintext() && bestPlain == nil {
			bestPlain = c
		}
		if c.NTLM != "" && !c.IsEmptyHash() && bestHash == nil {
			bestHash = c
		}
		if bestPlain != nil && bestHash != nil {
			break
		}
	}

	if bestPlain != nil {
		identity := bestPlain.Domain + "/" + bestPlain.Username
		fmt.Fprintf(w, "║  # Auth check (password)                               ║\n")
		cmd := fmt.Sprintf("nxc smb <TARGET> -u '%s' -p '%s'", identity, bestPlain.Password)
		fmt.Fprintf(w, "║  %-55s ║\n", truncStat(cmd, 55))
		fmt.Fprintf(w, "║                                                        ║\n")
	}

	if bestHash != nil {
		identity := bestHash.Domain + "/" + bestHash.Username
		fmt.Fprintf(w, "║  # Auth check (pass-the-hash)                          ║\n")
		cmd := fmt.Sprintf("nxc smb <TARGET> -u '%s' -H '%s'", identity, bestHash.NTLM)
		fmt.Fprintf(w, "║  %-55s ║\n", truncStat(cmd, 55))
		fmt.Fprintf(w, "║                                                        ║\n")
	}

	fmt.Fprintf(w, "║  # Dump SAM from targets                               ║\n")
	fmt.Fprintf(w, "║  nxc smb <TARGET> -u <user> -p <pass> --sam            ║\n")
	fmt.Fprintf(w, "║                                                        ║\n")
	fmt.Fprintf(w, "║  # Dump LSA secrets                                    ║\n")
	fmt.Fprintf(w, "║  nxc smb <TARGET> -u <user> -p <pass> --lsa            ║\n")
	fmt.Fprintf(w, "║                                                        ║\n")
	fmt.Fprintf(w, "║  # Spray password across subnet                        ║\n")
	fmt.Fprintf(w, "║  nxc smb <CIDR> -u users.txt -p '<pass>' --continue    ║\n")
	fmt.Fprintf(w, "║                                                        ║\n")
	fmt.Fprintf(w, "║  # Spray hash across subnet                            ║\n")
	fmt.Fprintf(w, "║  nxc smb <CIDR> -u users.txt -H hashes.txt --continue ║\n")

	hasPriv := false
	for _, c := range creds {
		if c.HasTag(TagDA) || c.HasTag(TagEA) || c.HasTag(TagPRIV) {
			hasPriv = true
			break
		}
	}
	if hasPriv {
		fmt.Fprintf(w, "║                                                        ║\n")
		fmt.Fprintf(w, "║  # DCSync (requires DA/replication rights)             ║\n")
		fmt.Fprintf(w, "║  nxc smb <DC> -u <DA> -p <pass> --ntds                ║\n")
	}

	fmt.Fprintf(w, "╚══════════════════════════════════════════════════════════╝\n")
}
