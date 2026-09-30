package parser

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

var (
	// secretsdump.py formats:
	// DOMAIN/user:RID:LMhash:NThash:::
	// DOMAIN\user:RID:LMhash:NThash:::
	// user:RID:LMhash:NThash::: (SAM, no domain)
	reSecretsDump = regexp.MustCompile(`^([^/:]+)/([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::$`)
	reSDBackslash = regexp.MustCompile(`^([^\\:]+)\\([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::$`)
	reSDNoDomain  = regexp.MustCompile(`^([^\\/:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::$`)

	// DCC2 cached domain creds: DOMAIN/user:$DCC2$iter#user#hash
	reSDDCC2 = regexp.MustCompile(`^([^/\\:]+)[/\\]([^:]+):\$DCC2\$(\d+)#([^#]+)#([0-9a-fA-F]+)`)

	// Kerberos keys: DOMAIN\user:aes256-cts-hmac-sha1-96:hex
	reSDKerberos = regexp.MustCompile(`^([^\\:]+)\\([^:]+):(aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96):([0-9a-fA-F]+)$`)

	// Cleartext from secretsdump: DOMAIN/user:CLEARTEXT:password
	reSDCleartext = regexp.MustCompile(`(?i)^([^/\\:]+)[/\\]([^:]+):CLEARTEXT:(.+)$`)

	// pypykatz: module credtype domain username NThash LMhash
	rePypykatz = regexp.MustCompile(`^(msv|wdigest|kerberos|tspkg|ssp|credman|dpapi)\s+(password|hash|aes)\s+(\S+)\s+(\S+)\s+(.+)$`)

	// nxc/cme protocol line
	reNXC = regexp.MustCompile(`(?i)^(SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|WMI)\s+(\S+)\s+(\d+)\s+(\S+)\s+(.+)$`)

	// nxc credential patterns
	reNXCSuccess = regexp.MustCompile(`\[\+\]\s+(.+)`)
	reNXCCred    = regexp.MustCompile(`([^\\]+)\\([^:]+):(.+)`)
	reNXCHash    = regexp.MustCompile(`^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$`)
	reNXCSAM     = regexp.MustCompile(`(?i)SAM\s+(.+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::`)
	reNXCNTDS    = regexp.MustCompile(`(?i)(\S+)\\(\S+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::`)
)

type InputFormat int

const (
	FormatMimikatz InputFormat = iota
	FormatSecretsDump
	FormatPypykatz
	FormatNXC
	FormatUnknown
)

func DetectFormat(line string) InputFormat {
	if reSecretsDump.MatchString(line) || reSDBackslash.MatchString(line) || reSDNoDomain.MatchString(line) || reSDDCC2.MatchString(line) {
		return FormatSecretsDump
	}
	if rePypykatz.MatchString(line) {
		return FormatPypykatz
	}
	if reNXC.MatchString(line) {
		return FormatNXC
	}
	if reAuthBlock.MatchString(line) || strings.Contains(line, "mimikatz") {
		return FormatMimikatz
	}
	return FormatUnknown
}

// ParseAuto detects format from early lines, then dispatches.
// Mimikatz streams via io.Pipe to avoid holding full file in memory.
// Other formats collect lines with maxInputLines cap.
func ParseAuto(r io.Reader) ([]Credential, error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	detected := FormatUnknown
	var lines []string
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		line := scanner.Text()
		lines = append(lines, line)

		if detected == FormatUnknown && strings.TrimSpace(line) != "" {
			d := DetectFormat(line)
			if d != FormatUnknown {
				detected = d
			}
		}

		if lineCount >= maxInputLines {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	switch detected {
	case FormatSecretsDump:
		return parseSecretsDump(lines), nil
	case FormatPypykatz:
		return parsePypykatz(lines), nil
	case FormatNXC:
		return parseNXC(lines), nil
	default:
		return Parse(strings.NewReader(strings.Join(lines, "\n")))
	}
}

func parseSecretsDump(lines []string) []Credential {
	var creds []Credential
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "#") {
			continue
		}

		// DOMAIN/user:RID:LM:NT:::
		if m := reSecretsDump.FindStringSubmatch(line); m != nil {
			c := Credential{
				Domain:   m[1],
				Username: m[2],
				NTLM:     m[5],
				Source:   "secretsdump",
			}
			if strings.ToLower(m[4]) != EmptyLM {
				c.SHA1 = m[4]
			}
			if c.HasContent() {
				creds = append(creds, c)
			}
			continue
		}

		// DOMAIN\user:RID:LM:NT:::
		if m := reSDBackslash.FindStringSubmatch(line); m != nil {
			c := Credential{
				Domain:   m[1],
				Username: m[2],
				NTLM:     m[5],
				Source:   "secretsdump",
			}
			if strings.ToLower(m[4]) != EmptyLM {
				c.SHA1 = m[4]
			}
			if c.HasContent() {
				creds = append(creds, c)
			}
			continue
		}

		// user:RID:LM:NT::: (no domain, local SAM)
		if m := reSDNoDomain.FindStringSubmatch(line); m != nil {
			c := Credential{
				Username: m[1],
				NTLM:     m[4],
				Source:   "secretsdump",
			}
			if strings.ToLower(m[3]) != EmptyLM {
				c.SHA1 = m[3]
			}
			if c.HasContent() {
				creds = append(creds, c)
			}
			continue
		}

		// DCC2: DOMAIN/user:$DCC2$iter#user#hash
		if m := reSDDCC2.FindStringSubmatch(line); m != nil {
			iter := m[3]
			dccUser := m[4]
			dccHash := m[5]
			c := Credential{
				Domain:   m[1],
				Username: m[2],
				DCC2:     "$DCC2$" + iter + "#" + dccUser + "#" + dccHash,
				Source:   "secretsdump-dcc2",
			}
			creds = append(creds, c)
			continue
		}

		// Kerberos keys: DOMAIN\user:aes256-cts-...:hex
		if m := reSDKerberos.FindStringSubmatch(line); m != nil {
			c := Credential{
				Domain:   m[1],
				Username: m[2],
				Source:   "secretsdump-kerberos",
			}
			switch m[3] {
			case "aes256-cts-hmac-sha1-96":
				c.AES256 = m[4]
			case "aes128-cts-hmac-sha1-96":
				c.AES128 = m[4]
			}
			if c.HasContent() {
				creds = append(creds, c)
			}
			continue
		}

		// CLEARTEXT: DOMAIN/user:CLEARTEXT:password
		if m := reSDCleartext.FindStringSubmatch(line); m != nil {
			c := Credential{
				Domain:   m[1],
				Username: m[2],
				Password: m[3],
				Source:   "secretsdump",
			}
			if c.HasContent() {
				creds = append(creds, c)
			}
			continue
		}

		// Fallback: domain/user:something
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			userPart := parts[0]
			rest := parts[1]
			domain, user := splitDomainUser(userPart, "/")
			if domain != "" && user != "" && rest != "" {
				c := Credential{
					Domain:   domain,
					Username: user,
					Password: strings.TrimSuffix(rest, ":::"),
					Source:   "secretsdump",
				}
				if c.HasContent() {
					creds = append(creds, c)
				}
			}
		}
	}
	return creds
}

func parsePypykatz(lines []string) []Credential {
	var creds []Credential
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "==") || strings.HasPrefix(line, "--") {
			continue
		}

		m := rePypykatz.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		source := m[1]
		credType := m[2]
		domain := m[3]
		user := m[4]
		value := strings.TrimSpace(m[5])

		if user == "(null)" || value == "(null)" || value == "" {
			continue
		}

		c := Credential{
			Domain:   domain,
			Username: user,
			Source:   source,
		}

		switch credType {
		case "password":
			c.Password = value
		case "hash":
			if len(value) == 32 {
				c.NTLM = value
			}
		case "aes":
			if len(value) == 64 {
				c.AES256 = value
			} else if len(value) == 32 {
				c.AES128 = value
			}
		}

		if c.HasContent() {
			creds = append(creds, c)
		}
	}
	return creds
}

func parseNXC(lines []string) []Credential {
	var creds []Credential

	for _, line := range lines {
		line = strings.TrimSpace(line)

		m := reNXC.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		host := m[2]
		hostname := m[4]
		payload := m[5]

		sourceHost := hostname
		if sourceHost == "" {
			sourceHost = host
		}

		// --sam output: SAM user:rid:lm:nt:::
		if sm := reNXCSAM.FindStringSubmatch(payload); sm != nil {
			user := strings.TrimSpace(sm[1])
			lm := sm[3]
			nt := sm[4]

			c := Credential{
				Username: user,
				NTLM:     nt,
				Source:   "nxc-sam",
				Host:     sourceHost,
			}
			if strings.ToLower(lm) != EmptyLM {
				c.SHA1 = lm
			}
			if c.HasContent() {
				creds = append(creds, c)
			}
			continue
		}

		// --ntds output: DOMAIN\user:rid:lm:nt:::
		if nm := reNXCNTDS.FindStringSubmatch(payload); nm != nil {
			domain := nm[1]
			user := nm[2]
			lm := nm[4]
			nt := nm[5]

			c := Credential{
				Domain:   domain,
				Username: user,
				NTLM:     nt,
				Source:   "nxc-ntds",
				Host:     sourceHost,
			}
			if strings.ToLower(lm) != EmptyLM {
				c.SHA1 = lm
			}
			if c.HasContent() {
				creds = append(creds, c)
			}
			continue
		}

		// [+] successful auth lines
		sm := reNXCSuccess.FindStringSubmatch(payload)
		if sm == nil {
			continue
		}
		credPayload := strings.TrimSpace(sm[1])

		cm := reNXCCred.FindStringSubmatch(credPayload)
		if cm == nil {
			continue
		}

		domain := cm[1]
		user := cm[2]
		secret := cm[3]

		// strip status suffixes like (Pwn3d!) (Pwned!)
		secret = strings.TrimSpace(secret)
		for _, suffix := range []string{"(Pwn3d!)", "(Pwned!)", "(Admin!)", "(admin)"} {
			secret = strings.TrimSuffix(secret, suffix)
		}
		secret = strings.TrimSpace(secret)

		c := Credential{
			Domain:   domain,
			Username: user,
			Source:   "nxc",
			Host:     sourceHost,
		}

		if reNXCHash.MatchString(secret) {
			parts := strings.SplitN(secret, ":", 2)
			c.NTLM = parts[1]
		} else {
			c.Password = secret
		}

		if c.HasContent() {
			creds = append(creds, c)
		}
	}
	return creds
}

func splitDomainUser(s string, sep string) (string, string) {
	idx := strings.Index(s, sep)
	if idx < 0 {
		idx = strings.Index(s, "\\")
	}
	if idx < 0 {
		return "", s
	}
	return s[:idx], s[idx+1:]
}
