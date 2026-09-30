package parser

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

var (
	reAuthBlock = regexp.MustCompile(`(?i)^Authentication Id\s*:`)
	reUsername   = regexp.MustCompile(`(?i)^\s*\*?\s*Username\s*:\s*(.+)`)
	reDomain    = regexp.MustCompile(`(?i)^\s*\*?\s*Domain\s*:\s*(.+)`)
	reNTLM      = regexp.MustCompile(`(?i)^\s*\*?\s*NTLM\s*:\s*([0-9a-fA-F]{32})`)
	reSHA1      = regexp.MustCompile(`(?i)^\s*\*?\s*SHA1\s*:\s*([0-9a-fA-F]{40})`)
	rePassword  = regexp.MustCompile(`(?i)^\s*\*?\s*Password\s*:\s*(.+)`)
	reProvider  = regexp.MustCompile(`(?i)^\s+(msv|tspkg|wdigest|kerberos|ssp|credman|cloudap|dpapi)\s*:`)
	reSID       = regexp.MustCompile(`(?i)^\s*SID\s*:\s*(S-\d+[\d-]+)`)

	reBlockUser   = regexp.MustCompile(`(?i)^\s*User Name\s*:\s*(.+)`)
	reBlockDomain = regexp.MustCompile(`(?i)^\s*Domain\s*:\s*(.+)`)

	// ekeys — unified regex handles both "* aes256_hmac : <hex>" and "  aes256_hmac  <hex>"
	reAES256 = regexp.MustCompile(`(?i)^\s*\*?\s*aes256_hmac\s*:?\s*([0-9a-fA-F]{64})`)
	reAES128 = regexp.MustCompile(`(?i)^\s*\*?\s*aes128_hmac\s*:?\s*([0-9a-fA-F]{32})`)
	reRC4    = regexp.MustCompile(`(?i)^\s*\*?\s*rc4_hmac_nt\s*:?\s*([0-9a-fA-F]{32})`)

	// lsadump::sam
	reSAMUser = regexp.MustCompile(`(?i)^User\s*:\s*(.+)`)
	reSAMHash = regexp.MustCompile(`(?i)^\s*Hash NTLM\s*:\s*([0-9a-fA-F]{32})`)

	// lsadump::dcsync
	reDCSyncUser   = regexp.MustCompile(`(?i)^\s*SAMAccountName\s*:\s*(.+)`)
	reDCSyncHash   = regexp.MustCompile(`(?i)^\s*Hash NTLM\s*:\s*([0-9a-fA-F]{32})`)
	reDCSyncSID    = regexp.MustCompile(`(?i)^\s*Object Security ID\s*:\s*(S-\d+[\d-]+)`)
	reDCSyncDomain = regexp.MustCompile(`(?i)^\[DC\]\s+'([^']+)'\s+will be the domain`)
	reDCSyncAES256 = regexp.MustCompile(`(?i)^\s+aes256_hmac\s+\(\d+\)\s*:\s*([0-9a-fA-F]{64})`)
	reDCSyncAES128 = regexp.MustCompile(`(?i)^\s+aes128_hmac\s+\(\d+\)\s*:\s*([0-9a-fA-F]{32})`)

	// vault::cred
	reVaultTarget = regexp.MustCompile(`(?i)^\s*TargetName\s*:\s*(.+)`)
	reVaultUser   = regexp.MustCompile(`(?i)^\s*UserName\s*:\s*(.+)`)
	reVaultCred   = regexp.MustCompile(`(?i)^\s*Credential\s*:\s*(.+)`)
)

const maxInputLines = 5_000_000

type parseState struct {
	creds []Credential

	blockUser, blockDomain, blockSID string
	curProvider                       string
	curUser, curDomain                string
	curNTLM, curSHA1, curPassword     string
	curAES256, curAES128              string
	curSID                            string
	inBlock                           bool

	inDCSync     bool
	dcsyncDomain string

	inVault   bool
	vaultUser string
	vaultCred string

	inDPAPI       bool
	dpapiUser     string
	dpapiDomain   string
	dpapiPassword string
}

func (s *parseState) flush(source string) {
	user := s.curUser
	if user == "" || user == "(null)" {
		user = s.blockUser
	}
	if user == "" || user == "(null)" {
		return
	}
	domain := s.curDomain
	if domain == "" || domain == "(null)" {
		domain = s.blockDomain
	}
	sid := s.curSID
	if sid == "" {
		sid = s.blockSID
	}

	c := Credential{
		Domain:   strings.TrimSpace(domain),
		Username: strings.TrimSpace(user),
		NTLM:     strings.TrimSpace(s.curNTLM),
		SHA1:     strings.TrimSpace(s.curSHA1),
		AES256:   strings.TrimSpace(s.curAES256),
		AES128:   strings.TrimSpace(s.curAES128),
		Password: strings.TrimSpace(s.curPassword),
		SID:      strings.TrimSpace(sid),
		Source:   source,
	}
	if c.HasContent() {
		s.creds = append(s.creds, c)
	}
	s.curUser, s.curDomain = "", ""
	s.curNTLM, s.curSHA1, s.curPassword = "", "", ""
	s.curAES256, s.curAES128 = "", ""
	s.curSID = ""
}

func (s *parseState) flushVault() {
	if s.vaultUser == "" || s.vaultCred == "" {
		s.vaultUser, s.vaultCred = "", ""
		return
	}
	cred := strings.TrimSpace(s.vaultCred)
	if cred == "(null)" || cred == "" {
		s.vaultUser, s.vaultCred = "", ""
		return
	}

	user := s.vaultUser
	domain := ""
	if idx := strings.Index(user, "\\"); idx >= 0 {
		domain = user[:idx]
		user = user[idx+1:]
	}

	c := Credential{
		Domain:   strings.TrimSpace(domain),
		Username: strings.TrimSpace(user),
		Password: cred,
		Source:   "vault",
	}
	s.creds = append(s.creds, c)
	s.vaultUser, s.vaultCred = "", ""
}

func (s *parseState) flushDPAPI() {
	if s.dpapiUser == "" {
		return
	}
	pass := strings.TrimSpace(s.dpapiPassword)
	if pass == "" || pass == "(null)" {
		s.dpapiUser, s.dpapiDomain, s.dpapiPassword = "", "", ""
		return
	}

	c := Credential{
		Domain:   strings.TrimSpace(s.dpapiDomain),
		Username: strings.TrimSpace(s.dpapiUser),
		Password: pass,
		Source:   "dpapi",
	}
	s.creds = append(s.creds, c)
	s.dpapiUser, s.dpapiDomain, s.dpapiPassword = "", "", ""
}

func Parse(r io.Reader) ([]Credential, error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	st := &parseState{}
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		if lineCount > maxInputLines {
			break
		}
		line := scanner.Text()

		if m := reDCSyncDomain.FindStringSubmatch(line); m != nil {
			st.dcsyncDomain = m[1]
			st.inDCSync = true
			continue
		}

		if strings.Contains(line, "vault::cred") || strings.Contains(line, "Vault :") {
			st.inVault = true
			continue
		}

		if strings.Contains(line, "dpapi::cred") || strings.Contains(line, "DPAPI :") {
			st.inDPAPI = true
			continue
		}

		if reAuthBlock.MatchString(line) {
			if st.inBlock {
				st.flush(st.curProvider)
			}
			st.inBlock = true
			st.inVault = false
			st.inDPAPI = false
			st.blockUser, st.blockDomain, st.blockSID = "", "", ""
			st.curUser, st.curDomain = "", ""
			st.curNTLM, st.curSHA1, st.curPassword = "", "", ""
			st.curAES256, st.curAES128 = "", ""
			st.curSID = ""
			st.curProvider = ""
			continue
		}

		if st.inVault {
			if m := reVaultUser.FindStringSubmatch(line); m != nil {
				st.flushVault()
				st.vaultUser = strings.TrimSpace(m[1])
				continue
			}
			if m := reVaultCred.FindStringSubmatch(line); m != nil {
				st.vaultCred = strings.TrimSpace(m[1])
				st.flushVault()
				continue
			}
			if reVaultTarget.MatchString(line) {
				continue
			}
		}

		if st.inDPAPI {
			if m := reUsername.FindStringSubmatch(line); m != nil {
				val := strings.TrimSpace(m[1])
				if val != "(null)" {
					st.flushDPAPI()
					st.dpapiUser = val
				}
				continue
			}
			if m := reDomain.FindStringSubmatch(line); m != nil {
				st.dpapiDomain = strings.TrimSpace(m[1])
				continue
			}
			if m := rePassword.FindStringSubmatch(line); m != nil {
				val := strings.TrimSpace(m[1])
				if val != "(null)" {
					st.dpapiPassword = val
					st.flushDPAPI()
				}
				continue
			}
		}

		if st.inBlock {
			if m := reBlockUser.FindStringSubmatch(line); m != nil {
				st.blockUser = m[1]
				continue
			}
			if m := reBlockDomain.FindStringSubmatch(line); m != nil {
				st.blockDomain = m[1]
				continue
			}
			if m := reSID.FindStringSubmatch(line); m != nil {
				st.blockSID = m[1]
				continue
			}
		}

		if m := reProvider.FindStringSubmatch(line); m != nil {
			st.flush(st.curProvider)
			st.curProvider = strings.ToLower(strings.TrimSpace(m[1]))
			continue
		}

		if m := reUsername.FindStringSubmatch(line); m != nil {
			val := strings.TrimSpace(m[1])
			if val != "(null)" {
				st.curUser = val
			}
			continue
		}
		if m := reDomain.FindStringSubmatch(line); m != nil {
			st.curDomain = strings.TrimSpace(m[1])
			continue
		}
		if m := reNTLM.FindStringSubmatch(line); m != nil {
			st.curNTLM = m[1]
			continue
		}
		if m := reSHA1.FindStringSubmatch(line); m != nil {
			st.curSHA1 = m[1]
			continue
		}
		if m := rePassword.FindStringSubmatch(line); m != nil {
			val := strings.TrimSpace(m[1])
			if val != "(null)" {
				st.curPassword = val
			}
			continue
		}

		if m := reAES256.FindStringSubmatch(line); m != nil {
			st.curAES256 = m[1]
			continue
		}
		if m := reAES128.FindStringSubmatch(line); m != nil {
			st.curAES128 = m[1]
			continue
		}
		if m := reRC4.FindStringSubmatch(line); m != nil {
			if st.curNTLM == "" {
				st.curNTLM = m[1]
			}
			continue
		}

		if m := reSAMUser.FindStringSubmatch(line); m != nil {
			st.flush("sam")
			st.curUser = strings.TrimSpace(m[1])
			continue
		}
		if m := reSAMHash.FindStringSubmatch(line); m != nil {
			st.curNTLM = m[1]
			continue
		}

		if m := reDCSyncUser.FindStringSubmatch(line); m != nil {
			st.flush("dcsync")
			st.curUser = strings.TrimSpace(m[1])
			if st.dcsyncDomain != "" {
				st.curDomain = st.dcsyncDomain
			}
			continue
		}
		if m := reDCSyncHash.FindStringSubmatch(line); m != nil {
			st.curNTLM = m[1]
			continue
		}
		if m := reDCSyncSID.FindStringSubmatch(line); m != nil {
			st.curSID = m[1]
			continue
		}
		if m := reDCSyncAES256.FindStringSubmatch(line); m != nil {
			st.curAES256 = m[1]
			continue
		}
		if m := reDCSyncAES128.FindStringSubmatch(line); m != nil {
			st.curAES128 = m[1]
			continue
		}
	}

	st.flush(st.curProvider)
	st.flushVault()
	st.flushDPAPI()

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return st.creds, nil
}
