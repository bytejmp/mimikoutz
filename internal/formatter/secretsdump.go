package formatter

import (
	"fmt"
	"io"

	"github.com/bytejmp/mimikoutz/internal/parser"
)

// SecretsDump outputs in impacket secretsdump.py format:
// DOMAIN/username:RID:LMhash:NThash:::
func SecretsDump(w io.Writer, creds []parser.Credential) error {
	seen := make(map[string]struct{})
	for _, c := range creds {
		if c.NTLM == "" {
			continue
		}

		domain := c.Domain
		if domain == "" {
			domain = "UNKNOWN"
		}

		key := domain + "/" + c.Username + ":" + c.NTLM
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		lm := parser.EmptyLM
		_, err := fmt.Fprintf(w, "%s/%s:0:%s:%s:::\n", domain, c.Username, lm, c.NTLM)
		if err != nil {
			return err
		}
	}
	return nil
}
