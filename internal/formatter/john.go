package formatter

import (
	"fmt"
	"io"

	"github.com/bytejmp/mimikoutz/internal/parser"
)

// John outputs in PWDUMP format for John the Ripper:
// username:RID:LMhash:NThash:::
func John(w io.Writer, creds []parser.Credential) error {
	seen := make(map[string]struct{})
	for _, c := range creds {
		if c.NTLM == "" {
			continue
		}
		key := c.Username + ":" + c.NTLM
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		lm := parser.EmptyLM
		_, err := fmt.Fprintf(w, "%s:0:%s:%s:::\n", c.Username, lm, c.NTLM)
		if err != nil {
			return err
		}
	}
	return nil
}
