package formatter

import (
	"fmt"
	"io"

	"github.com/bytejmp/mimikoutz/internal/parser"
)

// Hashcat outputs hashes grouped by hashcat mode:
//   -m 1000: NTLM     → username:hash
//   -m 2100: DCC2     → $DCC2$iter#user#hash
func Hashcat(w io.Writer, creds []parser.Credential) error {
	var ntlm, dcc2 []string
	seenNTLM := make(map[string]struct{})
	seenDCC2 := make(map[string]struct{})

	for _, c := range creds {
		if c.NTLM != "" {
			key := c.Username + ":" + c.NTLM
			if _, exists := seenNTLM[key]; !exists {
				seenNTLM[key] = struct{}{}
				ntlm = append(ntlm, key)
			}
		}
		if c.DCC2 != "" {
			if _, exists := seenDCC2[c.DCC2]; !exists {
				seenDCC2[c.DCC2] = struct{}{}
				dcc2 = append(dcc2, c.DCC2)
			}
		}
	}

	if len(ntlm) > 0 {
		fmt.Fprintln(w, "# hashcat -m 1000 --username (NTLM)")
		for _, h := range ntlm {
			if _, err := fmt.Fprintln(w, h); err != nil {
				return err
			}
		}
	}

	if len(dcc2) > 0 {
		if len(ntlm) > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, "# hashcat -m 2100 (DCC2)")
		for _, h := range dcc2 {
			if _, err := fmt.Fprintln(w, h); err != nil {
				return err
			}
		}
	}

	return nil
}
