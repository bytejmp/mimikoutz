package formatter

import (
	"fmt"
	"io"

	"github.com/bytejmp/mimikoutz/internal/parser"
)

func Grep(w io.Writer, creds []parser.Credential) error {
	for _, c := range creds {
		pass := c.Password
		if pass == "" {
			pass = "<blank>"
		}
		ntlm := c.NTLM
		if ntlm == "" {
			ntlm = "<no-hash>"
		}
		_, err := fmt.Fprintf(w, "%s\\%s:%s:%s:%s\n", c.Domain, c.Username, ntlm, pass, c.Source)
		if err != nil {
			return err
		}
	}
	return nil
}
