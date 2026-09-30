package formatter

import (
	"encoding/csv"
	"io"

	"github.com/bytejmp/mimikoutz/internal/parser"
)

func CSV(w io.Writer, creds []parser.Credential) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{"domain", "username", "ntlm", "sha1", "aes256", "aes128", "password", "sid", "source", "host", "tags"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, c := range creds {
		row := []string{c.Domain, c.Username, c.NTLM, c.SHA1, c.AES256, c.AES128, c.Password, c.SID, c.Source, c.Host, c.TagString()}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}
