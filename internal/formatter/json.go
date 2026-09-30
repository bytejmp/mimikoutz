package formatter

import (
	"encoding/json"
	"io"

	"github.com/bytejmp/mimikoutz/internal/parser"
)

func JSON(w io.Writer, creds []parser.Credential) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(creds)
}
