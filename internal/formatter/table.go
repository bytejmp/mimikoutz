package formatter

import (
	"fmt"
	"io"
	"strings"

	"github.com/bytejmp/mimikoutz/internal/parser"
)

func Table(w io.Writer, creds []parser.Credential) error {
	if len(creds) == 0 {
		fmt.Fprintln(w, "No credentials found.")
		return nil
	}

	colDomain := len("DOMAIN")
	colUser := len("USERNAME")
	colNTLM := len("NTLM")
	colPassword := len("PASSWORD")
	colSource := len("SOURCE")
	colTags := len("TAGS")

	for _, c := range creds {
		if len(c.Domain) > colDomain {
			colDomain = len(c.Domain)
		}
		if len(c.Username) > colUser {
			colUser = len(c.Username)
		}
		if len(c.NTLM) > colNTLM {
			colNTLM = len(c.NTLM)
		}
		if len(c.Password) > colPassword {
			colPassword = len(c.Password)
		}
		if len(c.Source) > colSource {
			colSource = len(c.Source)
		}
		tagStr := c.TagString()
		if len(tagStr) > colTags {
			colTags = len(tagStr)
		}
	}

	if colDomain > 40 {
		colDomain = 40
	}
	if colUser > 40 {
		colUser = 40
	}
	if colPassword > 50 {
		colPassword = 50
	}
	if colTags < 10 {
		colTags = 10
	}

	fmtStr := fmt.Sprintf("%%-%ds  %%-%ds  %%-%ds  %%-%ds  %%-%ds  %%-%ds",
		colDomain, colUser, colNTLM, colPassword, colSource, colTags)

	header := fmt.Sprintf(fmtStr, "DOMAIN", "USERNAME", "NTLM", "PASSWORD", "SOURCE", "TAGS")
	fmt.Fprintf(w, "%s%s%s\n", ColorBold, header, ColorReset)
	fmt.Fprintln(w, strings.Repeat("─", len(header)))

	for _, c := range creds {
		domain := truncate(c.Domain, colDomain)
		user := truncate(c.Username, colUser)
		pass := truncate(c.Password, colPassword)
		tagStr := c.TagString()

		colorUser := colorizeUser(c, user)
		colorPass := colorizePassword(pass)
		colorHash := colorizeHash(c)
		colorTags := colorizeTags(c, tagStr)

		fmt.Fprintf(w, "%-*s  %s  %s  %s  %-*s  %s\n",
			colDomain, domain,
			padColored(colorUser, colUser),
			padColored(colorHash, colNTLM),
			padColored(colorPass, colPassword),
			colSource, c.Source,
			colorTags,
		)
	}
	return nil
}

func colorizeUser(c parser.Credential, display string) string {
	if !UseColor {
		return display
	}
	if c.HasTag(parser.TagDA) || c.HasTag(parser.TagEA) {
		return ColorBgRed + ColorWhite + ColorBold + display + ColorReset
	}
	if c.HasTag(parser.TagPRIV) || c.HasTag(parser.TagSA) {
		return ColorRed + ColorBold + display + ColorReset
	}
	if c.IsMachine() {
		return ColorGray + display + ColorReset
	}
	if c.IsService() {
		return ColorCyan + display + ColorReset
	}
	return display
}

func colorizePassword(pass string) string {
	if !UseColor || pass == "" {
		return pass
	}
	return ColorRed + ColorBold + pass + ColorReset
}

func colorizeHash(c parser.Credential) string {
	hash := c.NTLM
	if hash == "" {
		return ""
	}
	if !UseColor {
		return hash
	}
	if c.IsEmptyHash() {
		return ColorYellow + hash + ColorReset
	}
	return ColorGreen + hash + ColorReset
}

func colorizeTags(c parser.Credential, display string) string {
	if !UseColor || display == "" {
		return display
	}
	if c.HasTag(parser.TagDA) || c.HasTag(parser.TagEA) {
		return ColorBgRed + ColorWhite + ColorBold + display + ColorReset
	}
	if c.HasTag(parser.TagPRIV) || c.HasTag(parser.TagSA) {
		return ColorRed + ColorBold + display + ColorReset
	}
	if c.HasTag(parser.TagKRBAST) {
		return ColorMagenta + display + ColorReset
	}
	if c.HasTag(parser.TagSVC) {
		return ColorCyan + display + ColorReset
	}
	if c.HasTag(parser.TagMACHINE) {
		return ColorGray + display + ColorReset
	}
	return display
}

func padColored(s string, width int) string {
	visible := visibleLen(s)
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}

func visibleLen(s string) int {
	n := 0
	inEscape := false
	for _, r := range s {
		if r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		n++
	}
	return n
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
