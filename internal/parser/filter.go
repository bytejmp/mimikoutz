package parser

import "strings"

type Filter struct {
	Username    string
	Domain      string
	HasPassword bool
	HasHash     bool
	NoMachine   bool
}

func (f Filter) IsEmpty() bool {
	return f.Username == "" && f.Domain == "" && !f.HasPassword && !f.HasHash && !f.NoMachine
}

func ApplyFilters(creds []Credential, f Filter) []Credential {
	if f.IsEmpty() {
		return creds
	}

	var result []Credential
	for _, c := range creds {
		if f.Username != "" && !strings.EqualFold(c.Username, f.Username) {
			continue
		}
		if f.Domain != "" && !strings.EqualFold(c.Domain, f.Domain) {
			continue
		}
		if f.HasPassword && !c.HasPlaintext() {
			continue
		}
		if f.HasHash && !c.HasHash() {
			continue
		}
		if f.NoMachine && c.IsMachine() {
			continue
		}
		result = append(result, c)
	}
	return result
}
