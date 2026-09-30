package parser

func Diff(baseline, current []Credential) []Credential {
	baseKeys := make(map[string]struct{}, len(baseline))
	for _, c := range baseline {
		baseKeys[c.DedupeKey()] = struct{}{}
	}

	var newCreds []Credential
	for _, c := range current {
		if _, exists := baseKeys[c.DedupeKey()]; !exists {
			newCreds = append(newCreds, c)
		}
	}
	return newCreds
}
