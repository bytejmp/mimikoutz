package parser

import "sort"

func Deduplicate(creds []Credential) []Credential {
	seen := make(map[string]int)
	var result []Credential

	for _, c := range creds {
		key := c.DedupeKey()
		if idx, exists := seen[key]; exists {
			existing := result[idx]
			if existing.Source == "" && c.Source != "" {
				result[idx].Source = c.Source
			}
			continue
		}
		seen[key] = len(result)
		result = append(result, c)
	}
	return result
}

func Sort(creds []Credential) {
	sort.Slice(creds, func(i, j int) bool {
		if creds[i].Domain != creds[j].Domain {
			return creds[i].Domain < creds[j].Domain
		}
		if creds[i].Username != creds[j].Username {
			return creds[i].Username < creds[j].Username
		}
		if creds[i].Password != "" && creds[j].Password == "" {
			return true
		}
		if creds[i].Password == "" && creds[j].Password != "" {
			return false
		}
		return creds[i].NTLM < creds[j].NTLM
	})
}
