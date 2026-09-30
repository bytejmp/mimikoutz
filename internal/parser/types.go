package parser

import "strings"

type PrivTag string

const (
	TagDA      PrivTag = "DA"
	TagEA      PrivTag = "EA"
	TagSA      PrivTag = "SA"
	TagPRIV    PrivTag = "PRIV"
	TagSVC     PrivTag = "SVC"
	TagMACHINE PrivTag = "MACHINE"
	TagKRBAST  PrivTag = "KRBAST"
)

type Credential struct {
	Domain   string    `json:"domain"`
	Username string    `json:"username"`
	NTLM     string    `json:"ntlm,omitempty"`
	SHA1     string    `json:"sha1,omitempty"`
	AES256   string    `json:"aes256,omitempty"`
	AES128   string    `json:"aes128,omitempty"`
	DCC2     string    `json:"dcc2,omitempty"`
	Password string    `json:"password,omitempty"`
	SID      string    `json:"sid,omitempty"`
	Source   string    `json:"source"`
	Host     string    `json:"host,omitempty"`
	Tags     []PrivTag `json:"tags,omitempty"`
}

func (c Credential) DedupeKey() string {
	return c.Domain + "\\" + c.Username + "|" + c.NTLM + "|" + c.SHA1 + "|" + c.AES256 + "|" + c.DCC2 + "|" + c.Password
}

func (c Credential) HasContent() bool {
	return c.NTLM != "" || c.SHA1 != "" || c.AES256 != "" || c.AES128 != "" || c.DCC2 != "" ||
		(c.Password != "" && c.Password != "(null)")
}

func (c Credential) IsMachine() bool {
	return strings.HasSuffix(c.Username, "$")
}

func (c Credential) IsService() bool {
	lower := strings.ToLower(c.Username)
	return isServiceName(lower)
}

func (c Credential) HasPlaintext() bool {
	return c.Password != "" && c.Password != "(null)"
}

func (c Credential) HasHash() bool {
	return c.NTLM != "" || c.SHA1 != "" || c.AES256 != "" || c.AES128 != "" || c.DCC2 != ""
}

const EmptyNTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"
const EmptyLM = "aad3b435b51404eeaad3b435b51404ee"

func (c Credential) IsEmptyHash() bool {
	lower := strings.ToLower(c.NTLM)
	return lower == EmptyNTLM || lower == EmptyLM
}

func (c Credential) HasTag(t PrivTag) bool {
	for _, tag := range c.Tags {
		if tag == t {
			return true
		}
	}
	return false
}

func (c Credential) TagString() string {
	if len(c.Tags) == 0 {
		return ""
	}
	var parts []string
	for _, t := range c.Tags {
		parts = append(parts, string(t))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func isServiceName(lower string) bool {
	prefixes := []string{"svc_", "svc-", "sql_", "sql-", "iis_", "iis-", "http_", "http-",
		"mssql_", "mssql-", "exchange_", "exchange-", "ftp_", "ftp-", "smtp_", "smtp-",
		"web_", "web-", "app_", "app-", "scom_", "scom-", "wsus_", "wsus-",
		"adfs_", "adfs-", "azure_", "azure-", "backup_", "backup-"}
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return strings.HasSuffix(lower, "_svc") || strings.HasSuffix(lower, "-svc") ||
		strings.HasSuffix(lower, "service")
}
