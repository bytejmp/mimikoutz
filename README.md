```
    /\_/\
   ( ^.^ )    mimikoutz v1.0
    > ^ <     "Tame the chaos, own the hash"
   /|   |\
  (_|   |_)   /*** Clean. Dedup. Dominate. ***/
```

# mimikoutz

Cross-platform CLI tool that parses, deduplicates, and organizes credential dump output. Supports multiple input formats, multiple output formats, Active Directory analysis, and lateral movement assistance.

Zero external dependencies — built with Go stdlib only.

## Features

- **Multi-format input** — auto-detects: Mimikatz, Impacket secretsdump, pypykatz, NXC/NetExec/CrackMapExec
- **7 output formats** — table (colorized), CSV, JSON, grep, hashcat, john, secretsdump
- **Deduplication** — eliminates repeated credentials by composite key
- **AD analysis** — privilege tagging, path-to-DA detection, password reuse, kerberoastable candidates
- **Filtering** — by username, domain, plaintext, hash, machine accounts
- **Diff mode** — compare dumps, show only new credentials
- **NXC integration** — generates ready-to-use NetExec commands
- **Cross-platform** — Linux (amd64), Windows (amd64), macOS (arm64)
- **PowerShell module** — `Import-Module` support with full feature parity

## Quick Start

### Build

```bash
# Docker (recommended — cross-compiles all platforms)
make build

# Direct (current platform only)
go build -o mimikoutz .
```

Binaries output to `dist/`:
- `mimikoutz-linux-amd64`
- `mimikoutz-windows-amd64.exe`
- `mimikoutz-darwin-arm64`

### Usage

```bash
# Pipe from mimikatz
mimikatz.exe "sekurlsa::logonpasswords" | mimikoutz

# Pipe from nxc
nxc smb 10.0.0.0/24 --sam | mimikoutz

# From file
mimikoutz -i dump.txt

# Positional file args (no -i needed)
mimikoutz dump1.txt dump2.txt --stats

# Multiple files (auto-detects format per file)
mimikoutz -i mimikatz.log -i secretsdump.txt -i nxc_output.txt

# Output formats
mimikoutz -i dump.txt -f json
mimikoutz -i dump.txt -f csv -o creds.csv
mimikoutz -i dump.txt -f hashcat -o hashes.txt
mimikoutz -i dump.txt -f john -o pwdump.txt
mimikoutz -i dump.txt -f secretsdump
mimikoutz -i dump.txt -f grep

# AD analysis + stats
mimikoutz -i dump.txt --stats

# NXC lateral movement commands
mimikoutz -i dump.txt --nxc

# Diff two dumps (show new creds only)
mimikoutz -i new_dump.txt --diff baseline.txt

# Filters
mimikoutz -i dump.txt -u admin              # by username
mimikoutz -i dump.txt -d CORP               # by domain
mimikoutz -i dump.txt --has-password         # only plaintext
mimikoutz -i dump.txt --has-hash             # only hashes
mimikoutz -i dump.txt --no-machine           # exclude machine accounts ($)

# Combine
mimikoutz -i dump.txt --has-password --no-machine --stats -f csv -o report.csv
```

### PowerShell (Windows)

```powershell
# Direct execution
.\powershell\mimikoutz.ps1 -InputFile .\dump.txt -Format json

# Positional file args
.\powershell\mimikoutz.ps1 .\dump1.txt .\dump2.txt -Stats

# As module (recommended)
Import-Module .\powershell\mimikoutz.psm1

# Then use anywhere in session
Invoke-Mimikoutz -InputFile .\dump.txt -Stats -Nxc
mimikoutz -i .\dump.txt -f grep                          # alias

# Pipeline
.\mimikatz.exe "sekurlsa::logonpasswords" | mimikoutz -Stats
nxc smb 10.0.0.0/24 --sam | mimikoutz

# Suppress banner
mimikoutz -i .\dump.txt -Silent                          # or -s or -NoBanner

# Filters
mimikoutz -i .\dump.txt -FilterUser admin -HasPassword
mimikoutz -i .\dump.txt -FilterDomain CORP -HasHash -NoMachine
```

## Input Formats

| Format | Source | Auto-detected |
|--------|--------|---------------|
| Mimikatz | `sekurlsa::logonpasswords`, `sekurlsa::ekeys`, `lsadump::sam`, `lsadump::dcsync`, `vault::cred`, `dpapi::cred` | Yes |
| Secretsdump | Impacket `secretsdump.py` | Yes |
| Pypykatz | pypykatz tabular output | Yes |
| NXC/NetExec | `--sam`, `--ntds`, auth success `[+]` lines | Yes |
| CrackMapExec | Legacy CME format (same parser as NXC) | Yes |

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| table | `-f table` | Colorized table with dynamic column widths (default) |
| csv | `-f csv` | 11-column CSV (domain, username, ntlm, sha1, aes256, aes128, password, sid, source, host, tags) |
| json | `-f json` | JSON array with 2-space indent |
| grep | `-f grep` | `domain\username:ntlm:password:source` one per line |
| hashcat | `-f hashcat` | `username:hash` for hashcat `-m 1000` |
| john | `-f john` | PWDUMP format `username:0:LMhash:NThash:::` |
| secretsdump | `-f secretsdump` | `DOMAIN/username:0:LMhash:NThash:::` |

## AD Analysis (`--stats`)

When `--stats` is enabled, mimikoutz performs Active Directory-focused analysis:

### Privilege Tagging

Every credential is tagged automatically:

| Tag | Meaning | Detection |
|-----|---------|-----------|
| `DA` | Domain Admin | SID RID 512 or name match |
| `EA` | Enterprise Admin | SID RID 519 |
| `SA` | Schema Admin | SID RID 518 |
| `PRIV` | Privileged | SID RID 500, admin name patterns |
| `SVC` | Service Account | `svc_`, `sql_`, `mssql_` prefixes etc. |
| `MACHINE` | Machine Account | Trailing `$` |
| `KRBAST` | Kerberoastable | Service account with hash, no plaintext |

### Password Reuse Detection

Groups accounts sharing the same NTLM hash or plaintext password — highlights credential reuse across the domain.

### Path-to-DA Detection

Alerts when Domain Admin or Enterprise Admin credentials are captured, especially service accounts on DC-like hosts.

### Kerberoastable Candidates

Flags service accounts that have hashes but no plaintext — candidates for TGS request + offline cracking.

## NXC Integration (`--nxc`)

Generates ready-to-use NetExec commands from captured credentials:

```
nxc smb <target> -u <user> -p '<password>' -d <domain>
nxc smb <target> -u <user> -H <ntlm_hash> -d <domain>
```

Prioritizes plaintext passwords over hashes, skips machine accounts and empty hashes.

## Options Reference

```
usage: mimikoutz [-i file [-i file2]] [-f format] [-o output] [filters]

input:
  -i <file>         input file (repeatable for multiple files)
  <file> [file2]    positional file args (without -i flag)
                    reads from stdin if no files given

output:
  -f <format>       table, csv, json, grep, hashcat, john, secretsdump
  -o <file>         write to file (default: stdout)

filters:
  -u <user>         filter by username (exact, case-insensitive)
  -d <domain>       filter by domain (exact, case-insensitive)
  --has-password    only entries with plaintext password
  --has-hash        only entries with hash
  --no-machine      exclude machine accounts ($)

analysis:
  --stats           show statistics, password reuse, path-to-DA, kerberoastable
  --nxc             generate NetExec lateral movement commands
  --diff <file>     compare against baseline dump, show only new credentials

display:
  --no-color        disable ANSI colors (also respects NO_COLOR env var)
  --no-banner       suppress ASCII banner
  -s, --silent      suppress ASCII banner (alias for --no-banner)
```

## Project Structure

```
mimikoutz/
├── main.go                          # entrypoint
├── flags.go                         # CLI flag parsing
├── banner.go                        # ASCII banner
├── go.mod
├── internal/
│   ├── parser/
│   │   ├── types.go                 # Credential struct, PrivTag, helpers
│   │   ├── parser.go                # Mimikatz format parser
│   │   ├── autodetect.go            # Format detection + secretsdump/pypykatz/nxc parsers
│   │   ├── dedup.go                 # Deduplication + sorting
│   │   ├── diff.go                  # Diff between dumps
│   │   ├── filter.go                # Filter logic
│   │   ├── adanalysis.go            # AD privilege tagging + analysis
│   │   └── stats.go                 # Statistics computation + display
│   └── formatter/
│       ├── color.go                 # ANSI color support
│       ├── table.go                 # Colorized table output
│       ├── csv.go                   # CSV output
│       ├── json.go                  # JSON output
│       ├── grep.go                  # Grep-friendly output
│       ├── hashcat.go               # Hashcat format
│       ├── john.go                  # John the Ripper PWDUMP format
│       └── secretsdump.go           # Secretsdump format
├── powershell/
│   ├── mimikoutz.ps1                # Direct-run PowerShell wrapper
│   └── mimikoutz.psm1              # PowerShell module (Import-Module)
├── testdata/                        # Sample input files for testing
├── Dockerfile                       # Multi-stage cross-compilation
└── Makefile                         # Build + test targets
```

## Building

### Requirements

- **Docker** (recommended) — no local Go installation needed
- **Go 1.22+** — for local builds

### Docker Build (Cross-Platform)

```bash
make build
```

Produces all three platform binaries + PowerShell module in `dist/`.

### Local Build

```bash
go build -ldflags="-s -w" -o mimikoutz .
```

### Testing

```bash
make test              # basic table + stats output
make test-all          # all formats + parsers + diff + merge
make test-filters      # filter combinations
```

## Environment Variables

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | Set to any value to disable ANSI colors (follows [no-color.org](https://no-color.org)) |

## License

For authorized security testing and educational use only.
