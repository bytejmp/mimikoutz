<#
.SYNOPSIS
    PowerShell wrapper for mimikoutz - Mimikatz output parser and deduplicator.

.DESCRIPTION
    Accepts piped Mimikatz output or file paths and passes them to the mimikoutz binary.
    All flags mirror the Go binary for feature parity.
    Auto-detects input format: mimikatz, secretsdump, pypykatz, nxc/netexec.

.EXAMPLE
    .\mimikatz.exe "sekurlsa::logonpasswords" | .\mimikoutz.ps1
    .\mimikoutz.ps1 -InputFile .\dump1.txt,.\dump2.txt -Format json
    .\mimikoutz.ps1 -InputFile .\dump.txt -Format csv -OutputFile creds.csv -Stats
    .\mimikoutz.ps1 -InputFile .\dump.txt -FilterUser admin -FilterDomain CORP
    .\mimikoutz.ps1 -InputFile .\new.txt -DiffFile .\baseline.txt
    nxc smb 10.0.0.0/24 --sam | .\mimikoutz.ps1
    .\mimikoutz.ps1 .\dump1.txt .\dump2.txt -Stats
#>

param(
    [Parameter(ValueFromPipeline=$true)]
    [string[]]$PipedInput,

    [Alias("i")]
    [string[]]$InputFile,

    [Alias("f")]
    [ValidateSet("table", "csv", "json", "grep", "hashcat", "john", "secretsdump")]
    [string]$Format = "table",

    [Alias("o")]
    [string]$OutputFile,

    [Alias("u")]
    [string]$FilterUser,

    [Alias("d")]
    [string]$FilterDomain,

    [switch]$HasPassword,
    [switch]$HasHash,
    [switch]$NoMachine,
    [switch]$NoColor,

    [Alias("s", "Silent")]
    [switch]$NoBanner,

    [switch]$Stats,
    [switch]$Nxc,

    [string]$DiffFile,

    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$PositionalFiles
)

begin {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $ProjectDir = Split-Path -Parent $ScriptDir
    $Binary = Join-Path $ScriptDir "mimikoutz-windows-amd64.exe"

    if (-not (Test-Path $Binary)) {
        $Binary = Join-Path $ProjectDir "mimikoutz-windows-amd64.exe"
    }
    if (-not (Test-Path $Binary)) {
        $Binary = Join-Path $ProjectDir "dist\mimikoutz-windows-amd64.exe"
    }
    if (-not (Test-Path $Binary)) {
        Write-Error "mimikoutz binary not found. Run 'make build' first."
        exit 1
    }

    $collectedInput = @()
}

process {
    if ($PipedInput) {
        $collectedInput += $PipedInput
    }
}

end {
    $cmdArgs = @("-f", $Format)

    if ($OutputFile)    { $cmdArgs += @("-o", $OutputFile) }
    if ($FilterUser)    { $cmdArgs += @("-u", $FilterUser) }
    if ($FilterDomain)  { $cmdArgs += @("-d", $FilterDomain) }
    if ($HasPassword)   { $cmdArgs += "--has-password" }
    if ($HasHash)       { $cmdArgs += "--has-hash" }
    if ($NoMachine)     { $cmdArgs += "--no-machine" }
    if ($NoColor)       { $cmdArgs += "--no-color" }
    if ($NoBanner)      { $cmdArgs += "--no-banner" }
    if ($Stats)         { $cmdArgs += "--stats" }
    if ($Nxc)           { $cmdArgs += "--nxc" }
    if ($DiffFile)      { $cmdArgs += @("--diff", $DiffFile) }

    # Merge positional file args into InputFile
    if ($PositionalFiles) {
        $resolvedPositional = @()
        foreach ($pf in $PositionalFiles) {
            if (Test-Path $pf) {
                $resolvedPositional += $pf
            }
        }
        if ($resolvedPositional.Count -gt 0) {
            if ($InputFile) {
                $InputFile = $InputFile + $resolvedPositional
            } else {
                $InputFile = $resolvedPositional
            }
        }
    }

    if ($InputFile) {
        foreach ($file in $InputFile) {
            $cmdArgs += @("-i", $file)
        }
        & $Binary @cmdArgs
    }
    elseif ($collectedInput.Count -gt 0) {
        $collectedInput | & $Binary @cmdArgs
    }
    else {
        Write-Error "No input provided. Pipe mimikatz output or use -InputFile."
        exit 1
    }
}
