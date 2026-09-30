function Invoke-Mimikoutz {
    <#
    .SYNOPSIS
        Parse, deduplicate, and organize Mimikatz output.

    .DESCRIPTION
        PowerShell module wrapper for the mimikoutz binary.
        Supports piped input, multiple input files, all output formats, filters, and AD analysis.
        Auto-detects input format: mimikatz, secretsdump, pypykatz, nxc/netexec.

    .EXAMPLE
        .\mimikatz.exe "sekurlsa::logonpasswords" | Invoke-Mimikoutz
        Invoke-Mimikoutz -InputFile .\dump1.txt,.\dump2.txt -Format json
        Invoke-Mimikoutz -InputFile .\dump.txt -Stats -Nxc
        Invoke-Mimikoutz -InputFile .\dump.txt -FilterUser admin -FilterDomain CORP
        Invoke-Mimikoutz -InputFile .\new.txt -DiffFile .\baseline.txt
        nxc smb 10.0.0.0/24 --sam | Invoke-Mimikoutz
        mimikoutz -i .\dump.txt -f grep
        Invoke-Mimikoutz .\dump1.txt .\dump2.txt -Stats
    #>

    [CmdletBinding()]
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
        $ModuleDir = $PSScriptRoot
        $ProjectDir = Split-Path -Parent $ModuleDir
        $Binary = Join-Path $ModuleDir "mimikoutz-windows-amd64.exe"

        if (-not (Test-Path $Binary)) {
            $Binary = Join-Path $ProjectDir "mimikoutz-windows-amd64.exe"
        }
        if (-not (Test-Path $Binary)) {
            $Binary = Join-Path $ProjectDir "dist\mimikoutz-windows-amd64.exe"
        }
        if (-not (Test-Path $Binary)) {
            throw "mimikoutz binary not found. Run 'make build' first."
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
            throw "No input provided. Pipe mimikatz output or use -InputFile."
        }
    }
}

Set-Alias -Name mimikoutz -Value Invoke-Mimikoutz

Export-ModuleMember -Function Invoke-Mimikoutz -Alias mimikoutz
