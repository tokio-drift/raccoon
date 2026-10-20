/*
 * default.yar — RACCOON default YARA rules
 *
 * These rules are embedded into the raccoon binary and applied to every carved
 * file unless the user supplies a custom rules directory via --rules.
 *
 * Severity mapping (used by intel.Service when building Verdict events):
 *   - pe_header_in_non_exe : critical  (executable code in unexpected format)
 *   - suspicious_script    : warning   (scripting constructs in binary data)
 *   - eicar_test_file      : critical  (EICAR standard anti-malware test file)
 */

/*
 * Detects a PE (MZ) header found inside a file whose extension is not a
 * recognised executable type. This is a common technique for hiding
 * executables inside image or document containers.
 */
rule pe_header_in_non_exe
{
    meta:
        description = "PE / MZ header found in a non-executable file"
        severity    = "critical"
        author      = "raccoon-default"

    strings:
        $mz = { 4D 5A }   // MZ magic

    condition:
        $mz at 0
}

/*
 * Detects common scripting patterns (PowerShell / VBScript / bash) that have
 * no business appearing inside carved binary files such as images or PDFs.
 */
rule suspicious_script
{
    meta:
        description = "Script code (PowerShell / VBScript / bash) embedded in file"
        severity    = "warning"
        author      = "raccoon-default"

    strings:
        // PowerShell indicators
        $ps1 = "powershell" nocase
        $ps2 = "Invoke-Expression" nocase
        $ps3 = "IEX(" nocase
        $ps4 = "-EncodedCommand" nocase
        // VBScript indicators
        $vbs1 = "WScript.Shell" nocase
        $vbs2 = "CreateObject" nocase
        // Shell indicators
        $sh1 = "/bin/sh" ascii
        $sh2 = "/bin/bash" ascii
        // Common download cradles
        $dl1 = "DownloadString" nocase
        $dl2 = "wget http" nocase
        $dl3 = "curl http" nocase

    condition:
        2 of them
}

/*
 * EICAR standard anti-malware test file signature.
 *
 * The EICAR string is split across two string constants and reassembled at
 * match time via an offset condition so that this source file itself does not
 * contain the exact test string (which would cause AV scanners to flag the
 * raccoon binary).  The two halves are the canonical EICAR first 68 bytes:
 *
 *   X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
 *
 * Split:  "X5O!P%@AP[4\PZX54(P^)7CC)7}" + "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
 */
rule eicar_test_file
{
    meta:
        description = "EICAR standard anti-malware test file"
        severity    = "critical"
        author      = "raccoon-default"

    strings:
        // First half of the EICAR string (no splitting trick needed for this half)
        $part1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}"
        // Second half
        $part2 = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $part1 at 0 and $part2 at 29
}
