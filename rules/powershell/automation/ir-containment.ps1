<#
.SYNOPSIS
    Execute containment actions on a compromised Entra ID account.
.DESCRIPTION
    Performs a multi-step containment sequence: disable account, revoke sessions,
    reset password, block sign-in, and optionally block the attacker's IP via
    a Named Location used in a blocking CA policy.
.PARAMETER UserPrincipalName
    The UPN of the compromised account.
.PARAMETER BlockIP
    Optional: attacker IP address to add to a blocking Named Location.
.PARAMETER CaseNumber
    Incident identifier for logging and audit trail.
.PARAMETER SkipPasswordReset
    If set, skips the password reset step (use when you want to preserve the
    current password hash for forensic analysis).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [string]$BlockIP,

    [Parameter(Mandatory)]
    [string]$CaseNumber,

    [switch]$SkipPasswordReset
)

$ErrorActionPreference = 'Stop'

Connect-MgGraph -Scopes @(
    "User.ReadWrite.All",
    "Directory.AccessAsUser.All"
) -NoWelcome

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = ".\Containment_${CaseNumber}_${timestamp}.log"

function Write-Log {
    param([string]$Action, [string]$Result, [string]$Detail)
    $entry = "[{0}] [{1}] {2}: {3}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Result, $Action, $Detail
    Write-Host $entry -ForegroundColor $(
        switch ($Result) { "SUCCESS" { "Green" } "FAILED" { "Red" } "SKIPPED" { "Yellow" } default { "White" } }
    )
    Add-Content -Path $logPath -Value $entry
}

Write-Log -Action "CONTAINMENT START" -Result "INFO" -Detail "Case: $CaseNumber | Target: $UserPrincipalName"

# Step 1: Disable account
Write-Host "`n[Step 1/5] Disabling account..." -ForegroundColor Cyan
try {
    Update-MgUser -UserId $UserPrincipalName -AccountEnabled:$false
    Write-Log -Action "Disable Account" -Result "SUCCESS" -Detail "Account disabled"
} catch {
    Write-Log -Action "Disable Account" -Result "FAILED" -Detail $_.Exception.Message
}

# Step 2: Revoke all sessions
Write-Host "[Step 2/5] Revoking sessions..." -ForegroundColor Cyan
try {
    Revoke-MgUserSignInSession -UserId $UserPrincipalName
    Write-Log -Action "Revoke Sessions" -Result "SUCCESS" -Detail "All refresh tokens revoked"
} catch {
    Write-Log -Action "Revoke Sessions" -Result "FAILED" -Detail $_.Exception.Message
}

# Step 3: Reset password
if ($SkipPasswordReset) {
    Write-Log -Action "Reset Password" -Result "SKIPPED" -Detail "SkipPasswordReset flag set (forensic preservation)"
} else {
    Write-Host "[Step 3/5] Resetting password..." -ForegroundColor Cyan
    try {
        $newPassword = -join ((65..90) + (97..122) + (48..57) + (33..38) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
        $passwordProfile = @{
            Password                      = $newPassword
            ForceChangePasswordNextSignIn = $true
        }
        Update-MgUser -UserId $UserPrincipalName -PasswordProfile $passwordProfile
        Write-Log -Action "Reset Password" -Result "SUCCESS" -Detail "Password reset, force change on next sign-in"

        # Securely output the temp password
        Write-Host "  Temporary password (provide to user via secure channel): $newPassword" -ForegroundColor Yellow
    } catch {
        Write-Log -Action "Reset Password" -Result "FAILED" -Detail $_.Exception.Message
    }
}

# Step 4: Block sign-in (belt and suspenders with account disable)
Write-Host "[Step 4/5] Blocking sign-in..." -ForegroundColor Cyan
try {
    Update-MgUser -UserId $UserPrincipalName -AccountEnabled:$false
    Write-Log -Action "Block Sign-In" -Result "SUCCESS" -Detail "Sign-in blocked (account disabled confirmed)"
} catch {
    Write-Log -Action "Block Sign-In" -Result "FAILED" -Detail $_.Exception.Message
}

# Step 5: Block attacker IP (optional)
if ($BlockIP) {
    Write-Host "[Step 5/5] Blocking attacker IP $BlockIP..." -ForegroundColor Cyan

    $blockLocationName = "IR-Blocked-IPs"

    try {
        # Check if blocking Named Location exists
        $existingLocations = Get-MgIdentityConditionalAccessNamedLocation -All |
            Where-Object { $_.DisplayName -eq $blockLocationName }

        $ipRange = @{
            "@odata.type" = "#microsoft.graph.iPv4CidrRange"
            CidrAddress   = "$BlockIP/32"
        }

        if ($existingLocations) {
            $location = $existingLocations[0]
            $currentRanges = $location.AdditionalProperties.ipRanges
            $currentRanges += $ipRange

            Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId $location.Id `
                -AdditionalProperties @{ ipRanges = $currentRanges }

            Write-Log -Action "Block IP" -Result "SUCCESS" -Detail "$BlockIP added to $blockLocationName"
        } else {
            $params = @{
                "@odata.type" = "#microsoft.graph.ipNamedLocation"
                DisplayName   = $blockLocationName
                IsTrusted     = $false
                IpRanges      = @($ipRange)
            }
            New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
            Write-Log -Action "Block IP" -Result "SUCCESS" -Detail "Created $blockLocationName with $BlockIP"
            Write-Host "  NOTE: Create a CA policy to block sign-ins from '$blockLocationName'" -ForegroundColor Yellow
        }
    } catch {
        Write-Log -Action "Block IP" -Result "FAILED" -Detail $_.Exception.Message
    }
} else {
    Write-Log -Action "Block IP" -Result "SKIPPED" -Detail "No BlockIP specified"
}

# Summary
Write-Host "`n[✓] Containment complete for $UserPrincipalName" -ForegroundColor Green
Write-Host "  Log: $logPath"
Write-Host "  NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Audit inbox rules and forwarding (Invoke-ForwardingAudit.ps1)"
Write-Host "  2. Review OAuth consent grants (Invoke-ConsentGrantAudit.ps1)"
Write-Host "  3. Check sign-in logs for scope assessment (Invoke-SignInAnalysis.ps1)"
Write-Host "  4. Verify MFA methods — remove any attacker-registered methods"
Write-Host "  5. Check audit logs for persistence actions during compromise window"
