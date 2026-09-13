[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Path
)

$signature = Get-AuthenticodeSignature -FilePath $Path
if ($signature.Status -ne 'Valid') {
    throw "Authenticode signature status for '$Path' is '$($signature.Status)'"
}

$subject = $signature.SignerCertificate.Subject
if ($subject -notmatch 'WireGuard LLC') {
    throw "Unexpected Wintun signer: $subject"
}

Write-Output "Valid Authenticode signature: $subject"
