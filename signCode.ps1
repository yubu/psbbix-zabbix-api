Set-AuthenticodeSignature psbbix.psm1 @(Get-ChildItem cert:\CurrentUser\My -codesign)[0]
Set-AuthenticodeSignature manageZabbixAgent.ps1 @(Get-ChildItem cert:\CurrentUser\My -codesign)[0]