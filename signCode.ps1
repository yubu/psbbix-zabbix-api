Set-AuthenticodeSignature .\psbbix.psm1 @(Get-ChildItem cert:\CurrentUser\My -codesign)[0]