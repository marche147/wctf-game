# Secure access so attackers can't extract the secret from registry even if they have remote code execution :p
$acl = Get-Acl HKLM:\SOFTWARE\WCTF\
$sddl = "O:BAG:S-1-5-21-4269827912-1333813219-4110619441-513D:PAI(D;CI;RP;;;AC)(D;CI;RP;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;CIIO;KA;;;CO)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)"
$acl.SetSecurityDescriptorSddlForm($sddl)
Set-Acl -Path HKLM:\SOFTWARE\WCTF\ -AclObject $acl
