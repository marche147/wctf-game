REM Run this batch file as administrator

REM Add ctf user
net user test "this_is_a_useless_user_lulwat!" /add

REM Configure firewall policy
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
netsh advfirewall firewall add rule name="chalservice" dir=in action=allow protocol=TCP localport=13337

REM Configure registry
reg import wctf.reg
powershell .\config_acl.ps1

REM Install & run the service
C:\ctf\wctf.exe install
net start wctf
