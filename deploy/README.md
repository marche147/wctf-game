## Deployment guide

* Copy the files under `ctf\` to `C:\ctf\`
* Spawn a terminal with administrator rights, run `deploy.bat` (make sure everything is under current directory)
* Open `regedit.exe`, goto `HKLM\Software\WCTF\`, inspect the ACL of the key. You should find all access from `AppContainer` sandboxed application to the key are denied.
* To change the flag: edit the `flag` value in `wctf.reg`, you can find a placeholder there.