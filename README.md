# iCULeak.py

![](https://i.imgur.com/oHWRgmH.png)

Tool to find and extract credentials from phone configuration files in environments managed by Cisco's CUCM (Call Manager).

When using Cisco's CUCM (Call Manager), phone configuration files are stored on a TFTP server. These phone configuration files quite frequently contain sensitive data, including phone SSH/admin credentials.

There is an issue with how some browsers autofill fields such as the SSH Username & Password fields with credentials if the administrator has auto-save enabled. While the issue was [fixed in CUCM 12.0](https://lists.gt.net/cisco/voip/199231), credentials stored in the past may still be discoverable.

The tool utilises a lot of code from [Dirk-jan's tool adidnsdump](https://github.com/dirkjanm/adidnsdump) to extract a list of phone hostnames from ADIDNS over LDAP. To read more aboout the technique and tool, you can read the [associated blog post](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/). So credit goes to him for a lot of the code.

# Installation and usage
To install the tool:
```
git clone https://github.com/llt4l/iCULeak.py
cd iCULeak.py
pip install -r requirements.txt
```

Usage:

Pass the '-h' flag to iCULeak.py for help.

![](https://i.imgur.com/C7Vm2n3.png)
