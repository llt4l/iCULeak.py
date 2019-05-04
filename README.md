# iCULeak.py

![](https://i.imgur.com/oHWRgmH.png)

Tool to find and extract credentials from phone configuration files in environments managed by Cisco's CUCM (Call Manager).

When using Cisco's CUCM (Call Manager), phone configuration files are stored on a TFTP server. These VoIP phone configuration files quite frequently contain sensitive data, including phone SSH/admin credentials.

There is also an issue with how some browsers **autofill fields such as the SSH Username & Password fields with their CUCM credentials (commonly their AD credentials)**, if the administrator has saved the credentials in their browser. This issue has also been faced by administrators using password managers that automatically plug in credentials, where they found that their credentials were being automatically inputted into the SSH Username & Password fields, and then being saved (and stored in plaintext in the configuration files).

While the issue was [fixed in CUCM 12.0](https://lists.gt.net/cisco/voip/199231), credentials stored in the past may still be discoverable.

The issue can be somewhat mitigated by the following actions:
1. Regularly purging existing configuration files from leaked credentials.
2. Blocking autosave/autofill on CUCM.
3. Enabling encryption of phone configuration files. Read more on that [here](https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/security/8_5_1/secugd/sec-851-cm/secuencp.html). Note that this doesn't completely mitigate the issue, as the encryption password could be obtained from the phones' memory or through administrative access of CUCM - but it reduces the impact of a hacker/pentester dumping the configuraiton files.

This tool utilises a lot of code from [Dirk-jan's tool adidnsdump](https://github.com/dirkjanm/adidnsdump) to extract a list of phone hostnames from ADIDNS over LDAP. To read more aboout the technique and tool, you can read the [associated blog post](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/). So credit goes to him for a lot of the code.

## Installation
To install the tool:
```
git clone https://github.com/llt4l/iCULeak.py
cd iCULeak.py
pip install -r requirements.txt
```

## Usage:

Run iCULeak.py against phones with hostnames found in the DNS zone

```shell
python iCULeak.py -u domain\\llt4l -c 10.100.1.29 10.100.1.1
```

Run iCULeak.py against a list of phones provided in a file 

```shell
python iCULeak.py -l phones_hostnames -c 10.100.1.29 10.100.1.1
```

**Flags:**

* **View the help page** with `-h` or `--help`
* **Pass the username** of the user that will authenticate to ADIDNS with the `-u` or `--user` flags. The user should be preceded by the user's domain, so it should look something like this: **`domain\\llt4l`**. This flag is optional if a list is passed instead.
* **Pass the password** to the program with the `-p` or `--password` flag. If you do not pass it as an argument, but do pass a username, then the program will prompt for a password when run .
* The **IP address or hostname of the CUCM server** should be passed to the program with either the `-c` or `--cucm-server` flag. If, for any reason, the TFTP server being used by CUCM to store phone configuration files is found on another host, please provide that address.
* Provide a **file that contains a list of phone hostnames** with the `-l` or `--list` flag. The file should just be a list of phone hostnames, such that each line would look something like `SEP112233445566`.
* If you'd like to **save the results to a CSV file**, pass the `-s` or `--save` flag along with the filename to be saved to.
* By default iCULeak.py checks credentials leaked for validity in the AD. To **disable authentication attempts** being made to verify the leaked credentials, pass the `-nA` or `--no-authentication` flag.
* To **save all the phone configuration files** dumped to a directory, pass the `-O` or `--out-dir` flag, along with the name of the folder you want to save it to.
* For **increased verbosity**, you can pass the `-v` or `--verbose` flag.
* If the DNS entries for the phones are in a **different DNS zone** to the default zone of the domain you are authenticating against, you can pass the zone along with the `-z` or `--zone` flag.
