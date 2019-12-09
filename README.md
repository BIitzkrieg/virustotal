# virustotal
Collection of VT scripts for InfoSec

## Requirements

the vtjwalk library  
An API key, defined in the vtwalk library.  
- Standard, 4 requests/min
- Enterprise, 1000 or however much you pay for

These values are configurable in the vtMain() function. Set the "premium_api" variable to True or False depending on what API key you use.

# vtjwalk.py

Ported Jalcon Walker's VT API 2.x to work with Python 3:
https://github.com/jwalker/Virustotal-Module

# vt-lookup.py

Reads in a list of IOC's from a file (IP, Domain, URL, MD5, SHA-1, SHA-256 hashes) and returns information from VT.

Usage: python3 vt3-lookup.py

- Hashes
  - Last scan date
  - Positive AV results / total
  
- URL
   - Last scan date
   - Positive AV results / total

- Domain
  - WHOIS Data
    - Query Time
    - Create Date
    - Expiry data
    - Update Date
    - Administrative Country
  - Detected URL's (First 5)
  - Detected Referrer Samples (First 5)
  - Detected Downloaded Samples (First 5)
  - Detected Communicating Samples (First 5)
  - Passive DNS Results (First 5)
    
- IP
  - Country Code
  - Owner
  - Detected URL's (First 5)
  - Detected Referrer Samples (First 5)
  - Detected Downloaded Samples (First 5)
  - Detected Communicating Samples (First 5)
  - Passive DNS Results (First 5)
  
# vt-lookup-arg.py

Reads in 1 or more IOC's as aguments (IP, Domain, URL, MD5, SHA-1, SHA-256 hashes) and returns information from VT.

Usage: python3 vt-lookup-arg.py [ioc]

Provides same data as above.


# Example Output:
```
========================================================================
SHA-256:c88fe271ef62527aa9041e92c3afe773674c82fceb82dd2d5ac767d5fc78b4f2

Last Scan: 2019-12-05 16:49:39
VT Results: 67 \ 72
========================================================================
IP: 159.69.186.9

Country Code: DE
Owner: Hetzner Online GmbH

First 5 Detected URL's Under This IP:
https://ubabnkplc.com/sdcx/e4563cdce29de5103cde72db0917527f/login.php?cmd=login_submit&id=9232c87d763e6f4556cf876409478d099232c87d763e6f4556cf876409478d09&session=9232c87d763e6f4556cf876409478d099232c87d763e6f4556cf876409478d09 6 \ 72

http://luxgate.toutnet.de/ins.exe 6 \ 72
http://www.secureservis.com/DelM/workplace/ 14 \ 72
https://mobiiler-efuind.com/directing/desjardins/identifiantunique/questions.php 12 \ 73
http://tube.animal64u.com/videos-of-women-giving-head-to-animals.html 3 \ 72

First 5 Detected Downloaded Files:
4fdaf6b7ac08558f3984f855b17342dbabfc1ad7bd86892fa53b19f79046b3c2 1 \ 72
6c6b2e1e9f755c1859320d2962e18b0cd6815562d43a34e67213b8fcb1336217 1 \ 73
3aabcde1148ef8a27142d0e54411f1c88c88fe4628896db13ddff967237ae5af 1 \ 72

First 5 Detected Communicating Samples:
55a3438c9b4fd161fc97c12cc3702f5d2137908f94c2574a7b018d4df24f7642 31 \ 71
9fcd67629e836de8332d6cbd4b1ff768f8bf0dfa87c2eb03589325fe74829e46 37 \ 71
4466a2bb3dda59cd53f882cd44974225b8ec03f9a645e6f646a727de5553f248 29 \ 71
66c0d3f98c9617ddc258cc48431239adc5f778800d20013086cf5efbd6101c35 37 \ 70
2aa9cd83d4f2b932b0fed1d2811564056370870d9c857946ff6eb5f00902233c 57 \ 73

First 5 Passive DNS Results:
0-24booking.com - Last Resolved: 2019-11-22 00:02:15
0-60grand.com - Last Resolved: 2019-10-03 09:05:36
0.facebook.com.mrproxy.de - Last Resolved: 2019-11-14 13:03:28
0.gz.cn.com - Last Resolved: 2019-11-28 12:01:00
0.rqcu.com - Last Resolved: 2019-11-06 08:50:28

```
