# virustotal
Collection of VT scripts for InfoSec

# vtjwalk.py

Ported Jalcon Walker's VT API 2.x to work with Python 3:
https://github.com/jwalker/Virustotal-Module

# vt-lookup.py

Reads in a list of IOC's (IP, Domain, URL, MD5, SHA-1, SHA-256 hashes) and returns information from VT.

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
  - Detected URL's
  - Detected Referrer Samples
  - Detected Downloaded Samples
  - Detected Communicating Samples
  - Passive DNS Results
    
- IP
  - Country Code
  - Owner
  - Detected URL's
  - Detected Referrer Samples
  - Detected Downloaded Samples
  - Detected Communicating Samples
  - Passive DNS Results
