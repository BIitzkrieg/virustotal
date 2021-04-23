import os
import sys
import virustotal3.core
import re
import time
import json
from datetime import *

API_KEY = ''
vt_files = virustotal3.core.Files(API_KEY)
premium_api = True

def seperator():
    print("========================================================================")

def vtMain(iocList):
    count = 0
    for ioc in iocList:
        count += 1
        if premium_api == True:
            #print("Premium API set... We will use up to the limit you set in the script based on your subscription")
            if count == 1000:
                print("Hit Premium API limit.. exiting")
                break
            vtLogic(ioc, count)

        elif premium_api == False:
            #print("Regular API set... Script will wait 60 seconds every 4 IOC's")
            if count == 4:
                count = 0
                print("Sleeping, waiting for VT API", time.sleep(60))
                continue
            vtLogic(ioc, count)

def vtLogic(ioc, count):
    # MD5
    try:
        if re.match(r"(^[a-fA-F\d]{32}$)", str(ioc)):
            results = vt_files.info_file(ioc)
            #pprint.pprint(results)
            seperator()

            if results['data']:
                count += 1
                print("MD5: " + str(ioc))
                print()
                #print(json.dumps(results, indent=4,sort_keys=True))
                last_scan = results['data']['attributes']['last_analysis_date']
                local_time = datetime.fromtimestamp(last_scan).strftime('%c')
                print("Last Scan: " + local_time + " EST")
                print("Equivalent SHA-1: " + results['data']['attributes']['sha1'])
                print("Equivalent SHA-256: " + results['data']['attributes']['sha256'])
                num_malicious = int(results['data']['attributes']['last_analysis_stats']['malicious'])
                num_undetected = int(results['data']['attributes']['last_analysis_stats']['undetected'])
                total = num_malicious + num_undetected
                print("VT Results:", num_malicious, '\\', total)
    except:
        raise

def main(iocList):
    vtMain(iocList)

if __name__ == '__main__':
    iocList = list(dict.fromkeys(sys.argv[1:]))
    main(iocList)
