import re
import virustotal3.core
from datetime import *

API_KEY = ''
vt_files = virustotal3.core.Files(API_KEY)
vt_domains = virustotal3.core.Domains(API_KEY)
vt_IP = virustotal3.core.IP(API_KEY)
vt_URL = virustotal3.core.URL(API_KEY)
premium_api = True

def seperator():
    print("========================================================================")

def vtMain():
    f = open("ioc.txt")
    contents = f.read()
    file_as_list = list(dict.fromkeys((contents.splitlines())))
    count = 0
    for ioc in file_as_list:
        count += 1
        if premium_api == True:
            # print("Premium API set... We will use up to the limit you set in the script based on your subscription")
            if count == 1000:
                print("Hit Premium API limit.. exiting")
                break
            vtLogic(ioc, count)

def vtLogic(ioc, count):
    # MD5
    if re.match(r"(^[a-fA-F\d]{32}$)", str(ioc)):
        try:
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
    # SHA-1
    elif re.match(r"(^[a-fA-F\d]{40}$)", str(ioc)):
        try:
            results = vt_files.info_file(ioc)
            #pprint.pprint(results)
            seperator()

            if results['data']:
                count += 1
                print("SHA-1: " + str(ioc))
                print()
                #print(json.dumps(results, indent=4,sort_keys=True))
                last_scan = results['data']['attributes']['last_analysis_date']
                local_time = datetime.fromtimestamp(last_scan).strftime('%c')
                print("Last Scan: " + local_time + " EST")
                print("Equivalent MD5: " + results['data']['attributes']['md5'])
                print("Equivalent SHA-256: " + results['data']['attributes']['sha256'])
                num_malicious = int(results['data']['attributes']['last_analysis_stats']['malicious'])
                num_undetected = int(results['data']['attributes']['last_analysis_stats']['undetected'])
                total = num_malicious + num_undetected
                print("VT Results:", num_malicious, '\\', total)
        except:
            pass
    # SHA-256
    elif re.match(r"(^[a-fA-F\d]{64}$)", str(ioc)):
        try:
            results = vt_files.info_file(ioc)
            #pprint.pprint(results)
            seperator()

            if results['data']:
                count += 1
                print("SHA-1: " + str(ioc))
                print()
                #print(json.dumps(results, indent=4,sort_keys=True))
                last_scan = results['data']['attributes']['last_analysis_date']
                local_time = datetime.fromtimestamp(last_scan).strftime('%c')
                print("Last Scan: " + local_time + " EST")
                print("Equivalent MD5: " + results['data']['attributes']['md5'])
                print("Equivalent SHA-1: " + results['data']['attributes']['sha1'])
                num_malicious = int(results['data']['attributes']['last_analysis_stats']['malicious'])
                num_undetected = int(results['data']['attributes']['last_analysis_stats']['undetected'])
                total = num_malicious + num_undetected
                print("VT Results:", num_malicious, '\\', total)
        except:
            pass


    # Domain
    elif re.match(r"^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$", str(ioc)):
        try:
            results = vt_domains.info_domain(ioc)
            seperator()
            if results['data']:
                count += 1
                print("Domain: " + str(ioc))
                num_malicious = int(results['data']['attributes']['last_analysis_stats']['malicious'])
                num_undetected = int(results['data']['attributes']['last_analysis_stats']['undetected'])
                total = num_malicious + num_undetected
                print("VT Results:", num_malicious, '\\', total)

        except:
            pass
    # URL
    elif re.match(r"(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})", str(ioc)):
        try:
            results = vt_URL.info_url(ioc)
            seperator()
            if results['data']:
                count += 1
                print("URL: " + str(ioc))
                num_malicious = int(results['data']['attributes']['last_analysis_stats']['malicious'])
                num_undetected = int(results['data']['attributes']['last_analysis_stats']['undetected'])
                total = num_malicious + num_undetected
                print("VT Results:", num_malicious, '\\', total)
        except:
            pass
    # IP
    elif re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", str(ioc)):
        try:
            results = vt_IP.info_ip(ioc)
            seperator()
            if results['data']:
                count += 1
                print("IP: " + str(ioc))
                num_malicious = int(results['data']['attributes']['last_analysis_stats']['malicious'])
                num_undetected = int(results['data']['attributes']['last_analysis_stats']['undetected'])
                total = num_malicious + num_undetected
                print("VT Results:", num_malicious, '\\', total)
        except:
            pass


def main():
    vtMain()

if __name__ == '__main__':
    main()
