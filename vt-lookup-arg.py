# VT Lookup Script
# Andrew Danis
# Looks up info on Hashes, Domains, IP's, and URL's via Virustotal

from vtjwalk import *
import re
from time import sleep
import sys

premium_api = True


def seperator():
    print("========================================================================")


def vtMain(iocList):
    v = Virustotal()
    count = 0
    for ioc in iocList:
        count += 1
        if premium_api == True:
            #print("Premium API set... We will use up to the limit you set in the script based on your subscription")
            if count == 1000:
                print("Hit Premium API limit.. exiting")
                break
            vtLogic(ioc, v, count)

        elif premium_api == False:
            #print("Regular API set... Script will wait 60 seconds every 4 IOC's")
            if count == 4:
                count = 0
                print("Sleeping, waiting for VT API", sleep(60))
                continue
            vtLogic(ioc, v, count)

def vtLogic(ioc, v, count):
    # MD5
    if re.match(r"(^[a-fA-F\d]{32}$)", str(ioc)):
        results = v.rscReport(ioc)
        seperator()
        if results['response_code'] == 1:
            count += 1
            print("MD5: " + str(ioc))
            print()
            print("Last Scan: " + results['scan_date'])
            print("VT Results:", results['positives'], '\\', results['total'])
        elif results['response_code'] == 0:
            count += 1
            print("Hash: ", str(ioc),"\nNot Found in VT")

    # SHA-1
    elif re.match(r"(^[a-fA-F\d]{40}$)", str(ioc)):
        results = v.rscReport(ioc)
        seperator()
        if results['response_code'] == 1:
            count += 1
            print("SHA-1:" + str(ioc))
            print()
            print("Last Scan: " + results['scan_date'])
            print("VT Results:", results['positives'], '\\', results['total'])
        elif results['response_code'] == 0:
            count += 1
            print("Hash: ", str(ioc),"\nNot Found in VT")

    # SHA - 256
    elif re.match(r"(^[a-fA-F\d]{64}$)", str(ioc)):
        results = v.rscReport(ioc)
        seperator()
        if results['response_code'] == 1:
            count += 1
            print("SHA-256:" + str(ioc))
            print()
            print("Last Scan: " + results['scan_date'])
            print("VT Results:", results['positives'], '\\', results['total'])
        elif results['response_code'] == 0:
            count += 1
            print("Hash: ", str(ioc),"\nNot Found in VT")


    # URL
    elif re.match(r"(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})", str(ioc)):
        results = v.urlReport(ioc)
        seperator()
        if results['response_code'] == 1:
            count += 1
            print("URL: " + str(ioc))
            print()
            print("Last Scan: " + results['scan_date'])
            print("VT Results:", results['positives'], '\\', results['total'])
        elif results['response_code'] == 0:
            count += 1
            print("URL: ", str(ioc), "\nNot Found in VT")


    # Domain
    elif re.match(r"^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$", str(ioc)):
        results = v.domainReport(ioc)
        seperator()
        if results['response_code'] == 1:
            count += 1
            print("Domain: " + str(ioc))
            print()
            try:
                if results['whois']:
                    whois = results['whois']
                    whoisQuery = re.search(r"(Query time: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", str(whois))
                    whoisCreate = re.search(r"(Create date:|Creation Date: \d{4}-\d{2}-\d{2})", str(whois))
                    whoisExpiry = re.search(r"(Expiry date:|Expiration Date: \d{4}-\d{2}-\d{2})", str(whois))
                    whoisUpdate = re.search(r"(Update date:|Updated Date: \d{4}-\d{2}-\d{2})", str(whois))
                    whoisRegistrar= re.search(r"(Registrar: [a-zA-Z].+)", str(whois))
                    print("Domain", whoisRegistrar.group())
                    print("Domain", whoisCreate.group())
                    print("Domain", whoisExpiry.group())
                    print("Domain", whoisUpdate.group())
                    print("Domain", whoisQuery.group())
            except:
                pass

            try:
                if results['detected_urls']:
                    print()
                    print("First 5 Detected URL's Under This Domain:")
                    for hit in results['detected_urls'][:5]:
                        print(hit['url'] + " " + str(hit['positives']), '\\', str(hit['total']))
            except:
                pass

            try:
                if results['detected_referrer_samples']:
                    print()
                    print("First 5 Detected Referrer Samples:")
                    for hit in results['detected_referrer_samples'][:5]:
                        print(hit['sha256'] + " " + str(hit['positives']), '\\', str(hit['total']))
            except:
                pass

            try:
                if results['detected_downloaded_samples']:
                    print()
                    print("First 5 Detected Downloaded Files:")
                    for hit in results['detected_downloaded_samples'][:5]:
                        print(hit['sha256'] + " " + str(hit['positives']), '\\', str(hit['total']))
            except:
                pass

            try:
                if results['detected_communicating_samples']:
                    print()
                    print("First 5 Detected Communicating Samples:")
                    for hit in results['detected_communicating_samples'][:5]:
                        print(hit['sha256'] + " " + str(hit['positives']), '\\', str(hit['total']))
            except:
                pass

            try:
                if results['resolutions']:
                    print()
                    print("First 5 Passive DNS Results:")
                    for hit in results['resolutions'][:5]:
                        print(hit['ip_address'] + " - " + "Last Resolved: " + str(hit['last_resolved']))
                elif len(results['resolutions']) == 0:
                    print()
                    print("No passive DNS results for this Domain")
            except:
                pass

        elif results['response_code'] == 0:
            count += 1
            print("Domain: ", str(ioc), "\nNot Found in VT")
            print()

    # IP
    elif re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", str(ioc)):
        results = v.ipReport(ioc)
        seperator()
        if results['response_code'] == 1:
            count += 1
            print("IP: " + str(ioc))
            print()
            try:
                if results['country']:
                    print("Country Code: " + results['country'])
                if results['as_owner']:
                    print("Owner: " + results['as_owner'])
            except:
                pass
            try:
                if results['detected_urls']:
                    print()
                    print("First 5 Detected URL's Under This IP:")
                    for hit in results['detected_urls'][:5]:
                        print(hit['url'] + " " + str(hit['positives']), '\\', str(hit['total']))
            except:
                pass

            try:
                if results['detected_referrer_samples']:
                    print()
                    print("First 5 Detected Referrer Samples:")
                    for hit in results['detected_referrer_samples'][:5]:
                        print(hit['sha256'] + " " + str(hit['positives']), '\\', str(hit['total']))

            except:
                pass

            try:
                if results['detected_downloaded_samples']:
                    print()
                    print("First 5 Detected Downloaded Files:")
                    for hit in results['detected_downloaded_samples'][:5]:
                        print(hit['sha256'] + " " + str(hit['positives']), '\\', str(hit['total']))
            except:
                pass

            try:
                if results['detected_communicating_samples']:
                    print()
                    print("First 5 Detected Communicating Samples:")
                    for hit in results['detected_communicating_samples'][:5]:
                        print(hit['sha256'] + " " + str(hit['positives']), '\\', str(hit['total']))

            except:
                pass

            try:
                if results['resolutions']:
                    print()
                    print("First 5 Passive DNS Results:")
                    for hit in results['resolutions'][:5]:
                        print(hit['hostname'] + " - " + "Last Resolved: " + str(hit['last_resolved']))
                elif len(results['resolutions']) == 0:
                    print()
                    print("No passive DNS results for this IP")
            except:
                pass

        elif results['response_code'] == 0:
            count += 1
            print("IP: ", str(ioc), "\nNot Found in VT")
            print()
    return count

def main(iocList):
    vtMain(iocList)

if __name__ == '__main__':
    iocList = set(sys.argv[1:])
    main(iocList)
