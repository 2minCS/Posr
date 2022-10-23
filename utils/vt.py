import json
import requests
#https://www.virustotal.com/ui/files/{SHA256_HASH}
#https://www.virustotal.com/ui/domains/{DOMAIN}
#https://www.virustotal.com/ui/ip_addresses/{IP_ADDRESS}
#f8ee4c00a3a53206d8d37abe5ed9f4bfc210a188cd5b819d3e1f77b34504061e


def vt_file(input):
    '''
  Query VirusTotal with a SHA256 hash.
  '''
    url = f"https://www.virustotal.com/ui/files/{input}"
    url2= f"https://www.virustotal.com/gui/file/{input}"
    headers = {
        "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36 Edg/92.0.902.67",
        "X-Tool": "vt-ui-main",
        "X-App-Version": "v1x37x1",
        "X-VT-Anti-Abuse-Header":"MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNjMxMTE3NzQyLjY1",
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
        #"X-Recaptcha-Response": "",
    }

    data = requests.get(url, headers=headers).json()
    #print(data.text)
    # uncomment this to print all data:
    #print(json.dumps(data, indent=4))

    # print some data:
    #for k, v in data["data"]["attributes"]["last_analysis_results"].items():
    #print("{:<30} {:<30}".format(k, str(v["result"])))
    try:
        
        threat=(json.dumps(
             data["data"]["attributes"]["popular_threat_classification"]
                ["suggested_threat_label"]))
        #print(
            #json.dumps(data["data"]["attributes"]["last_analysis_stats"],
                       #indent=4))
        #print(data["data"]["attributes"]["last_analysis_stats"]["malicious"])
        ret = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return threat,ret, url2
    except:
        #print("File not found in VirusTotal")
        pass


def vt_domain(input):
    '''
  Query VirusTotal with a domain.
  '''
    url = f"https://www.virustotal.com/ui/domains/{input}"
    url2 = f"https://www.virustotal.com/gui/domain/{input}"
    headers = {
        "User-Agent":
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "X-Tool": "vt-ui-main",
        "X-VT-Anti-Abuse-Header":
        "MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNjMxMTE3NzQyLjY1",
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
    }
    
    data = requests.get(url, headers=headers).json()
    #print(data.text)
    # uncomment this to print all data:
    #print(json.dumps(data, indent=4))
    try:
        # print some data:
        #for k, v in data["data"]["attributes"]["last_analysis_results"].items(
        #):
           # print("{:<30} {:<30}".format(k, str(v["result"])))
        #print(
            #json.dumps(data["data"]["attributes"]["last_analysis_stats"],
                       #indent=4))
        #print(data["data"]["attributes"]["last_analysis_stats"]["malicious"])
        ret = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return ret, url2
    except:
        #print("Domain not found in VirusTotal")
        pass


def vt_ip(input):
    '''
    Query VirusTotal with an IP.
    '''
    url = f"https://www.virustotal.com/ui/ip_addresses/{input}"
    headers = {
        "User-Agent":
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "X-Tool": "vt-ui-main",
        "X-VT-Anti-Abuse-Header":
        "MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNjMxMTE3NzQyLjY1",
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
    }

    data = requests.get(url, headers=headers).json()
    #print(data.text)
    # uncomment this to print all data:
    #print(json.dumps(data, indent=4))
    try:
        # print some data:
        #for k, v in data["data"]["attributes"]["last_analysis_results"].items(
        #):
           # print("{:<30} {:<30}".format(k, str(v["result"])))
        #print(
            #json.dumps(data["data"]["attributes"]["last_analysis_stats"],
                       #indent=4))
        #print(data["data"]["attributes"]["last_analysis_stats"]["malicious"])
        ret = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return ret
    except:
        #print("Domain not found in VirusTotal")
        pass
