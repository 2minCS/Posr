import json
import requests
import os
import pathlib
import concurrent.futures



#-------------------------------------------------------------------------------------------------

  
# function to return the file extension
def xten(file):
  file_extension = pathlib.Path(file).suffix
  return file_extension



#-------------------------------------------------------------------------------------------------
# Convert a list to string using join()
   
# Function to convert 
def listToString(s):
   
    # initialize an empty string
    str1 = " "
   
    # return string 
    return (str1.join(s))

#-------------------------------------------------------------------------------------------------
def otx_file(input):
  url = f"https://otx.alienvault.com/otxapi/indicators/file/analysis/{input}"
  #url2 = f"https://otx.alienvault.com/indicator/file/{input}"
  headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
  }
  
  try:
    data = requests.get(url, headers=headers).json()
  except:
    print('API error')
  #print(json.dumps(data, indent=4))
  try:
    det=json.dumps(data["analysis"]["plugins"]["cuckoo"]["result"]["info"]["combined_score"])
    return float(det)#, url2
  except:
    pass
  



#-------------------------------------------------------------------------------------------------
def otx_domain(input):
  url = f"https://otx.alienvault.com/otxapi/indicators/domain/analysis/{input}"
  headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
  }
  try:
    data = requests.get(url, headers=headers).json()
  except:
    print('API error')
  try:
    #print(json.dumps(data, indent=4))
    ver=data["facts"]["verdict"]
    det=data["detections"]["antivirus_detections"][:]
    ratio=data["detections"]["malicious_benign_ratio"]
    if det == []:
      det = None
    else:
      det=listToString(det) 
    return ver, det, ratio
  except:
    pass
  



#-------------------------------------------------------------------------------------------------
def otx_ip(input):
  url = f"https://otx.alienvault.com/otxapi/indicators/ip/analysis/{input}"
  headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
  }
    

  try:  
    data = requests.get(url, headers=headers).json()
  except:
    print('API error')
    #print(json.dumps(data, indent=4))
  try:
    det=data["detections"]["antivirus_detections"][:]
    ratio=data["detections"]["malicious_benign_ratio"]
    if det == []:
      det = None
    else:
      det = listToString(det)
    return det, ratio
  except:
    pass
    



#
deviceid = os.environ['deviceid']
oemid = os.environ['oemid']

#-------------------------------------------------------------------------------------------------
def bc_file(input):
  url = f"https://api.bcti.brightcloud.com/1.0/file/getinfo?file={input}&oemid={oemid}&deviceid={deviceid}&uid=null"
  headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
  }

  data = requests.get(url, headers=headers).json()
  #print(json.dumps(data, indent=4))
  det=json.dumps(data["results"][0]["queries"]["getinfo"]["det"])
  return det

#-------------------------------------------------------------------------------------------------
def bc_domain(input):
  url = f"https://api.bcti.brightcloud.com/1.0/url/getrepinfo?url={input}&oemid={oemid}&deviceid={deviceid}&uid=null"
  headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
  }

  data = requests.get(url, headers=headers).json()
  #print(json.dumps(data, indent=4))
  det=data["results"][0]["queries"]["getrepinfo"]["reputation"]
  return det

#-------------------------------------------------------------------------------------------------
def bc_ip(input):
  url = f"https://api.bcti.brightcloud.com/1.0/ip/getthreathistory?ip={input}&oemid={oemid}&deviceid={deviceid}&uid=null"
  headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
  }
  
  threat_tags=[]
  
  data = requests.get(url, headers=headers).json()
  
  #print(json.dumps(data, indent=4))
  det=data["results"][0]["queries"]["getthreathistory"]["threat_count"]
  det1=data["results"][0]["queries"]["getthreathistory"]
  try:
    for cnt in range(0, len(det1['history'])):
      if det1['history'][cnt]['is_threat'] == 1:
                        a = det1['history'][cnt]['threat_types']
                        #TEST IP 146.185.239.19
                        for i in range (0, len(a)):
                          #print (a[i], end ="\n")
                          a[i]=a[i].title()
                          threat_tags.append(a[i])

    d = dict((l, threat_tags.count(l)) for l in set(threat_tags))
  #print (dict((l, threat_tags.count(l)) for l in set(threat_tags)))
    mk = sorted(d, key=d.get, reverse=True)[:2]
    #print(mk)
    trt1=mk[0]
    if len(mk) == 1:
      trt2=None
      return det,trt1,trt2
    else:
      trt2=mk[1]
      return det,trt1,trt2
  except:
      trt1=None
      trt2=None
      return det, trt1, trt2



#-------------------------------------------------------------------------------------------------
def vt_file(input):
    '''
  Query VirusTotal with a SHA256 hash.
  '''
    url = f"https://www.virustotal.com/ui/files/{input}"
    #url2= f"https://www.virustotal.com/gui/file/{input}"
    headers = {
        "accept": "application/json",
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
        "content-type": "application/json",
        "Referer": "https://www.virustotal.com/",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
        "x-app-version": "v1x127x0",
        "X-Tool": "vt-ui-main",
        "X-VT-Anti-Abuse-Header": "MTY3NzE2MjQ0NzQtWkc5dWRDQmlaU0JsZG1scy0xNjY2NjY4MjMxLjk2NA=="
    }

    try:
      data = requests.get(url, headers=headers).json()
    except:
      print('VT API error')
    
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
        return threat,ret#, url2
    except:
        #print("File not found in VirusTotal")
        pass

#-------------------------------------------------------------------------------------------------
def vt_domain(input):
    '''
  Query VirusTotal with a domain.
  '''
    url = f"https://www.virustotal.com/ui/domains/{input}"
    #url2 = f"https://www.virustotal.com/gui/domain/{input}"
    headers = {
        "User-Agent":
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "X-Tool": "vt-ui-main",
        "X-VT-Anti-Abuse-Header":
        "MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNjMxMTE3NzQyLjY1",
        "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
    }
    
    data = requests.get(url, headers=headers).json()
    
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
        return ret#, url2
    except:
        #print("Domain not found in VirusTotal")
        pass

#-------------------------------------------------------------------------------------------------
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


ha_api = os.environ['HA_API']

#-------------------------------------------------------------------------------------------------
def ha_file(input):
  url = "https://www.hybrid-analysis.com/api/v2/search/hash"

  headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
    "Content-Type": "application/x-www-form-urlencoded",
    "api-key": ha_api,
  }
  data = {
    'hash': input,
}
  try:
    data = requests.post(url, headers=headers, data=data).json()
  except:
    print('API error')
  #print(json.dumps(data, indent=4))
  try:
    #det=json.dumps(data[0]["av_detect"])
    vx=json.dumps(data[0]["vx_family"])
    tl=json.dumps(data[0]["threat_level"])
    ver=json.dumps(data[0]["verdict"]) 
    #print(vx, tl, ver)
    #print(type(tl))
    return(vx,tl,ver)
  except:
    pass
  
  
  



#-------------------------------------------------------------------------------------------------
def ha_domain(input):
  url = "https://www.hybrid-analysis.com/api/v2/search/terms"
  headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
    "Content-Type": "application/x-www-form-urlencoded",
    "api-key": ha_api,
  }
  data = {
    'domain': input,
  }
  try:
    data = requests.post(url, headers=headers, data=data).json()
  except:
    print('API error')
  try:  
    ver=data["result"][0]["verdict"]
    fam=data["result"][0]["vx_family"]
    score=data["result"][0]["threat_score"]
     
    return ver, fam, score
  except:
    return ver, fam, score
    #print(json.dumps(data, indent=4))
    
    pass
  

#-------------------------------------------------------------------------------------------------
def ha_ip(input):
  url = "https://www.hybrid-analysis.com/api/v2/search/terms"
  headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
    "Content-Type": "application/x-www-form-urlencoded",
    "api-key": ha_api,
  }
  data = {
    'host': input,
  }

  try:  
    data = requests.post(url, headers=headers, data=data).json()
  except:
    print('API error')
    #print(json.dumps(data, indent=4))
  try:
    #print(json.dumps(data, indent=4))
    cnt = data["count"]
    if cnt > 0:
      ver=data["result"][0]["verdict"]
      det=data["result"][0]["vx_family"]
      ratio=data["result"][0]["av_detect"]
    else:
      det, ver, ratio = ['','','']
      #print(ratio, det, ver)
    return ver, det, ratio
    
  except:
    det, ver, ratio = ['','','']
    return ver, det, ratio
    
    
#only a few second difference. May need to refactor the code or try a difference method.
with concurrent.futures.ProcessPoolExecutor() as executor:
  if __name__ == '__main__':
    executor.submit(otx_file, input)
    executor.submit(otx_domain, input)
    executor.submit(otx_ip, input)
    executor.submit(vt_file, input)
    executor.submit(vt_domain, input)
    executor.submit(vt_ip, input)
    executor.submit(bc_file, input)
    executor.submit(bc_domain, input)
    executor.submit(bc_ip, input)
    executor.submit(ha_file, input)
    executor.submit(ha_domain, input)
    executor.submit(ha_ip, input)
    
    
  
