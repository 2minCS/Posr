import os
import json
import requests

#
deviceid = os.environ['deviceid']
oemid = os.environ['oemid']

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
    trt2=mk[1]
    return det,trt1,trt2
  except:
      trt1=None
      trt2=None
      return det, trt1, trt2
#bc_ip('146.185.239.19')
#bc_ip('157.69.58.24')