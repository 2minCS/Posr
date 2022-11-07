import json
import requests
import os
#from utils.l2s import listToString
ha_api = os.environ['HA_API']


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
  
  
  #return float(det), url2
#ha_file('01fd6e0c8393a5f4112ea19a26bedffb31d6a01f4d3fe5721ca20f479766208f') # Score 6 
#ha_file('f8ee4c00a3a53206d8d37abe5ed9f4bfc210a188cd5b819d3e1f77b34504061e') # Score 10 MALICIOUS
#ha_file('21774b77bbf7739178beefe647e7ec757b08367c2a2db6b5bbc0d2982310ef12') # Score 3.8 Medium Risk
#ha_file('303243e4a8bf71cbb208d608277ab25241ecbd1a0b8930a68c27ab03b0d4d8ae') # Score 1.8 Low Risk




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
    #print(json.dumps(data, indent=4))
    ver=data["result"][0]["verdict"]
    fam=data["result"][0]["vx_family"]
    score=data["result"][0]["threat_score"]
    #print(ver,det,score)
    #if det == []:
      #det = None
    #else:
      #det=listToString(det) 
    return ver, fam, score
  except:
    
    #print(json.dumps(data, indent=4))
    #print(type(score), fam, ver)
    pass
  #print(ver)
  #return det
#ha_domain('waterintoairi.com')
#x=open('domains.csv')
#for d in x:
  #ha_domain(d)

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
    print(json.dumps(data, indent=4))
    ver=data["result"][0]["verdict"]
    det=data["result"][0]["vx_family"]
    ratio=data["result"][0]["av_detect"]
    if det and ver and ratio == []:
      det, ver, ratio = None
    #else:
      #det=listToString(det) 
    return ver, det, ratio
      #print(ratio, det, ver)
  except:
    #print("No results seen")
    pass
  
  #print(ratio, det, ver)
    
  #print(det)
  #print(ratio)

ha_ip('50.116.30.23')
x=open('ips.csv')
for d in x:
  ha_ip(d)
