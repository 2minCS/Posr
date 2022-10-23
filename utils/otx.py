import json
import requests
from utils.l2s import listToString


def otx_file(input):
  url = f"https://otx.alienvault.com/otxapi/indicators/file/analysis/{input}"
  url2 = f"https://otx.alienvault.com/indicator/file/{input}"
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
    return float(det), url2
  except:
    pass
  #print(det)
  
  #return float(det), url2
#otx_file('01fd6e0c8393a5f4112ea19a26bedffb31d6a01f4d3fe5721ca20f479766208f') # Score 6 
#otx_file('f8ee4c00a3a53206d8d37abe5ed9f4bfc210a188cd5b819d3e1f77b34504061e') # Score 10 MALICIOUS
#otx_file('21774b77bbf7739178beefe647e7ec757b08367c2a2db6b5bbc0d2982310ef12') # Score 3.8 Medium Risk
#otx_file('303243e4a8bf71cbb208d608277ab25241ecbd1a0b8930a68c27ab03b0d4d8ae') # Score 1.8 Low Risk




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
  
  #print(det)
  #print(ratio)
  #return det
#otx_domain('waterintoairi.com') 

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
    
  #print(det)
  #print(ratio)
  
#otx_ip('157.69.58.24')
