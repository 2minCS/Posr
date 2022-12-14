from configparser import ConfigParser
import random 
import os

high = [
    'đˇ', 'đ¤', 'đ¤', 'đ¤ĸ', 'đ¤Ž', 'đ¤§', 'đĨĩ', 'đĨļ', 'đĨ´', 'đĩ', 'đ¤¯', 'đ¤', 'đ ', 'đ¤Ŧ', 'đ',
    'đŋ', 'đ', 'â ī¸', 'đ', 'đ', 'đ', 'âšī¸', 'đŽ', 'đ¯', 'đ˛', 'đŗ', 'đĨē', 'đĻ', 'đ§',
    'đ¨', 'đ°', 'đĨ', 'đĸ', 'đ­', 'đą', 'đ', 'đŖ', 'đ', 'đ', 'đŠ', 'đĢ'
]
low = [
    'đ', 'đ', 'đ', 'đ', 'đ', 'đ', 'đ¤Ŗ', 'đ', 'đ', 'đ', 'đ', 'đ', 'đ', 'đĨ°', 'đ',
    'đ¤Š', 'đ¤', 'đ¤­', 'đĒ', 'đ'
]
bc = ':partly_sunny:'
vt = 'đ§Ŧ'
otx = 'đŊ'
ha = 'đ¤'

config = ConfigParser()
conf_fp = './config/conf.ini'

def hapi_conf():
  config.read(conf_fp)
  with open(conf_fp,'r') as f:
    if config['DEFAULT']['HA_API']:
      h_Api = config['DEFAULT']['HA_API']
    else 
      h_Api = os.environ['HA_API']
    return ha_Api
    
def bcapi_conf():
  config.read(conf_fp)
  with open(conf_fp,'r') as f:
    if config['DEFAULT']['BC_OEMID'] and config['DEFAULT']['BC_DEVICE']:
      bc_oemid = config['DEFAULT']['BC_OEMID']
      bc_device = config['DEFAULT']['BC_DEVICE']
    else 
      bc_oemid = os.environ['oemid']
      bc_device = os.environ['deviceid']
    return bc_oemid, bc_device
    
def emoji_select(x):
  config.read(conf_fp)
  with open(conf_fp, 'r') as f:
    config.read(f)
    if config['DEFAULT']['emojis'] == 'on':
      if x == 1:
        emoji = random.choice(low)
      elif x == 2:
        emoji = random.choice(high)
      elif x == 3:
        emoji = bc
      elif x == 4:
        emoji = vt
      elif x == 5:
        emoji = otx
      elif x == 6:
        emoji = ha
    if config['DEFAULT']['emojis'] == 'off':
      if x == 1 or 2:
        emoji = ''
      if x == 3:
        emoji = 'BrightCloud'
      if x == 4:
        emoji = 'VirusTotal'
      if x == 5:
        emoji = 'OTX Alienvault'
      if x == 6:
        emoji = 'Hybrid Analysis'
    return emoji


def gen_caption():
  config.read(conf_fp)
  with open(conf_fp, 'r') as f:
    config.read(f)
    if config['DEFAULT']['emojis'] == 'on':
      caption = '[not italic]đ§Ŧ = VirusTotal, :partly_sunny:  = BrightCloud, đŊ = OTX Alienvault, đ¤ = Hybrid Analysis'
      return caption
    else:
      caption = None
      return caption