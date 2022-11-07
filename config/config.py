from configparser import ConfigParser
import random 


high = [
    '😷', '🤒', '🤕', '🤢', '🤮', '🤧', '🥵', '🥶', '🥴', '😵', '🤯', '😤', '😠', '🤬', '😈',
    '👿', '💀', '☠️', '😕', '😟', '🙁', '☹️', '😮', '😯', '😲', '😳', '🥺', '😦', '😧',
    '😨', '😰', '😥', '😢', '😭', '😱', '😖', '😣', '😞', '😓', '😩', '😫'
]
low = [
    '😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂', '🙂', '🙃', '😉', '😊', '😇', '🥰', '😍',
    '🤩', '🤗', '🤭', '💪', '👍'
]
bc = ':partly_sunny:'
vt = '🧬'
otx = '👽'
ha = '🤖'

config = ConfigParser()
conf_fp = './config/conf.ini'

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
      caption = '[not italic]🧬 = VirusTotal, :partly_sunny:  = BrightCloud, 👽 = OTX Alienvault, 🤖 = Hybrid Analysis'
      return caption
    else:
      caption = None
      return caption