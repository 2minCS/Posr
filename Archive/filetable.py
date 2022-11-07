import random
from utils.tools import vt_file, bc_file, otx_file
from rich.table import Table
from ha import ha_file


high = [
    '😷', '🤒', '🤕', '🤢', '🤮', '🤧', '🥵', '🥶', '🥴', '😵', '🤯', '😤', '😠', '🤬', '😈',
    '👿', '💀', '☠️', '😕', '😟', '🙁', '☹️', '😮', '😯', '😲', '😳', '🥺', '😦', '😧',
    '😨', '😰', '😥', '😢', '😭', '😱', '😖', '😣', '😞', '😓', '😩', '😫'
]
low = [
    '😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂', '🙂', '🙃', '😉', '😊', '😇', '🥰', '😍',
    '🤩', '🤗', '🤭', '💪', '👍'
]
table = Table(
    title="\nFile Hash Results",
    caption='[not italic]🧬 = VirusTotal, 🌥️  = BrightCloud, 👽 = OTX Alienvault, 🤖 = Hybrid Analysis'
    )
  #table.add_column("Tool", justify="center", no_wrap=True)
table.add_column("File", width=10, style="cyan", justify="center")
table.add_column("Suggested Threat?", width=30, justify="center")
table.add_column("Tool Findings?", justify="center")


def filegen(x):
    try:
        vt_th, vt_ret, vlnk = vt_file(x)
        #print(vt_th)
        if vt_ret == 0:
            str(vt_ret)
            vt_ret = f"{vt_ret} vendors flagged this file {random.choice(low)}"
        elif vt_ret == None:
            str(vt_ret)
            vt_ret = "File not found :see_no_evil:"
        else:
            str(vt_ret)
            vt_ret = f"{vt_ret} vendors flagged this file [red1]Malicious {random.choice(high)}"
        #print(type(vt_ret))
        #console.print(vt_ret, style="red1")
        #print(x)
    except:
        print("VT API error, suggest refreshing browser")
        #vt_th,vt_ret="API ERROR"
        pass
    det = bc_file(x)
    #print(det)
    if det == "\"G\"":
        #console.print('File is [green]Clean :smile:')
        det = f'File is [green]Clean {random.choice(low)}'
    elif det == "\"B\"":
        #console.print('File is [red1]Malicious :cold_sweat:')
        det = f"File is [red1]Malicious {random.choice(high)}"
    else:
        det = 'File is [yellow1]Unknown :sweat_smile:'
    #print(x)
    otxd, olnk = otx_file(x)
    #print(otxd)
    if 0.0 <= otxd <= 2.9:
        otxd = f"Score: {otxd}. [green]Low Risk"
    elif 3.0 <= otxd <= 7.9:
        otxd = f"Score: {otxd}. [orange1]Medium Risk"
    elif otxd >= 8.0:
        otxd = f"Score: {otxd}. [red1]Malicious[/red1] file"
    #print(otxd)
    ha_vx, ha_tl, ha_ver = ha_file(x)
    if ha_tl == '0':
      ha_tl=f"Threat Level: {ha_tl}. [green]{ha_ver}"
    else:
      ha_tl = f"Threat Level: {ha_tl}. [red1]{ha_ver}"
    table.add_row(x, vt_th, f'🧬 says: {vt_ret}')  #, vlnk)
    table.add_row(None, None, f'🌥️  says: {det}')  #, "No valid link")
    table.add_row(None, None,
                  f'👽 says: {otxd}')  #,f"[link={olnk}]OTX Link[/link]")
    table.add_row(None,ha_vx,f'🤖 says: {ha_tl}')
    table.add_row()
    table.add_section()
    #print(table.columns[0]._cells[:])
    return table
    #console.print(table)


#for x in f:
#x = x.strip('\n')
#filegen(x)

#print(table.columns[:])
#known_links = set()
#newlist = []
#t = table.columns[0]._cells[:]
#for d in t:
#link = d[:]
#if link in known_links: continue
#newlist.append(d)
#known_links.add(link)

#t = newlist
#print(type(t))
#print(table.columns[0]._cells[:])
#res = [sorted(set(table.columns[0]._cells[:]), key=lambda x: mylist.index(x))]
#print(t)
