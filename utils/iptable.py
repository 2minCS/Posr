import random
from utils.vt import vt_ip
from utils.bc import bc_ip
from utils.otx import otx_ip
from rich.table import Table


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
    title="\nIP Rep Results",
    caption='[not italic]🧬 = VirusTotal, 🌥️  = BrightCloud, 👽 = OTX Alienvault'
)
table.add_column("IP", style="cyan")
table.add_column("Tool Findings?", justify="center")


def ipgen(x):
    vt_iret = vt_ip(x)
    if vt_iret == 0:
        str(vt_iret)
        vt_iret = f"{vt_iret} vendors flagged this IP {random.choice(low)}"
    elif vt_iret == None:
        str(vt_iret)
        vt_iret = "IP not found :question:"
    else:
        str(vt_iret)
        vt_iret = f"{vt_iret} vendors flagged this [red1]Malicious {random.choice(high)}"
    bc_irep, trt1, trt2 = bc_ip(x)
    if bc_irep == 0:
        str(bc_irep)
        bc_irep = f"{bc_irep} detections : No threats seen {random.choice(low)}"
    elif bc_irep > 0:
        str(bc_irep)
        bc_irep = f"{bc_irep} detections : This IP is probably associated with [red1]{trt1} or {trt2} {random.choice(high)}"
    otxi, irat = otx_ip(x)
    if otxi == None:
        otxi = '[green]None![/green]'
    else:
        otxi = f'[red1]{otxi}[/red1]'
    if irat == '0 / 0':
        irat = f'[green]{irat}[/green]'
    else:
        irat = f'[red1]{irat}[/red1]'
    table.add_row(x, f'🧬 says: {vt_iret}')  #, vlnk)
    table.add_row(None,  f'🌥️  says: {bc_irep}')  #, 'No valid link')
    table.add_row(None, f'👽 says: AV detections: {otxi}, AV Detection ratio: {irat}')
    table.add_row()
    table.add_section()
    return table
