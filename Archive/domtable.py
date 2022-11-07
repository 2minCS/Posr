import random
from utils.tools import vt_domain, bc_domain, otx_domain
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
    title="\nDomain Rep Results",
    caption='[not italic]🧬 = VirusTotal, 🌥️  = BrightCloud, 👽 = OTX Alienvault'
)
table.add_column("Domain", style="cyan")
table.add_column("Tool Findings?", justify="center")


#table.add_column("Link", width=20)
def domgen(x):
    vt_dret, vlnk = vt_domain(x)
    if vt_dret == 0:
        str(vt_dret)
        vt_dret = f"{vt_dret} vendors flagged this Domain {random.choice(low)}"
    elif vt_dret == None:
        str(vt_dret)
        vt_dret = "Domain not found :see_no_evil:"
    else:
        str(vt_dret)
        vt_dret = f"{vt_dret} vendors flagged this [red1]Malicious {random.choice(high)}"
    bc_drep = bc_domain(x)
    if bc_drep >= 80:
        str(bc_drep)
        bc_drep = f"{bc_drep} : Looks pretty [green]Trustworthy {random.choice(low)}"
    elif bc_drep in range(60, 80):
        str(bc_drep)
        bc_drep = f"{bc_drep} : Looking a little [bright_yellow]Sus {random.choice(low)}"
    elif bc_drep in range(40, 60):
        str(bc_drep)
        bc_drep = f"{bc_drep} : Yikes, getting [orange1]Riskier {random.choice(high)}"
    elif bc_drep in range(0, 40):
        str(bc_drep)
        bc_drep = f"{bc_drep} : [red1]Danger![/red1] Watch where you click {random.choice(high)}"
    otxv,otxd, drat = otx_domain(x)
    if otxv == "Malicious":
        otxv = f"[red1]{otxv}[/red1]"
    if otxd == None:
        otxd = '[green]None!'
    else:
        otxd = f'[red1]{otxd}[/red1]'
    if drat == '0 / 0':
        drat = f'[green]{drat}[/green]'
    else:
        drat = f'[red1]{drat}[/red1]'
    #table.add_row(domain,vt_dret,bc_drep)
    table.add_row(x, f'🧬 says:{vt_dret}')  #, vlnk)
    table.add_row(None, f'🌥️  says: {bc_drep}')  #, 'No valid link')
    table.add_row(None, f'👽 says: Verdict: {otxv}, AV detections: {otxd}')#, AV Detection ratio: {drat}')
    table.add_row()
    table.add_section()
    return table
