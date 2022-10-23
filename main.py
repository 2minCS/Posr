import os
import getopt
import sys
import rich
from rich import print
from rich.text import Text
import click
from utils.vt import vt_file, vt_domain, vt_ip
from utils.bc import bc_file, bc_domain, bc_ip
from utils.otx import otx_file, otx_domain, otx_ip
from rich.console import Console
from rich.table import Table

console = Console(highlight=False)
#from bs4 import BeautifulSoup
VERSION = "0.1.0"


# Sweet banner
def banner():
    banner = '''
    
          ____                 __  
         |  _ \ ___  ___ _ __  \ \ 
         | |_) / _ \/ __| '__|  \ \
         |  __/ (_) \__ \ |     / /
         |_|   \___/|___/_|    /_/ 
                                             
                                            BETA      

'''
    console.print(banner)
    console.print(
        "-= Posr - The Python OSR tool for [bold underline]minimalists[/bold underline]. - v"
        + VERSION + " =-\n")


# Usage
def usage():
    usage = """
    -f --file       Runs specified SHA256 File hash through OSR
    -d --domain     Runs specified Domain through OSR
    -i --ip         Runs specified IP through OSR
    """
    console.print(usage)
    #sys.exit(0)


#f = open('tld.json', 'w')
#print("Please enter a SHA256 hash, domain, or IP.\n")
@click.command()
#@click.argument('file', )
#@click.argument('domain')
@click.option('-f',
              '--file',
              type=str,
              prompt='Please enter a SHA256 file hash',
              prompt_required=True)
@click.option('-d',
              '--domain',
              type=str,
              prompt='Please enter a domain',
              prompt_required=True)
@click.option('-i',
              '--ip',
              type=str,
              prompt='Please enter an IP',
              prompt_required=True)
#file = input("Please enter a SHA256,domain, or IP: ")
def main(file, domain, ip):
    '''
  Runs files, domains, and ips through the tools.
  '''
    if file:
        table = Table(title="\nFile Hash Results", leading=1,highlight=False)
        table.add_column("Tool", justify="center", no_wrap=True)
        table.add_column("File", width=10, style="cyan")
        table.add_column("Suggested Threat?")
        table.add_column("Findings?")
        #table.add_column("Link", justify="center", overflow="crop") BROKEN
        #table.add_column("VirusTotal says..")
        #table.add_column("BrightCloud says..")
        vt_th, vt_ret, vlnk = vt_file(file)
        if vt_ret == 0:
            str(vt_ret)
            vt_ret = f"{vt_ret} vendors flagged this file :innocent:"
        elif vt_ret == None:
            str(vt_ret)
            vt_ret = "File not found :see_no_evil:"
        else:
            str(vt_ret)
            vt_ret = f"{vt_ret} vendors flagged this file [red1]Malicious :rage:"
        #print(type(vt_ret))
        #console.print(vt_ret, style="red1")
        det = bc_file(file)
        #print(det)
        if det == "\"G\"":
            #console.print('File is [green]Clean :smile:')
            det = 'File is [green]Clean :smile:'
        elif det == "\"B\"":
            #console.print('File is [red1]Malicious :cold_sweat:')
            det = 'File is [red1]Malicious :cold_sweat:'
        else:
            console.print('Unknown error occurred :sweat_smile:')
        otxd, olnk = otx_file(file)
        #print(otxd)
        if 0.0 <= otxd <= 2.9:
          otxd = f"Score: {otxd}. Low Risk"
        elif 3.0<= otxd <= 7.9:
          otxd = f"Score: {otxd}. [orange1]Medium Risk"
        elif otxd >= 8.0:
          otxd = f"Score: {otxd}. [red1]Malicious[/red1] file"
        #print(otxd)
        table.add_row(':dna: VirusTotal says..', file, vt_th, vt_ret)#, vlnk)
        table.add_row(':sun_behind_large_cloud:  BrightCloud says..', '', '',
                      det)#, "No valid link")
        table.add_row(':alien: OTX Alienvault says..','','',otxd)#,f"[link={olnk}]OTX Link[/link]")
        console.print(table)

      
    if domain:
        table = Table(title="\nDomain Rep Results", leading=1)
        table.add_column("Tool", justify="center", no_wrap=True)
        table.add_column("Domain", style="cyan")
        table.add_column("Findings?")
        #table.add_column("Link", width=20)
        vt_dret, vlnk = vt_domain(domain)
        if vt_dret == 0:
            str(vt_dret)
            vt_dret = f"{vt_dret} vendors flagged this Domain :innocent:"
        elif vt_dret == None:
            str(vt_dret)
            vt_dret = "Domain not found :see_no_evil:"
        else:
            str(vt_dret)
            vt_dret = f"{vt_dret} vendors flagged this [red1]Malicious :rage:"
        bc_drep = bc_domain(domain)
        if bc_drep >= 80:
            str(bc_drep)
            bc_drep = f"{bc_drep} : Looks pretty [green]Trustworthy :muscle:"
        elif bc_drep in range(60, 80):
            str(bc_drep)
            bc_drep = f"{bc_drep} : Looking a little [bright_yellow]Sus :monocle_face:"
        elif bc_drep in range(40, 60):
            str(bc_drep)
            bc_drep = f"{bc_drep} : Yikes, getting [orange1]Riskier :fearful:"
        elif bc_drep in range(0, 40):
            str(bc_drep)
            bc_drep = f"{bc_drep} : [red1]Danger![/red1] Watch where you click :grimacing:"
        otxd, drat= otx_domain(domain)
        if otxd == None:
          otxd = '[green]None!'
        else:
          otxd = f'[red1]{otxd}[/red1]'
        if drat == '0 / 0':
          drat = f'[green]{drat}[/green]'
        else:
          drat = f'[red1]{drat}[/red1]'
        #table.add_row(domain,vt_dret,bc_drep)
        table.add_row(':dna: VirusTotal says..', domain, vt_dret)#, vlnk)
        table.add_row(':sun_behind_large_cloud:  BrightCloud says..', '',
                      bc_drep)#, 'No valid link')
        table.add_row(':alien: OTX Alienvault says..','',f'AV detections: {otxd}, AV Detection ratio: {drat}')
        console.print(table)

      
    if ip:
        table = Table(title="\nIP Threat Results", leading=1)
        table.add_column("Tool", justify="center", no_wrap=True)
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Findings?")
        vt_iret = vt_ip(ip)
        if vt_iret == 0:
            str(vt_iret)
            vt_iret = f"{vt_iret} vendors flagged this IP :innocent:"
        elif vt_iret == None:
            str(vt_iret)
            vt_iret = "IP not found :question:"
        else:
            str(vt_iret)
            vt_iret = f"{vt_iret} vendors flagged this [red1]Malicious :rage:"
        bc_irep, trt1, trt2 = bc_ip(ip)
        if bc_irep == 0:
            str(bc_irep)
            bc_irep = f"{bc_irep} detections : No threats seen :muscle:"
        elif bc_irep > 0:
            str(bc_irep)
            bc_irep = f"{bc_irep} detections : This IP is probably associated with [red1]{trt1} or {trt2} :sob:"
        otxi, irat = otx_ip(ip)
        if otxi == None:
          otxi = '[green]None![/green]'
        else:
          otxi = f'[red1]{otxi}[/red1]'
        if irat == '0 / 0':
          irat = f'[green]{irat}[/green]'
        else:
          irat = f'[red1]{irat}[/red1]'
        table.add_row(':dna: VirusTotal says..', ip, vt_iret)#, vlnk)
        table.add_row(':sun_behind_large_cloud:  BrightCloud says..', '',
                      bc_irep)#, 'No valid link')
        table.add_row(':alien: OTX Alienvault says..','',f'AV detections: {otxi}, AV Detection ratio: {irat}')
        console.print(table)


#data = requests.get(url, headers=headers).json()
#soup = BeautifulSoup(r.content, 'html.parser')
#print(soup,file=f)
# uncomment this to print all data:
#print (json.dumps(r.json(), indent = 4 ))
#print(r.text)

# print some data:
#for k, v in data["data"]["attributes"]["last_analysis_results"].items():
#print("{:<30} {:<30}".format(k, str(v["result"])))
#print(json.dumps(data["data"]["attributes"]["last_analysis_stats"], indent=4))
#print(json.dumps(data, indent=4))
if __name__ == '__main__':
    banner()
    #usage()
    main()
