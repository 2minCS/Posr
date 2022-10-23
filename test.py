import click
from click_shell import shell
from rich.console import Console
from utils.filetable import filegen
from utils.domtable import domgen
from utils.iptable import ipgen

console = Console(highlight=False,
                  legacy_windows=False,
                  color_system="truecolor")

VERSION = "0.2.0"


# Sweet banner
def banner():
    banner = '''
          ____                 __  
         |  _ \ ___  ___ _ __  \ \ 
         | |_) / _ \/ __| '__|  \ \\  
         |  __/ (_) \__ \ |     / /
         |_|   \___/|___/_|    /_/ 
                                             
                                    BETA      
'''
    console.print(banner)
    console.print(
        "-= Posr - The Python OSR tool for [bold underline]minimalists[/bold underline]. - v"
        + VERSION + " =-\n")


@shell(prompt='Posr > ',
       intro='Starting Posr... type \'osr --help\' to see commands')
def my_app():
    pass


@my_app.command()
@click.option('-mf',
              'files',
              type=click.File('r'),
              help="For a file containing multiple SHA256 hashes")
@click.option('-sf', 'file', type=str, help="For a single SHA256 hash")
@click.option('-md',
              'domains',
              type=click.File('r'),
              help="For a file containing multiple domains")
@click.option('-sd', 'domain', type=str, help="For a single domain")
@click.option('-mi',
              'ips',
              type=click.File('r'),
              help="For a file containing multiple IPs")
@click.option('-si', 'ip', type=str, help="For a single IP")
def osr(files, domain, ip, file, domains, ips):
    if files:
        for x in files:
            x = x.strip('\n')
            table = filegen(x)
        console.print(table)
    if file:
        table = filegen(file)
        console.print(table)
    if domains:
        for x in domains:
            x = x.strip('\n')
            table = domgen(x)
        console.print(table)
    if domain:
        table = domgen(domain)
        console.print(table)
    if ips:
        for x in ips:
            x = x.strip('\n')
            table = ipgen(x)
        console.print(table)
    if ip:
        table = ipgen(ip)
        console.print(table)


# more commands
#@my_app.command()
#def refresh():
#table = Table(None)
#console.print(table)
if __name__ == '__main__':
    banner()
    my_app()
