import click
from click_shell import shell
from rich.console import Console
from utils.printhandler import ph_run
from utils.tablehandler import tablehandler
from configparser import ConfigParser
from time import perf_counter
th = tablehandler()

console = Console(highlight=False,
                  legacy_windows=False,
                  color_system="truecolor",
                  record=True)



VERSION = "0.3.5"

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
        "-= Posr> - The Python OSR tool for [bold underline]minimalists[/bold underline]. - v"
        + VERSION + " =-\n")


@shell(prompt='Posr > ',
       intro='Starting Posr... type \'osr --help\' or help to see commands')
def posr():
    pass


@posr.command()
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
@click.option('-xp',
              'export',
              type=click.File('wt', lazy=False),
              help="Exporting a table")
@click.option('--noprint', 'noprint', flag_value=True)
@click.option('--print', 'noprint', flag_value=False, default=False)

def osr(files, domain, ip, file, domains, ips, export, noprint):
    start = perf_counter()
    if files:
      with console.status("Running hashes through tools...") as status:
        th.tab_build(1,0,0)
        
        for x in files:
            x = x.strip('\n')
            table = th.filegen(x)
            #console.log('[green]Hash processed!')
            status.update(status='Building table...')
        status.update(status='Table complete!')
        ph_run(table, export, noprint)
    if domains:
      with console.status("Running domains through tools...") as status:
        th.tab_build(0,1,0)
        for x in domains:
            x = x.strip('\n')
            table = th.domgen(x)
            status.update(status='Building table...')
        status.update(status='Table complete!')
        ph_run(table, export, noprint)
    if ips:
      with console.status("Running IPs through tools...") as status:
        th.tab_build(0,0,1)
        for x in ips:
            x = x.strip('\n')
            table = th.ipgen(x)
            status.update(status='Building table...')
        status.update(status='Table complete!')
        ph_run(table, export, noprint)
    if file:
            th.tab_build(1,0,0)
            table = th.filegen(file)
            ph_run(table, export, noprint)
    if domain:
            th.tab_build(0,1,0)
            table = th.domgen(domain)
            ph_run(table, export, noprint)
    if ip:
            th.tab_build(0,0,1)
            table = th.ipgen(ip)
            ph_run(table, export, noprint)

    stop = perf_counter()
    print("time taken:", stop - start)
# more commands
@posr.command()
def cls():
  '''Clears console and resets cursor to the top.'''
  console.clear()

@posr.command()
@click.option('--noemoji', 'noemoji', flag_value='off')
@click.option('--emoji', 'noemoji', flag_value='on', default='on')
def config(noemoji):
  '''Sets up the conf.ini file.'''
#Read conf.ini file
  config = ConfigParser()
  config.read("./config/conf.ini")
  if noemoji == 'off':
    key = config["DEFAULT"]
    key["emojis"] = "off"
    with open('./config/conf.ini', 'w') as conf:
      config.write(conf)
  else:
    key = config["DEFAULT"]
    key["emojis"] = "on"
    with open('./config/conf.ini', 'w') as conf:
      config.write(conf)

if __name__ == '__main__':
    banner()
    posr()
