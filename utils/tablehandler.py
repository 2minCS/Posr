from utils.tools import vt_file, bc_file, otx_file,vt_domain, bc_domain, otx_domain,vt_ip, bc_ip, otx_ip, ha_file, ha_domain, ha_ip
from rich.table import Table
from config.config import emoji_select, gen_caption
#import concurrent.futures
                
  
class tablehandler():
    '''
    Auto generates the title, header, columns and rows of passed tables.
    '''

    def tab_build(self,x,y,z):
      tab_intro=[x,y,z]
  
      if tab_intro[0]==1:
                self.table = Table(
                    title="\nFile Hash Results",
                    caption=gen_caption()
                )
                self.table.add_column("File", width=10, style="cyan", justify="center")
                self.table.add_column("Suggested Threat?", width=30, justify="center")
                self.table.add_column("Tool Findings?", justify="center")
                #print(table)
      elif tab_intro[1]==1:
                self.table = Table(
                  title="\nDomain Rep Results",
                  caption=gen_caption()
                )
                self.table.add_column("Domain", style="cyan")
                self.table.add_column("Tool Findings?", justify="center")
      elif tab_intro[2]==1:
                self.table = Table(
                  title="\nIP Rep Results",
                  caption=gen_caption()
                )
                self.table.add_column("IP", style="cyan")
                self.table.add_column("Tool Findings?", justify="center")
    
    
    def filegen(self,x):
        try:
            vt_th, vt_ret = vt_file(x)
            #print(vt_th)
            if vt_ret == 0:
                str(vt_ret)
                vt_ret = f"{vt_ret} vendors flagged this file {emoji_select(1)}"
            elif vt_ret == None:
                str(vt_ret)
                vt_ret = "File not found :see_no_evil:"
            else:
                str(vt_ret)
                vt_ret = f"{vt_ret} vendors flagged this file [red1]Malicious {emoji_select(2)}"
            
        except KeyError:
            print("VT API error, suggest refreshing browser")
            pass
        det = bc_file(x)
        #print(det)
        if det == "\"G\"":
           
            det = f'File is [green]Clean {emoji_select(1)}'
        elif det == "\"B\"":
           
            det = f"File is [red1]Malicious {emoji_select(2)}"
        else:
            det = 'File is [yellow1]Unknown'
        #print(x)
        otxd = otx_file(x) #olnk
        #print(otxd)
        if 0.0 <= otxd <= 2.9:
            otxd = f"Score: {otxd}. [green]Low Risk"
        elif 3.0 <= otxd <= 7.9:
            otxd = f"Score: {otxd}. [orange1]Medium Risk"
        elif otxd >= 8.0:
            otxd = f"Score: {otxd}. [red1]Malicious[/red1] file"
        #print(otxd)
        ha_vx, ha_tl, ha_ver = ha_file(x)
        if ha_vx == 'null':
          ha_vx=None
        if ha_tl == '0':
          ha_tl=f"Threat Level: {ha_tl}. [green]{ha_ver}"
        else:
          ha_tl = f"Threat Level: {ha_tl}. [red1]{ha_ver}"
        self.table.add_row(x, vt_th, f'{emoji_select(4)} says: {vt_ret}')  #, vlnk)
        self.table.add_row(None, None, f'{emoji_select(3)}  says: {det}')  #, "No valid link")
        self.table.add_row(None, None,
                      f'{emoji_select(5)} says: {otxd}')  #,f"[link={olnk}]OTX Link[/link]")
        self.table.add_row(None,ha_vx,f'{emoji_select(6)} says: {ha_tl}')
        self.table.add_row()
        self.table.add_section()
        return self.table

    def domgen(self,x):
      try:
        vt_dret = vt_domain(x) #vlnk
        if vt_dret == 0:
            str(vt_dret)
            vt_dret = f"{vt_dret} vendors flagged this Domain {emoji_select(1)}"
        elif vt_dret == None:
            str(vt_dret)
            vt_dret = "Domain not found :see_no_evil:"
        else:
            str(vt_dret)
            vt_dret = f"{vt_dret} vendors flagged this [red1]Malicious {emoji_select(2)}"
      except KeyError:
            print("VT API error, suggest refreshing browser")
            pass
      bc_drep = bc_domain(x)
      if bc_drep >= 80:
          str(bc_drep)
          bc_drep = f"{bc_drep} : Looks pretty [green]Trustworthy {emoji_select(1)}"
      elif bc_drep in range(60, 80):
          str(bc_drep)
          bc_drep = f"{bc_drep} : Looking a little [bright_yellow]Sus {emoji_select(1)}"
      elif bc_drep in range(40, 60):
          str(bc_drep)
          bc_drep = f"{bc_drep} : Yikes, getting [orange1]Riskier {emoji_select(2)}"
      elif bc_drep in range(0, 40):
          str(bc_drep)
          bc_drep = f"{bc_drep} : [red1]Danger![/red1] Watch where you click {emoji_select(2)}"
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
      ver, fam, score = ha_domain(x)
      #print(ver,fam, score)
      if ver == 'null':
        ver=None
      if fam == '0':
        fam=f"Threat Level: {score}. [green]{fam}[/]"
      else:
        fam = f"Threat Level: {score}. Malware class: [red1]{fam}[/]"
      self.table.add_row(x, f'{emoji_select(4)} says: {vt_dret}')  #, vlnk)
      self.table.add_row(None, f'{emoji_select(3)}  says: {bc_drep}')  #, 'No valid link')
      self.table.add_row(None, f'{emoji_select(5)} says: Verdict: {otxv}, AV detections: {otxd}')#, AV Detection ratio: {drat}')
      self.table.add_row(None,f'{emoji_select(6)} says: {fam}')
      self.table.add_row()
      self.table.add_section()
      return self.table

    def ipgen(self,x):
        vt_iret = vt_ip(x)
        if vt_iret == 0:
            str(vt_iret)
            vt_iret = f"{vt_iret} vendors flagged this IP {emoji_select(1)}"
        elif vt_iret == None:
            str(vt_iret)
            vt_iret = "Unknown error occurred. Suggest refreshing your browser"
        else:
            str(vt_iret)
            vt_iret = f"{vt_iret} vendors flagged this [red1]Malicious {emoji_select(2)}"
        bc_irep, trt1, trt2 = bc_ip(x)
        if bc_irep == 0:
            str(bc_irep)
            bc_irep = f"{bc_irep} detections : No threats seen {emoji_select(1)}"
        elif bc_irep > 0:
            str(bc_irep)
            if trt2 == None:
              bc_irep = f"{bc_irep} detections : This IP is probably associated with [red1]{trt1} {emoji_select(2)}"
            else:  
              bc_irep = f"{bc_irep} detections : This IP is probably associated with [red1]{trt1} or {trt2} {emoji_select(2)}"
        otxi, irat = otx_ip(x)
        if otxi == None:
            otxi = '[green]None![/green]'
        else:
            otxi = f'[red1]{otxi}[/red1]'
        if irat == '0 / 0':
            irat = f'[green]{irat}[/green]'
        else:
            irat = f'[red1]{irat}[/red1]'
        ver, fam, score = ha_ip(x)
        if not [x for x in (ver, fam, score) if x is None]:
          fam = "Nothing seen."
        #if ver == 'null':
          #ver=None
        elif fam == '0':
          fam=f"Threat Level: {score}. [green]{fam}[/]"
        else:
          fam = f"Threat Level: {score}. Malware class: [red1]{fam}[/]"
        
        self.table.add_row(x, f'{emoji_select(4)} says: {vt_iret}')  #, vlnk)
        self.table.add_row(None,  f'{emoji_select(3)}  says: {bc_irep}')  #, 'No valid link')
        self.table.add_row(None, f'{emoji_select(5)} says: AV detections: {otxi}, AV Detection ratio: {irat}')
        self.table.add_row(None,f'{emoji_select(6)} says: {fam}')
        self.table.add_row()
        self.table.add_section()
        return self.table

    #with concurrent.futures.ProcessPoolExecutor() as executor:
      #if __name__ == '__main__':
        #executor.submit(filegen)
        #executor.submit(domgen)
        #executor.submit(ipgen)
    