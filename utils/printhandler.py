from utils.tools import xten
from rich.console import Console
from utils.ncon import NewConsole


console = Console(highlight=False,
                  legacy_windows=False,
                  color_system="truecolor",record=True)

ncon = NewConsole(highlight=False,
              legacy_windows=False,
              color_system="truecolor",
              record=True)
  
def ph_run(table,export, noprint):
    '''Prints tables to console. The -xp flag allows for saving the output as a .txt, .html, or svg. Saved text and html files will append, allowing users to stack tables. SVGs are write only. The --noprint flag will prevent tables from printing and is only usable with -xp.'''
      
    if export and (noprint==True):
              with ncon.capture() as capture:
                ncon.print(table)
              with open(export.name, 'at'):
                if xten(export.name) == '.txt':
                  try:
                   
                    capture.get(ncon.save_text(export.name))
                  except TypeError:
                    pass
                elif xten(export.name) == '.html':
                  try:
                    capture.get(ncon.save_html(export.name, inline_styles=True))
                  except TypeError:
                    pass
                elif xten(export.name) == '.svg':
                  try:
                    capture.get(console.save_svg(export.name))
                  except TypeError:
                    pass
                else:
                  console.print("Invalid extension!")
                  
    elif export and (noprint==False):
              ncon.print(table)
              with open(export.name, 'at'): 
                if xten(export.name) == '.txt':
                  ncon.save_text(export.name)
                elif xten(export.name) == '.html':
                  ncon.save_html(export.name,inline_styles=True)
                elif xten(export.name) == '.svg':
                  console.save_svg(export.name)
                else:
                  console.print("Invalid extension!")
    else:
        console.print(table)
      

        