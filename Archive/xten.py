import pathlib
  
# function to return the file extension
def xten(file):
  file_extension = pathlib.Path(file).suffix
  return file_extension