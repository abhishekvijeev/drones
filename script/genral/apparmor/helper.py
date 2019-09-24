import subprocess
import sys
import glob, os 
from stat import *
 
def run(cmd):
    print("Executing",cmd)
    proc = subprocess.Popen(
    	['timeout' ,'10m',cmd],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()
 
    return proc.returncode, stdout, stderr
 
def getallfiles():
    path = os.getcwd()
    # files = [f for f in glob.glob(path + "*", recursive=True)]
    files = os.listdir(path)
    return files



files = getallfiles()
for f in files:
	# filename = f.split('/')[-1]
	# print(filename)
    if (os.path.islink(f)):
	    print(f,  oct(os.stat(f)[ST_MODE]), "Link file")
    else:
        print(f,  oct(os.stat(f)[ST_MODE]))