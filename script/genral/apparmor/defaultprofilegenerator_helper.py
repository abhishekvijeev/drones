import subprocess
import sys
import glob, os 

 
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



def appendslash(path):
    if path[len(path)-1] != "/":
        path = path + "/"
    return path

def make_apparmor_profile():
    if len(sys.argv) <= 1:
        print("Argv 1 should contain path")
        exit()

    path = sys.argv[1]
    if os.path.exists(path):
        path = appendslash(path) 
        for (root,dirs,files) in os.walk(path, topdown=True):
            for filename in files:
                f = appendslash(root) + filename 
                if not os.path.islink(f) and os.access(f, os.X_OK):
                    tmp = "rix ,"
                    if (f == "/bin/mount") or (f == "/sbin/apparmor_parser") or (f == "/bin/mountpoint"):
                        tmp = " rux ,"

                    print (f, tmp)


        


make_apparmor_profile()
