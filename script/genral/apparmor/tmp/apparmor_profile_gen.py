import subprocess
import sys
import glob, os 

default_profile = "#include <tunables/global> \n\n\
{%path}  flags=(complain){ \n\
  #include <abstractions/base> \n\n\
}"

 


def write_list_to_file(data, filename):
    with open(filename, 'w') as filehandle:
        filehandle.write('%s\n' % data)

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
                    if "[" in f:
                        continue
                    tmp = "rix ,"
                    if (f == "/bin/mount") or (f == "/sbin/apparmor_parser") or (f == "/bin/mountpoint"):
                        tmp = " rux ,"
                    prof = default_profile.replace("{%path}", f)
                    file_name = f[1:]
                    file_name = file_name.replace("/",".")
                    
                    #print(f, file_name)
                    #print(prof)
                    write_list_to_file(prof, file_name)
                    
                    #print("\n\n")

                    #exit(0)

        


make_apparmor_profile()
