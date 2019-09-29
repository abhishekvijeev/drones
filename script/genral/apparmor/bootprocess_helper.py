#!/usr/bin/python

import sys
initsystemd = []
bootprocesses = []
def write_list_to_file(listdata, filename):
    with open(filename, 'w') as filehandle:
        for listitem in listdata:
            filehandle.write('%s\n' % listitem)

def read_list_from_file(filename):
    listdata = []
    with open(filename, 'r') as filehandle:
        for line in filehandle:
            # remove linebreak which is the last character of the string
            currentPlace = line[:-1]

            listdata.append(currentPlace)
    return listdata


if(len(sys.argv) <= 1):
    print("Filename missing! Enter filename as first argument")
    exit()
try:
    initsystemd = read_list_from_file("initsystemd_list")
    bootprocesses = read_list_from_file("bootprocesses_list")
except:
    pass

input_data = str(sys.argv[1])
input_data = input_data.replace('\t', '').replace("\\n'}", "")
input_data = input_data.split("init-systemd//null-")
input_data = input_data[1:]
print(input_data)
for item in input_data:
    first_data = True
    for data in item.split("//null-"):
        if first_data:
            tmp = data + " rcx -> bootprocesses ,"
            if tmp not in initsystemd:
                initsystemd.append(tmp)
            first_data = False
        else:
            tmp = data + " rix ,"
            if tmp not in bootprocesses:
                bootprocesses.append(tmp)
    write_list_to_file(sorted(initsystemd), "initsystemd_list")
    write_list_to_file(sorted(bootprocesses), "bootprocesses_list")
    
    

print("\n")


