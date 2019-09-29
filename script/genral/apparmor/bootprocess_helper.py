#!/usr/bin/python

import sys


def print_data(final_data):
    for data in final_data:
        print(data['comm'])
        print (data['profile'].split("//null-")[-1])
        print(data['operation'])
        if "name" in data: 
            print(data['name'])
            if "requested_mask" in data:
                print(data['requested_mask'])
        elif data['operation'] == "capable":
            print(data['capname'])
        elif data['operation'] == "signal":
            print(data['signal'])
            print(data['peer'])
        
        elif data['operation'] == "ptrace":
            print(data['peer'])
        else:
            print("ELSE", data)
        print()

def group_data_by_app(final_data):
    group_data = {}
    for data in final_data:
        #appname = data['profile'].split("//null-")[-1]
        appname = data['comm']
        if appname not in group_data:
            group_data[appname] = []
            group_data[appname].append("profile " + appname + " flags=(complain){")
            group_data[appname].append(data['profile'].split("//null-")[-1] + " cx -> " + appname + ",")
            group_data[appname].append(data['profile'])



            group_data[appname].append("")
        if data['operation'] == "mount":
            if ("mount " + data['name']) not in group_data[appname]:
                group_data[appname].append("mount " + data['name'] )

        elif data['operation'] == "umount":
            if ("mount " + data['name']) not in group_data[appname]:
                group_data[appname].append("mount " + data['name'] )


        elif data['operation'] == "capable":
            if ("capability " + data['capname']) not in group_data[appname]:
                group_data[appname].append("capability " + data['capname']  )

        elif data['operation'] == "signal":
            if ("signal " + data['peer'] ) not in group_data[appname]:
                group_data[appname].append("signal " + data['peer'] )

        elif data['operation'] == "mount":
            if ("mount " + data) not in group_data[appname]:
                group_data[appname].append("mount " + data)
        else:
            if 'name'  in data and 'requested_mask' in data and len(data['name']) > 0:
                put_data = data['name'] + " " + data['requested_mask'] + ","

                if put_data not in group_data[appname]:
                    group_data[appname].append(put_data)
            else:
                if data not in group_data[appname]:
                    group_data[appname].append(data)



    return group_data

def print_gd(group_data):
    for key, value in group_data.items() :
        print(key)
        for item in value:
            print("\t" + str(item))
        print("\n\n")
        

if(len(sys.argv) <= 1):
    print("Filename missing! Enter filename as first argument")
    exit()

initsystemd = []
bootprocesses = []
remaining = []
input_data = str(sys.argv[1])
for data in input_data.split("\\n")[1:]:
    if "{" in data:
        if data not in remaining:
            remaining.append(data)
        continue
    if "}" in data:
        if data not in remaining:
            remaining.append(data)
        continue
    
    data = data.split("init-systemd//null-")[1:] 
    final_data = data[0].split("//null-")
    val = final_data[0].split("\\n'}")[0] + " rcx -> bootprocesses ,"
    if val not in initsystemd:
        initsystemd.append(val)
    for item in sorted(final_data[1:]):
        val = item.split("\\n'}")[0] + " rix ,"
        if val not in bootprocesses:
            bootprocesses.append(val)

print("InitSystemd:")
for data in sorted(initsystemd):
    print(data)

print("-----------------\n\n")
print("BootProcess:")
for data in sorted(bootprocesses):
    print(data)

print("-----------------\n\n")

print("Remaining:")
for data in remaining:
    print(data)

print("-----------------\n\n")
