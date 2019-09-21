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

filename = str(sys.argv[1])
f =  open(filename, "r")

data = f.read()
final_data = []
for item in data.split('audit:'):
    line = item.split('[')[0]
    
    tmp = {}
    for words in line.split(' '):
        if '=' in words:
            key, value = words.split("=") 
            tmp[key] = value.replace("\"","")
            final_data.append(tmp)

gd = group_data_by_app(final_data)
print_gd(gd)

