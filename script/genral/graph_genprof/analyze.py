#!/usr/bin/python

import sys


def set_final_data(data):
    final_data = {}
    process_flag = False
    key = ""
    for item in data.split("\n"):
        if len(item) > 1:
            if "\t" not in item:
                item = item.split("Process ")[1]
                key = item
                if item not in final_data:
                    final_data[item] = []
            else:
                final_data[key].append(item.strip())
        
    return final_data    
def print_gd(group_data):
    for key, value in group_data.items() :
        print(key)
        for item in sorted(value):
            print("\t" + str(item))
        #print("\n\n")

def LCA(status, start, end, final_data):
    newstatus = {}
    for key, value in status.items() :
        for key1, value1 in value.items() :
            if key1 == end and value1 == True:
                for item in status[key]['from']:
                    if item not in newstatus:
                        newstatus[item] = []

    print(newstatus)
    
    print("\nFLOW:\n")
    que = []
    allow_one = 1

    if start not in newstatus:
        que.append(start)
        newstatus[start] = []
    elif allow_one > 0 and status[start]['network'] != True:
        que.append(start)
        allow_one = allow_one - 1
    
    while len(que) > 0:
        key = que.pop()
        print(key)
        for item in final_data[key]:
            if "ipc" in item:
                item = item.split("ipc ")[1]
                item = item.strip()
                if item not in newstatus:
                    que.append(item)
                    newstatus[item] = []
                elif allow_one > 0 and status[item]['network'] != True:
                    que.append(item)
                    allow_one = allow_one - 1
                    

                

def DFS(start, end, final_data):
    que = []
    status = {}
    
    que.append(start)
    status[start] = {"network": False, "from": []}
    
    while len(que) > 0:
        key = que.pop()
        for item in final_data[key]:
            if "ipc" in item:
                item = item.split("ipc ")[1]
                item = item.strip()
                if item not in status:
                    que.append(item)
                    status[item] = {"network": False, "from": []}
                    status[item]["from"].append(key)
                else:
                    status[item]["from"].append(key)
            if end in item:
                status[key]["network"] = True
    for key, value in status.items() :
        print(key)
        for key1, value1 in value.items() :
            print("\t", key1, value1)
    LCA(status, start, end, final_data)
        
            


if(len(sys.argv) <= 1):
    print("Filename missing! Enter filename as first argument")
    exit()


filename = str(sys.argv[1])
f =  open(filename, "r")

data = f.read()
final_data = set_final_data(data)
print(final_data)
#print_gd(final_data)

DFS("F", "network", final_data)
