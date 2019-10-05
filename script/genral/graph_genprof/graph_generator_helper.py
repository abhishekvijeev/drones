#!/usr/bin/python

import sys



def group_data_by_app(final_data):
    group_data = {}
    for data in final_data:
        tmp = data.split(',')
        try:
            key = tmp[0]
            val = tmp[1] + " " + tmp[2]

            if tmp[0] not in group_data:
                group_data[key] = []
            
            if val not in group_data[key]:
                group_data[key].append(val)
        except:
            pass

    return group_data

def print_gd(group_data):
    for key, value in group_data.items() :
        print(key)
        for item in sorted(value):
            print("\t" + str(item))
        print("\n\n")
        

if(len(sys.argv) <= 1):
    print("Filename missing! Enter filename as first argument")
    exit()

filename = str(sys.argv[1])
f =  open(filename, "r")

data = f.read()
data = data.split('[GRAPH_GEN]')
final_data = []

for item in data:
    val = item
    if "[" in val:
        val = val.split('[')[0]
    final_data.append(val)

gd = group_data_by_app(final_data) 
print_gd(gd)