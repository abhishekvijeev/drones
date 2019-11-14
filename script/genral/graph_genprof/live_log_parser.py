#!/usr/bin/python

import sys, os
import time
import subprocess


def getDmesgProcessPID():
    name = "dmesg"
    pid = 0
    try:
        pid = int(subprocess.check_output(["pidof", name]))
    except Exception as e:
        print ("dmesg -wH is not running")
        exit(0)
    return pid

def print_gd(group_data):
    for key, value in group_data.items() :
        print(key)
        for item in sorted(value):
            print("\t" + str(item))
        print("\n\n")
def write_to_file(group_data):
    with open('/home/abhishek/live_logs.txt', 'w') as f:
        for key, value in group_data.items():
            f.write("%s\n" % key)
            # print(key)
            for item in sorted(value):
                # print("\t" + str(item))
                f.write("\t%s\n" % item)
            # print("\n\n")
            f.write("\n\n")
            
def followFile(thefile):
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

if __name__ == '__main__':
    pid = getDmesgProcessPID()
    filename = "/proc/$/fd/3"
    
    logfile = open(filename.replace("$", str(pid)),"r")
    loglines = followFile(logfile)
    group_data = {}
    for line in loglines:
        if "[GRAPH_GEN]" in line:
            # print line,
            # print (line, end = "")
            data = line.split('[GRAPH_GEN]')
            # print ("\t", data[1])
            tmp = data[1].split(',')
            try:
                key = tmp[0]
                val = tmp[1] + " " + tmp[2]
                if tmp[0] not in group_data:
                    group_data[key] = []
            
                if val not in group_data[key]:
                    group_data[key].append(val)
                    write_to_file(group_data)
            except:
                pass