#!/usr/bin/python

import sys

final_paths = []

def set_final_data(data):
    final_data = {}
    process_flag = False
    key = ""
    final_data["network"] = []
    final_data["disk"] = []
    
    for item in data.split("\n"):
        item = item.strip()
        item =  ' '.join(item.split())
        
        if len(item.split()) > 0:
            if "Process" in item.split()[0]:
                key = item.split("Process")[1]
                key = key.strip()
                if key not in final_data:
                    final_data[key] = []
            else:
                final_data[key].append(item)
    return final_data    

def print_adj_matrix(adj_matrix, final_data):
    print("adjacency matrix:")
    max_key_len = 0
    for item in final_data:
        if len(item) > max_key_len:
            max_key_len = len(item)
    
    max_key_len = max_key_len + len("\t")
    index  = 0
    for item in sorted(final_data):
        # if "/" in item:
        #     item = item.split("/")[-1]
        print(item, (" ")*(max_key_len - len(item)), end = " ")
        print(adj_matrix[index])
        index = index + 1
    print()
    
def setup_adj_matrix(final_data):
    key_position = {}
    index = 0
    for item in sorted(final_data):
        # if "/" in item:
        #     item = item.split("/")[-1]
        if item not in key_position:
            key_position[item] = index
            index = index + 1
    
    
    adj_matrix = [[0 for i in range(len(key_position))] for j in range(len(key_position))] 
    
    for key in sorted(final_data):
        for item in final_data[key]:
            # if "/" in key:
            #     key = key.split("/")[-1]
        
            if "ipc" in item:
                item = item.split("ipc ")[1]
                item = item.strip()
                # if "/" in item:
                #     item = item.split("/")[-1]
                    
                adj_matrix[key_position[key]][key_position[item]] = 1
            elif "network" in item:
                adj_matrix[key_position[key]][key_position["network"]] = 1
            elif "write_file" in item:
                adj_matrix[key_position[key]][key_position["disk"]] = 1
            
    return adj_matrix
    

def print_graph_representation(nodes_list, edge_list, red_edges, black_edges):
    import networkx as nx
    import matplotlib.pyplot as plt
    G = nx.DiGraph()
    G.add_nodes_from(nodes_list)
    G.add_edges_from(edge_list)
    pos = nx.spring_layout(G)
    nx.draw_networkx_nodes(G, pos, cmap=plt.get_cmap('jet'), 
                        node_color = 'white', node_size = 1000)
    nx.draw_networkx_labels(G, pos)
    nx.draw_networkx_edges(G, pos, edgelist=red_edges, edge_color='r', arrows=True)
    nx.draw_networkx_edges(G, pos, edgelist=black_edges, arrows=True)
    plt.show()



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

def path_helper(start, end, status, stack):
    key = stack[-1]
    for data in status[key]['from']:
        stack.append(data)
        # print("\t PRE: data", data)
        
        path_helper(start, end, status, stack)

        
        # print("\t", "KEY:", key, "\tdata:", data, "\tstack:", stack,  "\n")
        if start in stack:
            # print("PATH: ", end = " ")
            tmp = []
            tmp.append(end)
            
            for data in stack:
                tmp.append(data)
                # print(data, end= " -> ")
            # print(end)
            if tmp not in final_paths:
                final_paths.append(tmp)
        # print("\t POST: data", data, "\t", stack, end = " \t")
        
        stack.remove(data)
        
        
        
def set_all_paths(start, end, final_data, status):
    endpoints = []
    for key, value in status.items():
        if value[end] == True:
            endpoints.append(key)
    
    for item in endpoints:
        stack = []
        stack.append(item)
        path_helper(start, end, status, stack)
    
def print_path_helper(data, start, end):
    if start == end:
        print(data[start], end = " -> ")
    else:
        print_path_helper(data, start + 1, end)
        if start != 0:
            print(data[start], end = " -> ")
        else:
            print(data[start], end = " ")
        

def print_all_path():
    print("PATHS:")
    for val in final_paths:
        print_path_helper(val, 0, len(val)-1)
        print()
    print()
    
def print_dominator(status, final_data, end):
    print ("DOMINATOR:")
    for item in final_data:
        if str(item) != "network" and str(item) != "disk":
            flag = True
            for val in final_paths:
                if status[item][end] == True  or item not in val:
                    flag = False
                    break
            if flag:
                print(item, end = ",")
                
    print()

def DFS(start, end, final_data):
    
    que = []
    status = {}
    
    que.append(start)
    status[start] = {"disk":False,"network": False, "from": []}
    
    while len(que) > 0:
        key = que.pop()
        
        
        for item in final_data[key]:
            if "ipc" in item:
                item = item.split("ipc ")[1]
                item = item.strip()
                if item not in status:
                    que.append(item)
                    status[item] = {"disk":False,"network": False, "from": []}
                    status[item]["from"].append(key)
                else:
                    status[item]["from"].append(key)

            elif "write_file" in item:
                status[key]["disk"] = True

            elif "network" in item:
                status[key]["network"] = True
    return status
        
            


if(len(sys.argv) <= 1):
    print("Filename missing! Enter filename as first argument")
    exit()


filename = str(sys.argv[1])
f =  open(filename, "r")

data = f.read()
final_data = set_final_data(data)
adj_matrix = setup_adj_matrix(final_data)
print_adj_matrix(adj_matrix, final_data)

# print_gd(final_data)



# input_data = input("Enter starting and ending node (separated by a space):\n")
# start, end = input_data.split()
# status = DFS(start, end, final_data)

start = "A"
end = "network"
status = DFS("A", "network", final_data)

# start = "A"
# end = "disk"
# status = DFS("A", "disk", final_data)
set_all_paths(start, end, final_data, status)
print_all_path()

print_dominator(status, final_data, end)
# for key, value in status.items() :
#     print(key)
#     print("\t", value)
# LCA(status, start, end, final_data)
