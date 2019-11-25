import socket, time
import sys, os
import threading 
import xml.etree.ElementTree as ET

#extra space at the end is required
KILLER_PROCESS_SH = "/home/abhishek/sros2_demo/killprocess.sh "
SROS_PROFILE_SH = "/home/abhishek/sros2_demo/sros_profile_generator.sh "
ROS2_TOPIC_CHANGER_SH = "/home/abhishek/sros2_demo/ros2_topic_changer.sh "

def Parse_Topictype_Data(topic_with_type, topic_with_type_lock, recv_data):
    for item in recv_data.split("[Topic_Type] "):
        if (len(item) > 0):
            data = item.split(", ")
            topic_name = data[0]
            
            topic_with_type_lock.acquire()
            if topic_name not in topic_with_type:
                topic_with_type[topic_name] = []
            
            for types in data[1:]:
                types = types.strip()
                if types not in topic_with_type[topic_name]:
                    flag = True
                    for val in range(0,100):
                        if topic_name == "/tmp"+str(val):
                            flag =False
                            break
                    if flag:
                        topic_with_type[topic_name].append(types)
            topic_with_type_lock.release()
            
    
        
def TCP_Server(topic_with_type, topic_with_type_lock):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 8080)
    # print( 'starting up on %s port %s' % server_address)
    sock.bind(server_address)
    sock.listen(1)
    while True:
        # print( 'waiting for a connection')
        connection, client_address = sock.accept()
        try:
            # print( 'connection from', client_address)
            data = connection.recv(1000)
            data = data.decode("utf-8") 
            # print( 'received "%s"' % str(data))
            Parse_Topictype_Data(topic_with_type, topic_with_type_lock, data)
        finally:
            connection.close()


def Read_All_Sros_Profiles (app_with_topic):
    ignore_topic_list ={"rq/$/describe_parametersRequest",\
                        "rq/$/get_parameter_typesRequest",\
                        "rq/$/get_parametersRequest",\
                        "rq/$/list_parametersRequest",\
                        "rq/$/set_parametersRequest",\
                        "rq/$/set_parameters_atomicallyRequest",\
                        "rr/$/describe_parametersReply",\
                        "rr/$/get_parameter_typesReply",\
                        "rr/$/get_parametersReply",\
                        "rr/$/list_parametersReply",\
                        "rr/$/set_parametersReply",\
                        "rr/$/set_parameters_atomicallyReply",\
                        "rt/parameter_events"}

    path = "/home/abhishek/sros2_demo/demo_keys/"
    for (root,dirs,files) in os.walk(path, topdown=True):
        if "permissions.xml" in files:
            app_name = root.split("/")[-1]
            permissionxml_filename = root + "/permissions.xml"
            
            if app_name not in app_with_topic:
                app_with_topic[app_name] = {}

            if (os.path.exists(permissionxml_filename)):
                tree = ET.parse(permissionxml_filename)
                root = tree.getroot()
                publisher_list = []
                subscriber_list = []
                for permissions in root.findall('permissions'):
                    for grant in permissions.findall('grant'):
                        for allow_rule in grant.findall('allow_rule'):
                            for publish in allow_rule.findall('publish'):
                                for topics in publish.findall('topics'):
                                    for topic in topics.findall('topic'):
                                        ignore_flag = False
                                        for data in ignore_topic_list:
                                            if (data.replace("$", app_name) == topic.text):
                                                ignore_flag = True
                                        if not ignore_flag:
                                            publisher_list.append(topic.text)
                            for subscribe in allow_rule.findall('subscribe'):
                                for topics in subscribe.findall('topics'):
                                    for topic in topics.findall('topic'):
                                        ignore_flag = False
                                        for data in ignore_topic_list:
                                            if (data.replace("$", app_name) == topic.text):
                                                ignore_flag = True
                                        if not ignore_flag:
                                            subscriber_list.append(topic.text)
                if "publisher" not in app_with_topic[app_name]:
                    app_with_topic[app_name]["publisher"] = []
                if "subscriber" not in app_with_topic[app_name]:
                    app_with_topic[app_name]["subscriber"] = []
                
                for tmp in publisher_list:
                    if tmp not in app_with_topic[app_name]["publisher"]:
                        app_with_topic[app_name]["publisher"].append(tmp)
                for tmp in subscriber_list:
                    if tmp not in app_with_topic[app_name]["subscriber"]:
                        app_with_topic[app_name]["subscriber"].append(tmp)
                

def Get_New_Msgtype_Name(msgtype_applist, msgtype):
    if msgtype not in msgtype_applist:
        msgtype_applist[msgtype] = []
    
    app_name = "tmp" + str(len(msgtype_applist[msgtype]))
    msgtype_applist[msgtype].append(app_name)
    return app_name
    


def Remove_New_Msgtype_Name(msgtype_applist, msgtype, app_name):
    if msgtype in msgtype_applist:
        if app_name in msgtype_applist[msgtype]:
            msgtype_applist[msgtype].remove(app_name)
            
def Generate_Topic_Changer_Command(cmd_type, process_name, redirection_list, topic_change_list):
    cmd = ""
    if process_name in topic_change_list:
        for key, value in topic_change_list[process_name].items():
            key = key.replace("/","")
            value = value.replace("/","")
            if cmd_type == "redirect":
                cmd = cmd + " pub " + "/" + process_name + " " + key + " " + value 
            elif cmd_type == "revert":
                cmd = cmd + " pub " + "/" + process_name + " " + value + " " + key 
    
    # if process_name in redirection_list:
    #     for key, value in redirection_list[process_name].items():
    #         app_name = "\'" + key + " __node:=" + key + "_" + value[1] + "\'"
    #         topic = value[0].replace("/","")
    #         if cmd_type == "redirect":
    #             cmd = cmd + " pub " +  app_name + " " + "output" + " " + topic 
    #             cmd = cmd + " sub " +  app_name + " " + "input" + " " + topic_change_list[process_name][value[0]].replace("/","")
    #         elif cmd_type == "revert":
    #             cmd = cmd + " pub " +  app_name + " " + topic + " " + "output" 
    #             cmd = cmd + " sub " +  app_name + " " + topic_change_list[process_name][value[0]].replace("/","") + " " + "input"
    if process_name in redirection_list:
        for key, value in redirection_list[process_name].items():
            for idx in range(0, len(value), 2):
                app_name = "\'" + key + " __node:=" + key + "_" + value[idx+1] + "\'"
                topic = value[idx].replace("/","")
                if cmd_type == "redirect":
                    cmd = cmd + " pub " +  app_name + " " + "output" + " " + topic 
                    cmd = cmd + " sub " +  app_name + " " + "input" + " " + topic_change_list[process_name][value[idx]].replace("/","")
                elif cmd_type == "revert":
                    cmd = cmd + " pub " +  app_name + " " + topic + " " + "output" 
                    cmd = cmd + " sub " +  app_name + " " + topic_change_list[process_name][value[idx]].replace("/","") + " " + "input"
    
    cmd = cmd.strip()
    return cmd

            

def User_Input_Parser(topic_with_type, topic_with_type_lock, app_with_topic):
    Read_All_Sros_Profiles (app_with_topic)
    redirection_list = {}
    msgtype_applist = {}
    topic_change_list = {}
    sros_policy_cmd_list = {}
    while(True):
        data = input("Enter command:")
        if (data == "get types"):
            #ros2 topic pub /flowcontroller std_msgs/String 'data: 2, 15851' -1
            #os.system("ros2 topic pub /flowcontroller std_msgs/String 'data: 2, 15851' -1")
            pass
        elif (data == "print types"):
            topic_with_type_lock.acquire()
            for key, value in topic_with_type.items():
                print (key)
                print("\t", value)    
            topic_with_type_lock.release()
        elif (data == "print app"):
            for key, value in app_with_topic.items():
                print(key)
                for key1, value1 in value.items():
                    print ("\t", key1)
                    topic_with_type_lock.acquire()
                    for topic in value1:
                        topic = topic.replace("rt", "")
                        if topic == "/rosout" or topic == "/flowcontroller":
                            continue
                        if topic in topic_with_type:
                            print ("\t\t", topic, topic_with_type[topic])
                        # else:
                        #     print ("\t\t", topic)
                    topic_with_type_lock.release()
        elif (data == "print list"):
            print ("redirection_list:\n", redirection_list)
            print ("topic_change_list:\n", topic_change_list)
            print ("msgtype_applist:\n", msgtype_applist)
            print ("sros_policy_cmd_list:\n", sros_policy_cmd_list)
        elif "redirect" in data:
            values = data.split(" ")
            sros_profile_generator = ""
            if (len(values) == 2 and (values[1] in app_with_topic)):
                redirect_process_name = values[1]
                    
                for topic in app_with_topic[redirect_process_name]['publisher']:
                    topic = topic.replace("rt", "")
                    if topic == "/rosout" or topic == "/flowcontroller":
                        continue

                    topic_with_type_lock.acquire()
                    if topic in topic_with_type:
                        for newprocesstype in topic_with_type[topic]:
                            names = newprocesstype.split("/")
                            msgtype_name = names[0] + "_" + names[-1].lower()
                            
                            app_name_extension = Get_New_Msgtype_Name(msgtype_applist, msgtype_name)
                            app_name = msgtype_name + "_" + app_name_extension
                            
                            if (app_name + " " + msgtype_name) not in sros_profile_generator:
                                sros_profile_generator = sros_profile_generator + (app_name + " " + msgtype_name) + " " + redirect_process_name + " "


                            if redirect_process_name not in redirection_list:
                                redirection_list[redirect_process_name] = {}
                                topic_change_list[redirect_process_name] = {}
                                sros_policy_cmd_list[redirect_process_name] = []
                            
                            if msgtype_name not in redirection_list[redirect_process_name]:
                                redirection_list[redirect_process_name][msgtype_name] = []
                            
                            if topic not in redirection_list[redirect_process_name][msgtype_name]:
                                redirection_list[redirect_process_name][msgtype_name].append(topic)
                                redirection_list[redirect_process_name][msgtype_name].append(app_name_extension)
                                
                            
                            if topic not in topic_change_list[redirect_process_name]:
                                topic_change_list[redirect_process_name][topic] = "tmp"+str(len(topic_change_list[redirect_process_name]))
                            
                    topic_with_type_lock.release()

                #send command to sros_profile_generator.sh to generate sros profiles and run application in background
                if len(sros_profile_generator) > 0:
                    if sros_profile_generator not in sros_policy_cmd_list[redirect_process_name]:
                        sros_policy_cmd_list[redirect_process_name].append(sros_profile_generator)
                        print ("Sending command to sros_profile_generator with parameter:\n", sros_profile_generator)
                        os.system(SROS_PROFILE_SH + sros_profile_generator)

                #send command to change apparmor profile
                
                #send command to redirect ros2 topics
                topic_changer_cmd = Generate_Topic_Changer_Command("redirect", redirect_process_name, redirection_list, topic_change_list)
                if (len(topic_changer_cmd) > 0):
                    print ("topic_changer_cmd:\n", topic_changer_cmd)
                    os.system(ROS2_TOPIC_CHANGER_SH + topic_changer_cmd)
                
                    

            else:
                print("Error! command: redirect <ros process>")
        elif "revert" in data:
            values = data.split(" ")
            if (len(values) == 2 and (values[1] in app_with_topic)):
                redirect_process_name = values[1]
                #send command to change apparmor profile
                #send command to redirect ros2 topics
                topic_changer_cmd = Generate_Topic_Changer_Command("revert", redirect_process_name, redirection_list, topic_change_list)
                if (len(topic_changer_cmd) > 0):
                    print ("topic_changer_cmd:\n", topic_changer_cmd)
                    os.system(ROS2_TOPIC_CHANGER_SH + topic_changer_cmd)

                

                #delete entries
                if redirect_process_name in redirection_list:
                    for key, value in redirection_list[redirect_process_name].items():
                        Remove_New_Msgtype_Name(msgtype_applist, key, value[1])
                    del redirection_list[redirect_process_name]
                    del topic_change_list[redirect_process_name]
                if redirect_process_name in sros_policy_cmd_list:
                    print ("Sending command to killprocess with parameter:", sros_policy_cmd_list[redirect_process_name][0])
                    os.system(KILLER_PROCESS_SH + sros_policy_cmd_list[redirect_process_name][0])
                    del sros_policy_cmd_list[redirect_process_name]
            else:
                print("Error! command: revert <ros process>")

if __name__ == '__main__': 
    topic_with_type = {}
    topic_with_type_lock = threading.Lock()
    app_with_topic = {}
    
    t1 = threading.Thread(target=TCP_Server, args=(topic_with_type, topic_with_type_lock)) 
    t2 = threading.Thread(target=User_Input_Parser, args=(topic_with_type, topic_with_type_lock, app_with_topic)) 
    # starting thread 1 
    t1.start() 
    # starting thread 2 
    t2.start() 

    # wait until thread 1 is completely executed 
    t1.join() 
    # wait until thread 2 is completely executed 
    t2.join() 

    # both threads completely executed 
    print("Done!") 



