#!/bin/bash

# To Run: ./sros_profile_generator <newfilename> <derivedFilename>

if (( $# < 2 ));
  then
    # ./sros_profile_generator.sh std_msgs_string_tmp0 std_msgs_string talker lib_std_msgs_string.so
    echo "Not enough arguments supplied. To Run: ./sros_profile_generator <newfilename> <derivedFilename> <nodeWhosePermissionWillBeCopied> <libName>"
    exit 1
fi

USERNAME=$(whoami)
# source /home/$USERNAME/ros2_ws/install/local_setup.bash

for ((i = 1; i <= $#; i+=4 )); do
  first=${!i} #newfilename
  x=$(expr $i + 1)
  second=${!x} #derivedFilename
  y=$(expr $i + 2)
  third=${!y} #nodeWhosePermissionWillBeCopied
  z=$(expr $i + 3)
  fourth=${!z} #libName
  if [[ (-z "$first") || (-z "$second") || (-z "$third")  || (-z "$fourth")]]
    then
      echo "Error!"
      exit 1
  fi
  #TODO!
  #add checks to see if policies/template and policies/tmp exists

  
  cd /home/$USERNAME/sros2_demo

  ros2 security create_key demo_keys /$first 

  #create new sros policies from existing templates for that msg_type
  cp policies/templates/$second.xml policies/tmp/$first.xml
  sed -i -e "s/\($second\)/$first/" policies/tmp/$first.xml

  #get all publisher topics
  publisher=$(sed -n '/<publish/,/<\/publish/p' demo_keys/$third/permissions.xml | grep -v "<topic>rq/" | grep -v "<topic>rr/" | grep -v "<topic>rt/parameter_events</topic>" | grep -v "<topic>rt/rosout</topic>" | grep -v "<publish>" | grep -v "</publish>" | grep -v "<topics>" | grep -v "</topics>" | grep -vP "<topic>rt/tmp\d</topic>" | sed 's/rt\///g') 
  outputpattern="<topic>output</topic>"
  publisher="${outputpattern} $publisher"
  publisher=`echo ${publisher} | tr '\n' "\\n"`

  #get all subscriber topics
  subscriber=$(sed -n '/<subscribe/,/<\/subscribe/p' demo_keys/talker/permissions.xml | grep -v "<topic>rq/" | grep -v "<topic>rr/" | grep -v "<topic>rt/parameter_events</topic>" | grep -v "<topic>rt/rosout</topic>" | grep -v "<topic>rt/flowcontroller</topic>" | grep -v "<subscribe>" | grep -v "</subscribe>" | grep -v "<topics>" | grep -v "</topics>" | sed 's/rt\///g' ) 
  inputpattern="<topic>input</topic>"
  subscriber="${inputpattern} $subscriber"
  subscriber=`echo ${subscriber} | tr '\n' "\\n"`
  
  sed -i -e "s#\($outputpattern\)#$publisher#" -e "s#\($inputpattern\)#$subscriber#" policies/tmp/$first.xml


  ros2 security create_permission demo_keys /$first policies/tmp/$first.xml 
  
  ros2 run templates $second __node:=$first  -sl $fourth  > /dev/null 2>&1 &

done

