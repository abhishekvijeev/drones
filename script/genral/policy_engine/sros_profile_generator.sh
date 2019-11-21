#!/bin/bash

# To Run: ./sros_profile_generator <newfilename> <derivedFilename>

if (( $# < 2 ));
  then
    echo "Not enough arguments supplied. To Run: ./sros_profile_generator <newfilename> <derivedFilename>"
    exit 1
fi

USERNAME=$(whoami)
source /home/$USERNAME/ros2_ws/install/local_setup.bash

for ((i = 1; i <= $#; i+=2 )); do
  first=${!i}
  x=$(expr $i + 1)
  second=${!x}
  if [[ (-z "$first") || (-z "$second") ]]
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

  ros2 security create_permission demo_keys /$first policies/tmp/$first.xml

  ros2 run templates $second __node:=$first > /dev/null 2>&1 &

done

# #TODO!
# #add checks to see if policies/template and policies/tmp exists

# source /home/$USERNAME/ros2_ws/install/local_setup.bash

# cd /home/$USERNAME/sros2_demo

# ros2 security create_key demo_keys /$1

# #create new sros policies from existing templates for that msg_type
# cp policies/templates/$2.xml policies/tmp/$1.xml
# sed -i -e "s/\($2\)/$1/" policies/tmp/$1.xml

# ros2 security create_permission demo_keys /$1 policies/tmp/$1.xml

# ros2 run templates $2 __node:=$1 > /dev/null 2>&1 &

# #to kill process
# #ps -ef | grep -i "sensor_msgs_image __node:=sensor_msgs_image_tmp1" | grep -v grep | awk '{print "kill " $2}' | sh
