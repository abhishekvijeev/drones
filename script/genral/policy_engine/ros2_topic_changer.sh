#!/bin/bash

# To Run: ./sros_profile_generator <newfilename> <derivedFilename>

if (( $# < 2 ));
  then
    echo "Not enough arguments supplied. To Run: ./sros_profile_generator <newfilename> <derivedFilename>"
    exit 1
fi

USERNAME=$(whoami)
# source /home/$USERNAME/ros2_ws/install/local_setup.bash

for ((i = 1; i <= $#; i+=4 )); do
  first=${!i}
  x=$(expr $i + 1)
  second=${!x}
  y=$(expr $i + 2)
  third=${!y}
  z=$(expr $i + 3)
  fourth=${!z}
  if [[ (-z "$first") || (-z "$second") || (-z "$third") || (-z "$fourth") ]]
    then
      echo "Error in arguments! Should be in 4s"
      exit 1
  fi
  echo `ps -ef | grep -i "$second" | grep -v "/bin/bash" | grep -v grep | grep -v "ros2 run" | grep -v "ros2_topic_changer.sh" `
  pid=`ps -ef | grep -i "$second" | grep -v "/bin/bash" | grep -v grep | grep -v "ros2 run" | grep -v "ros2_topic_changer.sh" | awk '{print $2}'`
  if [[ -z "$pid" ]]
    then
      echo "$second process not running or was not able to find its pid"
      exit
  fi
  
  echo $first $pid $third $fourth 
  command="data: 2, $first, $pid, $third, $fourth"
  echo $command
  ros2 topic pub /flowcontroller std_msgs/String "$command" -1

  
done

#to get pid
#ps -ef | grep -i "/talker" | grep -v grep | awk '{print $2}'