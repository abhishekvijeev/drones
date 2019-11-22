#!/bin/bash

# To Run: ./killprocess <newfilename> <derivedFilename>

if (( $# < 2 ));
  then
    echo "Not enough arguments supplied. To Run: ./killprocess <newfilename> <derivedFilename>"
    exit 1
fi
USERNAME=$(whoami)
cd /home/$USERNAME/sros2_demo

for ((i = 1; i <= $#; i+=2 )); do
    first=${!i}
    x=$(expr $i + 1)
    second=${!x}
    if [[ (-z "$first") || (-z "$second") ]]
    then
        echo "Error!"
        exit 1
    fi
    #to kill process
    ps -ef | grep -i "$second __node:=$first" | grep -v "/bin/bash" | grep -v grep | grep -v "ros2 run" | grep -v "killprocess.sh"  | awk '{print "kill " $2}' | sh


    rm -rf demo_keys/$first
    rm -rf policies/tmp/$first.xml

done

