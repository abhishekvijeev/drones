#!/bin/bash

# To Run: ./killprocess <newfilename> <derivedFilename>

if (( $# < 2 ));
  then
    echo "Not enough arguments supplied. To Run: ./killprocess <newfilename> <derivedFilename>"
    exit 1
fi
USERNAME=$(whoami)
cd /home/$USERNAME/sros2_demo

for ((i = 1; i <= $#; i+=4 )); do
    first=${!i}
    x=$(expr $i + 1)
    second=${!x}
    y=$(expr $i + 2)
    third=${!y}
    z=$(expr $i + 3)
    fourth=${!z}

    if [[ (-z "$first") || (-z "$second") || (-z "$third")  || (-z "$fourth")]]
      then
        echo "Error!"
        exit 1
    fi
    #to kill process
    ps -ef | grep -i "$second __node:=$first" | grep -v "/bin/bash" | grep -v grep | grep -v "ros2 run" | grep -v "killprocess.sh"  | awk '{print "kill " $2}' | sh


    rm -rf demo_keys/$first
    rm -rf policies/tmp/$first.xml

done

