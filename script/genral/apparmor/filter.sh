#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
fi

cat $1 | grep "apparmor=\"ALLOWED\"" > tmp_filter_log

python3 log_parser.py tmp_filter_log
