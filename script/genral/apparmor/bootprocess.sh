#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied. usage ./bootprocess.sh filter_log10"
fi

OUTPUT="$(cat $1 | grep "//null-")"
VALUE=""

while IFS= read -r line
do
	python3 bootprocess_helper.py "$line"
done < <(printf '%s\n' "$OUTPUT")

