#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
fi

cat $1 | grep "[GRAPH_GEN]" > tmp_graph_generator_log

python3 graph_generator_helper.py tmp_graph_generator_log
rm tmp_graph_generator_log
