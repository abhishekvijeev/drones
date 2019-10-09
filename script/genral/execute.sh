dmesg > ~/kernel_log


cd ~/drones/script/genral/graph_genprof
./graph_generator.sh ~/kernel_log > ~/filter_graph

cd ~/drones/script/genral/apparmor
./filter.sh ~/kernel_log > ~/filter_log

code ~/filter_graph ~/filter_log

