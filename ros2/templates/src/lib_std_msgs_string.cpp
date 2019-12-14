// to compile
// g++  -I/home/abhishek/ros2_ws/src/ros2/demos/templates/include -I/home/abhishek/ros2_ws/install/rclcpp/include -I/home/abhishek/ros2_ws/install/rcl_yaml_param_parser/include -I/home/abhishek/ros2_ws/install/rcl/include -I/home/abhishek/ros2_ws/install/std_msgs/include -I/home/abhishek/ros2_ws/install/rosgraph_msgs/include -I/home/abhishek/ros2_ws/install/rcl_interfaces/include -I/home/abhishek/ros2_ws/install/builtin_interfaces/include -I/home/abhishek/ros2_ws/install/rosidl_typesupport_cpp/include -I/home/abhishek/ros2_ws/install/rosidl_typesupport_c/include -I/home/abhishek/ros2_ws/install/rosidl_typesupport_introspection_cpp/include -I/home/abhishek/ros2_ws/install/rosidl_typesupport_introspection_c/include -I/home/abhishek/ros2_ws/install/rosidl_generator_cpp/include -I/home/abhishek/ros2_ws/install/rmw/include -I/home/abhishek/ros2_ws/install/rosidl_generator_c/include -I/home/abhishek/ros2_ws/install/rcutils/include -I/home/abhishek/ros2_ws/install/rosidl_typesupport_interface/include  -fPIC   -Wall -Wextra -Wpedantic -rdynamic -fPIC -std=gnu++14 -c /home/abhishek/ros2_ws/src/ros2/demos/templates/src/lib_std_msgs_string.cpp -ldl -lm


//  g++ -shared -Wl,-soname,lib_std_msgs_string.so -o lib_std_msgs_string.so lib_std_msgs_string.o


#include <iostream> 
#include "std_msgs_string.hh"
using namespace std;

std_msgs::msg::String::SharedPtr class_std_msgs_string::exec(std_msgs::msg::String::SharedPtr msg)
{
   std::cout << "inside lib_std_msgs_string\n";
   std::cout << msg->data << std::endl;
   msg->data = msg->data + " filtered too!";
   return std::move(msg);
}

extern "C" {
baseclass_std_msgs_string *maker(){
   return new class_std_msgs_string;
}
class proxy {
public:
   proxy(){
      // register the maker with the factory
      factory_std_msgs_string["class_std_msgs_int32"] = maker;
   }
};
// our one instance of the proxy
proxy p;
}
