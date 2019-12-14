#ifndef __STD_MSGS_STRING_H
#define __STD_MSGS_STRING_H

#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/string.hpp"
#include "rclcpp/loadablemodules.hpp"

class class_std_msgs_string : public baseclass_std_msgs_string {
public:
   std_msgs::msg::String::SharedPtr exec(std_msgs::msg::String::SharedPtr msg);
};

#endif // __STD_MSGS_STRING_H