#ifndef __STD_MSGS_INT32_H
#define __STD_MSGS_INT32_H

#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/int32.hpp"
#include "rclcpp/loadablemodules.hpp"

class class_std_msgs_int32 : public baseclass_std_msgs_int32 {
public:
   std_msgs::msg::Int32::SharedPtr exec(std_msgs::msg::Int32::SharedPtr msg);
};

#endif // __STD_MSGS_INT32_H