#ifndef __SENSOR_MSGS_IMAGE_H
#define __SENSOR_MSGS_IMAGE_H

#include "rclcpp/rclcpp.hpp"
#include "sensor_msgs/msg/image.hpp"
#include "rclcpp/loadablemodules.hpp"

class class_sensor_msgs_image: public baseclass_sensor_msgs_image {
public:
   sensor_msgs::msg::Image::SharedPtr exec(sensor_msgs::msg::Image::SharedPtr msg);
};

#endif // __SENSOR_MSGS_IMAGE_H