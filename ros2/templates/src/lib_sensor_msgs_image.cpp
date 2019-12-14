// to compile
// g++ -I/home/abhishek/ros2_ws/src/ros2/demos/templates/include -I/home/abhishek/ros2_ws/install/rclcpp/include -I/home/abhishek/ros2_ws/install/rcl_yaml_param_parser/include -I/home/abhishek/ros2_ws/install/sensor_msgs/include -I/home/abhishek/ros2_ws/install/rcl/include -I/home/abhishek/ros2_ws/install/geometry_msgs/include -I/home/abhishek/ros2_ws/install/std_msgs/include -I/home/abhishek/ros2_ws/install/rosgraph_msgs/include -I/home/abhishek/ros2_ws/install/rcl_interfaces/include -I/home/abhishek/ros2_ws/install/builtin_interfaces/include -I/home/abhishek/ros2_ws/install/rosidl_typesupport_cpp/include -I/home/abhishek/ros2_ws/install/rosidl_typesupport_c/include -I/home/abhishek/ros2_ws/install/rosidl_typesupport_introspection_cpp/include -I/home/abhishek/ros2_ws/install/rosidl_typesupport_introspection_c/include -I/home/abhishek/ros2_ws/install/rosidl_generator_cpp/include -I/home/abhishek/ros2_ws/install/rmw/include -I/home/abhishek/ros2_ws/install/rosidl_generator_c/include -I/home/abhishek/ros2_ws/install/rcutils/include -I/home/abhishek/ros2_ws/install/rosidl_typesupport_interface/include -isystem /usr/include/opencv  -Wall -Wextra -Wpedantic -ldl -fPIC -Wl,-E -ggdb -c -std=gnu++14 -c /home/abhishek/ros2_ws/src/ros2/demos/templates/src/lib_sensor_msgs_image.cpp

//  g++ -shared -Wl,-soname,lib_sensor_msgs_image.so -o lib_sensor_msgs_image.so lib_sensor_msgs_image.o -lopencv_highgui -lopencv_imgproc -lopencv_core -lopencv_imgcodecs -lopencv_videoio  -L/usr/local/lib 


#include <iostream> 
#include "sensor_msgs_image.hh"

#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <memory>
#include <utility>
#include <opencv2/core/core.hpp> 
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/imgproc/imgproc.hpp>
#include "std_msgs/msg/bool.hpp"
#include "rclcpp/rclcpp.hpp"


#include "sensor_msgs/msg/image.hpp"
#include <stdio.h>

using namespace cv;

using namespace std;

std::string
mat_type2encoding(int mat_type)
{
  switch (mat_type) {
    case CV_8UC1:
      return "mono8";
    case CV_8UC3:
      return "bgr8";
    case CV_16SC1:
      return "mono16";
    case CV_8UC4:
      return "rgba8";
    default:
      throw std::runtime_error("Unsupported encoding type");
  }
}


void convert_frame_to_message(
  const cv::Mat & frame, string frame_id, sensor_msgs::msg::Image & msg)
{
  // copy cv information into ros message
  msg.height = frame.rows;
  msg.width = frame.cols;
  msg.encoding = mat_type2encoding(frame.type());
  msg.step = static_cast<sensor_msgs::msg::Image::_step_type>(frame.step);
  size_t size = frame.step * frame.rows;
  msg.data.resize(size);
  memcpy(&msg.data[0], frame.data, size);
  msg.header.frame_id = frame_id;
}
int
encoding2mat_type(const std::string & encoding)
{
  if (encoding == "mono8") {
    return CV_8UC1;
  } else if (encoding == "bgr8") {
    return CV_8UC3;
  } else if (encoding == "mono16") {
    return CV_16SC1;
  } else if (encoding == "rgba8") {
    return CV_8UC4;
  } else if (encoding == "bgra8") {
    return CV_8UC4;
  } else if (encoding == "32FC1") {
    return CV_32FC1;
  } else if (encoding == "rgb8") {
    return CV_8UC3;
  } else {
    throw std::runtime_error("Unsupported encoding type");
  }
}

sensor_msgs::msg::Image::SharedPtr class_sensor_msgs_image::exec(sensor_msgs::msg::Image::SharedPtr msg)
{
    std::cout << "inside lib_sensor_msgs_image\n";
   
    auto msgpub = std::make_unique<sensor_msgs::msg::Image>();
    // // Convert to an OpenCV matrix by assigning the data.
    cv::Mat frame(
            msg->height, msg->width, encoding2mat_type(msg->encoding),
            const_cast<unsigned char *>(msg->data.data()), msg->step);

    if (msg->encoding == "rgb8") {
        cv::cvtColor(frame, frame, cv::COLOR_RGB2BGR);
    }

    cv::Mat cvframe = frame;

    cv::Size size(480,480);
    cv::resize(cvframe, cvframe, size); 

    blur(cvframe,cvframe,Size(10,10)); 



    if (!cvframe.empty()) 
    {
        // Convert to a ROS image
        convert_frame_to_message(cvframe, msg->header.frame_id, *msgpub);
    }
    return std::move(msg); 
    
}

extern "C" {
baseclass_sensor_msgs_image *maker(){
   return new class_sensor_msgs_image;
}
class proxy {
public:
   proxy(){
      // register the maker with the factory
      factory_sensor_msgs_image["class_sensor_msgs_image"] = maker;
   }
};
// our one instance of the proxy
proxy p;
}
