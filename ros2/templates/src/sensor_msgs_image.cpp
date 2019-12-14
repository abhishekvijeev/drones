
// Copyright 2014 Open Source Robotics Foundation, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstdio>
#include <memory>
#include <string>
#include <chrono>
#include <memory>
#include <string>
#include <utility>


//LOADABLE MODULE
#include "rclcpp/loadablemodules.hpp"
#include <iostream>
#include <map>
#include <list>
#include <vector>
#include <string>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>


std::map<std::string, maker_sensor_msgs_image *, std::less<std::string> > factory_sensor_msgs_image;
std::list<void *> dl_list;
std::string basepath = "/home/abhishek/sros2_demo/library/";

void load_module(std::string libname)
{
  std::string filename = "";
  if (libname[0] != '/')
    filename = basepath + libname;
  else
    filename = libname;
  
  std::cout << "library=" << filename << std::endl;
  void *dlib;
  dlib = dlopen(filename.c_str(), RTLD_NOW);
  if(dlib == NULL)
  {
      std::cout << "ERROR in loading library:" << dlerror() << std::endl;
  }
  else
  {
    // add the handle to our list
    dl_list.insert(dl_list.end(), dlib);
  }
}
void close_module()
{
  std::cout << "Closing library\n";
  std::list<void *>::iterator itr;
  // close all the dynamic libs we opened
  for(itr=dl_list.begin(); itr!=dl_list.end(); itr++){
    dlclose(*itr);
  }
}

void parse_lib_arguments(int argc, char * argv[])
{
  for(int i = 0; i < argc; i++)
  {
    std::string arg = argv[i];
    if ( (arg == "-sl") || (arg == "--sharedlib"))
    {
      if (i+1 < argc)// Make sure we aren't at the end of argv!
      {
        arg = argv[i+1];
        if (arg != "NoModule")
          load_module(arg);
      }
    }
  }
  
}


// Create a Sensor_msgs_image class that subclasses the generic rclcpp::Node base class.
// The main function below will instantiate the class as a ROS node.
class Sensor_msgs_image : public rclcpp::Node
{
public:
  explicit Sensor_msgs_image(const std::string & sub_topic, const std::string & pub_topic)
  : Node("sensor_msgs_image")
  {
    // Create a callback function for when messages are received.
    // Variations of this function also exist using, for example UniquePtr for zero-copy transport.
    auto callback =
      [this](sensor_msgs::msg::Image::SharedPtr msg) -> void
      {
        if (factory_sensor_msgs_image.size() > 0)
        {
          // remove const from callback parameter
          baseclass_sensor_msgs_image *plugin = factory_sensor_msgs_image["class_sensor_msgs_image"]();
          msg = plugin->exec(std::move(msg));
          // std::cout << "Data returned is:" << msg->data << std::endl;
        }
        pub_->publish(std::move(msg));
      };
    
     // Initialize default demo parameters
    size_t depth = rmw_qos_profile_default.depth;
    rmw_qos_reliability_policy_t reliability_policy = rmw_qos_profile_default.reliability;
    rmw_qos_history_policy_t history_policy = rmw_qos_profile_default.history;
    
    // Set quality of service profile based on command line options.
    auto qos = rclcpp::QoS(
      rclcpp::QoSInitialization(
        // The history policy determines how messages are saved until taken by
        // the reader.
        // KEEP_ALL saves all messages until they are taken.
        // KEEP_LAST enforces a limit on the number of messages that are saved,
        // specified by the "depth" parameter.
        history_policy,
        // Depth represents how many messages to store in history when the
        // history policy is KEEP_LAST.
        depth
    ));
    // The reliability policy can be reliable, meaning that the underlying transport layer will try
    // ensure that every message gets received in order, or best effort, meaning that the transport
    // makes no guarantees about the order or reliability of delivery.
    qos.reliability(reliability_policy);
    
    sub_ = create_subscription<sensor_msgs::msg::Image>(sub_topic, qos, callback);
    pub_ = this->create_publisher<sensor_msgs::msg::Image>(pub_topic, qos);
  }

private:
  rclcpp::Subscription<sensor_msgs::msg::Image>::SharedPtr sub_;
  rclcpp::Publisher<sensor_msgs::msg::Image>::SharedPtr pub_;
  
  
};

int main(int argc, char * argv[])
{
  parse_lib_arguments(argc, argv);
  // Force flush of the stdout buffer.
  setvbuf(stdout, NULL, _IONBF, BUFSIZ);

  // Initialize any global resources needed by the middleware and the client library.
  // You must call this before using any other part of the ROS system.
  // This should be called once per process.
  rclcpp::init(argc, argv);

  // Parse the command line options.
  auto pub_topic = std::string("output");
  auto sub_topic = std::string("input");
  
  // Create a node.
  auto node = std::make_shared<Sensor_msgs_image>(sub_topic, pub_topic);
  

  // spin will block until work comes in, execute work as it becomes available, and keep blocking.
  // It will only be interrupted by Ctrl-C.
  rclcpp::spin(node);

  rclcpp::shutdown();
  close_module();
  return 0;
}

