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

#include "rclcpp/rclcpp.hpp"
#include "rcutils/cmdline_parser.h"

#include "std_msgs/msg/string.hpp"
#include "std_msgs/msg/int32.hpp"

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


std::map<std::string, maker_std_msgs_int32 *, std::less<std::string> > factory_std_msgs_int32;

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




// Create a std_msgs_int32 class that subclasses the generic rclcpp::Node base class.
// The main function below will instantiate the class as a ROS node.
class Std_msgs_int32 : public rclcpp::Node
{
public:
  explicit Std_msgs_int32(const std::string & sub_topic, const std::string & pub_topic)
  : Node("std_msgs_int32")
  {
    // Create a callback function for when messages are received.
    // Variations of this function also exist using, for example UniquePtr for zero-copy transport.
    auto callback =
      [this](std_msgs::msg::Int32::SharedPtr msg) -> void
      {
        RCLCPP_INFO(this->get_logger(), "I heard: [%d]", msg->data);
        if (factory_std_msgs_int32.size() > 0)
        {
          // remove const from callback parameter
          baseclass_std_msgs_int32 *plugin = factory_std_msgs_int32["class_std_msgs_int32"]();
          msg = plugin->exec(std::move(msg));
          // std::cout << "Data returned is:" << msg->data << std::endl;
        }
        pub_->publish(std::move(msg));
      };
    // Create a subscription to the topic which can be matched with one or more compatible ROS
    // publishers.
    // Note that not all publishers on the same topic with the same type will be compatible:
    // they must have compatible Quality of Service policies.
    sub_ = create_subscription<std_msgs::msg::Int32>(sub_topic, 10, callback);
    rclcpp::QoS qos(rclcpp::KeepLast(7));
    pub_ = this->create_publisher<std_msgs::msg::Int32>(pub_topic, qos);
  }

private:
  rclcpp::Subscription<std_msgs::msg::Int32>::SharedPtr sub_;
  std::unique_ptr<std_msgs::msg::Int32> msg1_;
  rclcpp::Publisher<std_msgs::msg::Int32>::SharedPtr pub_;
  
  
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
  auto node = std::make_shared<Std_msgs_int32>(sub_topic, pub_topic);
  

  // spin will block until work comes in, execute work as it becomes available, and keep blocking.
  // It will only be interrupted by Ctrl-C.
  rclcpp::spin(node);

  rclcpp::shutdown();
  close_module();
  return 0;
}
