cmake_minimum_required(VERSION 3.5)

project(templates)



# Default to C++14
if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 14)
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()


add_compile_options(-ldl -fPIC -Wl,-E  -ggdb -c)
SET(GCC_COVERAGE_LINK_FLAGS    "-rdynamic -fPIC")
SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")


find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(sensor_msgs REQUIRED)
find_package(std_msgs REQUIRED)


find_package(rcutils)
find_package(rmw REQUIRED)
find_package(OpenCV REQUIRED)
find_package(example_interfaces REQUIRED)

include_directories(include)

add_executable(cam2image
  src/burger.cpp
  src/cam2image.cpp
  src/options.cpp
)
add_executable(camera
  src/burger.cpp
  src/camera.cpp
  src/options.cpp
)

ament_target_dependencies(cam2image
  "rclcpp"
  "sensor_msgs"
  "std_msgs"
  "OpenCV")
ament_target_dependencies(camera
  "rclcpp"
  "sensor_msgs"
  "std_msgs"
  "OpenCV")

add_executable(showimage
  src/options.cpp
  src/showimage.cpp
)
add_executable(filterapp
  src/filterapp.cpp
  src/burger.cpp
  src/options.cpp
  
)



ament_target_dependencies(showimage
  "rclcpp"
  "sensor_msgs"
  "std_msgs"
  "OpenCV")
ament_target_dependencies(filterapp
  "rclcpp"
  "sensor_msgs"
  "std_msgs"
  "OpenCV")


install(TARGETS
  cam2image
  camera
  showimage
  filterapp
  DESTINATION lib/${PROJECT_NAME})





function(custom_executable target)
  add_executable(${target} src/${target}.cpp)
  ament_target_dependencies(${target}
    "example_interfaces"
    "rclcpp"
    "rcutils"
    "std_msgs"
    "sensor_msgs"
    )
  target_link_libraries(${target} ${CMAKE_DL_LIBS})
  install(TARGETS ${target}
  DESTINATION lib/${PROJECT_NAME})
endfunction()


custom_executable(std_msgs_int32)
custom_executable(std_msgs_string)
custom_executable(sensor_msgs_image)
custom_executable(testdcl)





if(BUILD_TESTING)
  find_package(ament_lint_auto REQUIRED)
  ament_lint_auto_find_test_dependencies()

  find_package(ament_cmake_pytest REQUIRED)
  find_package(launch_testing_ament_cmake REQUIRED)
  find_package(rmw_implementation_cmake REQUIRED)

  # These are the regex's for validating the output of the executables.
  set(RCLCPP_DEMO_SHOWIMAGE_EXPECTED_OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/test/showimage")
  set(RCLCPP_DEMO_CAM2IMAGE_EXPECTED_OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/test/cam2image")

  macro(testing_targets)
    set(RCLCPP_DEMO_CAM2IMAGE_EXECUTABLE $<TARGET_FILE:cam2image>)
    set(RCLCPP_DEMO_SHOWIMAGE_EXECUTABLE $<TARGET_FILE:showimage>)

    configure_file(
      test/test_executables_demo.py.in
      test_showimage_cam2image${target_suffix}.py.genexp
      @ONLY
    )

    file(GENERATE
      OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/test_showimage_cam2image${target_suffix}_$<CONFIG>.py"
      INPUT "${CMAKE_CURRENT_BINARY_DIR}/test_showimage_cam2image${target_suffix}.py.genexp"
    )

    add_launch_test(
      "${CMAKE_CURRENT_BINARY_DIR}/test_showimage_cam2image${target_suffix}_$<CONFIG>.py"
      TARGET test_showimage_cam2image${target_suffix}
      ENV
      RCL_ASSERT_RMW_ID_MATCHES=${rmw_implementation}
      RMW_IMPLEMENTATION=${rmw_implementation}
      TIMEOUT 30
    )
  endmacro()

  call_for_each_rmw_implementation(testing_targets)

endif()

ament_package()
