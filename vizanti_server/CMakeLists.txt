cmake_minimum_required(VERSION 3.20)
project(vizanti_server)

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 17)
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(ament_cmake REQUIRED)
find_package(ament_cmake_python REQUIRED)

# Keep the ROS package and its independently executable gateway on one version.
ament_package_xml()
set(_gateway_script "${CMAKE_CURRENT_SOURCE_DIR}/scripts/vizanti_gateway.py")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_gateway_script}")
file(STRINGS "${_gateway_script}" _gateway_version_lines
  REGEX "^VERSION = \"[0-9]+[.][0-9]+[.][0-9]+\"$")
list(LENGTH _gateway_version_lines _gateway_version_count)
if(NOT _gateway_version_count EQUAL 1)
  message(FATAL_ERROR "Expected one gateway VERSION = \"MAJOR.MINOR.PATCH\" declaration")
endif()
string(REGEX REPLACE "^VERSION = \"([^\"]+)\"$" "\\1"
  _gateway_version "${_gateway_version_lines}")
if(NOT "${${PROJECT_NAME}_VERSION}" STREQUAL "${_gateway_version}")
  message(FATAL_ERROR
    "vizanti_server package.xml version ${${PROJECT_NAME}_VERSION} differs from gateway VERSION ${_gateway_version}; update both together")
endif()

find_package(rclcpp REQUIRED)
find_package(rclpy REQUIRED)

find_package(std_msgs REQUIRED)
find_package(std_srvs REQUIRED)
find_package(tf2_msgs REQUIRED)
find_package(geometry_msgs REQUIRED)
find_package(vizanti_msgs REQUIRED)
find_package(rosbridge_suite REQUIRED)

install(DIRECTORY
  launch
  public
  deploy
  DESTINATION share/${PROJECT_NAME}/
)

install(PROGRAMS
  scripts/__init__.py
  scripts/server.py
  scripts/service_handler.py
  scripts/rqt_reconfigure_param_api.py
  scripts/vizanti_gateway.py
  DESTINATION lib/${PROJECT_NAME}
)

ament_package()
