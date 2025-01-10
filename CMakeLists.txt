cmake_minimum_required(VERSION 3.22)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(photoapp)

# Add the executable
add_executable(${PROJECT_NAME} main.cpp)

# Download and unpack smtpclientlibrary at configure time
configure_file(CMakeLists.txt.in smtpclientlibrary-download/CMakeLists.txt)
execute_process(
  COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/smtpclientlibrary-download)
if(result)
  message(FATAL_ERROR "CMake step for smtpclientlibrary failed: ${result}")
endif()
execute_process(
  COMMAND ${CMAKE_COMMAND} --build .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/smtpclientlibrary-download)
if(result)
  message(FATAL_ERROR "Build step for smtpclientlibrary failed: ${result}")
endif()

# Add smtpclientlibrary directly to our build. This defines the smtpclient
# target.
add_subdirectory(
  ${CMAKE_CURRENT_BINARY_DIR}/smtpclientlibrary-src
  ${CMAKE_CURRENT_BINARY_DIR}/smtpclientlibrary-build EXCLUDE_FROM_ALL)

include_directories(${CMAKE_CURRENT_BINARY_DIR}/smtpclientlibrary-src/src)

# Find and link the MySQL Connector/C++ library
find_library(MYSQLCPPCONN_LIBRARY NAMES mysqlcppconn)

add_subdirectory(libs/libbcrypt)
add_subdirectory(libs/jwt-cpp)
add_subdirectory(libs/Crow)
add_subdirectory(libs/dotenv-cpp)

# Add include directories for all libraries
target_include_directories(
  ${PROJECT_NAME}
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/libs/libbcrypt/include # for bcrypt
                                                             # headers
          ${CMAKE_CURRENT_SOURCE_DIR}/libs/jwt-cpp/include # for jwt-cpp headers
          ${CMAKE_CURRENT_SOURCE_DIR}/libs/Crow/include # for Crow headers
          ${CMAKE_CURRENT_SOURCE_DIR}/libs/dotenv-cpp/include # for dotenv
                                                              # headers
)

# Link additional libraries if necessary (e.g., pthread for multithreading)
find_package(Threads REQUIRED)
target_link_libraries(
  ${PROJECT_NAME} PRIVATE Threads::Threads bcrypt jwt-cpp Crow::Crow dotenv
                          ${MYSQLCPPCONN_LIBRARY})
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
