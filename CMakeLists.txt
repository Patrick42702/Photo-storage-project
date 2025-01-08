cmake_minimum_required(VERSION 3.28)

project(CrowApp)

# Add the executable
add_executable(CrowApp main.cpp dbm.cpp)

# Include the Crow headers (update the path if needed)
include_directories(/usr/include/crow)
include_directories(/usr/include/mysql-cppconn-8)

# Find and link the MySQL Connector/C++ library
find_library(MYSQLCPPCONN_LIBRARY NAMES mysqlcppconn)
# Find and link jwt
find_library(JWT NAMES jwt)

# Provide the path to the library if not found automatically
if(NOT MYSQLCPPCONN_LIBRARY)
    message(FATAL_ERROR "MySQL Connector/C++ library not found!")
endif()

# Link additional libraries if necessary (e.g., pthread for multithreading)
find_package(Threads REQUIRED)
# Specify Boost version
find_package(Boost 1.70 REQUIRED COMPONENTS filesystem system)
target_link_libraries(CrowApp PRIVATE Threads::Threads Boost::filesystem Boost::system ${MYSQLCPPCONN_LIBRARY} ${JWT})
