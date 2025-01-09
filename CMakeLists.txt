cmake_minimum_required(VERSION 3.22)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(photoapp)

# Add the executable
add_executable(${PROJECT_NAME} main.cpp)

# Find and link the MySQL Connector/C++ library
find_library(MYSQLCPPCONN_LIBRARY NAMES mysqlcppconn)
# # Find and link jwt
# find_library(JWT NAMES jwt)
# # Find and link bcrypt
# find_library(BCRYPT NAMES bcrypt)
# # Find and link crypto
# find_library(CRYPTO NAMES crypto)
# # Find and link dotenv
# find_package(laserpants_dotenv)

# # Provide the path to the library if not found automatically
# if(NOT MYSQLCPPCONN_LIBRARY)
#     message(FATAL_ERROR "MySQL Connector/C++ library not found!")
# endif()

add_subdirectory(libs/libbcrypt)
add_subdirectory(libs/jwt-cpp)
add_subdirectory(libs/Crow)
add_subdirectory(libs/dotenv-cpp)

# Add include directories for all libraries
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/libbcrypt/include  # for bcrypt headers
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/jwt-cpp/include    # for jwt-cpp headers
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/Crow/include      # for Crow headers
    ${CMAKE_CURRENT_SOURCE_DIR}/libs/dotenv-cpp/include # for dotenv headers
)


# Link additional libraries if necessary (e.g., pthread for multithreading)
find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE 
    Threads::Threads
    bcrypt
    jwt-cpp
    Crow::Crow
    dotenv
    ${MYSQLCPPCONN_LIBRARY}
)
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
