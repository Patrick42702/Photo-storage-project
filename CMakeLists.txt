cmake_minimum_required(VERSION 3.28)

project(CrowApp)

# Add the executable
add_executable(CrowApp main.cpp)

# Include the Crow headers (update the path if needed)
include_directories(/usr/include/crow)

# Link additional libraries if necessary (e.g., pthread for multithreading)
find_package(Threads REQUIRED)
target_link_libraries(CrowApp PRIVATE Threads::Threads)
