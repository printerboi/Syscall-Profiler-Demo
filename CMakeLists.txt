cmake_minimum_required(VERSION 3.16)
project(collector LANGUAGES CXX)

# Use a modern C++ standard (adjust if needed)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags equivalent to: -O2 -g
add_compile_options(-O2 -g)

# Define the executable
add_executable(collector
        collector.cpp
        syscall_trace.skel.h
        RaplReader.cpp
)

# Link required libraries: -lbpf -lelf -lz
target_link_libraries(collector
        PRIVATE
        bpf
        elf
        z
)
