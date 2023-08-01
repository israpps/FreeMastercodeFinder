cmake_minimum_required(VERSION 3.10)

# set the project name
project(FreeMastercodeFinder)

# add the executable
#include_directories(include)
add_executable(FreeMastercodeFinder
    main.c
	elf.c
)