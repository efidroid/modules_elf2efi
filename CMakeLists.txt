cmake_minimum_required(VERSION 2.8)
project(elf2efi C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow -Wstrict-prototypes")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os")

include_directories(
    include
)

add_executable(elf2efi
    src/main.c
    src/arch_32.c
    src/arch_64.c
    src/util.c
)
