cmake_minimum_required(VERSION 3.16)
project(scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

add_executable(scanner scanner.cpp)

target_compile_options(scanner PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/O2 /W3>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O3 -Wall>
)

target_link_libraries(scanner PRIVATE psapi)

# Copia o exe para a pasta raiz do projeto após build
add_custom_command(TARGET scanner POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:scanner>
        ${CMAKE_SOURCE_DIR}/../scanner.exe
    COMMENT "Copiando scanner.exe para a raiz do projeto"
)
