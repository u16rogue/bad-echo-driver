cmake_minimum_required(VERSION 3.18)

#Dependencies
add_subdirectory("deps/kita")

project(imgui_club)
add_library(${PROJECT_NAME} INTERFACE "deps/imgui_club/imgui_memory_editor/imgui_memory_editor.h")
target_include_directories(${PROJECT_NAME} INTERFACE "deps/imgui_club/")
target_link_libraries(${PROJECT_NAME} INTERFACE kita)

# Main project
project(
	bad_echo_driver
)

add_executable(
	${PROJECT_NAME}

	"src/utils.hpp"
    "src/utils.cpp"

    "src/global.hpp"

	"src/echo.hpp"
	"src/echo.cpp"

	"src/main.cpp"
)

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
    CXX_STANDARD 20
    OUTPUT_NAME "bad_echo"
)

add_custom_command(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/echo-bin/EchoDrv.sys" "$<TARGET_FILE_DIR:${PROJECT_NAME}>/EchoDrv.sys"
)

target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE
    kita
    imgui_club
)
