cmake_minimum_required(VERSION 3.18)

add_subdirectory("deps/kita")

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
)
