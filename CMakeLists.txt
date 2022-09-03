cmake_minimum_required(VERSION 3.18)

project(
	bad_echo_driver
)

add_executable(
	${PROJECT_NAME}
	"src/main.cpp"
)

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
    CXX_STANDARD 20
    OUTPUT_NAME "echo_bridge"
)

add_custom_command(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/echo-bin/EchoDrv.sys" "$<TARGET_FILE_DIR:${PROJECT_NAME}>/EchoDrv.sys"
)
