
file(GLOB SRC *.cpp)

add_executable(avca ${SRC})
target_link_libraries(avca avimproto)

install(TARGETS avca RUNTIME DESTINATION bin)

