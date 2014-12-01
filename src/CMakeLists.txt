
add_executable(avca main.cpp)
target_link_libraries(avca avimproto)

install(TARGETS avca RUNTIME DESTINATION bin)

