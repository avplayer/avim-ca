
file(GLOB SRC *.cpp)

add_executable(avca ${SRC})
target_link_libraries(avca avim++)

install(TARGETS avca RUNTIME DESTINATION bin)

