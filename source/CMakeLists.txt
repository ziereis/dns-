
set(SOURCES DnsPacket.cpp BufferParser.cpp DnsServer.cpp DnsServer.h)
set(LIBRARY_NAME Dns)
set(EXECUTABLE_NAME main)

add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(${LIBRARY_NAME} PROPERTIES LINKER_LANGUAGE CXX)

add_executable(${EXECUTABLE_NAME} main.cpp DnsPacket.h)
target_link_libraries(${EXECUTABLE_NAME} ${LIBRARY_NAME})