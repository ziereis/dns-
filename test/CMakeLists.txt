include(CTest)
include(doctest)

add_executable(dns_test dns_test.cpp)
target_link_libraries(dns_test PRIVATE doctest::doctest Dns)

doctest_discover_tests(dns_test)