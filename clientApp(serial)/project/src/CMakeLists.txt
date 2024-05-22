file(GLOB_RECURSE Headers CONFIGURE_DEPENDS src/include/*.h src/include/*.hpp src/include/*.hxx intermediate/code/*.h intermediate/code/*.hpp intermediate/code/*.hxx)
file(GLOB_RECURSE Sources CONFIGURE_DEPENDS src/*.cpp intermediate/code/*.cpp)
add_executable(test ${Sources})

find_package(ArpDevice REQUIRED)
find_package(ArpProgramming REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ArpDevice ArpProgramming ${CURL_LIBRARIES} OpenSSL::Crypto)

