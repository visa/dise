#project(fronend) 

#############################################
#               Build fronend               #
#############################################

file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
include_directories(${CMAKE_SOURCE_DIR}/frontend/)

add_executable(dEncFrontend ${SRC_FRONTEND})
#target_include_directories(dEncFrontend ${CMAKE_CURRENT_SOURCE_DIR})

#############################################
#            Link our libraries             #
#############################################
target_link_libraries(dEncFrontend dEnc_tests dEnc)
