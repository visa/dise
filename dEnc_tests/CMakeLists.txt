
#project(libPSI_Tests)


 

#############################################
#               Build dEnc_tests            #
#############################################

file(GLOB_RECURSE SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)



add_library(dEnc_tests ${SRCS})

target_include_directories(dEnc_tests PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dEnc_tests dEnc)
