cmake_minimum_required (VERSION 3.5)

project("dEnc")


set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)


#############################################
#            Flag and #defines              #
#############################################
add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")
set(CMAKE_C_FLAGS "-ffunction-sections -Wall -Wno-strict-aliasing  -maes -msse2 -msse4.1 -mpclmul -Wno-sign-compare -Wfatal-errors -pthread")
set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14 -Wno-ignored-attributes")

# Set a default build type for single-configuration
# CMake generators if no build type is set.
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE Release)
endif()


if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
  message(WARNING "\nConfiguration NOT set to Release. Please call cmake with -DCMAKE_BUILD_TYPE=Release  instead of ${CMAKE_BUILD_TYPE}")

    if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
      message(WARNING "Debug build.")
    elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release") 
      message(WARNING "Release build.")
    elseif("${CMAKE_BUILD_TYPE}" STREQUAL  "RELWITHDEBINFO")
      message(WARNING "RELWITHDEBINFO=Release with debug info build.")
    else()
      message(ERROR ": Unknown build type - ${CMAKE_BUILD_TYPE}  Please use one of Debug, Release, or RELWITHDEBINFO\n\n" )
    endif()

endif()

message(STATUS "Option: CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}\n\tRelease\n\tDebug\n\tRELWITHDEBINFO")

# Select flags.
SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -ggdb -rdynamic")
SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g3 -ggdb -rdynamic")


#############################################
#       Library/includes locations          #
#############################################

include_directories("${CMAKE_SOURCE_DIR}")

# default location for libOTe
set(CRYPTOTOOLS_DIR "${CMAKE_SOURCE_DIR}/../cryptoTools/" CACHE STRING "location of cryptoTools root")

# default location for Boost
set(BOOST_ROOT "${CRYPTOTOOLS_DIR}/thirdparty/linux/boost/" CACHE STRING "location of Boost root")

message(STATUS "Option: CRYPTOTOOLS_DIR  = ${CRYPTOTOOLS_DIR}")
message(STATUS "Option: BOOST_ROOT       = ${BOOST_ROOT}")

#############################################
#               Build libPSI                 #
#############################################
add_subdirectory(dEnc)

#############################################
#           Build libPSI Tests              #
#############################################
add_subdirectory(dEnc_tests)

#############################################
#              Build Frontend               #
#############################################
add_subdirectory(dEncFrontend)


