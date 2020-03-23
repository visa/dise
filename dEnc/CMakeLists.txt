#############################################
#                 Link Boost                #
#############################################

set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

find_package(Boost 1.69 COMPONENTS system thread)

if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIR}) 
  message( "Found Boost at ${Boost_LIBRARIES}")
else()
   message(FATAL_ERROR "Failed to find boost at > " ${BOOST_ROOT} " < Need system thread")
endif()


#############################################
#                 Link Relic                #
#############################################

find_package(Relic REQUIRED)

if (NOT Relic_FOUND)
   message(FATAL_ERROR "Failed to find Relic")
endif (NOT Relic_FOUND)


message(STATUS "Relic Lib: ${RLC_LIBRARY}")
message(STATUS "Relic inc: ${RLC_INCLUDE_DIR}")

#############################################
#                 Link libOTe               #
#############################################

find_library(
    cryptoTools_LIB
    NAMES cryptoTools
    HINTS "${CRYPTOTOOLS_DIR}/lib/")

  if (NOT cryptoTools_LIB)
    message(FATAL_ERROR "Failed to find cryptoTools library at ${CRYPTOTOOLS_DIR}/lib")
 endif (NOT cryptoTools_LIB)
 

#############################################
#              Build libPSI                 #
#############################################

file(GLOB_RECURSE SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
 

add_library(dEnc ${SRCS})
target_include_directories(dEnc PUBLIC 
    ${RELIC_INCLUDE_DIR} 
    ${RLC_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/.. 
    ${CRYPTOTOOLS_DIR}
    ${Boost_INCLUDE_DIR})

target_link_libraries(dEnc ${RLC_LIBRARY} ${RELIC_LIBRARIES} ${cryptoTools_LIB} ${MIRACL_LIB} ${NTL_LIB} ${Boost_LIBRARIES})

