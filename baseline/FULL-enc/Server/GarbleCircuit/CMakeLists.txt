aux_source_directory(. GCIRCUIT_SRC)




find_package(emp-ot)

find_path(EMP-SH2PC_INCLUDE_DIR emp-sh2pc/emp-sh2pc.h)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(emp-sh2pc DEFAULT_MSG EMP-SH2PC_INCLUDE_DIR)

if(EMP-SH2PC_FOUND)
	set(EMP-SH2PC_INCLUDE_DIRS ${EMP-SH2PC_INCLUDE_DIR}/include/ ${EMP-OT_INCLUDE_DIRS})
	set(EMP-SH2PC_LIBRARIES ${EMP-TOOL_LIBRARIES})
endif()



set (CMAKE_FOLDER "/usr/local")
message(STATUS "CMAKE_FOLDER11: ${CMAKE_FOLDER}")
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)
#printf cmake folder
message(STATUS "CMAKE_FOLDER: ${CMAKE_FOLDER}")

find_package(emp-tool REQUIRED)
include_directories(${EMP-TOOL_INCLUDE_DIRS})

# Installation
install(FILES cmake/emp-ot-config.cmake DESTINATION cmake/)
install(DIRECTORY emp-ot DESTINATION include/)




#src/app
#find_package(SGX REQUIRED)
find_package(Boost 1.36.0 REQUIRED COMPONENTS thread system serialization)
find_package(OpenSSL REQUIRED)

# if(NOT SGX_HW) 
#     message(STATUS "Using Simulation Mode, SGX_HW: ${SGX_HW}")
#     link_directories(${SGX_SIM_LIB_PATH})
#     set(SGX_UNTRUST_MUST_LINK sgx_urts_sim sgx_uae_service_sim sgx_capable)
# else() 
#     set(SGX_UNTRUST_MUST_LINK sgx_urts sgx_uae_service sgx_capable)
# endif()

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    link_directories(${Boost_LIBRARY_DIRS})
else()
    message(FATAL_ERROR "Cannot find boost library")
endif()

message(STATUS "Find OpenSSL version: ${OPENSSL_VERSION}")
if(OPENSSL_VERSION VERSION_LESS "1.1")
    message(FATAL_ERROR "OpenSSL version is less than 1.1")
endif()


add_library(GCIRCUITCore ${GCIRCUIT_SRC})
