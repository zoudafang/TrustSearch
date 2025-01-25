cmake_minimum_required(VERSION 3.1)
project(Test)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_VERBOSE_MAKEFILE TRUE)
set(CMAKE_MODULE_PATH /usr/share/cmake-3.16/Modules/)
list(APPEND CMAKE_MODULE_PATH ../cmake)
message(STATUS "CMAKE MODULE Path: ${CMAKE_MODULE_PATH}")

#    set(EXECUTABLE_OUTPUT_PATH ${DEBEStore_SOURCE_DIR}/bin)
#    set(LIBRARY_OUTPUT_PATH ${DEBEStore_SOURCE_DIR}/lib)

if (${SGX_HW})
    set(MY_OPTION "-Wno-implicit-exception-spec-mismatch -DCHECK_SGX_HW=1")
else()
    set(MY_OPTION "-Wno-implicit-exception-spec-mismatch -DCHECK_SGX_HW=0")
endif()
set(CMAKE_C_FLAGS_DEBUG "-Wall -g -ggdb3 ${MY_OPTION}") 
# set(CMAKE_CXX_FLAGS_DEBUG "-O0 -Wall -fsanitize=address -fno-omit-frame-pointer -g -ggdb3") 
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -Wall -g -ggdb ${MY_OPTION}") # for gbd
set(CMAKE_C_FLAGS_RELEASE "-O3 -Wall ${MY_OPTION}") 
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall ${MY_OPTION}") 

SET (CMAKE_C_COMPILER "/usr/bin/clang")
SET (CMAKE_CXX_COMPILER "/usr/bin/clang++")
SET (CMAKE_AR "/usr/bin/llvm-ar")
SET (CMAKE_LINKER "/usr/bin/llvm-ld")
SET (CMAKE_NM "/usr/bin/llvm-nm")
SET (CMAKE_OBJDUMP "/usr/bin/llvm-objdump")
SET (CMAKE_RANLIB "/usr/bin/llvm-ranlib")




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

set(BOOST_LIBRARY_OBJ boost_thread boost_system boost_serialization)

set(SYSTEM_LIBRARY_OBJ pthread)


set(SGX_INCLUDE_PATH /opt/intel/sgxsdk/include)
include_directories(../include ../App ${SGX_INCLUDE_PATH})

set(OPENSSL_LIBRARY_OBJ ssl crypto)
set(THIRD_OBJ ${OPENSSL_LIBRARY_OBJ}  ${BOOST_LIBRARY_OBJ} ${SYSTEM_LIBRARY_OBJ})

aux_source_directory(../Comm/ COMM_SRC)
add_library(CommCore ${COMM_SRC})

#set(INSIDE_OBJ UtilCore DatabaseCore IndexCore CommCore IASCore ClientCore ServerCore)
set(INSIDE_OBJ    CommCore   )
#set(FINAL_OBJ ${THIRD_OBJ} EnclaveCore ${INSIDE_OBJ})
set(FINAL_OBJ ${THIRD_OBJ}  ${INSIDE_OBJ})

set(SGXOPENSSL_INCLUDE_PATH /opt/intel/sgxssl/include)
set(SGXOPENSSL_LIBRARY_PATH /opt/intel/sgxssl/lib64)
include_directories(${SGXOPENSSL_INCLUDE_PATH})
link_directories(${SGXOPENSSL_LIBRARY_PATH})

# add_executable(server server.cc)
# target_link_libraries(server ${FINAL_OBJ})

add_executable(client client.cc)
target_link_libraries(client ${FINAL_OBJ})
