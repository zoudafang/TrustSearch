cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(readData)
 
find_package(Torch REQUIRED)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${TORCH_CXX_FLAGS}")
set(MKL_ROOT "/opt/intel/oneapi/mkl/2022.0.2")
set(MKL_LIB_DIR "${MKL_ROOT}/lib/intel64")
link_directories(${MKL_LIB_DIR}) 

add_executable(readData readData.cpp)
target_link_libraries(readData "${TORCH_LIBRARIES}")
set_property(TARGET readData PROPERTY CXX_STANDARD 17)
