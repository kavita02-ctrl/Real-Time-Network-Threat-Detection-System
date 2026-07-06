cmake_minimum_required(VERSION 3.16)

project(threat_detector LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(ENABLE_PCAP "Build libpcap packet capture support" ON)
set(ONNXRUNTIME_ROOT "" CACHE PATH "Path to an ONNX Runtime release directory")

if(NOT ONNXRUNTIME_ROOT)
  message(FATAL_ERROR "Set -DONNXRUNTIME_ROOT=/path/to/onnxruntime")
endif()

find_path(ONNXRUNTIME_INCLUDE_DIR onnxruntime_cxx_api.h
  HINTS "${ONNXRUNTIME_ROOT}/include")

find_library(ONNXRUNTIME_LIBRARY onnxruntime
  HINTS "${ONNXRUNTIME_ROOT}/lib" "${ONNXRUNTIME_ROOT}/lib64")

if(NOT ONNXRUNTIME_INCLUDE_DIR OR NOT ONNXRUNTIME_LIBRARY)
  message(FATAL_ERROR "Could not find ONNX Runtime headers/library under ${ONNXRUNTIME_ROOT}")
endif()

add_library(threatdetector STATIC
  src/FeatureConfig.cpp
  src/FeatureExtractor.cpp
  src/InferenceEngine.cpp
  src/OnnxModel.cpp
  src/PacketSource.cpp
)

target_include_directories(threatdetector
  PUBLIC include "${ONNXRUNTIME_INCLUDE_DIR}"
)

target_link_libraries(threatdetector PUBLIC "${ONNXRUNTIME_LIBRARY}")

if(ENABLE_PCAP)
  find_package(PkgConfig)
  if(PkgConfig_FOUND)
    pkg_check_modules(PCAP libpcap)
  endif()

  if(PCAP_FOUND)
    target_include_directories(threatdetector PRIVATE ${PCAP_INCLUDE_DIRS})
    target_link_libraries(threatdetector PUBLIC ${PCAP_LIBRARIES})
    target_compile_definitions(threatdetector PUBLIC THREATDETECTOR_HAS_PCAP=1)
  else()
    message(WARNING "libpcap not found; building synthetic source only")
  endif()
endif()

add_executable(threat_detector src/main.cpp)
target_link_libraries(threat_detector PRIVATE threatdetector)
