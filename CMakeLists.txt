cmake_minimum_required(VERSION 3.10)
project(Configuration_Integrity_Verification)

if (WIN32)
    link_directories(libs)
    add_definitions(-DTPM_WINDOWS)
    # Include IBM TSS directory (e.g. /opt/ibmtss/utils)
    include_directories(C:/opt/ibmtss130/utils)
endif (WIN32)

if (UNIX)
    add_definitions(-DTPM_POSIX)
    include_directories(/opt/ibmtss/utils)
endif(UNIX)
add_definitions(-DVERBOSE)


set (COMPILE_FLAGS "-Wall -Wno-sign-compare -O3 -Wno-comment -Wno-unused-function -Wno-write-strings -fexceptions -fpermissive -no-pie")


# Verbose: Does a ton of printing
# Set -DHWTPM if running on a hardware TPM
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${COMPILE_FLAGS}")


include_directories(include)

add_executable(Configuration_Integrity_Verification
        include/CreateResponse.h
        include/defines.h
        include/Orchestrator.h
        include/PCRSelection.h
        include/PolicyManager.h
        include/Template.h
        include/TpmManager.h
        include/tss_includes.h
        include/VirtualMachine.h
        include/VMStructure.h
        source/Orchestrator.cpp
        source/PolicyManager.cpp
        source/Template.cpp
        source/TpmManager.cpp
        source/VirtualMachine.cpp
        source/cryptoutils.c
        main.cpp)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(Configuration_Integrity_Verification ibmtss ${OPENSSL_LIBRARIES})
