# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.13

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/ubuntu/plc/epc/tool_chain/plcncli/cmake/bin/cmake

# The command to remove a file.
RM = /home/ubuntu/plc/epc/tool_chain/plcncli/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ubuntu/plc/epc/epc1522/work/HostidClient

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release

# Include any dependencies generated for this target.
include CMakeFiles/HostidClient.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/HostidClient.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/HostidClient.dir/flags.make

CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.o: CMakeFiles/HostidClient.dir/flags.make
CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.o: ../../../../src/ExampleAuthenticationProvider.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.o"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.o -c /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/ExampleAuthenticationProvider.cpp

CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.i"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/ExampleAuthenticationProvider.cpp > CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.i

CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.s"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/ExampleAuthenticationProvider.cpp -o CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.s

CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.o: CMakeFiles/HostidClient.dir/flags.make
CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.o: ../../../../src/ExampleAuthorizationProvider.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.o"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.o -c /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/ExampleAuthorizationProvider.cpp

CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.i"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/ExampleAuthorizationProvider.cpp > CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.i

CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.s"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/ExampleAuthorizationProvider.cpp -o CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.s

CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.o: CMakeFiles/HostidClient.dir/flags.make
CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.o: ../../../../src/UmModuleEx.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.o"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.o -c /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/UmModuleEx.cpp

CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.i"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/UmModuleEx.cpp > CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.i

CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.s"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/UmModuleEx.cpp -o CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.s

CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.o: CMakeFiles/HostidClient.dir/flags.make
CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.o: ../../../../src/UmModuleExConfig.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.o"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.o -c /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/UmModuleExConfig.cpp

CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.i"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/UmModuleExConfig.cpp > CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.i

CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.s"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/UmModuleExConfig.cpp -o CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.s

CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.o: CMakeFiles/HostidClient.dir/flags.make
CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.o: ../../../../src/UmModuleExLibrary.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.o"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.o -c /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/UmModuleExLibrary.cpp

CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.i"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/UmModuleExLibrary.cpp > CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.i

CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.s"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/UmModuleExLibrary.cpp -o CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.s

CMakeFiles/HostidClient.dir/src/curl.cpp.o: CMakeFiles/HostidClient.dir/flags.make
CMakeFiles/HostidClient.dir/src/curl.cpp.o: ../../../../src/curl.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/HostidClient.dir/src/curl.cpp.o"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HostidClient.dir/src/curl.cpp.o -c /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/curl.cpp

CMakeFiles/HostidClient.dir/src/curl.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HostidClient.dir/src/curl.cpp.i"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/curl.cpp > CMakeFiles/HostidClient.dir/src/curl.cpp.i

CMakeFiles/HostidClient.dir/src/curl.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HostidClient.dir/src/curl.cpp.s"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/curl.cpp -o CMakeFiles/HostidClient.dir/src/curl.cpp.s

CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.o: CMakeFiles/HostidClient.dir/flags.make
CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.o: ../../../../src/jsoncpp.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.o"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.o -c /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/jsoncpp.cpp

CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.i"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/jsoncpp.cpp > CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.i

CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.s"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/jsoncpp.cpp -o CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.s

CMakeFiles/HostidClient.dir/src/verify.cpp.o: CMakeFiles/HostidClient.dir/flags.make
CMakeFiles/HostidClient.dir/src/verify.cpp.o: ../../../../src/verify.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object CMakeFiles/HostidClient.dir/src/verify.cpp.o"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/HostidClient.dir/src/verify.cpp.o -c /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/verify.cpp

CMakeFiles/HostidClient.dir/src/verify.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HostidClient.dir/src/verify.cpp.i"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/verify.cpp > CMakeFiles/HostidClient.dir/src/verify.cpp.i

CMakeFiles/HostidClient.dir/src/verify.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HostidClient.dir/src/verify.cpp.s"
	/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/epc/epc1522/work/HostidClient/src/verify.cpp -o CMakeFiles/HostidClient.dir/src/verify.cpp.s

# Object files for target HostidClient
HostidClient_OBJECTS = \
"CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.o" \
"CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.o" \
"CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.o" \
"CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.o" \
"CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.o" \
"CMakeFiles/HostidClient.dir/src/curl.cpp.o" \
"CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.o" \
"CMakeFiles/HostidClient.dir/src/verify.cpp.o"

# External object files for target HostidClient
HostidClient_EXTERNAL_OBJECTS =

libHostidClient.so: CMakeFiles/HostidClient.dir/src/ExampleAuthenticationProvider.cpp.o
libHostidClient.so: CMakeFiles/HostidClient.dir/src/ExampleAuthorizationProvider.cpp.o
libHostidClient.so: CMakeFiles/HostidClient.dir/src/UmModuleEx.cpp.o
libHostidClient.so: CMakeFiles/HostidClient.dir/src/UmModuleExConfig.cpp.o
libHostidClient.so: CMakeFiles/HostidClient.dir/src/UmModuleExLibrary.cpp.o
libHostidClient.so: CMakeFiles/HostidClient.dir/src/curl.cpp.o
libHostidClient.so: CMakeFiles/HostidClient.dir/src/jsoncpp.cpp.o
libHostidClient.so: CMakeFiles/HostidClient.dir/src/verify.cpp.o
libHostidClient.so: CMakeFiles/HostidClient.dir/build.make
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libcurl.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libcrypto.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Acf.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Commons.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Core.a
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Plc.Commons.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Rsc.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Commons.Services.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Lm.Services.a
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Nm.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.NmPayload.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Security.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Security.Services.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Um.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Ve.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Plc.Domain.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Plc.Gds.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Plc.Meta.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Plc.Retain.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Device.Interface.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Services.NotificationLogger.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Services.OpcUAServer.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Services.TraceController.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Services.DataLogger.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Hardware.Nim.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libcppformat.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libpthread.so
libHostidClient.so: /home/ubuntu/plc/epc/epc1522/EPC1522/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Io.ProfinetStack.so
libHostidClient.so: CMakeFiles/HostidClient.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Linking CXX shared library libHostidClient.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/HostidClient.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/HostidClient.dir/build: libHostidClient.so

.PHONY : CMakeFiles/HostidClient.dir/build

CMakeFiles/HostidClient.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/HostidClient.dir/cmake_clean.cmake
.PHONY : CMakeFiles/HostidClient.dir/clean

CMakeFiles/HostidClient.dir/depend:
	cd /home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ubuntu/plc/epc/epc1522/work/HostidClient /home/ubuntu/plc/epc/epc1522/work/HostidClient /home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release /home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release /home/ubuntu/plc/epc/epc1522/work/HostidClient/intermediate/cmake/EPC1522,23.0.6.54/Release/CMakeFiles/HostidClient.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/HostidClient.dir/depend
