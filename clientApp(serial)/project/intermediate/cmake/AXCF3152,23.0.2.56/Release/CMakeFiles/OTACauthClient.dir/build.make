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
CMAKE_SOURCE_DIR = /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release

# Include any dependencies generated for this target.
include CMakeFiles/OTACauthClient.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/OTACauthClient.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/OTACauthClient.dir/flags.make

CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.o: CMakeFiles/OTACauthClient.dir/flags.make
CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.o: ../../../../src/ExampleAuthenticationProvider.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.o"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.o -c /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/ExampleAuthenticationProvider.cpp

CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.i"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/ExampleAuthenticationProvider.cpp > CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.i

CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.s"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/ExampleAuthenticationProvider.cpp -o CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.s

CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.o: CMakeFiles/OTACauthClient.dir/flags.make
CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.o: ../../../../src/ExampleAuthorizationProvider.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.o"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.o -c /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/ExampleAuthorizationProvider.cpp

CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.i"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/ExampleAuthorizationProvider.cpp > CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.i

CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.s"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/ExampleAuthorizationProvider.cpp -o CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.s

CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.o: CMakeFiles/OTACauthClient.dir/flags.make
CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.o: ../../../../src/UmModuleEx.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.o"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.o -c /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/UmModuleEx.cpp

CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.i"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/UmModuleEx.cpp > CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.i

CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.s"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/UmModuleEx.cpp -o CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.s

CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.o: CMakeFiles/OTACauthClient.dir/flags.make
CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.o: ../../../../src/UmModuleExConfig.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.o"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.o -c /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/UmModuleExConfig.cpp

CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.i"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/UmModuleExConfig.cpp > CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.i

CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.s"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/UmModuleExConfig.cpp -o CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.s

CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.o: CMakeFiles/OTACauthClient.dir/flags.make
CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.o: ../../../../src/UmModuleExLibrary.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.o"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.o -c /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/UmModuleExLibrary.cpp

CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.i"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/UmModuleExLibrary.cpp > CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.i

CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.s"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/UmModuleExLibrary.cpp -o CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.s

CMakeFiles/OTACauthClient.dir/src/curl.cpp.o: CMakeFiles/OTACauthClient.dir/flags.make
CMakeFiles/OTACauthClient.dir/src/curl.cpp.o: ../../../../src/curl.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/OTACauthClient.dir/src/curl.cpp.o"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/OTACauthClient.dir/src/curl.cpp.o -c /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/curl.cpp

CMakeFiles/OTACauthClient.dir/src/curl.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/OTACauthClient.dir/src/curl.cpp.i"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/curl.cpp > CMakeFiles/OTACauthClient.dir/src/curl.cpp.i

CMakeFiles/OTACauthClient.dir/src/curl.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/OTACauthClient.dir/src/curl.cpp.s"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/curl.cpp -o CMakeFiles/OTACauthClient.dir/src/curl.cpp.s

CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.o: CMakeFiles/OTACauthClient.dir/flags.make
CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.o: ../../../../src/jsoncpp.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.o"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.o -c /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/jsoncpp.cpp

CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.i"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/jsoncpp.cpp > CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.i

CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.s"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/jsoncpp.cpp -o CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.s

CMakeFiles/OTACauthClient.dir/src/verify.cpp.o: CMakeFiles/OTACauthClient.dir/flags.make
CMakeFiles/OTACauthClient.dir/src/verify.cpp.o: ../../../../src/verify.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object CMakeFiles/OTACauthClient.dir/src/verify.cpp.o"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/OTACauthClient.dir/src/verify.cpp.o -c /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/verify.cpp

CMakeFiles/OTACauthClient.dir/src/verify.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/OTACauthClient.dir/src/verify.cpp.i"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/verify.cpp > CMakeFiles/OTACauthClient.dir/src/verify.cpp.i

CMakeFiles/OTACauthClient.dir/src/verify.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/OTACauthClient.dir/src/verify.cpp.s"
	/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/x86_64-pokysdk-linux/usr/bin/x86_64-pxc-linux/x86_64-pxc-linux-g++ --sysroot=/home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/src/verify.cpp -o CMakeFiles/OTACauthClient.dir/src/verify.cpp.s

# Object files for target OTACauthClient
OTACauthClient_OBJECTS = \
"CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.o" \
"CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.o" \
"CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.o" \
"CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.o" \
"CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.o" \
"CMakeFiles/OTACauthClient.dir/src/curl.cpp.o" \
"CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.o" \
"CMakeFiles/OTACauthClient.dir/src/verify.cpp.o"

# External object files for target OTACauthClient
OTACauthClient_EXTERNAL_OBJECTS =

libOTACauthClient.so: CMakeFiles/OTACauthClient.dir/src/ExampleAuthenticationProvider.cpp.o
libOTACauthClient.so: CMakeFiles/OTACauthClient.dir/src/ExampleAuthorizationProvider.cpp.o
libOTACauthClient.so: CMakeFiles/OTACauthClient.dir/src/UmModuleEx.cpp.o
libOTACauthClient.so: CMakeFiles/OTACauthClient.dir/src/UmModuleExConfig.cpp.o
libOTACauthClient.so: CMakeFiles/OTACauthClient.dir/src/UmModuleExLibrary.cpp.o
libOTACauthClient.so: CMakeFiles/OTACauthClient.dir/src/curl.cpp.o
libOTACauthClient.so: CMakeFiles/OTACauthClient.dir/src/jsoncpp.cpp.o
libOTACauthClient.so: CMakeFiles/OTACauthClient.dir/src/verify.cpp.o
libOTACauthClient.so: CMakeFiles/OTACauthClient.dir/build.make
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libcurl.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libcrypto.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Acf.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Commons.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Core.a
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Plc.Commons.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Rsc.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Commons.Services.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Lm.Services.a
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Nm.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.NmPayload.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Security.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Security.Services.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Um.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.System.Ve.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Plc.Domain.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Plc.Gds.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Plc.Meta.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Plc.Retain.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Device.Interface.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Services.NotificationLogger.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Services.OpcUAServer.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Services.TraceController.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Services.DataLogger.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Hardware.Nim.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libcppformat.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libpthread.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Io.Axioline.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Io.Interbus.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Io.Profibus.so
libOTACauthClient.so: /home/ubuntu/plc/axcf/axcf3152/AXCF3152/sysroots/corei7-64-pxc-linux/usr/lib/libArp.Io.ProfinetStack.so
libOTACauthClient.so: CMakeFiles/OTACauthClient.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Linking CXX shared library libOTACauthClient.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/OTACauthClient.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/OTACauthClient.dir/build: libOTACauthClient.so

.PHONY : CMakeFiles/OTACauthClient.dir/build

CMakeFiles/OTACauthClient.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/OTACauthClient.dir/cmake_clean.cmake
.PHONY : CMakeFiles/OTACauthClient.dir/clean

CMakeFiles/OTACauthClient.dir/depend:
	cd /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release /home/ubuntu/plc/axcf/axcf3152/work/OTACauthClient/intermediate/cmake/AXCF3152,23.0.2.56/Release/CMakeFiles/OTACauthClient.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/OTACauthClient.dir/depend

