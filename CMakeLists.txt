cmake_minimum_required(VERSION 3.15)
project(ForensicScanner CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(SRC
  src/main.cpp src/core.cpp src/util.cpp src/report.cpp src/sigs_default.cpp
  src/common_checks.cpp)

if(WIN32)
  file(GLOB WIN_SRC CONFIGURE_DEPENDS src/windows/*.cpp)
  list(APPEND SRC ${WIN_SRC})
elseif(APPLE)
  list(APPEND SRC src/macos/macos_checks.cpp)
else()
  list(APPEND SRC src/linux/linux_checks.cpp)
endif()

# One executable, no static library, so the self-registering checks are
# never dropped by the linker.
add_executable(ForensicScanner ${SRC})

if(WIN32)
  target_compile_definitions(ForensicScanner PRIVATE UNICODE _UNICODE NOMINMAX
    _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(ForensicScanner PRIVATE
    psapi wintrust crypt32 advapi32 setupapi wevtapi ole32 oleaut32 wbemuuid
    shell32 user32 version dnsapi)
  if(MSVC)
    target_compile_options(ForensicScanner PRIVATE /W3 /EHsc /utf-8)
    set_property(TARGET ForensicScanner PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_options(ForensicScanner PRIVATE "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
  else()
    # MinGW: the manifest goes in through a resource file.
    enable_language(RC)
    target_sources(ForensicScanner PRIVATE res/app.rc)
    target_compile_options(ForensicScanner PRIVATE -Wall -Wextra)
    target_link_options(ForensicScanner PRIVATE -static)
  endif()
else()
  target_compile_options(ForensicScanner PRIVATE -Wall -Wextra)
endif()

# Test fixture for the Windows in-game checks (see tests/fakegame.cpp).
if(WIN32)
  add_executable(fakegame tests/fakegame.cpp)
  set_target_properties(fakegame PROPERTIES OUTPUT_NAME javaw)
  if(NOT MSVC)
    target_link_options(fakegame PRIVATE -static)
  endif()
endif()
