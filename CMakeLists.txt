cmake_minimum_required(VERSION 3.15)
project(Vestige CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(SRC
  src/main.cpp src/core.cpp src/util.cpp src/report.cpp src/sigs_default.cpp
  src/scan_run.cpp src/common_checks.cpp)

if(WIN32)
  file(GLOB WIN_SRC CONFIGURE_DEPENDS src/windows/*.cpp)
  # The GUI is Windows only. macOS and Linux stay command line.
  list(APPEND SRC ${WIN_SRC} src/gui/gui_win.cpp src/gui/gui_ui.cpp)
elseif(APPLE)
  list(APPEND SRC src/macos/macos_checks.cpp)
else()
  list(APPEND SRC src/linux/linux_checks.cpp)
endif()

# One executable, no static library, so the self-registering checks are
# never dropped by the linker.
add_executable(Vestige ${SRC})

if(WIN32)
  # Dear ImGui (vendored in third_party/imgui) with the Win32 + DirectX 11
  # backends. Built without the project's warning flags: it is not our code.
  set(IMGUI_DIR third_party/imgui)
  add_library(imgui STATIC
    ${IMGUI_DIR}/imgui.cpp ${IMGUI_DIR}/imgui_draw.cpp ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp)
  target_include_directories(imgui SYSTEM PUBLIC ${IMGUI_DIR} ${IMGUI_DIR}/backends)
  target_compile_definitions(imgui PUBLIC IMGUI_DISABLE_DEMO_WINDOWS IMGUI_DISABLE_DEBUG_TOOLS
    IMGUI_DISABLE_OBSOLETE_FUNCTIONS IMGUI_IMPL_WIN32_DISABLE_GAMEPAD)
  target_compile_definitions(imgui PRIVATE UNICODE _UNICODE NOMINMAX _WIN32_WINNT=0x0A00)
  target_link_libraries(imgui PUBLIC d3d11 dxgi d3dcompiler dwmapi imm32 gdi32)
  if(MSVC)
    set_property(TARGET imgui PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
  endif()
  target_link_libraries(Vestige PRIVATE imgui comdlg32)

  target_compile_definitions(Vestige PRIVATE UNICODE _UNICODE NOMINMAX
    _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(Vestige PRIVATE
    psapi wintrust crypt32 advapi32 setupapi wevtapi ole32 oleaut32 wbemuuid
    shell32 user32 version dnsapi iphlpapi ws2_32)
  if(MSVC)
    target_compile_options(Vestige PRIVATE /W3 /EHsc /utf-8)
    set_property(TARGET Vestige PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    target_link_options(Vestige PRIVATE "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
  else()
    # MinGW: the manifest goes in through a resource file.
    enable_language(RC)
    target_sources(Vestige PRIVATE res/app.rc)
    target_compile_options(Vestige PRIVATE -Wall -Wextra)
    target_link_options(Vestige PRIVATE -static)
  endif()
else()
  target_compile_options(Vestige PRIVATE -Wall -Wextra)
endif()

# Test fixture for the Windows in-game checks (see tests/fakegame.cpp).
if(WIN32)
  add_executable(fakegame tests/fakegame.cpp)
  set_target_properties(fakegame PROPERTIES OUTPUT_NAME javaw)
  if(NOT MSVC)
    target_link_options(fakegame PRIVATE -static)
  endif()
endif()
