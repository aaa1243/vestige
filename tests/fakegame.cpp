// Test fixture for the Windows in-game checks. Built as javaw.exe by CI.
// It makes the artifacts an injected cheat would leave, but only inside its
// own process: nothing here touches another program. Then it waits so the
// scanner can look at it.
//
//   javaw.exe net.minecraft.client.main.Main [seconds]
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <string>

static DWORD WINAPI idle_thread(LPVOID) {
    Sleep(INFINITE);
    return 0;
}

static std::wstring temp_copy(const wchar_t* system_dll, const wchar_t* new_name) {
    wchar_t sys[MAX_PATH], tmp[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    GetTempPathW(MAX_PATH, tmp);
    std::wstring src = std::wstring(sys) + L"\\" + system_dll, dst = std::wstring(tmp) + new_name;
    CopyFileW(src.c_str(), dst.c_str(), FALSE);
    return dst;
}

int main(int argc, char** argv) {
    int seconds = argc > 2 ? atoi(argv[2]) : 120;

    // 1. A program image in private executable memory (what manual mapping leaves).
    HMODULE self = GetModuleHandleW(nullptr);
    void* mem = VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem) memcpy(mem, self, 0x1000);

    // 2. A thread whose start address is in that private memory. It is created
    //    suspended and never resumed, so the copied bytes are never run.
    if (mem) CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<char*>(mem) + 0x2000),
                          nullptr, CREATE_SUSPENDED, nullptr);
    CreateThread(nullptr, 0, idle_thread, nullptr, 0, nullptr);

    // 3. A DLL with a cheat-like name that stays loaded, and one that is
    //    loaded and unloaded again. Both are plain copies of a Windows DLL.
    std::wstring kept = temp_copy(L"version.dll", L"slinky_test.dll");
    std::wstring gone = temp_copy(L"winmm.dll", L"vape_test.dll");
    HMODULE a = LoadLibraryW(kept.c_str());
    HMODULE b = LoadLibraryW(gone.c_str());
    if (b) FreeLibrary(b);

    printf("fake game ready: pid=%lu private=%p kept=%p unloaded=%s\n", GetCurrentProcessId(), mem,
           static_cast<void*>(a), b ? "yes" : "no");
    fflush(stdout);
    Sleep(static_cast<DWORD>(seconds) * 1000);
    return 0;
}
