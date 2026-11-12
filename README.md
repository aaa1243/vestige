# Forensic Scanner

A read-only screenshare scanner for Minecraft, written in C++. One exe on Windows, one binary on macOS and Linux. It looks at the running game and at what the system recorded since boot, then sorts everything into three groups like the big SS tools do:

| Group | What it means |
|---|---|
| **Detection** | Strong sign of a cheat or of evidence being destroyed |
| **Warning** | A lead. Needs a human to look at it |
| **Integrity** | Background info and proof that a check actually ran |

Every finding also gets a tag: **In game** (inside the running game right now), **Boot** (happened since the last boot) or **Out of instance** (older, or outside the game).

It never writes to the PC except for its own report, never touches accounts or tokens, and never injects into anything. Findings are leads. Confirm by hand before any ban.

## Download

Latest Windows exe (always the newest release):

    https://github.com/aaa1243/forensic-scanner/releases/latest/download/ForensicScanner.exe

Windows will show a SmartScreen warning because the exe is not signed. Click "More info" then "Run anyway".

## How to use it

**Windows:** have the player open the game they were playing on, then double click `ForensicScanner.exe` and accept the admin prompt. The report is printed in the window and saved to `C:\SSTools\ForensicScanner\report.html` and `report.json`.

**macOS / Linux:** build it (below), then

    sudo ./build/ForensicScanner --out ./report

Options:

    --out DIR      folder for report.html and report.json
    --sigs FILE    extra signatures (see signatures.example.txt)
    --only a,b     run only these checks
    --skip a,b     skip these checks
    --deep         slower, wider scans (whole game memory, whole USN journal, more folders)
    --list         list the checks for this system
    --no-pause     don't wait for Enter at the end (Windows)

If a check ever crashes on a weird system, the scanner prints which one and you can rerun with `--skip thatcheck`.

## What it checks on Windows

### Was the game injected into? (In game)

These look inside the running `javaw.exe`.

| Check | What it finds |
|---|---|
| `game_launch` | `-javaagent`, `-agentpath`, `-Xbootclasspath` on the launch command, Java option variables inside the game, who launched it |
| `game_agents` | A Java agent attached **after** launch (Java's instrument library loaded with no agent flag), a Java debugger, a native debugger |
| `game_modules` | Manually mapped DLLs (a program image sitting in private memory), modules hidden from the module list, known cheat DLLs, loaded DLLs whose file was deleted, unsigned DLLs from Downloads/Desktop/Temp |
| `game_threads` | Threads that start in memory with no file behind them, threads that start at `LoadLibrary` (the classic injection step), the Java "Attach Listener" thread |
| `game_hooks` | Render, input, network and loader functions (OpenGL swap buffers, GetAsyncKeyState, recv/send, LdrLoadDll and more) whose first bytes no longer match the DLL on disk and jump somewhere else |
| `game_unloaded` | DLLs that were loaded into the game and unloaded again. Windows keeps this list per process, so an inject, use, eject cheat still shows up |
| `game_handles` | Other programs that hold the game open with write or thread-create rights right now |
| `game_strings` | Known cheat class paths in the game's memory |
| `game_load_times` | The time every DLL was loaded. Anything unsigned that showed up minutes after the game started stands out |
| `screen_windows` | Streamproof windows (hidden from capture) and click-through overlays on top of the game |

### Was it injected earlier this session? (Boot)

Injection that already finished, or a game that was restarted, leaves no trace in memory. These checks use things that survive.

| Check | What it finds |
|---|---|
| `game_logs` | "A Java agent has been loaded dynamically" in the game log (Java 21+), cheat class names in stack traces, cheat files listed in Java crash logs (`hs_err_pid`) |
| `injection_history` | Game crashes where the crashing module is not Java, Windows or the GPU driver. Windows crash reports for Java, which list every module that was loaded. Code Integrity events for Java. Sysmon remote-thread events if Sysmon is installed |
| `file_dialogs` | DLLs picked in a file window this boot (injector GUIs make you pick the DLL) |
| `prefetch` | What ran, and the DLLs and jars the game opened at startup from user folders |
| `load_hijacks` | Things that inject at every launch: IFEO debugger or verifier DLL on javaw, AppInit_DLLs, AppCertDlls, custom shims, `JAVA_TOOL_OPTIONS` saved for every Java program |
| `defender` | Defender flagging a HackTool or injector, protection switched off, exclusions added |

### What ran and what was cleaned up

| Check | What it finds |
|---|---|
| `running_processes` | Known cheats and clickers running now |
| `bam` | Programs each user ran, tagged since boot or before, and ran-then-deleted programs |
| `bam_deleted` | BAM entries that were deleted, recovered from free space in the SYSTEM hive file |
| `pca` | Program Compatibility Assistant launch records (Windows 11 22H2+) |
| `service_memory` | Program names and paths held in DPS and PcaSvc memory since boot, including files that are gone now |
| `dns_cache` | Cheat sites looked up since boot |
| `usn_journal` | Journal deleted or recreated this boot, deleted prefetch files, cheat files created/renamed/deleted, exe/dll/jar renamed to another extension, mod jars deleted, programs deleted from user folders |
| `file_signatures` | Known cheat files in user folders by name, SHA-256 and content |
| `browser_history` | Cheat sites in browser history (only matches are shown) |

### Is the evidence intact? (Integrity)

| Check | What it finds |
|---|---|
| `integrity_boot` | Boot time, a restart right before the SS, explorer restarted mid-game, test signing, driver enforcement off, HVCI, Secure Boot |
| `integrity_services` | SysMain, DPS, PcaSvc, EventLog, Dnscache, BAM and others stopped, disabled or restarted after boot |
| `integrity_logs` | Security or other logs cleared (1102, 104), USN journal deleted (3079), clock changed by more than 5 minutes, recording services disabled this boot |
| `integrity_tamper` | MiniNt key, DisallowRun lists, Task Manager / regedit / cmd disabled, hosts file changed, Recycle Bin emptied |
| `drivers` | Known abusable drivers loaded, unsigned drivers, drivers registered from user folders |
| `autoruns`, `scheduled_tasks` | Run keys, Startup folder, WMI consumers, tasks that run hidden scripts |
| `hardware` | DMA cards (Xilinx IDs), kmbox / fuser style names, Arduino-type boards |

## macOS and Linux

Smaller set, same idea: agent flags on the game command, `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` / Java option injection, libraries loaded from temp or user folders or deleted after loading, fileless libraries in memory (Linux), a tracer attached (Linux), SIP and Gatekeeper state (macOS), download quarantine records (macOS), shell history, launch agents / cron / autostart, game logs, file signatures and browser history.

## Build it yourself

You need CMake and a C++17 compiler.

    cmake -S . -B build
    cmake --build build

Windows exe from Linux or macOS (this is how the release exe is built):

    cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-cross.cmake
    cmake --build build

On Windows itself, MinGW works with `-G "MinGW Makefiles"`. Visual Studio should work too but is not tested.

## Signatures

The built-in list in `src/sigs_default.cpp` is a small starter list, not a real database. Add your server's own list with `--sigs file.txt`. The format is in `signatures.example.txt`. Short names only match whole words so "vape" does not match "evaporate".

## What it does not do

Being honest about the limits matters more than a long feature list.

- It does not catch cheats that leave nothing behind. A closed-source ghost client that hooks through the JVM (JNI function table, JVMTI) without loading a DLL and without an agent can pass every memory check here.
- IAT hooks and JNI hooks are not checked, only inline hooks on a fixed list of functions.
- No image recognition. It cannot look at an overlay and tell you it is a cheat menu. It tells you an overlay or a capture-hidden window exists and who owns it.
- Injection that happened before the game was restarted is only visible through logs, crash reports, prefetch and the journal. If none of those recorded it, it is gone.
- DMA cards with spoofed IDs look like a network card and are not caught.
- No alt or account checks, and it never reads launcher accounts, tokens or Discord.
- Name-based matches can be coincidence. Unsigned-DLL warnings skip files whose path looks like a normal game library (lwjgl, jna and so on), so a cheat named like one of those gets a lower rating there. The memory checks do not use names.

## Testing

- `tests/linux_selftest.sh` fakes a cheated Java process on Linux and checks the scanner catches it.
- `tests/fakegame.cpp` is built as `javaw.exe` for the Windows test. It creates injection artifacts inside its own process only (an image in private memory, a thread that starts there, a cheat-named DLL loaded and one unloaded) so the in-game checks have something to find. It does nothing to any other program.
- CI builds all three systems and runs the tests on each.

## License

MIT
