// Hardware: devices used for DMA cheats and input boxes.
#ifdef _WIN32
#include "win_util.hpp"

#include <setupapi.h>

#include <set>

#include "../util.hpp"

namespace scan {
using namespace win;

namespace {

std::string dev_prop(HDEVINFO set, SP_DEVINFO_DATA& dev, DWORD prop) {
    std::vector<wchar_t> buf(2048);
    DWORD type = 0, need = 0;
    if (!SetupDiGetDeviceRegistryPropertyW(set, &dev, prop, &type, reinterpret_cast<PBYTE>(buf.data()),
                                           static_cast<DWORD>(buf.size() * sizeof(wchar_t)), &need))
        return std::string();
    if (type == REG_MULTI_SZ) {
        std::string out;
        for (const wchar_t* p = buf.data(); *p; p += wcslen(p) + 1) {
            if (!out.empty()) out += "; ";
            out += narrow(p, wcslen(p));
        }
        return out;
    }
    return narrow(buf.data(), wcsnlen(buf.data(), buf.size()));
}

}  // namespace

SCAN_CHECK(700, hardware, Scope::Boot, "DMA cards and input boxes plugged in") {
    HDEVINFO set = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) {
        ctx.note("could not list hardware devices");
        return;
    }
    SP_DEVINFO_DATA dev{};
    dev.cbSize = sizeof(dev);
    size_t count = 0;
    std::set<std::string> seen;
    for (DWORD i = 0; SetupDiEnumDeviceInfo(set, i, &dev); ++i) {
        ++count;
        std::string hw = dev_prop(set, dev, SPDRP_HARDWAREID);
        std::string desc = dev_prop(set, dev, SPDRP_DEVICEDESC);
        std::string friendly = dev_prop(set, dev, SPDRP_FRIENDLYNAME);
        std::string mfg = dev_prop(set, dev, SPDRP_MFG);
        std::string l = lower(hw + " " + desc + " " + friendly + " " + mfg);
        std::string ev = (friendly.empty() ? desc : friendly) + " | " + cut(hw, 160);
        if (!seen.insert(ev).second) continue;
        bool pci = starts_with(lower(hw), "pci\\");
        if (pci && contains(l, "ven_10ee")) {
            bool classic = contains(l, "dev_0666") || contains(l, "dev_7011") || contains(l, "dev_7021") || contains(l, "dev_7024");
            ctx.add(classic ? Severity::Detection : Severity::Warning,
                    classic ? "DMA card found (Xilinx FPGA with a known DMA device ID)" : "Xilinx FPGA card on PCI",
                    "DMA cheats use an FPGA card to read the game's memory from a second PC. Unchanged cards "
                    "show up as Xilinx (vendor 10EE). Real uses exist (capture or lab hardware) but are rare on a "
                    "gaming PC. Cards with spoofed IDs look like a network or sound card and are not caught here.", ev);
        } else if (pci && (contains(l, "ven_ffff") || contains(l, "ven_0000"))) {
            ctx.add(Severity::Warning, "PCI device with an invalid vendor ID",
                    "A vendor ID of FFFF or 0000 is not a real manufacturer. It can be a broken device or badly spoofed hardware.", ev);
        }
        for (const char* k : {"kmbox", "screamer", "pcileech", "squirrel dma", "captain dma", "lambdaconcept", "fuser",
                              "cronus", "xim apex", "xim matrix", "titan two", "strike pack", "reasnow"})
            if (contains(l, k))
                ctx.add(Severity::Detection, std::string("Cheat hardware by name: ") + k,
                        "The device reports a name used by DMA cards, input boxes or controller adapters.", ev);
        // Arduino style boards are used as hardware mouse movers
        if (contains(l, "vid_2341") || contains(l, "vid_1b4f") || contains(l, "arduino") || contains(l, "vid_16c0&pid_04") ||
            contains(l, "raspberry pi pico") || contains(l, "vid_2e8a"))
            ctx.add(Severity::Warning, "Programmable USB board plugged in",
                    "Arduino, Teensy and Pico boards can act as a mouse or keyboard and are used for "
                    "hardware aim assist and autoclicking. They are also normal hobby hardware.", ev);
    }
    SetupDiDestroyDeviceInfoList(set);

    // More than one mouse is normal on laptops; just report the count for the SSer.
    UINT n = 0;
    GetRawInputDeviceList(nullptr, &n, sizeof(RAWINPUTDEVICELIST));
    std::vector<RAWINPUTDEVICELIST> list(n);
    UINT got = n ? GetRawInputDeviceList(list.data(), &n, sizeof(RAWINPUTDEVICELIST)) : 0;
    size_t mice = 0, keyboards = 0;
    if (got != static_cast<UINT>(-1))
        for (UINT i = 0; i < got; ++i) {
            if (list[i].dwType == RIM_TYPEMOUSE) ++mice;
            if (list[i].dwType == RIM_TYPEKEYBOARD) ++keyboards;
        }
    ctx.add(Severity::Integrity, "Hardware checked",
            strf("%zu devices present, %zu mouse and %zu keyboard input devices (one physical device often "
                 "shows as several).", count, mice, keyboards), "", Scope::None);
}

}  // namespace scan
#endif
