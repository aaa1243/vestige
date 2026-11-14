#include "core.hpp"

// Built-in starter signatures. This is a small list, not a real database.
// Add your own with --sigs FILE (same format). Types:
//   name     file or process name of a known cheat or cheat tool
//   weak     generic word, only ever a lead
//   content  text found inside a file (class paths inside jars work well,
//            because zip stores file names uncompressed)
//   memory   text searched for in the running game's memory
//   domain   cheat website, matched in browser history and the DNS cache
//   driver   driver file name used to load kernel cheats
//   hash     SHA-256 of a known cheat file
namespace scan {
const char* const kDefaultSignatures = R"SIG(
# ---- known cheat and tool names ----
name|slinky|Slinky
name|vape|Vape
name|vapev4|Vape V4
name|vapelite|Vape Lite
name|vape_lite|Vape Lite
name|dopium|Dopium
name|doomsday|Doomsday
name|whiteout|Whiteout
name|liquidbounce|LiquidBounce
name|wurst-client|Wurst
name|wurstclient|Wurst
name|meteor-client|Meteor Client
name|meteorclient|Meteor Client
name|novoline|Novoline
name|aristois|Aristois
name|impact-client|Impact
name|sigmaclient|Sigma
name|itami|Itami
name|entropy|Entropy
name|kdmapper|kdmapper (driver mapper)
name|extreme injector|Extreme Injector
name|extremeinjector|Extreme Injector
name|xenos64|Xenos injector
name|xenos|Xenos injector
name|cheatengine|Cheat Engine
name|cheat engine|Cheat Engine
name|processhacker-inject|Injector
name|opautoclicker|OP Auto Clicker
name|op auto clicker|OP Auto Clicker
name|gs auto clicker|GS Auto Clicker
name|gsautoclicker|GS Auto Clicker

# ---- generic words (leads only) ----
weak|autoclick|
weak|psexec|
weak|pssuspend|
weak|auto-click|
weak|clicker|
weak|aimbot|
weak|triggerbot|
weak|killaura|
weak|injector|
weak|ghostclient|
weak|streamproof|
weak|spoofer|
weak|cheat|

# ---- text inside files (jar class paths) ----
content|net/ccbluex/liquidbounce|LiquidBounce
content|net/wurstclient|Wurst
content|meteordevelopment/meteorclient|Meteor Client
content|me/zeroeightsix/kami|KAMI
content|com/lambda/client|Lambda
content|me/earth/earthhack|3arthh4ck
content|me/deftware|Aristois (Deftware)

# ---- text in game memory ----
memory|net/ccbluex/liquidbounce|LiquidBounce
memory|net.ccbluex.liquidbounce|LiquidBounce
memory|net/wurstclient|Wurst
memory|net.wurstclient|Wurst
memory|meteordevelopment/meteorclient|Meteor Client
memory|meteordevelopment.meteorclient|Meteor Client
memory|me/zeroeightsix/kami|KAMI
memory|me/earth/earthhack|3arthh4ck
memory|me/deftware|Aristois (Deftware)

# ---- cheat sites (starter list, check these before relying on them) ----
domain|vape.gg|Vape
domain|intent.store|Intent Store
domain|liquidbounce.net|LiquidBounce
domain|wurstclient.net|Wurst
domain|meteorclient.com|Meteor Client
domain|slinky.gg|Slinky
domain|doomsdayclient.com|Doomsday
domain|riseclient.com|Rise
domain|novoline.wtf|Novoline
domain|impactclient.net|Impact
domain|aristois.net|Aristois
domain|sigmaclient.info|Sigma
domain|unknowncheats.me|UnknownCheats forum

# ---- drivers used to load kernel cheats ----
driver|iqvw64e.sys|Intel driver abused by kdmapper
driver|capcom.sys|Capcom driver (known vulnerable)
driver|gdrv.sys|Gigabyte driver (known vulnerable)
driver|dbutil_2_3.sys|Dell driver (known vulnerable)
)SIG";
}  // namespace scan
