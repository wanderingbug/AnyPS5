#include <cstdio>
#include <cstdlib>

#ifdef __APPLE__
namespace {
struct MacosTestSkip {
    MacosTestSkip() {
        const char* reason = std::getenv("APS5_MACOS_SKIP");
        if (reason == nullptr || reason[0] == '\0') return;
        std::puts(reason);
        std::fflush(stdout);
        std::_Exit(77);
    }
};
MacosTestSkip macosTestSkip;
}
#endif
