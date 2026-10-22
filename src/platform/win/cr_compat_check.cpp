// cr_compat_check.exe -- offline compatibility report for steamclient64.dll.
//
// Usage:
//   cr_compat_check --dll <path> [--out <json>] [--channel stable|beta]
//                   [--version <steam manifest version>]
//
// Exit codes: 0 = full, 2 = audit/unverified/blocked, 3 = tool error.

#include "compat.h"
#include "sc_resolver.h"
#include "sha256_hmac.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// sc_resolver.cpp logs through this stub; the standalone tool has no log file.
namespace Log {
void Write(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    std::vfprintf(stderr, fmt, args);
    std::fputc('\n', stderr);
    va_end(args);
}
} // namespace Log

namespace {

std::string WideToUtf8(const wchar_t* text) {
    if (!text || !*text) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return {};
    std::string out(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), len, nullptr, nullptr);
    return out;
}

std::string Sha256File(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    std::vector<char> bytes((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
    if (bytes.empty()) return {};
    const auto digest = crypto::Sha256(
        reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    return crypto::ToHex(digest.data(), digest.size());
}

size_t ImageSize(uintptr_t base) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

void PrintUsage() {
    std::fprintf(stderr,
        "usage: cr_compat_check --dll <steamclient64.dll> [--out <json>]\n"
        "                       [--channel stable|beta] [--version <n>]\n");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    std::filesystem::path dllPath;
    std::filesystem::path outPath;
    std::string channel = "stable";
    uint64_t steamVersion = 0;

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        auto next = [&](std::filesystem::path& target) -> bool {
            if (i + 1 >= argc) return false;
            target = argv[++i];
            return true;
        };
        if (arg == L"--dll") {
            if (!next(dllPath)) { PrintUsage(); return 3; }
        } else if (arg == L"--out") {
            if (!next(outPath)) { PrintUsage(); return 3; }
        } else if (arg == L"--channel") {
            std::filesystem::path value;
            if (!next(value)) { PrintUsage(); return 3; }
            channel = WideToUtf8(value.c_str());
            if (channel != "stable" && channel != "beta") {
                std::fprintf(stderr, "cr_compat_check: invalid channel\n");
                return 3;
            }
        } else if (arg == L"--version") {
            std::filesystem::path value;
            if (!next(value)) { PrintUsage(); return 3; }
            steamVersion = _wcstoui64(value.c_str(), nullptr, 10);
        } else if (arg == L"--help" || arg == L"-h") {
            PrintUsage();
            return 0;
        } else {
            PrintUsage();
            return 3;
        }
    }

    if (dllPath.empty()) {
        PrintUsage();
        return 3;
    }

    const std::string sha256 = Sha256File(dllPath);
    if (sha256.empty()) {
        std::fprintf(stderr, "cr_compat_check: cannot hash %ls\n", dllPath.c_str());
        return 3;
    }

    HMODULE module = LoadLibraryExW(dllPath.c_str(), nullptr,
                                    DONT_RESOLVE_DLL_REFERENCES);
    if (!module) {
        std::fprintf(stderr, "cr_compat_check: LoadLibraryExW failed (%lu)\n",
                     GetLastError());
        return 3;
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(module);
    const size_t imageSize = ImageSize(base);
    if (!imageSize) {
        std::fprintf(stderr, "cr_compat_check: invalid PE image\n");
        FreeLibrary(module);
        return 3;
    }

    const ScResolver::ResolvedAddrs resolved = ScResolver::Resolve(base);
    SteamMessageLayout::Layout layout;
    const bool layoutOk = Compat::ProbeMessageLayout(resolved, layout);
    const uint32_t accountId = Compat::ScanAccountIdOffset(base, imageSize);

    Compat::Report report = Compat::BuildStatic(
        base, imageSize, resolved, accountId, accountId != 0, layout);
    report.channel = channel;
    report.steamVersion = steamVersion;
    report.sha256 = sha256;
    report.allowlisted = Compat::IsAllowlisted(sha256);

    const std::string json = Compat::ToJson(report);
    std::printf("%s\n", json.c_str());
    if (!outPath.empty()) {
        std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::fprintf(stderr, "cr_compat_check: cannot write %ls\n",
                         outPath.c_str());
            FreeLibrary(module);
            return 3;
        }
        out.write(json.data(), static_cast<std::streamsize>(json.size()));
        if (!out.good()) {
            std::fprintf(stderr, "cr_compat_check: write failed\n");
            FreeLibrary(module);
            return 3;
        }
    }

    FreeLibrary(module);
    if (!layoutOk) {
        std::fprintf(stderr, "cr_compat_check: message layout unresolved\n");
    }
    return report.status == Compat::Status::Full ? 0 : 2;
}
