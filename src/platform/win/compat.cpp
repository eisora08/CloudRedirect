#include "compat.h"
#include "sig_scanner.h"
#include "json.h"
#include "log.h"
#include "file_util.h"
#include "http_util.h"
#include "cloud_provider_base.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <sstream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

namespace Compat {

namespace {

// Simple WinHTTP GET, returns empty string on failure.
static std::string HttpGet(const std::string& url) {
    // Parse URL: https://host/path
    if (url.rfind("https://", 0) != 0) return {};
    std::string rest = url.substr(8);
    size_t slash = rest.find('/');
    std::string host = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    std::string path = (slash == std::string::npos) ? "/" : rest.substr(slash);

    // Convert to wide
    auto toWide = [](const std::string& s) {
        int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        std::wstring w(len, 0);
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], len);
        return w;
    };
    std::wstring wHost = toWide(host);
    std::wstring wPath = toWide(path);

    HINTERNET hSession = WinHttpOpen(L"CloudRedirect/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return {};

    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(),
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return {};
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return {};
    }

    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        nullptr, 0, 0, 0);
    if (!ok || !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return {};
    }

    std::string body;
    const size_t bufSize = 8192;
    std::vector<char> buf(bufSize);
    DWORD read = 0;
    while (WinHttpReadData(hRequest, buf.data(), static_cast<DWORD>(bufSize), &read) && read > 0) {
        body.append(buf.data(), read);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return body;
}

bool InRange(uintptr_t p, size_t width, uintptr_t base, size_t size) {
    if (!p || !base || !size || width > size) return false;
    if (p < base) return false;
    const uintptr_t off = p - base;
    return off <= size - width;
}

bool InText(uintptr_t p) {
    return InRange(p, 1, SigScanner::GetTextBase(), SigScanner::GetTextSize());
}

bool InData(uintptr_t p, size_t width = sizeof(void*)) {
    return InRange(p, width, SigScanner::GetDataBase(), SigScanner::GetDataSize());
}

bool InRdata(uintptr_t p, size_t width = sizeof(void*)) {
    return InRange(p, width, SigScanner::GetRdataBase(), SigScanner::GetRdataSize());
}

bool InImage(uintptr_t p, size_t width = sizeof(void*)) {
    return InRange(p, width, SigScanner::GetImageBase(), SigScanner::GetImageSize());
}

std::string NowIso() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_s(&tm, &t);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

Json::Value BoolValue(bool value) {
    Json::Value v;
    v.type = Json::Type::Bool;
    v.boolVal = value;
    return v;
}

void AddField(Report& r, const char* name, bool ok, uint32_t subsystems,
              const char* kind, const std::string& detail = {}) {
    FieldResult f;
    f.name = name;
    f.ok = ok;
    f.subsystems = subsystems;
    f.critical = subsystems != 0;
    f.kind = kind;
    f.detail = detail;
    r.fields.push_back(std::move(f));
    if (f.critical && !ok) r.reasons.push_back(name);
}

bool OffsetOk(uint32_t offset) {
    return offset != 0 && offset < 0x20000;
}

void ComputeSubsystems(Report& report) {
    Subsystems s{true, true, true, true};
    for (const FieldResult& f : report.fields) {
        if (f.ok) continue;
        if (HasFeature(f.subsystems, kCloud)) s.cloud = false;
        if (HasFeature(f.subsystems, kManifest)) s.manifest = false;
        if (HasFeature(f.subsystems, kPlaytime)) s.playtime = false;
        if (HasFeature(f.subsystems, kKv)) s.kv = false;
    }
    report.subsystems = s;
    report.status = s.cloud ? Status::Full : Status::Audit;
}

} // namespace

bool ProbeMessageLayout(const ScResolver::ResolvedAddrs& resolved,
                        SteamMessageLayout::Layout& out) {
    out = {};
    if (!resolved.serviceTransportVtable) return false;

    __try {
        const uintptr_t vt = resolved.serviceTransportVtable;
        const uintptr_t slot5 = *reinterpret_cast<const uintptr_t*>(
            vt + 5 * sizeof(uintptr_t));
        const uintptr_t slot8 = *reinterpret_cast<const uintptr_t*>(
            vt + 8 * sizeof(uintptr_t));
        if (!InText(slot5) || !InText(slot8)) return false;
        // The adapters are longer than the pattern window; 0x100 bytes is
        // enough for SteamMessageLayout::Resolve and bounded.
        constexpr size_t kWindow = 0x100;
        return SteamMessageLayout::Resolve(
            reinterpret_cast<const uint8_t*>(slot5), kWindow,
            reinterpret_cast<const uint8_t*>(slot8), kWindow, out);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out = {};
        return false;
    }
}

uint32_t ScanAccountIdOffset(uintptr_t imageBase, size_t imageSize) {
    if (!imageBase || imageSize < 0x1000) return 0;
    const uint8_t* img = reinterpret_cast<const uint8_t*>(imageBase);

    __try {
        // Step 1: find "UserGameStats_%u" in .rdata (may be mid-string).
        const char needle[] = "UserGameStats_%u";
        const size_t needleLen = sizeof(needle) - 1;
        uintptr_t matchAddr = 0;
        for (size_t i = 0; i + needleLen < imageSize; ++i) {
            if (std::memcmp(img + i, needle, needleLen) == 0) {
                matchAddr = imageBase + i;
                break;
            }
        }
        if (!matchAddr) return 0;

        // Walk back to the start of the containing NUL-terminated string.
        uintptr_t strAddr = matchAddr;
        const uint8_t* matchPtr = img + (matchAddr - imageBase);
        while (matchPtr > img && *(matchPtr - 1) != 0) {
            --matchPtr;
            --strAddr;
        }

        // Step 2: find an 8-byte pointer to that string.
        uintptr_t ptrAddr = 0;
        for (size_t i = 0; i + sizeof(uintptr_t) <= imageSize; i += sizeof(uintptr_t)) {
            uintptr_t value = 0;
            std::memcpy(&value, img + i, sizeof(value));
            if (value == strAddr) {
                ptrAddr = imageBase + i;
                break;
            }
        }
        if (!ptrAddr) return 0;

        // Step 3: find `mov rdx, [rip+disp32]` (48 8B 15) targeting that pointer.
        uintptr_t xrefAddr = 0;
        for (size_t i = 0; i + 7 < imageSize; ++i) {
            if (img[i] == 0x48 && img[i + 1] == 0x8B && img[i + 2] == 0x15) {
                int32_t disp = 0;
                std::memcpy(&disp, img + i + 3, sizeof(disp));
                const uintptr_t target = imageBase + i + 7 + static_cast<intptr_t>(disp);
                if (target == ptrAddr) {
                    xrefAddr = imageBase + i;
                    break;
                }
            }
        }
        if (!xrefAddr) return 0;

        // Step 4: walk backward for `mov r32, [reg+disp32]` and take a
        // plausible CUser member offset (256..4096).
        const uint8_t* scan = reinterpret_cast<const uint8_t*>(xrefAddr);
        const uint8_t* scanStart = scan > img + 64 ? scan - 64 : img;
        for (const uint8_t* p = scan - 3; p >= scanStart; --p) {
            const uint8_t op = *p;
            const bool hasRex = (op >= 0x40 && op <= 0x4F);
            const uint8_t* modrmP = hasRex ? p + 1 : p;
            if (*modrmP != 0x8B) continue;
            const uint8_t modrm = *(modrmP + 1);
            const uint8_t mod = (modrm >> 6) & 3;
            const uint8_t rm = modrm & 7;
            if (mod != 2 || rm == 4) continue;
            int32_t offset = 0;
            std::memcpy(&offset, modrmP + 2, sizeof(offset));
            if (offset >= 256 && offset <= 4096) {
                return static_cast<uint32_t>(offset);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return 0;
}

Report BuildStatic(uintptr_t imageBase, size_t imageSize,
                   const ScResolver::ResolvedAddrs& r,
                   uint32_t accountIdOffset, bool accountIdResolved,
                   const SteamMessageLayout::Layout& layout) {
    Report report;
    report.tool = "cr_compat_check/0.1";
    report.liveAvailable = false;
    report.liveOk = false;
    report.liveDetail = "static report only";

    const bool imageOk = imageBase != 0 && imageSize != 0;
    AddField(report, "image", imageOk,
             kCloud | kManifest | kPlaytime | kKv, "pe");

    AddField(report, "ccmInterfaceVtable", InImage(r.ccmInterfaceVtable),
             kCloud, "vtable");
    AddField(report, "serviceTransportVtable", InImage(r.serviceTransportVtable),
             kCloud, "vtable");
    AddField(report, "globalEngine", InData(r.globalEngine),
             kCloud | kPlaytime | kKv, "global");

    AddField(report, "parseFromArray", InText(r.parseFromArray),
             kCloud | kPlaytime, "func");
    AddField(report, "serializeToArray", InText(r.serializeToArray),
             kCloud | kPlaytime, "func");
    AddField(report, "wrapPacket", InText(r.wrapPacket), kCloud, "func");
    AddField(report, "bRouteMsgToJob", InText(r.bRouteMsgToJob), kCloud, "func");
    AddField(report, "releaseWrapped", InText(r.releaseWrapped), kCloud, "func");
    AddField(report, "refCountHelper", InText(r.refCountHelper), kCloud, "func");
    AddField(report, "findJob", InText(r.findJob), kCloud, "func");

    const bool engineOffsetsOk = OffsetOk(r.engineOffGlobalHandle) &&
                                 OffsetOk(r.engineOffUserMap);
    AddField(report, "engineOffsets", engineOffsetsOk,
             kCloud | kPlaytime, "offset");

    // These three feed the legacy Approach-D response injection only. If the
    // resolver can't prove them, that path stays disabled; cloud saves,
    // manifest pinning, playtime and KV must still work.
    AddField(report, "engineOffJobMgr", OffsetOk(r.engineOffJobMgr),
             0, "optional-offset");
    AddField(report, "ccmOffConnContext", OffsetOk(r.ccmOffConnContext),
             0, "optional-offset");
    AddField(report, "userOffCcmInterface", OffsetOk(r.userOffCcmInterface),
             0, "optional-offset");

    const bool accountOk = accountIdResolved && accountIdOffset >= 256 &&
                           accountIdOffset <= 4096;
    AddField(report, "accountIdOffset", accountOk,
             kCloud | kPlaytime | kKv, "offset",
             accountOk ? std::to_string(accountIdOffset)
                       : "unresolved (no 570 fallback)");

    const bool layoutOk = (layout.header == 0x28 || layout.header == 0x30) &&
                          layout.body == layout.header + sizeof(void*) &&
                          layout.emsg != 0 && layout.hdr == layout.header;
    AddField(report, "messageLayout", layoutOk,
             kCloud | kPlaytime, "offset",
             layoutOk ? "header/body verified" : "unresolved");

    AddField(report, "buildDepotDependency", InText(r.buildDepotDependency),
             kManifest, "func");

    AddField(report, "bAsyncSend", InText(r.bAsyncSend), kPlaytime, "func");
    AddField(report, "pbMsgCtor", InText(r.pbMsgCtor), kPlaytime, "func");
    AddField(report, "pbMsgFinalize", InText(r.pbMsgFinalize), kPlaytime, "func");
    AddField(report, "pbMsgCleanup", InText(r.pbMsgCleanup), kPlaytime, "func");
    AddField(report, "getAppMinutesPlayedData",
             InText(r.getAppMinutesPlayedData), kPlaytime, "func");
    AddField(report, "flushAppMinutesPlayed",
             InText(r.flushAppMinutesPlayed), kPlaytime, "func");
    AddField(report, "setAppLastPlayedTime",
             InText(r.setAppLastPlayedTime), kPlaytime, "func");
    AddField(report, "playtimeWriter", InText(r.playtimeWriter), kPlaytime, "func");
    AddField(report, "yieldIfTimeSlice", InText(r.yieldIfTimeSlice),
             kPlaytime, "func");
    AddField(report, "jobCurGlobal", InData(r.jobCurGlobal),
             kPlaytime, "global");
    AddField(report, "refCountGlobal", InData(r.refCountGlobal),
             kPlaytime, "global");
    AddField(report, "getUserStatsDesc", InImage(r.getUserStatsDesc),
             kPlaytime, "descriptor");
    // Schema auto-fetch is best-effort at runtime: an unresolved vtable
    // disables it gracefully. Critical only when the wrapper class exists in
    // the image but resolution failed; builds that never instantiate the
    // wrapper (RTTI type absent) must not block playtime.
    {
        const bool vtableOk = InImage(r.getUserStatsVtable);
        if (vtableOk) {
            AddField(report, "getUserStatsVtable", true, kPlaytime, "vtable");
        } else if (r.getUserStatsVtableRttiAbsent) {
            AddField(report, "getUserStatsVtable", false, 0, "vtable",
                     "RTTI type absent from build: schema auto-fetch unavailable");
        } else {
            AddField(report, "getUserStatsVtable", false, kPlaytime, "vtable");
        }
    }
    AddField(report, "respDescriptor", InImage(r.respDescriptor),
             kPlaytime, "descriptor");
    AddField(report, "respWrapperVtable", InImage(r.respWrapperVtable),
             kPlaytime, "vtable");
    AddField(report, "regKeySyncTime", InImage(r.regKeySyncTime),
             kPlaytime, "global");

    AddField(report, "appInfoCacheOffset", OffsetOk(r.engineOffAppInfoCache),
             kKv, "offset");
    AddField(report, "getAppInfo", InText(r.getAppInfo), kKv, "func");
    AddField(report, "getSection", InText(r.getSection), kKv, "func");
    AddField(report, "readConfigU64", InText(r.readConfigU64), kKv, "func");
    AddField(report, "kvFindKey", InText(r.kvFindKey), kKv, "func");
    AddField(report, "kvGetUint64", InText(r.kvGetUint64), kKv, "func");
    AddField(report, "kvGetInt", InText(r.kvGetInt), kKv, "func");
    AddField(report, "kvSetUint64", InText(r.kvSetUint64), kKv, "func");
    AddField(report, "kvSetInt", InText(r.kvSetInt), kKv, "func");
    AddField(report, "kvSetString", InText(r.kvSetString), kKv, "func");

    ComputeSubsystems(report);
    return report;
}

bool IsAllowlisted(const std::string& sha256) {
    if (sha256.empty()) return false;
    // Builds validated against this DLL. Keep this list append-only; the feed
    // can validate newer builds without a DLL rebuild. The current stable hash
    // is included so a fresh install works offline before the first feed fetch.
    static const char* const kValidated[] = {
        // 2026-10-22: stable builds validated with this report schema.
        "e9045710ec7ee47d7b7488d1c5dda2d933dec7e251e965967a5c48f4df68eb4e",
        "253e0a11a4415b38c78a42f7bdd6ecc426455f06c1ba6453a48090df3142dbbc",
    };
    for (const char* hash : kValidated) {
        if (sha256 == hash) return true;
    }
    return false;
}

bool LoadDynamicPatterns(const std::string& steamRoot, const std::string& sha256) {
    if (sha256.empty()) return false;

    // Helper: parse TOML content into vector of patterns
    struct Entry { std::string name, pattern, mask; uint32_t len = 0; };
    auto ParseToml = [](const std::string& content) {
        std::vector<Entry> entries;
        Entry cur{};
        bool inEntry = false;
        size_t pos = 0;
        while (pos < content.size()) {
            size_t nl = content.find('\n', pos);
            std::string line = (nl == std::string::npos) ? content.substr(pos) : content.substr(pos, nl - pos);
            pos = (nl == std::string::npos) ? content.size() : nl + 1;

            // trim
            size_t l = line.find_first_not_of(" \t\r");
            if (l == std::string::npos) continue;
            size_t r = line.find_last_not_of(" \t\r");
            std::string t = line.substr(l, r - l + 1);
            if (t.empty() || t[0] == '#') continue;

            if (t.rfind("[[patterns]]", 0) == 0) {
                if (inEntry && !cur.name.empty()) entries.push_back(cur);
                cur = Entry{};
                inEntry = true;
                continue;
            }
            if (!inEntry) continue;

            auto eq = t.find('=');
            if (eq == std::string::npos) continue;
            std::string key = t.substr(0, eq);
            std::string val = t.substr(eq + 1);
            // trim key/val
            size_t kt = key.find_first_not_of(" \t");
            key = key.substr(kt);
            kt = key.find_last_not_of(" \t");
            key = key.substr(0, kt + 1);
            size_t vt = val.find_first_not_of(" \t");
            val = val.substr(vt);
            vt = val.find_last_not_of(" \t");
            val = val.substr(0, vt + 1);
            if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
                val = val.substr(1, val.size() - 2);

            if (key == "name") cur.name = val;
            else if (key == "pattern") cur.pattern = val;
            else if (key == "mask") cur.mask = val;
            else if (key == "len") cur.len = static_cast<uint32_t>(std::stoul(val));
        }
        if (inEntry && !cur.name.empty()) entries.push_back(cur);
        return entries;
    };

    // Try local file first
    std::string localPath = steamRoot;
    if (!localPath.empty() && localPath.back() != '\\' && localPath.back() != '/')
        localPath += '\\';
    localPath += "cloud_redirect\\patterns\\";
    localPath += sha256;
    localPath += ".toml";

    std::string content;
    std::ifstream ifs(localPath);
    if (ifs) {
        content.assign((std::istreambuf_iterator<char>(ifs)), {});
    }

    // If not found locally, try remote mirrors.
    // Source: this repository's own 'pattern' branch, populated by
    // .github/workflows/update-patterns.yml (ExportFullPatterns output --
    // [[patterns]] entries with the critical symbol names the resolver
    // queries). steam-monitor's mirrored 'pattern' branch is NOT usable:
    // mirror.yml force-replaces its whole tree every 10 min from an
    // unrelated upstream that publishes a different schema ([0xHASH]/rva/sig)
    // and none of the critical names.
    if (content.empty()) {
        static const std::vector<std::string> kPatternMirrors = {
            "https://raw.githubusercontent.com/eisora08/steam-monitor/pattern-cloud/patterns/",
            "https://cdn.jsdelivr.net/gh/eisora08/steam-monitor@pattern-cloud/patterns/"
        };
        for (const auto& base : kPatternMirrors) {
            std::string url = base + sha256 + ".toml";
            std::string remote = HttpGet(url);
            if (!remote.empty()) {
                content = std::move(remote);
                // cache locally for next run
                std::error_code ec;
                std::filesystem::create_directories(FileUtil::Utf8ToPath(localPath).parent_path(), ec);
                if (!ec) FileUtil::AtomicWriteText(localPath, content);
                LOG("[Compat] Downloaded pattern TOML from %s", url.c_str());
                break;
            }
            LOG("[Compat] Pattern mirror %s failed", url.c_str());
        }
    }

    if (content.empty()) return false;

    auto entries = ParseToml(content);
    if (entries.empty()) {
        // Not fatal: the resolver falls back to built-in discovery. Log it so
        // a stale cache in the wrong schema is visible instead of silent.
        LOG("[Compat] Pattern TOML for SHA %s parsed to 0 entries (schema mismatch or empty)", sha256.c_str());
        return false;
    }

    size_t okCount = 0;
    for (const auto& e : entries) {
        if (e.name.empty() || e.pattern.empty() || e.mask.empty() || e.len == 0) continue;
        std::vector<uint8_t> patBytes;
        patBytes.reserve(e.len);
        for (size_t i = 0; i + 1 < e.pattern.size(); i += 2) {
            unsigned int byte = 0;
            if (sscanf_s(e.pattern.c_str() + i, "%2x", &byte) == 1)
                patBytes.push_back(static_cast<uint8_t>(byte));
        }
        if (patBytes.size() != e.len) continue;
        if (e.mask.size() != e.len) continue;

        uint8_t* patBuf = new uint8_t[e.len];
        std::memcpy(patBuf, patBytes.data(), e.len);
        char* maskBuf = new char[e.len + 1];
        std::memcpy(maskBuf, e.mask.c_str(), e.len);
        maskBuf[e.len] = '\0';

        SigScanner::DynamicPattern dp{};
        char* nameCopy = new char[e.name.size() + 1];
        std::strcpy(nameCopy, e.name.c_str());
        dp.name = nameCopy;
        dp.pattern = patBuf;
        dp.mask = maskBuf;
        dp.len = e.len;
        dp.post = nullptr;

        if (SigScanner::RegisterDynamicPattern(dp)) ++okCount;
    }
    LOG("[Compat] Loaded %zu dynamic patterns for SHA %s", okCount, sha256.c_str());
    return okCount > 0;
}

bool ExportPatterns(const std::string& outPath, const std::string& sha256) {
    (void)sha256; // currently unused, but kept for future use

    // Helper to convert bytes to hex string (lowercase, no spaces)
    auto toHex = [](const uint8_t* data, size_t len) -> std::string {
        static const char* hex = "0123456789abcdef";
        std::string s;
        s.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            s.push_back(hex[data[i] >> 4]);
            s.push_back(hex[data[i] & 0xF]);
        }
        return s;
    };

    std::ostringstream toml;
    toml << "# Auto-generated pattern file for steamclient64.dll (SHA " << sha256 << ")\n";

    // 1) Dynamic patterns registered at runtime
    for (const auto& dp : SigScanner::GetDynamicPatternsCopy()) {
        toml << "[[patterns]]\n";
        toml << "name = \"" << dp.name << "\"\n";
        toml << "pattern = \"" << toHex(dp.pattern, dp.len) << "\"\n";
        toml << "mask = \"" << std::string(dp.mask, dp.len) << "\"\n";
        toml << "len = " << dp.len << "\n\n";
    }

    // 2) Built‑in patterns for symbols that have dynamic fallback but also a static signature
    // GetAppInfo
    {
        static const uint8_t pat[] = {
            0x44, 0x8B, 0x41, 0x68,
            0x44, 0x8B, 0xCA,
            0x41, 0x83, 0xF8, 0xFF
        };
        static const char mask[] = "xxxxxxxxxxx";
        toml << "[[patterns]]\n";
        toml << "name = \"GetAppInfo\"\n";
        toml << "pattern = \"" << toHex(pat, sizeof(pat)) << "\"\n";
        toml << "mask = \"" << std::string(mask, sizeof(mask)-1) << "\"\n";
        toml << "len = " << sizeof(pat) << "\n\n";
    }
    // FlushAppMinutesPlayed (prologue pattern used for dynamic fallback)
    {
        static const uint8_t pat[] = {
            0x40, 0x55, 0x57, 0x41, 0x56,
            0x48, 0x83, 0xEC, 0x30,
            0x48, 0x8B, 0x05
        };
        static const char mask[] = "xxxxxxxxxxxx";
        toml << "[[patterns]]\n";
        toml << "name = \"FlushAppMinutesPlayed\"\n";
        toml << "pattern = \"" << toHex(pat, sizeof(pat)) << "\"\n";
        toml << "mask = \"" << std::string(mask, sizeof(mask)-1) << "\"\n";
        toml << "len = " << sizeof(pat) << "\n\n";
    }

    std::string out = toml.str();
    std::ofstream ofs(outPath, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    ofs.write(out.c_str(), static_cast<std::streamsize>(out.size()));
    return ofs.good();
}

// ExportFullPatterns: generate a TOML with concrete byte patterns for every
// resolved critical symbol that lives in .text (data-section symbols are
// excluded: see the relocation note below). Entries are only emitted when a
// first-match scan reproduces the resolved address on this build, so the
// resolver's dynamic hooks can never return an earlier colliding site. This
// gives a new build a complete, self-verifying pattern set.
bool ExportFullPatterns(uintptr_t imageBase,
                        const ScResolver::ResolvedAddrs& resolved,
                        const std::string& sha256,
                        const std::string& outPath) {
    // Helper to convert bytes to hex string (lowercase, no spaces)
    auto toHex = [](const uint8_t* data, size_t len) -> std::string {
        static const char* hex = "0123456789abcdef";
        std::string s;
        s.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            s.push_back(hex[data[i] >> 4]);
            s.push_back(hex[data[i] & 0xF]);
        }
        return s;
    };

    // Determine .text range for validation
    const uint8_t* textBase = reinterpret_cast<const uint8_t*>(SigScanner::GetTextBase());
    const size_t textSize = SigScanner::GetTextSize();
    const uintptr_t textStart = reinterpret_cast<uintptr_t>(textBase);
    const uintptr_t textEnd = textStart + textSize;

    std::ostringstream toml;
    toml << "# Auto-generated FULL pattern file for steamclient64.dll (SHA " << sha256 << ")\n";

    // 1) Patterns registered at runtime are NOT re-emitted: the only runtime
    // registration path is LoadDynamicPatterns() itself, so re-emitting them
    // would just copy the previously cached file (stale, unverified) back into
    // the new one. The export below is built solely from verified captures.

    // 2) Built-in static patterns are intentionally NOT emitted unconditionally.
    // The resolver's own fallbacks already do first-match on those short
    // built-ins -- and its Flush fallback additionally VERIFIES the RIP
    // displacement. Re-emitting 11-12 byte patterns without verification would
    // hand the dynamic hook a weaker result than the built-in path it is
    // meant to replace. Every entry emitted below is verified instead.

    // 3) Concrete patterns for critical resolved addresses in .text.
    // The resolver's dynamic hooks take the FIRST match in range, so an entry
    // is emitted only when that first match IS the resolved address on this
    // build. The file is SHA-gated (LoadDynamicPatterns only reads it for the
    // exact same steamclient64.dll), so runtime bytes are identical and the
    // verified first match holds at runtime too. Grow the capture when a
    // shorter prefix collides with an earlier site; skip when never unique.
    size_t emitted = 0, skipped = 0;
    std::string skippedNames;
    auto emitTextPattern = [&](const char* name, uintptr_t addr) {
        if (!addr || addr < textStart || addr >= textEnd) return; // not code
        const size_t maxLen = textEnd - addr;
        const size_t tryLens[] = { 16, 32, 64 };
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(addr);
        for (size_t len : tryLens) {
            if (len > maxLen) break;
            std::string mask(len, 'x');
            if (SigScanner::FindPatternInRange(textStart, textSize, bytes, mask.c_str(), len) != addr)
                continue; // an earlier site matches: too short to disambiguate
            toml << "[[patterns]]\n";
            toml << "name = \"" << name << "\"\n";
            toml << "pattern = \"" << toHex(bytes, len) << "\"\n";
            toml << "mask = \"" << mask << "\"\n";
            toml << "len = " << len << "\n\n";
            ++emitted;
            return;
        }
        ++skipped;
        skippedNames += std::string(name) + " ";
    };

    struct Sym { const char* name; uintptr_t addr; };
    const Sym critical[] = {
        { "GlobalEngine",          resolved.globalEngine },
        { "GetUserStatsVtable",    resolved.getUserStatsVtable },
        { "GetAppInfo",            resolved.getAppInfo },
        { "GetSection",            resolved.getSection },
        { "ReadConfigU64",         resolved.readConfigU64 },
        { "FlushAppMinutesPlayed", resolved.flushAppMinutesPlayed },
        { "GetAppMinutesPlayedData", resolved.getAppMinutesPlayedData },
        { "SetAppLastPlayedTime",  resolved.setAppLastPlayedTime },
        { "PlaytimeWriter",        resolved.playtimeWriter },
        { "ParseFromArray",        resolved.parseFromArray },
        { "SerializeToArray",      resolved.serializeToArray },
        { "WrapPacket",            resolved.wrapPacket },
        { "BRouteMsgToJob",        resolved.bRouteMsgToJob },
        { "ReleaseWrapped",        resolved.releaseWrapped },
        { "RefCountHelper",        resolved.refCountHelper },
        { "FindJob",               resolved.findJob },
        { "BuildDepotDependency",  resolved.buildDepotDependency },
        { "BAsyncSend",            resolved.bAsyncSend },
        { "PbMsgCtor",             resolved.pbMsgCtor },
        { "PbMsgFinalize",         resolved.pbMsgFinalize },
        { "PbMsgCleanup",          resolved.pbMsgCleanup },
        { "YieldIfTimeSlice",      resolved.yieldIfTimeSlice },
        { "GetUserStatsDesc",      resolved.getUserStatsDesc },
        { "RespWrapperVtable",     resolved.respWrapperVtable },
        { "RespDescriptor",        resolved.respDescriptor },
        { "RegKeySyncTime",        resolved.regKeySyncTime },
        { "KvFindKey",             resolved.kvFindKey },
        { "KvGetUint64",           resolved.kvGetUint64 },
        { "KvGetInt",              resolved.kvGetInt },
        { "KvSetUint64",           resolved.kvSetUint64 },
        { "KvSetInt",              resolved.kvSetInt },
        { "KvSetString",           resolved.kvSetString },
    };

    for (const auto& s : critical) emitTextPattern(s.name, s.addr);

    // No data-section patterns, deliberately: .data/.rdata pointer tables are
    // rewritten by base relocations at load time, so a byte capture taken in
    // one process (cr_compat_check) can never match in another (Steam, ASLR).
    // Symbols outside .text recover through their semantic paths instead
    // (ResolveGlobalEngine's UFS walk; GetUserStatsVtable via RTTI).

    LOG("[Compat] ExportFullPatterns: %zu verified pattern(s), %zu skipped (no unique first match): %s",
        emitted, skipped, skippedNames.c_str());

    std::string out = toml.str();
    std::ofstream ofs(outPath, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    ofs.write(out.c_str(), static_cast<std::streamsize>(out.size()));
    return ofs.good();
}

Status Decide(const Report& local, bool feedPresent, Status feedStatus,
              bool strict, bool allowlisted) {
    if (local.status != Status::Full) return Status::Audit;
    if (!feedPresent) {
        if (!strict) return Status::Full;
        return allowlisted ? Status::Full : Status::Unverified;
    }
    if (feedStatus == Status::Blocked) return Status::Blocked;
    if (feedStatus == Status::Full) return Status::Full;
    return Status::Audit;
}

Subsystems DecideSubsystems(const Report& local, bool feedPresent,
                            Status feedStatus, bool strict, bool allowlisted) {
    if (Decide(local, feedPresent, feedStatus, strict, allowlisted) !=
        Status::Full) {
        return {};
    }
    // A locally full cloud report is the prerequisite for every feature. The
    // optional features keep their own local verdict.
    if (!local.subsystems.cloud) return {};
    return local.subsystems;
}

const char* StatusName(Status status) {
    switch (status) {
    case Status::Full: return "full";
    case Status::Unverified: return "unverified";
    case Status::Audit: return "audit";
    case Status::Blocked: return "blocked";
    }
    return "audit";
}

Status ParseStatus(const std::string& text) {
    if (text == "full") return Status::Full;
    if (text == "unverified") return Status::Unverified;
    if (text == "blocked") return Status::Blocked;
    return Status::Audit;
}

std::string ToJson(const Report& report) {
    Json::Value root = Json::Object();
    root.objVal["schema"] = Json::Number(report.schema);
    root.objVal["channel"] = Json::String(report.channel);
    root.objVal["build_id"] = Json::String(std::to_string(report.steamVersion));
    root.objVal["steam_version"] = Json::Number(static_cast<double>(report.steamVersion));
    root.objVal["steamclient_sha256"] = Json::String(report.sha256);
    root.objVal["tested_at"] = Json::String(NowIso());
    root.objVal["tool"] = Json::String(report.tool);
    root.objVal["dll_version"] = Json::String(report.dllVersion);
    root.objVal["status"] = Json::String(StatusName(report.status));
    root.objVal["allowlisted"] = BoolValue(report.allowlisted);

    Json::Value subsystems = Json::Object();
    subsystems.objVal["cloud"] = BoolValue(report.subsystems.cloud);
    subsystems.objVal["manifest"] = BoolValue(report.subsystems.manifest);
    subsystems.objVal["playtime"] = BoolValue(report.subsystems.playtime);
    subsystems.objVal["kv"] = BoolValue(report.subsystems.kv);
    root.objVal["subsystems"] = std::move(subsystems);

    Json::Value reasons = Json::Array();
    for (const std::string& reason : report.reasons)
        reasons.arrVal.push_back(Json::String(reason));
    root.objVal["reasons"] = std::move(reasons);

    Json::Value fields = Json::Object();
    for (const FieldResult& f : report.fields) {
        Json::Value field = Json::Object();
        field.objVal["ok"] = BoolValue(f.ok);
        field.objVal["kind"] = Json::String(f.kind);
        field.objVal["critical"] = BoolValue(f.critical);
        if (!f.detail.empty())
            field.objVal["detail"] = Json::String(f.detail);
        Json::Value fieldSubs = Json::Array();
        if (HasFeature(f.subsystems, kCloud)) fieldSubs.arrVal.push_back(Json::String("cloud"));
        if (HasFeature(f.subsystems, kManifest)) fieldSubs.arrVal.push_back(Json::String("manifest"));
        if (HasFeature(f.subsystems, kPlaytime)) fieldSubs.arrVal.push_back(Json::String("playtime"));
        if (HasFeature(f.subsystems, kKv)) fieldSubs.arrVal.push_back(Json::String("kv"));
        field.objVal["subsystems"] = std::move(fieldSubs);
        fields.objVal[f.name] = std::move(field);
    }
    root.objVal["fields"] = std::move(fields);

    Json::Value live = Json::Object();
    live.objVal["ok"] = BoolValue(report.liveOk);
    live.objVal["available"] = BoolValue(report.liveAvailable);
    live.objVal["detail"] = Json::String(report.liveDetail);
    root.objVal["live"] = std::move(live);

    return Json::Stringify(root);
}

} // namespace Compat
