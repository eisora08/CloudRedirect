#include "compat.h"
#include "sig_scanner.h"
#include "json.h"

#include <cstdio>
#include <cstring>
#include <ctime>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace Compat {

namespace {

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

void AddField(Report& r, const char* name, bool ok, bool critical,
              const char* kind, const std::string& detail = {}) {
    FieldResult f;
    f.name = name;
    f.ok = ok;
    f.critical = critical;
    f.kind = kind;
    f.detail = detail;
    r.fields.push_back(std::move(f));
    if (critical && !ok) r.reasons.push_back(name);
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
    AddField(report, "image", imageOk, true, "pe");

    AddField(report, "ccmInterfaceVtable", InRdata(r.ccmInterfaceVtable), true, "vtable");
    AddField(report, "serviceTransportVtable", InRdata(r.serviceTransportVtable), true, "vtable");
    AddField(report, "globalEngine", InData(r.globalEngine), true, "global");

    AddField(report, "parseFromArray", InText(r.parseFromArray), true, "func");
    AddField(report, "serializeToArray", InText(r.serializeToArray), true, "func");
    AddField(report, "wrapPacket", InText(r.wrapPacket), true, "func");
    AddField(report, "bRouteMsgToJob", InText(r.bRouteMsgToJob), true, "func");
    AddField(report, "releaseWrapped", InText(r.releaseWrapped), true, "func");
    AddField(report, "refCountHelper", InText(r.refCountHelper), true, "func");
    AddField(report, "findJob", InText(r.findJob), true, "func");

    const bool offsetsOk =
        r.engineOffGlobalHandle != 0 && r.engineOffGlobalHandle < 0x20000 &&
        r.engineOffUserMap != 0 && r.engineOffUserMap < 0x20000 &&
        r.engineOffAppInfoCache != 0 && r.engineOffAppInfoCache < 0x20000;
    AddField(report, "engineOffsets", offsetsOk, true, "offset");

    const bool accountOk = accountIdResolved && accountIdOffset >= 256 &&
                           accountIdOffset <= 4096;
    AddField(report, "accountIdOffset", accountOk, true, "offset",
             accountOk ? std::to_string(accountIdOffset) : "unresolved (no 570 fallback)");

    const bool layoutOk = (layout.header == 0x28 || layout.header == 0x30) &&
                          layout.body == layout.header + sizeof(void*);
    AddField(report, "messageLayout", layoutOk, true, "offset",
             layoutOk ? "header/body verified" : "unresolved");

    // Optional subsystems: a failure disables the feature, not cloud saves.
    AddField(report, "buildDepotDependency", InText(r.buildDepotDependency), false, "func");
    AddField(report, "bAsyncSend", InText(r.bAsyncSend), false, "func");
    AddField(report, "pbMsgCtor", InText(r.pbMsgCtor), false, "func");
    AddField(report, "pbMsgFinalize", InText(r.pbMsgFinalize), false, "func");
    AddField(report, "pbMsgCleanup", InText(r.pbMsgCleanup), false, "func");
    AddField(report, "getAppInfo", InText(r.getAppInfo), false, "func");
    AddField(report, "getSection", InText(r.getSection), false, "func");
    AddField(report, "readConfigU64", InText(r.readConfigU64), false, "func");
    AddField(report, "kvFindKey", InText(r.kvFindKey), false, "func");
    AddField(report, "kvGetUint64", InText(r.kvGetUint64), false, "func");
    AddField(report, "kvGetInt", InText(r.kvGetInt), false, "func");
    AddField(report, "kvSetUint64", InText(r.kvSetUint64), false, "func");
    AddField(report, "kvSetInt", InText(r.kvSetInt), false, "func");
    AddField(report, "kvSetString", InText(r.kvSetString), false, "func");
    AddField(report, "jobCurGlobal", InData(r.jobCurGlobal), false, "global");
    AddField(report, "refCountGlobal", InData(r.refCountGlobal), false, "global");
    AddField(report, "getUserStatsDesc", InImage(r.getUserStatsDesc), false, "descriptor");
    AddField(report, "getUserStatsVtable", InRdata(r.getUserStatsVtable), false, "vtable");
    AddField(report, "respDescriptor", InImage(r.respDescriptor), false, "descriptor");
    AddField(report, "respWrapperVtable", InRdata(r.respWrapperVtable), false, "vtable");
    AddField(report, "regKeySyncTime", InImage(r.regKeySyncTime), false, "global");

    AddField(report, "engineOffJobMgr", true, false, "hardcoded",
             "validated on first use");
    AddField(report, "ccmOffConnContext", true, false, "hardcoded",
             "validated on first use");
    AddField(report, "userOffCcmInterface", true, false, "hardcoded",
             "validated on first use");

    report.status = report.reasons.empty() ? Status::Full : Status::Audit;
    return report;
}

Status Decide(const Report& local, bool feedPresent, Status feedStatus, bool strict) {
    if (local.status != Status::Full) return Status::Audit;
    if (!feedPresent) return strict ? Status::Unverified : Status::Full;
    if (feedStatus == Status::Blocked) return Status::Blocked;
    if (feedStatus == Status::Full) return Status::Full;
    return Status::Audit;
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
    root.objVal["steam_version"] = Json::Number(static_cast<double>(report.steamVersion));
    root.objVal["steamclient_sha256"] = Json::String(report.sha256);
    root.objVal["tested_at"] = Json::String(NowIso());
    root.objVal["tool"] = Json::String(report.tool);
    root.objVal["status"] = Json::String(StatusName(report.status));

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
