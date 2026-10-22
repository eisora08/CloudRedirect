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

    AddField(report, "ccmInterfaceVtable", InRdata(r.ccmInterfaceVtable),
             kCloud, "vtable");
    AddField(report, "serviceTransportVtable", InRdata(r.serviceTransportVtable),
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
    AddField(report, "getUserStatsVtable", InRdata(r.getUserStatsVtable),
             kPlaytime, "vtable");
    AddField(report, "respDescriptor", InImage(r.respDescriptor),
             kPlaytime, "descriptor");
    AddField(report, "respWrapperVtable", InRdata(r.respWrapperVtable),
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
