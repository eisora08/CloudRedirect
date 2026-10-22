#pragma once
// compat.h -- Static compatibility report for steamclient64.dll.
//
// The report is computed before any hook is installed. It never trusts the
// network feed: the feed can only add or remove a "full" decision on top of a
// locally verified report. All addresses are supplied by ScResolver, so a
// Steam update that breaks a pattern shows up as an audit, not as a wrong
// pointer.

#include "sc_resolver.h"
#include "steam_message_layout.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Compat {

enum class Status {
    Full,
    Unverified,
    Audit,
    Blocked,
};

struct FieldResult {
    std::string name;
    bool ok = false;
    bool critical = false;
    std::string kind;
    std::string detail;
};

struct Report {
    int schema = 1;
    std::string channel;
    uint64_t steamVersion = 0;
    std::string sha256;
    std::string tool;
    Status status = Status::Audit;
    std::vector<FieldResult> fields;
    std::vector<std::string> reasons;
    bool liveOk = false;
    bool liveAvailable = false;
    std::string liveDetail = "not run";
};

// Run the resolver and produce a report. imageBase/imageSize are the mapped
// steamclient64.dll; accountIdOffset is the value found by ScanAccountIdOffset.
Report BuildStatic(uintptr_t imageBase, size_t imageSize,
                   const ScResolver::ResolvedAddrs& resolved,
                   uint32_t accountIdOffset, bool accountIdResolved,
                   const SteamMessageLayout::Layout& messageLayout);

// Resolve the CProtoBufMsg wrapper offsets by reading the service transport
// vtable slots. Fails closed.
bool ProbeMessageLayout(const ScResolver::ResolvedAddrs& resolved,
                        SteamMessageLayout::Layout& out);

// Find CUser::accountId from the "UserGameStats_%u" xref. 0 on failure.
// Pure read-only scan; safe on a DONT_RESOLVE_DLL_REFERENCES mapping.
uint32_t ScanAccountIdOffset(uintptr_t imageBase, size_t imageSize);

// Merge a local report with the feed. strict=true means an absent feed keeps
// the session in audit; strict=false allows a locally full build to run.
Status Decide(const Report& local, bool feedPresent, Status feedStatus, bool strict);

const char* StatusName(Status status);
Status ParseStatus(const std::string& text);
std::string ToJson(const Report& report);

} // namespace Compat
