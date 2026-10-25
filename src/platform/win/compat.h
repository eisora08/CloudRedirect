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

// Feature bits carried by every field. A field can gate more than one feature
// (e.g. the global engine is needed by cloud, playtime and KV).
enum Feature : uint32_t {
    kCloud    = 1u << 0,
    kManifest = 1u << 1,
    kPlaytime = 1u << 2,
    kKv       = 1u << 3,
};

inline bool HasFeature(uint32_t mask, Feature feature) {
    return (mask & static_cast<uint32_t>(feature)) != 0;
}

struct Subsystems {
    bool cloud = false;
    bool manifest = false;
    bool playtime = false;
    bool kv = false;

    bool All() const { return cloud && manifest && playtime && kv; }
    bool None() const { return !cloud && !manifest && !playtime && !kv; }
};

struct FieldResult {
    std::string name;
    bool ok = false;
    uint32_t subsystems = 0;
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
    std::string dllVersion;
    Status status = Status::Audit;
    bool allowlisted = false;
    Subsystems subsystems;
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

// True when sha256 is one of the builds shipped/validated with this DLL. This
// only matters when the feed is absent and strict=true: it lets a fresh
// install work offline without weakening the unknown-build rule.
bool IsAllowlisted(const std::string& sha256);

// Load dynamic patterns from a JSON file located at
// <steamRoot>/cloud_redirect/patterns/<sha256>.json.
// The JSON format is an array of objects:
//   { "name": "...", "pattern": "hexstring", "mask": "x?xx...", "len": N }
// Returns true on success.
bool LoadDynamicPatterns(const std::string& steamRoot, const std::string& sha256);

// Export all patterns (dynamic + built‑in) to a JSON file at outPath.
// Returns true on success.
bool ExportPatterns(const std::string& outPath, const std::string& sha256);

// Export full pattern set for a given image: includes dynamic patterns,
// built‑ins, and concrete byte patterns for every critical symbol that was
// resolved (functions/vtables). Writes TOML to outPath.
bool ExportFullPatterns(uintptr_t imageBase,
                        const ScResolver::ResolvedAddrs& resolved,
                        const std::string& sha256,
                        const std::string& outPath);

// Merge a local report with the feed. strict=true means an absent feed keeps
// the session in audit unless the build hash is in the compiled allowlist.
// strict=false preserves the old behaviour for local-only setups.
Status Decide(const Report& local, bool feedPresent, Status feedStatus,
              bool strict, bool allowlisted = false);

// Per-feature decision. A cloud failure disables everything; a manifest,
// playtime or KV failure disables only that feature.
Subsystems DecideSubsystems(const Report& local, bool feedPresent,
                            Status feedStatus, bool strict, bool allowlisted);

const char* StatusName(Status status);
Status ParseStatus(const std::string& text);
std::string ToJson(const Report& report);

} // namespace Compat
