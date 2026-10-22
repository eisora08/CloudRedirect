#pragma once
// Pure planning for orphan-blob GC grace. Kept header-only and side-effect
// free so the "never delete on first sight" rule can be unit tested without a
// provider, and so cloud_storage.cpp only performs the I/O.

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace GcGrace {

struct Plan {
    // Orphans old enough to delete now. Failures stay in `pending` so the next
    // GC retries them instead of losing the record.
    std::vector<std::string> toDelete;
    std::unordered_map<std::string, uint64_t> pending;
    int deferred = 0;
};

inline Plan PlanDeletes(const std::vector<std::string>& orphans,
                        std::unordered_map<std::string, uint64_t> pending,
                        uint64_t now, uint64_t graceSeconds) {
    Plan plan;
    plan.pending = std::move(pending);

    // Drop journal entries that are no longer orphaned (they were re-uploaded
    // or the listing changed). Do this before adding first-seen timestamps.
    std::unordered_set<std::string> orphanSet(orphans.begin(), orphans.end());
    for (auto it = plan.pending.begin(); it != plan.pending.end();) {
        if (!orphanSet.count(it->first))
            it = plan.pending.erase(it);
        else
            ++it;
    }

    for (const auto& path : orphans) {
        auto inserted = plan.pending.emplace(path, now);
        if (inserted.second) {
            ++plan.deferred;  // first sight: journal only
            continue;
        }
        const uint64_t firstSeen = inserted.first->second;
        const uint64_t age = now >= firstSeen ? now - firstSeen : 0;
        if (age < graceSeconds) {
            ++plan.deferred;
            continue;
        }
        plan.toDelete.push_back(path);
    }
    return plan;
}

} // namespace GcGrace
