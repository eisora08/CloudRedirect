#pragma once
// Small local trash for files CloudRedirect is about to delete or prune.
// Moving (not copying) keeps the operation cheap even for multi-GB saves.
// Entries older than the retention window are removed at startup.

#include "platform.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace TrashUtil {

inline constexpr int kRetentionDays = 30;

inline std::string WithSep(const std::string& root) {
    if (root.empty()) return root;
    if (root.back() == '\\' || root.back() == '/') return root;
    return root + Platform().PathSeparator();
}

inline std::string Stamp() {
    static std::atomic<uint64_t> seq{0};
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return std::to_string(static_cast<long long>(ms)) + "-" +
           std::to_string(seq.fetch_add(1, std::memory_order_relaxed));
}

// relPath is the file's path relative to the storage root. The leaf gets a
// timestamp suffix so repeated deletes never overwrite an earlier copy.
inline std::string Destination(const std::string& trashRoot,
                               const std::string& relPath) {
    std::string rel = relPath;
    for (char& c : rel) {
        if (c == '\\') c = '/';
    }
    while (!rel.empty() && rel.front() == '/') rel.erase(rel.begin());
    size_t slash = rel.rfind('/');
    const std::string dir = slash == std::string::npos ? std::string() : rel.substr(0, slash + 1);
    const std::string leaf = slash == std::string::npos ? rel : rel.substr(slash + 1);
    return WithSep(trashRoot) + dir + leaf + "." + Stamp() + ".deleted";
}

inline bool Move(const std::string& trashRoot, const std::string& sourceUtf8,
                 const std::string& relPath) {
    if (trashRoot.empty() || sourceUtf8.empty()) return false;
    std::filesystem::path source = Platform().Utf8ToPath(sourceUtf8);
    std::error_code ec;
    if (!std::filesystem::exists(source, ec) || ec) return false;

    const std::string destUtf8 = Destination(trashRoot, relPath);
    std::string trashBase = trashRoot;
    while (!trashBase.empty() &&
           (trashBase.back() == '\\' || trashBase.back() == '/')) {
        trashBase.pop_back();
    }
    if (trashBase.empty() || !Platform().IsPathWithin(trashBase, destUtf8))
        return false;
    std::filesystem::path dest = Platform().Utf8ToPath(destUtf8);
    std::filesystem::create_directories(dest.parent_path(), ec);
    if (ec) return false;

    std::filesystem::rename(source, dest, ec);
    if (!ec) return true;

    // Cross-volume or an open handle: copy then remove. copy_file streams.
    ec.clear();
    std::filesystem::copy_file(source, dest, std::filesystem::copy_options::none, ec);
    if (ec) return false;
    std::error_code rmEc;
    std::filesystem::remove(source, rmEc);
    return true;
}

inline void Prune(const std::string& trashRoot, int retentionDays = kRetentionDays) {
    if (trashRoot.empty() || retentionDays < 0) return;
    std::error_code ec;
    std::filesystem::path root = Platform().Utf8ToPath(trashRoot);
    if (!std::filesystem::exists(root, ec) || ec) return;

    const auto retention = std::chrono::hours(24 * retentionDays);
    const auto now = std::filesystem::file_time_type::clock::now();
    std::vector<std::filesystem::path> dirs;
    std::filesystem::recursive_directory_iterator it(
        root, std::filesystem::directory_options::skip_permission_denied, ec);
    const std::filesystem::recursive_directory_iterator end;
    if (ec) return;
    while (it != end) {
        std::error_code entryEc;
        const auto& entry = *it;
        if (entry.is_directory(entryEc) && !entryEc) {
            dirs.push_back(entry.path());
        } else if (entry.is_regular_file(entryEc) && !entryEc) {
            auto mtime = std::filesystem::last_write_time(entry.path(), entryEc);
            if (!entryEc && now - mtime >= retention) {
                std::filesystem::remove(entry.path(), entryEc);
            }
        }
        std::error_code stepEc;
        it.increment(stepEc);
        if (stepEc) break;
    }

    // Deepest-first so empty parents can be removed too.
    for (auto itDir = dirs.rbegin(); itDir != dirs.rend(); ++itDir) {
        std::error_code rmEc;
        std::filesystem::remove(*itDir, rmEc);
    }
}

} // namespace TrashUtil
