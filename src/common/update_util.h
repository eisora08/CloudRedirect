#pragma once
// Small, dependency-free parsing helpers shared by the self-updater. Keeping
// them header-only lets the release pipeline's hash format be unit-tested
// without linking WinHTTP or the update client.

#include <string>
#include <string_view>

namespace UpdateUtil {

inline std::string LowerAscii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

// The release workflow writes exactly 64 lowercase hex characters and no
// newline. Anything else is not a trustworthy checksum.
inline bool IsSha256Hex(std::string_view s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

} // namespace UpdateUtil
