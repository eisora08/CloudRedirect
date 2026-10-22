#pragma once
// compat_feed.h -- Read the CloudRedirect compatibility feed.
//
// The feed is untrusted data: only the status string is consumed. Addresses
// are never taken from the network; the local Compat::Report decides whether
// a "full" status is allowed.

#include "compat.h"

#include <string>
#include <vector>

namespace CompatFeed {

struct Result {
    bool present = false;   // a usable feed document was obtained
    bool fromCache = false;
    Compat::Status status = Compat::Status::Audit;
    std::string sha256;
    std::string body;
    std::string source;
    std::string error;
};

std::vector<std::string> DefaultUrls(const std::string& sha256);

// Read cloud_redirect/compat/<sha>.json. Never touches the network.
Result LoadCached(const std::string& steamPath, const std::string& sha256);

// Fetch and validate one of the URLs. Returns present=false on any failure.
Result Fetch(const std::string& sha256, const std::vector<std::string>& urls);

// Atomically write cloud_redirect/compat/<sha>.json.
bool SaveCache(const std::string& steamPath, const std::string& sha256,
               const std::string& body);

} // namespace CompatFeed
