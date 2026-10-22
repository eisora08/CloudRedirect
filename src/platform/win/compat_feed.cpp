#include "compat_feed.h"
#include "cloud_provider_base.h"
#include "file_util.h"
#include "http_util.h"
#include "json.h"
#include "log.h"

#include <filesystem>
#include <fstream>
#include <iterator>

namespace CompatFeed {

namespace {

std::string CachePath(const std::string& steamPath, const std::string& sha256) {
    std::string root = steamPath;
    if (!root.empty() && root.back() != '\\' && root.back() != '/')
        root += '\\';
    return root + "cloud_redirect\\compat\\" + sha256 + ".json";
}

Result Parse(const std::string& body, const std::string& expectedSha,
             const std::string& source, bool fromCache) {
    Result out;
    out.body = body;
    out.source = source;
    out.fromCache = fromCache;

    if (body.empty()) {
        out.error = "empty body";
        return out;
    }

    Json::Value root = Json::Parse(body);
    if (root.type != Json::Type::Object) {
        out.error = "not a JSON object";
        return out;
    }
    if (root["schema"].type != Json::Type::Number || root["schema"].integer() != 1) {
        out.error = "unsupported schema";
        return out;
    }
    const std::string sha = root["steamclient_sha256"].str();
    if (sha != expectedSha) {
        out.error = "sha mismatch";
        return out;
    }
    const std::string status = root["status"].str();
    if (status != "full" && status != "unverified" &&
        status != "audit" && status != "blocked") {
        out.error = "unknown status";
        return out;
    }

    out.status = Compat::ParseStatus(status);
    out.sha256 = sha;
    out.present = true;
    return out;
}

} // namespace

std::vector<std::string> DefaultUrls(const std::string& sha256) {
    return {
        "https://raw.githubusercontent.com/eisora08/steam-monitor/compat/steamclient64/" + sha256 + ".json",
        "https://cdn.jsdelivr.net/gh/eisora08/steam-monitor@compat/steamclient64/" + sha256 + ".json",
    };
}

Result LoadCached(const std::string& steamPath, const std::string& sha256) {
    Result out;
    const std::string path = CachePath(steamPath, sha256);
    std::ifstream file(FileUtil::Utf8ToPath(path), std::ios::binary);
    if (!file) {
        out.error = "cache miss";
        return out;
    }
    std::string body((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    return Parse(body, sha256, path, true);
}

Result Fetch(const std::string& sha256, const std::vector<std::string>& urls) {
    Result out;
    if (urls.empty()) {
        out.error = "no feed urls";
        return out;
    }

    auto transport = CreateHttpTransport("CompatFeed");
    if (!transport || !transport->Init()) {
        out.error = "http transport init failed";
        return out;
    }

    for (const std::string& url : urls) {
        HttpUtil::HttpResp response = transport->RequestUrl("GET", url, "", {});
        if (response.status != 200 || response.body.empty()) {
            LOG("[CompatFeed] %s -> HTTP %d", url.c_str(), response.status);
            continue;
        }
        Result parsed = Parse(response.body, sha256, url, false);
        if (!parsed.present) {
            LOG("[CompatFeed] %s rejected: %s", url.c_str(), parsed.error.c_str());
            continue;
        }
        LOG("[CompatFeed] %s -> %s", url.c_str(),
            Compat::StatusName(parsed.status));
        return parsed;
    }

    out.error = "all mirrors failed";
    return out;
}

bool SaveCache(const std::string& steamPath, const std::string& sha256,
               const std::string& body) {
    const std::string path = CachePath(steamPath, sha256);
    std::error_code ec;
    std::filesystem::create_directories(
        FileUtil::Utf8ToPath(path).parent_path(), ec);
    if (ec) {
        LOG("[CompatFeed] create_directories failed: %s", ec.message().c_str());
        return false;
    }
    if (!FileUtil::AtomicWriteText(path, body)) {
        LOG("[CompatFeed] atomic write failed: %s", path.c_str());
        return false;
    }
    return true;
}

} // namespace CompatFeed
