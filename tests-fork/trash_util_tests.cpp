// Exercise the local delete trash without touching Steam or real saves.
#include "platform.h"
#include "trash_util.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace {

int g_failures = 0;

void Check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        ++g_failures;
    }
}

std::string ReadFile(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f),
                       std::istreambuf_iterator<char>());
}

std::filesystem::path FindOneFile(const std::filesystem::path& root) {
    std::error_code ec;
    for (std::filesystem::recursive_directory_iterator it(root, ec), end;
         !ec && it != end; it.increment(ec)) {
        if (it->is_regular_file(ec) && !ec) return it->path();
    }
    return {};
}

} // namespace

int main() {
    std::error_code ec;
    const auto base = std::filesystem::temp_directory_path(ec) /
                      "cloudredirect_trash_test";
    if (ec) {
        std::fprintf(stderr, "FAIL: temp_directory_path: %s\n", ec.message().c_str());
        return 1;
    }
    std::filesystem::remove_all(base, ec);
    std::filesystem::create_directories(base, ec);
    if (ec) {
        std::fprintf(stderr, "FAIL: create base: %s\n", ec.message().c_str());
        return 1;
    }

    const auto trash = base / "trash";
    std::string trashUtf8 = Platform().PathToUtf8(trash) +
                            Platform().PathSeparator();
    const auto source = base / "storage" / "1" / "2" / "save.sav";
    std::filesystem::create_directories(source.parent_path(), ec);
    {
        std::ofstream f(source, std::ios::binary);
        f << "save-data";
    }

    const std::string sourceUtf8 = Platform().PathToUtf8(source);
    Check(TrashUtil::Move(trashUtf8, sourceUtf8, "1/2/save.sav"),
          "move existing file to trash");
    Check(!std::filesystem::exists(source), "source removed after trash move");

    const auto trashedFile = FindOneFile(trash);
    Check(!trashedFile.empty(), "trashed file exists");
    Check(ReadFile(trashedFile) == "save-data", "trashed content preserved");

    // Fresh trash is retained; old trash is pruned.
    TrashUtil::Prune(trashUtf8, 30);
    Check(std::filesystem::exists(trashedFile), "fresh trash retained");
    std::filesystem::last_write_time(
        trashedFile,
        std::filesystem::file_time_type::clock::now() -
            std::chrono::hours(24 * 40), ec);
    Check(!ec, "set old mtime");
    TrashUtil::Prune(trashUtf8, 30);
    Check(!std::filesystem::exists(trashedFile), "old trash pruned");

    // A traversal-shaped relative path must not move the source out of trash.
    const auto source2 = base / "storage" / "1" / "2" / "other.sav";
    {
        std::ofstream f(source2, std::ios::binary);
        f << "other";
    }
    const std::string source2Utf8 = Platform().PathToUtf8(source2);
    Check(!TrashUtil::Move(trashUtf8, source2Utf8, "../../escape.sav"),
          "traversal rel path rejected");
    Check(std::filesystem::exists(source2), "source kept when trash fails");

    std::filesystem::remove_all(base, ec);
    std::printf("trash_util_tests: %s\n", g_failures == 0 ? "ok" : "FAILED");
    return g_failures == 0 ? 0 : 1;
}
