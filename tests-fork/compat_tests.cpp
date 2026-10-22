#include "compat.h"

#include <cstdio>
#include <cstdarg>
#include <string>

namespace Log {
void Write(const char*, ...) {}
}

namespace {

int g_failures = 0;

void Check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        ++g_failures;
    }
}

Compat::Report LocalFull() {
    Compat::Report report;
    report.status = Compat::Status::Full;
    return report;
}

} // namespace

int main() {
    using Compat::Status;

    Check(Compat::ParseStatus("full") == Status::Full, "parse full");
    Check(Compat::ParseStatus("unverified") == Status::Unverified, "parse unverified");
    Check(Compat::ParseStatus("audit") == Status::Audit, "parse audit");
    Check(Compat::ParseStatus("blocked") == Status::Blocked, "parse blocked");
    Check(Compat::ParseStatus("garbage") == Status::Audit, "parse unknown -> audit");

    Check(Compat::Decide(LocalFull(), false, Status::Audit, false) == Status::Full,
          "local full, no feed, lenient");
    Check(Compat::Decide(LocalFull(), false, Status::Audit, true) == Status::Unverified,
          "local full, no feed, strict");
    Check(Compat::Decide(LocalFull(), true, Status::Full, true) == Status::Full,
          "local full, feed full");
    Check(Compat::Decide(LocalFull(), true, Status::Audit, false) == Status::Audit,
          "feed audit wins");
    Check(Compat::Decide(LocalFull(), true, Status::Blocked, false) == Status::Blocked,
          "feed blocked wins");

    Compat::Report audited;
    audited.status = Status::Audit;
    Check(Compat::Decide(audited, true, Status::Full, false) == Status::Audit,
          "local audit cannot be upgraded by feed");

    Compat::Report report = LocalFull();
    report.sha256 = "abc";
    report.channel = "stable";
    const std::string json = Compat::ToJson(report);
    Check(json.find("\"status\":\"full\"") != std::string::npos, "json status");
    Check(json.find("\"schema\":1") != std::string::npos, "json schema");

    if (g_failures) {
        std::fprintf(stderr, "compat_tests: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("compat_tests: 0 failures\n");
    return 0;
}
