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
    report.subsystems = {true, true, true, true};
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
          "local full, no feed, strict, not allowlisted");
    Check(Compat::Decide(LocalFull(), false, Status::Audit, true, true) == Status::Full,
          "local full, no feed, strict, allowlisted");
    Check(Compat::Decide(LocalFull(), true, Status::Full, true) == Status::Full,
          "local full, feed full");
    Check(Compat::IsAllowlisted(
              "e9045710ec7ee47d7b7488d1c5dda2d933dec7e251e965967a5c48f4df68eb4e"),
          "previous steamclient hash allowlisted");
    Check(Compat::IsAllowlisted(
              "253e0a11a4415b38c78a42f7bdd6ecc426455f06c1ba6453a48090df3142dbbc"),
          "current steamclient hash allowlisted");
    Check(!Compat::IsAllowlisted("deadbeef"), "unknown hash not allowlisted");

    const Compat::Subsystems all = Compat::DecideSubsystems(
        LocalFull(), false, Status::Audit, true, true);
    Check(all.All(), "allowlisted strict enables all subsystems");
    const Compat::Subsystems none = Compat::DecideSubsystems(
        LocalFull(), false, Status::Audit, true, false);
    Check(none.None(), "unknown strict build disables all subsystems");
    const Compat::Subsystems feedAudit = Compat::DecideSubsystems(
        LocalFull(), true, Status::Audit, false, true);
    Check(feedAudit.None(), "feed audit disables all subsystems");

    Compat::Report partial = LocalFull();
    partial.subsystems.manifest = false;
    const Compat::Subsystems partialResult = Compat::DecideSubsystems(
        partial, false, Status::Audit, true, true);
    Check(partialResult.cloud && !partialResult.manifest &&
              partialResult.playtime && partialResult.kv,
          "manifest failure disables only manifest");
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
    Check(json.find("\"subsystems\":{") != std::string::npos,
          "json subsystems object");
    Check(json.find("\"cloud\":true") != std::string::npos &&
              json.find("\"manifest\":true") != std::string::npos &&
              json.find("\"playtime\":true") != std::string::npos &&
              json.find("\"kv\":true") != std::string::npos,
          "json subsystems all true");
    Check(json.find("\"allowlisted\":false") != std::string::npos,
          "json allowlisted");

    if (g_failures) {
        std::fprintf(stderr, "compat_tests: %d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("compat_tests: 0 failures\n");
    return 0;
}
