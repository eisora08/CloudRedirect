cmake_minimum_required(VERSION 3.20)
project(CloudRedirect LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ── Read version from Version.props ─────────────────────────────────────
file(READ "${CMAKE_SOURCE_DIR}/Version.props" VERSION_PROPS_CONTENT)
string(REGEX MATCH "<ReleaseVersion>([^<]+)</ReleaseVersion>" _ "${VERSION_PROPS_CONTENT}")
set(CR_RELEASE_VERSION "${CMAKE_MATCH_1}")
if(NOT DEFINED CR_PRERELEASE)
    string(REGEX MATCH "<ReleasePrerelease>([^<]*)</ReleasePrerelease>" _ "${VERSION_PROPS_CONTENT}")
    set(CR_PRERELEASE "${CMAKE_MATCH_1}")
endif()

if(NOT CR_RELEASE_VERSION)
    set(CR_RELEASE_VERSION "0.0.0")
endif()
set(CR_RELEASE_VERSION "${CR_RELEASE_VERSION}${CR_PRERELEASE}")

# ── Generate version string with git SHA ────────────────────────────────
# Release builds may pass -DCR_GIT_SHA to pin the build id (e.g. when the build
# runs in a sandbox whose worktree shows spurious eol-only diffs).
if(NOT DEFINED CR_GIT_SHA)
    execute_process(
        COMMAND git rev-parse --short=7 HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_SHA
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE GIT_RESULT
    )
    if(NOT GIT_RESULT EQUAL 0)
        set(GIT_SHA "unknown")
    endif()

    execute_process(
        COMMAND git status --porcelain
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_STATUS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(GIT_STATUS)
        set(GIT_SHA "${GIT_SHA}-dirty")
    endif()
else()
    set(GIT_SHA "${CR_GIT_SHA}")
endif()

set(CR_SO_VERSION "${CR_RELEASE_VERSION}+${GIT_SHA}")

# ── Common sources (platform-agnostic) ──────────────────────────────────

set(COMMON_SOURCES
    src/common/protobuf.cpp
    src/common/json.cpp
    src/common/coop_yield.cpp
    src/common/vdf.cpp
    src/common/remotecache_repair.cpp
    src/common/manifest_store.cpp
    src/common/app_state.cpp
    src/common/token_store.cpp
    src/common/batch_tracker.cpp
    src/common/cloud_staging.cpp
    src/common/pending_ops_journal.cpp
    src/common/rpc_handlers.cpp
    src/common/batch_merge.cpp
    src/common/cloud_work_queue.cpp
    src/common/cloud_storage.cpp
    src/common/local_storage.cpp
    src/common/local_metadata_store.cpp
    src/common/legacy_metadata_cleanup.cpp
    src/common/cloud_provider_base.cpp
    src/common/sigv4.cpp
    src/common/sha256_hmac.cpp
    src/common/autocloud_scan.cpp
    src/common/steam_kv_injector.cpp
    src/common/parental_bypass.cpp
    src/common/metadata_sync.cpp
    src/common/stats_store.cpp
    src/common/stats_handlers.cpp
    src/common/miniz.c
    src/common/miniz_tdef.c
    src/common/miniz_tinfl.c
    src/common/miniz_zip.c
)

# ── Platform-specific sources ───────────────────────────────────────────

set(PROVIDER_SOURCES
    src/providers/google_drive.cpp
    src/providers/onedrive.cpp
    src/providers/local_disk_provider.cpp
    src/providers/s3_provider.cpp
    src/providers/r2_provider.cpp
)

if(WIN32)
    set(PLATFORM_SOURCES
        src/platform/win/dllmain.cpp
        src/platform/win/cr_api.cpp
        src/platform/win/cloud_intercept.cpp
        src/platform/win/sig_scanner.cpp
        src/platform/win/sc_resolver.cpp
        src/platform/win/compat.cpp
        src/platform/win/compat_feed.cpp
        src/platform/win/log.cpp
        src/platform/win/http_server.cpp
        src/platform/win/http_util.cpp
        src/platform/win/http_transport_win.cpp
        src/platform/win/token_store_win.cpp
        src/platform/win/platform_win.cpp
    )
else()
    set(PLATFORM_SOURCES
        src/platform/linux/init.cpp
        src/platform/linux/vtable_hook.cpp
        src/platform/linux/cloud_hooks.cpp
        src/platform/linux/cloud_intercept.cpp
        src/platform/linux/stats_hooks.cpp
        src/platform/linux/stats_store_hook.cpp
        src/platform/linux/gamesplayed_hook.cpp
        src/platform/linux/live_playtime.cpp
        src/platform/linux/http_transport_linux.cpp
        src/platform/linux/token_store_linux.cpp
        src/platform/linux/log.cpp
        src/platform/linux/http_server.cpp
        src/platform/linux/http_util.cpp
        src/platform/linux/platform_linux.cpp
        src/platform/linux/file_util.cpp
    )
endif()

# ── Build target ────────────────────────────────────────────────────────

add_library(cloud_redirect SHARED
    ${COMMON_SOURCES}
    ${PLATFORM_SOURCES}
    ${PROVIDER_SOURCES}
)

set_target_properties(cloud_redirect PROPERTIES PREFIX "")

target_include_directories(cloud_redirect PRIVATE
    src/common
    src/providers
)

target_compile_definitions(cloud_redirect PRIVATE
    MINIZ_NO_STDIO
    CR_VERSION_STRING="${CR_SO_VERSION}"
    CR_RELEASE_VERSION="${CR_RELEASE_VERSION}"
)

if(WIN32)
    target_include_directories(cloud_redirect PRIVATE src/platform/win)
    target_link_libraries(cloud_redirect PRIVATE
        Shlwapi Advapi32 ws2_32 winhttp Crypt32 Shell32 Ole32 Psapi
    )
else()
    target_include_directories(cloud_redirect PRIVATE src/platform/linux)
    target_link_libraries(cloud_redirect PRIVATE dl pthread)
    # Steam on Linux is 32-bit; use LINUX_32BIT=ON when cross-compiling on 64-bit host
    # Match Steam's pre-C++11 ABI
    target_compile_definitions(cloud_redirect PRIVATE _GLIBCXX_USE_CXX11_ABI=0 _FILE_OFFSET_BITS=64)
    target_compile_options(cloud_redirect PRIVATE -fvisibility=hidden)
    set_target_properties(cloud_redirect PROPERTIES C_VISIBILITY_PRESET hidden CXX_VISIBILITY_PRESET hidden)
    if(LINUX_32BIT)
        target_compile_options(cloud_redirect PRIVATE -m32)
        target_link_options(cloud_redirect PRIVATE -m32)

        if(NOT DEFINED DEPS32_PREFIX)
            set(DEPS32_PREFIX "${CMAKE_SOURCE_DIR}/deps/install32")
        endif()
        set(DEPS32 "${DEPS32_PREFIX}")
        target_include_directories(cloud_redirect PRIVATE "${DEPS32}/include")
        target_link_libraries(cloud_redirect PRIVATE
            "${DEPS32}/lib/libcurl.a"
            "${DEPS32}/lib/libssl.a"
            "${DEPS32}/lib/libcrypto.a"
        )
        # Hide static curl/OpenSSL symbols so they can't be interposed.
        target_link_options(cloud_redirect PRIVATE -Wl,--exclude-libs,ALL)
        target_link_libraries(cloud_redirect PRIVATE atomic)
        # Fix multilib include path for i686 libstdc++ headers on Fedora
        # Try to detect GCC version for correct path
        execute_process(
            COMMAND ${CMAKE_CXX_COMPILER} -dumpversion
            OUTPUT_VARIABLE GCC_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        string(REGEX MATCH "^[0-9]+" GCC_MAJOR "${GCC_VERSION}")
        target_include_directories(cloud_redirect SYSTEM BEFORE PRIVATE
            /usr/include/c++/${GCC_MAJOR}/i686-redhat-linux
        )
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
        # Cross-compiling 32-bit on 64-bit: find the multilib atomic
        find_library(LIBATOMIC_32 NAMES atomic
            PATHS /usr/lib/gcc/x86_64-redhat-linux/16/32
                  /usr/lib/gcc/x86_64-redhat-linux/14/32
                  /usr/lib/gcc/x86_64-linux-gnu/13/32
                  /usr/lib/gcc/x86_64-linux-gnu/12/32
                  /usr/lib/gcc/x86_64-linux-gnu/11/32
                  /usr/lib/i386-linux-gnu
                  /usr/lib32
            NO_DEFAULT_PATH)
        if(LIBATOMIC_32)
            target_link_libraries(cloud_redirect PRIVATE ${LIBATOMIC_32})
        else()
            target_link_libraries(cloud_redirect PRIVATE atomic)
        endif()
    endif()
    # Strip in release
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_options(cloud_redirect PRIVATE -s)
    endif()
endif()

# ── Tests ───────────────────────────────────────────────────────────────

enable_testing()

# pending_ops_journal_tests (upstream test file, kept by the fork; moved into
# tests-fork/) covers the upload journal the anti-loss paths depend on.
add_executable(pending_ops_journal_tests
    tests-fork/pending_ops_journal_tests.cpp
    src/common/pending_ops_journal.cpp
    src/common/json.cpp
)
target_include_directories(pending_ops_journal_tests PRIVATE src/common)
target_compile_definitions(pending_ops_journal_tests PRIVATE
    CR_RELEASE_VERSION="${CR_RELEASE_VERSION}")
if(WIN32)
    target_include_directories(pending_ops_journal_tests PRIVATE src/platform/win)
    target_sources(pending_ops_journal_tests PRIVATE src/platform/win/log.cpp src/platform/win/platform_win.cpp)
else()
    target_include_directories(pending_ops_journal_tests PRIVATE src/platform/linux)
    target_sources(pending_ops_journal_tests PRIVATE src/platform/linux/log.cpp src/platform/linux/platform_linux.cpp)
endif()
add_test(NAME pending_ops_journal_tests COMMAND pending_ops_journal_tests)

# Local delete trash: move, retention prune, and traversal rejection.
add_executable(trash_util_tests tests-fork/trash_util_tests.cpp)
target_include_directories(trash_util_tests PRIVATE src/common)
target_compile_definitions(trash_util_tests PRIVATE
    CR_RELEASE_VERSION="${CR_RELEASE_VERSION}")
if(WIN32)
    target_include_directories(trash_util_tests PRIVATE src/platform/win)
    target_sources(trash_util_tests PRIVATE
        src/platform/win/log.cpp
        src/platform/win/platform_win.cpp)
else()
    target_include_directories(trash_util_tests PRIVATE src/platform/linux)
    target_sources(trash_util_tests PRIVATE
        src/platform/linux/log.cpp
        src/platform/linux/platform_linux.cpp)
endif()
add_test(NAME trash_util_tests COMMAND trash_util_tests)

# ── Fork tests (tests-fork/) ────────────────────────────────────────────
add_executable(steam_message_layout_tests tests-fork/steam_message_layout_tests.cpp)
target_include_directories(steam_message_layout_tests PRIVATE src/platform/win)
add_test(NAME steam_message_layout_tests COMMAND steam_message_layout_tests)

add_executable(steam_resolver_tests tests-fork/steam_resolver_tests.cpp)
target_include_directories(steam_resolver_tests PRIVATE src/platform/win)
if(WIN32)
    target_sources(steam_resolver_tests PRIVATE
        src/platform/win/sc_resolver.cpp src/platform/win/sig_scanner.cpp)
endif()
add_test(NAME steam_resolver_tests COMMAND steam_resolver_tests)

if(WIN32)
    add_executable(compat_tests
        tests-fork/compat_tests.cpp
        src/platform/win/compat.cpp
        src/platform/win/sig_scanner.cpp
        src/common/json.cpp
    )
    target_include_directories(compat_tests PRIVATE
        src/common
        src/platform/win
    )
    add_test(NAME compat_tests COMMAND compat_tests)
endif()

# Standalone compatibility checker consumed by the local steam-monitor watcher.
# It maps steamclient64.dll without imports or DllMain and never installs hooks.
if(WIN32)
    add_executable(cr_compat_check
        src/platform/win/cr_compat_check.cpp
        src/platform/win/compat.cpp
        src/platform/win/sc_resolver.cpp
        src/platform/win/sig_scanner.cpp
        src/common/json.cpp
        src/common/sha256_hmac.cpp
    )
    target_include_directories(cr_compat_check PRIVATE
        src/common
        src/platform/win
    )
endif()

add_executable(autocloud_injection_tests tests-fork/autocloud_injection_tests.cpp)
target_include_directories(autocloud_injection_tests PRIVATE src/common)
if(WIN32)
    target_include_directories(autocloud_injection_tests PRIVATE src/platform/win)
else()
    target_include_directories(autocloud_injection_tests PRIVATE src/platform/linux)
    if(LINUX_32BIT)
        target_compile_options(autocloud_injection_tests PRIVATE -m32)
        target_link_options(autocloud_injection_tests PRIVATE -m32)
    endif()
endif()
add_test(NAME autocloud_injection_tests COMMAND autocloud_injection_tests)

if(NOT WIN32 AND (LINUX_32BIT OR CMAKE_SIZEOF_VOID_P EQUAL 4))
    add_library(sls_hook_fixture SHARED tests-fork/sls_hook_fixture.cpp)
    set_target_properties(sls_hook_fixture PROPERTIES PREFIX "" OUTPUT_NAME "SLSsteam"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/hook-test-fixture")
    add_executable(stats_store_hook_tests tests-fork/stats_store_hook_tests.cpp)
    target_include_directories(stats_store_hook_tests PRIVATE src/common src/platform/linux)
    target_link_libraries(stats_store_hook_tests PRIVATE dl pthread)
    if(LINUX_32BIT)
        foreach(test_target sls_hook_fixture stats_store_hook_tests)
            target_compile_options(${test_target} PRIVATE -m32)
            target_link_options(${test_target} PRIVATE -m32)
        endforeach()
    endif()
    add_dependencies(stats_store_hook_tests sls_hook_fixture)
    add_test(NAME stats_store_hook_tests COMMAND stats_store_hook_tests $<TARGET_FILE:sls_hook_fixture>)
endif()

# Pure-logic regression tests for the cross-device playtime merge and the
# GetUserStats answer (versioned in tests-fork/ and run by CI).
if(EXISTS ${CMAKE_SOURCE_DIR}/tests-fork/stats_store_fork_tests.cpp)
    add_executable(stats_store_fork_tests
        tests-fork/stats_store_fork_tests.cpp
        src/common/stats_store.cpp
        src/common/stats_handlers.cpp
        src/common/protobuf.cpp
        src/common/json.cpp
        src/common/metadata_sync.cpp
        src/common/vdf.cpp
    )
    target_include_directories(stats_store_fork_tests PRIVATE src/common)
    target_compile_definitions(stats_store_fork_tests PRIVATE CR_RELEASE_VERSION="${CR_RELEASE_VERSION}")
    if(WIN32)
        target_include_directories(stats_store_fork_tests PRIVATE src/platform/win)
        target_sources(stats_store_fork_tests PRIVATE
            src/platform/win/log.cpp
            src/platform/win/platform_win.cpp
        )
        target_link_libraries(stats_store_fork_tests PRIVATE Shlwapi Advapi32 Crypt32 Shell32 Ole32)
    else()
        target_include_directories(stats_store_fork_tests PRIVATE src/platform/linux)
        target_sources(stats_store_fork_tests PRIVATE
            src/platform/linux/log.cpp
            src/platform/linux/platform_linux.cpp
            src/platform/linux/file_util.cpp
        )
        target_link_libraries(stats_store_fork_tests PRIVATE pthread dl)
    endif()
    add_test(NAME stats_store_fork_tests COMMAND stats_store_fork_tests)
endif()

# The upstream WPF UI (`ui/`) and Qt UI (`ui-linux/`) are intentionally not
# maintained in this fork: it ships only the native binaries (DLL/.so).
