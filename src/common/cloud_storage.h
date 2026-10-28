#pragma once
#include "cloud_provider.h"
#include "cloud_work_queue.h"
#include "local_storage.h"
#include "local_metadata_store.h"
#include "manifest_store.h"
#include "token_store.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <atomic>
#include <unordered_map>
#include <unordered_set>

namespace CloudStorage {

struct CloudAppState; // defined in app_state.h

void Init(const std::string& localRoot, std::unique_ptr<ICloudProvider> provider);
void Shutdown();
bool IsCloudActive();

bool StoreBlob(uint32_t accountId, uint32_t appId,
               const std::string& filename,
               const uint8_t* data, size_t len);

bool StoreBlobStaged(uint32_t accountId, uint32_t appId, uint64_t batchId,
                     const std::string& filename,
                     const uint8_t* data, size_t len);

// Cloud-first when active; returns empty if not found.
// Sets *found=true if the blob exists (even if 0 bytes).
// expectedShaHex: cloud SHA; skip network if local cache matches.
std::vector<uint8_t> RetrieveBlob(uint32_t accountId, uint32_t appId,
                                   const std::string& filename,
                                   bool* found = nullptr,
                                   const std::string& expectedShaHex = {});

bool DeleteBlob(uint32_t accountId, uint32_t appId,
                const std::string& filename);
bool DeleteBlobStaged(uint32_t accountId, uint32_t appId,
                      const std::string& filename);

// CN must not advance unless this succeeds.
bool PromoteStagedBatchForCommit(uint32_t accountId, uint32_t appId,
                                 uint64_t batchId,
                                 const std::vector<std::string>& uploads,
                                 const std::vector<std::string>& deletes);

// Verify CAS blobs are durable before publishing; heals or drops phantoms.
// Returns false only when blob listing is unavailable.
bool VerifyAndHealManifestForPublish(uint32_t accountId, uint32_t appId,
                                     CloudAppState& state);

std::vector<uint64_t> ListStagedBatchIds(uint32_t accountId, uint32_t appId);
bool RemoveStagedBatch(uint32_t accountId, uint32_t appId, uint64_t batchId);

ICloudProvider::ExistsStatus CheckBlobExists(uint32_t accountId, uint32_t appId,
                                             const std::string& filename);

// Local-only mode returns true with an empty set.
bool ListRemoteBlobNames(uint32_t accountId, uint32_t appId,
                         std::unordered_set<std::string>& outNames);

bool HasLocalBlob(uint32_t accountId, uint32_t appId,
                   const std::string& filename);

// Fire-and-forget: start the blobs/ listing in the background so the publish
// path can await a listing that is already in flight instead of issuing its own
// inside the ack-critical window. Safe to call every BeginBatch; duplicate
// in-flight listings for the same app are collapsed.
void PrefetchBlobListing(uint32_t accountId, uint32_t appId);

// Keep the listing cache warm (< 60s TTL) while an app's cloud session is
// active: re-prefetches every ~50s so publish-time verification finds a fresh
// listing instead of listing inline. Read-only, idempotent; Stop on session
// release (and automatically on shutdown).
void StartBlobListingRefresher(uint32_t accountId, uint32_t appId);
void StopBlobListingRefresher(uint32_t accountId, uint32_t appId);

// GC: delete unreferenced blobs. Returns count deleted, or -1 on error.
int GarbageCollectBlobs(uint32_t accountId, uint32_t appId);

bool SyncFromCloud(uint32_t accountId, uint32_t appId);
std::vector<uint32_t> SyncAllFromCloud(uint32_t accountId);

// Pauses background uploads so foreground SyncFromCloud doesn't queue behind sweeps.
struct ForegroundSyncScope {
    ForegroundSyncScope();
    ~ForegroundSyncScope();
    ForegroundSyncScope(const ForegroundSyncScope&)            = delete;
    ForegroundSyncScope& operator=(const ForegroundSyncScope&) = delete;
};

void NotifyAuthFailure(const std::string& providerName);

// True once ShutdownProvider is called; checked between retry iterations.
bool IsShuttingDown();

// Internal: shared with manifest_store.cpp and token_store.cpp.
struct InflightSyncScope {
    bool entered = false;
    InflightSyncScope();
    ~InflightSyncScope();
    explicit operator bool() const { return entered; }
    InflightSyncScope(const InflightSyncScope&) = delete;
    InflightSyncScope& operator=(const InflightSyncScope&) = delete;
};
std::string CloudMetadataPath(uint32_t accountId, uint32_t appId, const std::string& name);
bool DownloadCloudMetadataWithLegacyFallback(uint32_t accountId, uint32_t appId,
    const char* canonicalName, const char* legacyName,
    std::vector<uint8_t>& outData, bool* outUsedLegacy = nullptr);
enum class MetadataFetch { Ok, Missing, Error };
MetadataFetch FetchCloudMetadataStatus(uint32_t accountId, uint32_t appId,
    const char* canonicalName, std::vector<uint8_t>& outData);
// Download the first-format per-app playtime blob (account-scope
// <acct>/0/blobs/Playtime/<appId>.bin). False if absent/unavailable. Migration-only.
bool DownloadLegacyPlaytimeBlob(uint32_t accountId, uint32_t appId,
    std::vector<uint8_t>& outData);
// Fetch the legacy per-app stats blobs (<accountId>/<appId>/stats.json) of the
// given apps in a single provider search, as appId -> content; only those blobs
// are downloaded. False when the provider has no server-side search or the
// search failed. *outComplete is true only when the provider vouched that the
// listing is authoritative (an app absent from it has no such blob). Migration-only.
bool ListLegacyStatsBlobs(uint32_t accountId, const std::vector<uint32_t>& appIds,
    std::unordered_map<uint32_t, std::string>& out, bool* outComplete = nullptr);
bool UploadCloudMetadataText(uint32_t accountId, uint32_t appId,
    const char* name, const std::string& content);
// Queued (thread-safe) variant: serializes on the cloud work queue.
void UploadCloudMetadataTextAsync(uint32_t accountId, uint32_t appId,
    const char* name, const std::string& content);
void RemoveCloudMetadataIfPresent(uint32_t accountId, uint32_t appId, const char* name);
void RemoveLegacyCloudMetadataIfCanonicalExists(uint32_t accountId, uint32_t appId,
    const char* canonicalName, const char* legacyName);
std::string CanonicalizeInternalMetadataName(std::string_view filename);
bool ParseCloudBlobPath(const std::string& cloudPath,
    uint32_t& accountId, uint32_t& appId, std::string& filename);
std::shared_ptr<std::mutex> AcquireAppSyncMutex(uint32_t accountId, uint32_t appId);

} // namespace CloudStorage
