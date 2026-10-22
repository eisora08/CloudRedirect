#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace SteamMessageLayout {

struct Layout {
    uint32_t header = 0;
    uint32_t body = 0;
    // Fields derived from the probed header. emsg/hdr follow the same +8 shift
    // as header/body when Steam grows CProtoBufMsgBase. desc/conn are only
    // known for the verified 0x30 header layout; zero means "do not use".
    uint32_t emsg = 0;
    uint32_t hdr = 0;
    uint32_t desc = 0;
    uint32_t conn = 0;
};

// Decode the wrapper accesses used by Steam itself, independently in the
// request/reply (slot 5) and notification (slot 8) adapters. October 2026 added
// eight bytes to CProtoBufMsgBase; reading the old body offset then serialized
// the header instead, silently losing the appid. Unknown layouts fail closed.
inline bool Resolve(const uint8_t* reply, size_t replySize,
                    const uint8_t* notify, size_t notifySize, Layout& out) {
    out = {};
    if (!reply || !notify) return false;
    Layout notification{};
    unsigned notificationMatches = 0;
    for (size_t i = 0; i + 8 <= notifySize; ++i) {
        // mov rax,[r8+header]; mov r8,[r8+body]
        if (notify[i] == 0x49 && notify[i+1] == 0x8B && notify[i+2] == 0x40 &&
            notify[i+4] == 0x4D && notify[i+5] == 0x8B && notify[i+6] == 0x40) {
            notification = {notify[i+3], notify[i+7]};
            ++notificationMatches;
        }
    }
    if (notificationMatches != 1 ||
        (notification.header != 0x28 && notification.header != 0x30) ||
        notification.body != notification.header + sizeof(uint64_t)) return false;

    unsigned bodyMatches = 0;
    bool headerMatches = false;
    for (size_t i = 0; i + 4 <= replySize; ++i) {
        // mov rax,[r8+header]
        if (reply[i] == 0x49 && reply[i+1] == 0x8B && reply[i+2] == 0x40 &&
            reply[i+3] == notification.header) headerMatches = true;
        // mov r9,[r9+body]; mov r8,[r8+body]; call [rax+0x20]
        if (i + 11 <= replySize &&
            reply[i] == 0x4D && reply[i+1] == 0x8B && reply[i+2] == 0x49 &&
            reply[i+3] == notification.body &&
            reply[i+4] == 0x4D && reply[i+5] == 0x8B && reply[i+6] == 0x40 &&
            reply[i+7] == notification.body &&
            reply[i+8] == 0xFF && reply[i+9] == 0x50 && reply[i+10] == 0x20)
            ++bodyMatches;
    }
    if (!headerMatches || bodyMatches != 1) return false;
    out = notification;
    // The EMsg word sits immediately before the header pointer. The header is
    // the same pointer field the adapters read. desc/conn are known for the
    // current 0x30 layout only; leaving them zero makes callers fail closed.
    out.emsg = out.header >= 8 ? out.header - 8 : 0;
    out.hdr = out.header;
    if (out.header == 0x30) {
        out.desc = 0x08;
        out.conn = 0x1C;
    }
    return true;
}

// A copied pointer avoids alignment/aliasing assumptions about wrapper storage.
inline void* Header(const void* wrapper, const Layout& layout) {
    void* result = nullptr;
    if (wrapper && layout.header)
        std::memcpy(&result, static_cast<const uint8_t*>(wrapper) + layout.header, sizeof(result));
    return result;
}
inline void* Body(const void* wrapper, const Layout& layout) {
    void* result = nullptr;
    if (wrapper && layout.body)
        std::memcpy(&result, static_cast<const uint8_t*>(wrapper) + layout.body, sizeof(result));
    return result;
}

} // namespace SteamMessageLayout
