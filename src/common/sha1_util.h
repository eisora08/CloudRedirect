#pragma once
// Streaming SHA-1 for files. The platform SHA1() helpers take a whole buffer;
// save files can be much larger than memory, so file hashing must be
// incremental. The digest is byte-for-byte compatible with SHA1().

#include "platform.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace Sha1Util {

class Sha1 {
public:
    Sha1() { Reset(); }

    void Reset() {
        h_[0] = 0x67452301u;
        h_[1] = 0xEFCDAB89u;
        h_[2] = 0x98BADCFEu;
        h_[3] = 0x10325476u;
        h_[4] = 0xC3D2E1F0u;
        totalBytes_ = 0;
        bufLen_ = 0;
    }

    void Update(const void* data, size_t len) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        totalBytes_ += len;
        while (len > 0) {
            const size_t take = (len < (sizeof(buf_) - bufLen_))
                                    ? len : (sizeof(buf_) - bufLen_);
            for (size_t i = 0; i < take; ++i) buf_[bufLen_ + i] = p[i];
            bufLen_ += take;
            p += take;
            len -= take;
            if (bufLen_ == sizeof(buf_)) {
                Block(buf_);
                bufLen_ = 0;
            }
        }
    }

    std::array<uint8_t, 20> Final() {
        const uint64_t bitLen = totalBytes_ * 8u;
        const uint8_t pad = 0x80;
        UpdateRaw(&pad, 1);
        const uint8_t zero = 0;
        while (bufLen_ != 56) UpdateRaw(&zero, 1);
        uint8_t lenBytes[8];
        for (int i = 7; i >= 0; --i) {
            lenBytes[i] = static_cast<uint8_t>(bitLen >> ((7 - i) * 8));
        }
        UpdateRaw(lenBytes, sizeof(lenBytes));

        std::array<uint8_t, 20> out{};
        for (int i = 0; i < 5; ++i) {
            out[i * 4 + 0] = static_cast<uint8_t>(h_[i] >> 24);
            out[i * 4 + 1] = static_cast<uint8_t>(h_[i] >> 16);
            out[i * 4 + 2] = static_cast<uint8_t>(h_[i] >> 8);
            out[i * 4 + 3] = static_cast<uint8_t>(h_[i]);
        }
        return out;
    }

private:
    // Padding must not update totalBytes_: Final() captured the real length.
    void UpdateRaw(const void* data, size_t len) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        while (len > 0) {
            const size_t take = (len < (sizeof(buf_) - bufLen_))
                                    ? len : (sizeof(buf_) - bufLen_);
            for (size_t i = 0; i < take; ++i) buf_[bufLen_ + i] = p[i];
            bufLen_ += take;
            p += take;
            len -= take;
            if (bufLen_ == sizeof(buf_)) {
                Block(buf_);
                bufLen_ = 0;
            }
        }
    }

    static uint32_t Rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    void Block(const uint8_t* p) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(p[i * 4 + 0]) << 24) |
                   (static_cast<uint32_t>(p[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(p[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(p[i * 4 + 3]));
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = Rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f = 0, k = 0;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999u;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1u;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCu;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6u;
            }
            const uint32_t temp = Rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = Rotl(b, 30);
            b = a;
            a = temp;
        }
        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
    }

    uint32_t h_[5];
    uint64_t totalBytes_;
    uint8_t buf_[64];
    size_t bufLen_;
};

inline std::vector<uint8_t> Digest(const void* data, size_t len) {
    Sha1 sha;
    sha.Update(data, len);
    const auto digest = sha.Final();
    return std::vector<uint8_t>(digest.begin(), digest.end());
}

// Hash a path incrementally. Returns empty on open/read error.
// maxBytes limits how much is read; outTruncated is set when the file has more.
inline std::vector<uint8_t> File(const std::filesystem::path& path,
                                 uint64_t maxBytes = (std::numeric_limits<uint64_t>::max)(),
                                 uint64_t* outBytesRead = nullptr,
                                 bool* outTruncated = nullptr) {
    if (outBytesRead) *outBytesRead = 0;
    if (outTruncated) *outTruncated = false;

    std::ifstream f(path, std::ios::binary);
    if (!f) return {};

    Sha1 sha;
    std::vector<char> buf(1u << 20);
    uint64_t total = 0;
    while (f) {
        size_t want = buf.size();
        if (maxBytes != (std::numeric_limits<uint64_t>::max)()) {
            if (total >= maxBytes) {
                // Only a real extra byte means the read was truncated. Do not
                // flag a file whose size is exactly maxBytes.
                if (outTruncated && f.peek() != std::char_traits<char>::eof())
                    *outTruncated = true;
                break;
            }
            const uint64_t remaining = maxBytes - total;
            if (remaining < want) want = static_cast<size_t>(remaining);
        }
        if (want == 0) break;
        f.read(buf.data(), static_cast<std::streamsize>(want));
        const std::streamsize got = f.gcount();
        if (got > 0) {
            sha.Update(buf.data(), static_cast<size_t>(got));
            total += static_cast<uint64_t>(got);
        }
        if (got < static_cast<std::streamsize>(want)) break;
    }
    if (f.bad()) return {};
    if (outBytesRead) *outBytesRead = total;
    const auto digest = sha.Final();
    return std::vector<uint8_t>(digest.begin(), digest.end());
}

// UTF-8 overload used by the product code.
inline std::vector<uint8_t> File(const std::string& utf8Path,
                                 uint64_t maxBytes = (std::numeric_limits<uint64_t>::max)(),
                                 uint64_t* outBytesRead = nullptr,
                                 bool* outTruncated = nullptr) {
    return File(Platform().Utf8ToPath(utf8Path), maxBytes, outBytesRead, outTruncated);
}

} // namespace Sha1Util
