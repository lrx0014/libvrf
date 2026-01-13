#include "base64.h"

#include <cstdint>
#include <stdexcept>

namespace {
constexpr char kB64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
} // namespace

namespace base64 {

std::string encode(std::span<const std::byte> data) {
    if (data.empty()) return {};

    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 3 <= data.size()) {
        const uint32_t n =
            (static_cast<uint32_t>(data[i + 0]) & 0xFFu) << 16 |
            (static_cast<uint32_t>(data[i + 1]) & 0xFFu) << 8  |
            (static_cast<uint32_t>(data[i + 2]) & 0xFFu);

        out.push_back(kB64Alphabet[(n >> 18) & 0x3Fu]);
        out.push_back(kB64Alphabet[(n >> 12) & 0x3Fu]);
        out.push_back(kB64Alphabet[(n >> 6)  & 0x3Fu]);
        out.push_back(kB64Alphabet[n & 0x3Fu]);
        i += 3;
    }

    const std::size_t rem = data.size() - i;
    if (rem == 1) {
        const uint32_t n = (static_cast<uint32_t>(data[i]) & 0xFFu) << 16;
        out.push_back(kB64Alphabet[(n >> 18) & 0x3Fu]);
        out.push_back(kB64Alphabet[(n >> 12) & 0x3Fu]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        const uint32_t n =
            (static_cast<uint32_t>(data[i]) & 0xFFu) << 16 |
            (static_cast<uint32_t>(data[i + 1]) & 0xFFu) << 8;
        out.push_back(kB64Alphabet[(n >> 18) & 0x3Fu]);
        out.push_back(kB64Alphabet[(n >> 12) & 0x3Fu]);
        out.push_back(kB64Alphabet[(n >> 6)  & 0x3Fu]);
        out.push_back('=');
    }
    return out;
}

std::vector<std::byte> decode(std::string_view s) {
    std::string cleaned;
    cleaned.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '\r' || c == '\n' || c == '\t' || c == ' ') continue;
        cleaned.push_back(static_cast<char>(c));
    }
    if (cleaned.empty()) return {};
    if (cleaned.size() % 4 != 0) {
        throw std::invalid_argument("Base64: invalid length");
    }

    std::vector<std::byte> out;
    out.reserve((cleaned.size() / 4) * 3);

    for (std::size_t i = 0; i < cleaned.size(); i += 4) {
        const unsigned char c0 = cleaned[i + 0];
        const unsigned char c1 = cleaned[i + 1];
        const unsigned char c2 = cleaned[i + 2];
        const unsigned char c3 = cleaned[i + 3];

        const int v0 = b64_val(c0);
        const int v1 = b64_val(c1);
        const int v2 = (c2 == '=') ? 0 : b64_val(c2);
        const int v3 = (c3 == '=') ? 0 : b64_val(c3);

        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
            throw std::invalid_argument("Base64: invalid character");
        }

        const uint32_t n =
            (static_cast<uint32_t>(v0) << 18) |
            (static_cast<uint32_t>(v1) << 12) |
            (static_cast<uint32_t>(v2) << 6)  |
            static_cast<uint32_t>(v3);

        out.push_back(static_cast<std::byte>((n >> 16) & 0xFFu));
        if (c2 != '=') out.push_back(static_cast<std::byte>((n >> 8) & 0xFFu));
        if (c3 != '=') out.push_back(static_cast<std::byte>(n & 0xFFu));
    }

    return out;
}

} // namespace base64
