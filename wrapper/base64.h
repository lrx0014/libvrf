#ifndef FRAMEWORK_BASE64_H
#define FRAMEWORK_BASE64_H

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <span>

namespace base64 {

// RFC 4648 Base64 encode
std::string encode(std::span<const std::byte> data);

// RFC 4648 Base64 decode; throws std::invalid_argument on malformed input.
std::vector<std::byte> decode(std::string_view s);

} // namespace base64

#endif // FRAMEWORK_BASE64_H
