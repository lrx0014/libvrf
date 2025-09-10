#pragma once

#include <cstddef>

namespace vrf
{

struct RSATag
{
};

struct ECTag
{
};

enum class Type : std::size_t
{
    RSASSA_FDH_VRF_RSA2048_SHA256,
    RSASSA_FDH_VRF_RSA3072_SHA256,
    RSASSA_FDH_VRF_RSA4096_SHA512,
    RSASSA_FDH_VRF_RSA8192_SHA512,
    RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256,
    RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256,
    RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512,
    RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512,
    UNKNOWN_VRF_TYPE
};

inline constexpr bool is_rsa_type(Type type)
{
    return type == Type::RSASSA_FDH_VRF_RSA2048_SHA256 || type == Type::RSASSA_FDH_VRF_RSA3072_SHA256 ||
           type == Type::RSASSA_FDH_VRF_RSA4096_SHA512 || type == Type::RSASSA_FDH_VRF_RSA8192_SHA512 ||
           type == Type::RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256 || type == Type::RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256 ||
           type == Type::RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512 || type == Type::RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512;
}

inline constexpr bool is_ec_type(Type type)
{
    // Not implemented.
    return false;
}

inline constexpr const char *type_to_string(Type type)
{
    switch (type)
    {
    case Type::RSASSA_FDH_VRF_RSA2048_SHA256:
        return "RSASSA_FDH_VRF_RSA2048_SHA256";
    case Type::RSASSA_FDH_VRF_RSA3072_SHA256:
        return "RSASSA_FDH_VRF_RSA3072_SHA256";
    case Type::RSASSA_FDH_VRF_RSA4096_SHA512:
        return "RSASSA_FDH_VRF_RSA4096_SHA512";
    case Type::RSASSA_FDH_VRF_RSA8192_SHA512:
        return "RSASSA_FDH_VRF_RSA8192_SHA512";
    case Type::RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256:
        return "RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256";
    case Type::RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256:
        return "RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256";
    case Type::RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512:
        return "RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512";
    case Type::RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512:
        return "RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512";
    default:
        return "Unknown VRF Type";
    }
}

} // namespace vrf
