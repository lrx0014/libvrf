#pragma once

#include <cstddef>

namespace vrf
{

enum class Type : std::size_t
{
    RSA_FDH_VRF_RSA2048_SHA256,
    RSA_FDH_VRF_RSA3072_SHA256,
    RSA_FDH_VRF_RSA4096_SHA384,
    RSA_FDH_VRF_RSA8192_SHA512,
    RSA_PSS_NOSALT_VRF_RSA2048_SHA256,
    RSA_PSS_NOSALT_VRF_RSA3072_SHA256,
    RSA_PSS_NOSALT_VRF_RSA4096_SHA384,
    RSA_PSS_NOSALT_VRF_RSA8192_SHA512,
    UNKNOWN_VRF_TYPE
};

inline constexpr bool is_rsa_type(Type type)
{
    return type == Type::RSA_FDH_VRF_RSA2048_SHA256 || type == Type::RSA_FDH_VRF_RSA3072_SHA256 ||
           type == Type::RSA_FDH_VRF_RSA4096_SHA384 || type == Type::RSA_FDH_VRF_RSA8192_SHA512 ||
           type == Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256 || type == Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256 ||
           type == Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384 || type == Type::RSA_PSS_NOSALT_VRF_RSA8192_SHA512;
}

inline constexpr bool is_ec_type(Type)
{
    // Not implemented.
    return false;
}

inline constexpr const char *type_to_string(Type type)
{
    switch (type)
    {
    case Type::RSA_FDH_VRF_RSA2048_SHA256:
        return "RSA_FDH_VRF_RSA2048_SHA256";
    case Type::RSA_FDH_VRF_RSA3072_SHA256:
        return "RSA_FDH_VRF_RSA3072_SHA256";
    case Type::RSA_FDH_VRF_RSA4096_SHA384:
        return "RSA_FDH_VRF_RSA4096_SHA512";
    case Type::RSA_FDH_VRF_RSA8192_SHA512:
        return "RSA_FDH_VRF_RSA8192_SHA512";
    case Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256:
        return "RSA_PSS_NOSALT_VRF_RSA2048_SHA256";
    case Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256:
        return "RSA_PSS_NOSALT_VRF_RSA3072_SHA256";
    case Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384:
        return "RSA_PSS_NOSALT_VRF_RSA4096_SHA512";
    case Type::RSA_PSS_NOSALT_VRF_RSA8192_SHA512:
        return "RSA_PSS_NOSALT_VRF_RSA8192_SHA512";
    default:
        return "Unknown VRF Type";
    }
}

} // namespace vrf
