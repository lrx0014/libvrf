#include "rsa/params.h"
#include <cstring>
#include <openssl/rsa.h>

#define RSAVRF_PARAMS(KEY_SIZE, DIGEST, PAD_MODE, SUITE_STRING)                                                        \
    "RSA", KEY_SIZE, 2, 65537, DIGEST, PAD_MODE, SUITE_STRING, std::strlen(SUITE_STRING)

namespace rsavrf
{

RSAVRFParams get_rsavrf_params(vrf::Type type)
{
    switch (type)
    {
    // RSASSA-FDH VRF types
    case vrf::Type::RSASSA_FDH_VRF_RSA2048_SHA256:
        return RSAVRFParams{RSAVRF_PARAMS(2048, "SHA256", RSA_NO_PADDING, "\001")};
    case vrf::Type::RSASSA_FDH_VRF_RSA3072_SHA256:
        return RSAVRFParams{RSAVRF_PARAMS(3072, "SHA256", RSA_NO_PADDING, "\001")};
    case vrf::Type::RSASSA_FDH_VRF_RSA4096_SHA512:
        return RSAVRFParams{RSAVRF_PARAMS(4096, "SHA384", RSA_NO_PADDING, "\002")};
    case vrf::Type::RSASSA_FDH_VRF_RSA8192_SHA512:
        return RSAVRFParams{RSAVRF_PARAMS(8192, "SHA512", RSA_NO_PADDING, "\003")};
    // RSASSA-PSS "NOSALT" VRF types
    case vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256:
        return RSAVRFParams{RSAVRF_PARAMS(2048, "SHA256", RSA_PKCS1_PSS_PADDING, "\367RSASSA-PSS\001")};
    case vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256:
        return RSAVRFParams{RSAVRF_PARAMS(3072, "SHA256", RSA_PKCS1_PSS_PADDING, "\367RSASSA-PSS\001")};
    case vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512:
        return RSAVRFParams{RSAVRF_PARAMS(4096, "SHA384", RSA_PKCS1_PSS_PADDING, "\367RSASSA-PSS\002")};
    case vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512:
        return RSAVRFParams{RSAVRF_PARAMS(8192, "SHA512", RSA_PKCS1_PSS_PADDING, "\367RSASSA-PSS\003")};
    default:
        return RSAVRFParams{};
    }
}

} // namespace rsavrf
