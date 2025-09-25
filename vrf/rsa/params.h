#pragma once

#include "vrf/type.h"
#include <openssl/evp.h>

namespace vrf::rsavrf
{

struct RSAVRFParams
{
    const char *algorithm_name = nullptr;
    unsigned bits = 0;
    unsigned primes = 0;
    unsigned e = 0;
    const char *digest = nullptr;
    int pad_mode = 0;
    const char *suite_string = nullptr;
    std::size_t suite_string_len = 0;
};

RSAVRFParams get_rsavrf_params(vrf::Type type);

} // namespace vrf::rsavrf
