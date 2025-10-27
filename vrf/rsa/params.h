// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/type.h"

namespace vrf::rsa
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

[[nodiscard]]
RSAVRFParams get_rsavrf_params(Type type) noexcept;

} // namespace vrf::rsa
