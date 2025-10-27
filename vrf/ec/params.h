// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/common.h"
#include "vrf/ec/utils.h"
#include "vrf/type.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

namespace vrf::ec
{

struct ECVRFParams
{
    const char *algorithm_name = nullptr;
    Curve curve = Curve::UNDEFINED;
    unsigned cofactor = 0;
    const char *digest = nullptr;
    BytesToIntMethod bytes_to_int = BytesToIntMethod::UNDEFINED;
    PointToBytesMethod point_to_bytes = PointToBytesMethod::UNDEFINED;
    BytesToPointMethod bytes_to_point = BytesToPointMethod::UNDEFINED;
    E2CSaltMethod e2c_salt = E2CSaltMethod::UNDEFINED;
    E2CMethod e2c = E2CMethod::UNDEFINED;
    NonceGenMethod nonce_gen = NonceGenMethod::UNDEFINED;
    const char *suite_string = nullptr;
    std::size_t suite_string_len = 0;
    std::size_t f_len = 0;
    std::size_t c_len = 0;
    std::size_t q_len = 0;
    std::size_t pt_len = 0;
    std::size_t h_len = 0;
};

[[nodiscard]]
ECVRFParams get_ecvrf_params(Type type) noexcept;

} // namespace vrf::ec
