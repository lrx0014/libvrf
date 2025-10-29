// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/guards.h"
#include "vrf/type.h"
#include "vrf/vrf_base.h"
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace vrf::tests::utils
{

BIGNUM_Guard hex_string_to_bignum(const std::string &hex_str);

EVP_PKEY_Guard make_rsa_secret_key(Type type, const std::string &p_hex, const std::string &q_hex);

std::unique_ptr<SecretKey> make_rsa_vrf_secret_key(Type type, const std::string &p_hex, const std::string &q_hex);

std::unique_ptr<SecretKey> make_ec_vrf_secret_key(Type type, const std::string &sk_hex);

std::vector<std::byte> parse_hex_bytes(std::string_view s);

struct RSA_VRF_TestVectorParams
{
    std::string p;
    std::string q;
    std::string m;
    std::string proof;
    std::string value;
};

RSA_VRF_TestVectorParams get_rsa_vrf_test_vector_params(Type type);

struct EC_VRF_TestVectorParams
{
    std::vector<std::string> sk;
    std::vector<std::string> m;
    std::vector<std::string> proof;
    std::vector<std::string> value;
};

EC_VRF_TestVectorParams get_ec_vrf_test_vector_params(Type type);

} // namespace vrf::tests::utils
