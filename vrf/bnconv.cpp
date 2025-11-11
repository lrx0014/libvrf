// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/guards.h"
#include "vrf/log.h"
#include <cstddef>
#include <openssl/bn.h>
#include <span>
#include <utility>

namespace vrf
{

namespace
{

using BN_bin2bn_func_t = BIGNUM *(*)(const unsigned char *, int, BIGNUM *);

using BN_bn2binpad_func_t = int (*)(const BIGNUM *, unsigned char *, int);

BIGNUM_Guard bytes_to_int_core(BN_bin2bn_func_t func, std::span<const std::byte> in, bool secure)
{
    if (in.empty() && !std::in_range<int>(in.size()))
    {
        GetLogger()->error("bytes_to_int_core called with empty or too-large input data.");
        return {};
    }

    BIGNUM_Guard bn{secure};
    if (!bn.has_value() ||
        nullptr == func(reinterpret_cast<const unsigned char *>(in.data()), static_cast<int>(in.size()), bn.get()))
    {
        GetLogger()->error("Failed to convert bytes to BIGNUM in bytes_to_int_core.");
        return {};
    }

    return bn;
}

std::size_t int_to_bytes_core(BN_bn2binpad_func_t func, const BIGNUM_Guard &bn, std::span<std::byte> out)
{
    if (!bn.has_value())
    {
        GetLogger()->error("int_to_bytes_core called with uninitialized BIGNUM.");
        return 0;
    }
    if (!std::in_range<int>(out.size()))
    {
        GetLogger()->error("int_to_bytes_core called with too-large output buffer size.");
        return 0;
    }

    const std::size_t bn_size = static_cast<std::size_t>(BN_num_bytes(bn.get()));
    if (0 == bn_size)
    {
        GetLogger()->error("BIGNUM has zero size in int_to_bytes_core.");
        return 0;
    }

    if (out.empty())
    {
        return bn_size;
    }

    // Require at least bn_size bytes in out.
    if (out.size() < bn_size)
    {
        GetLogger()->error("int_to_bytes_core called with insufficient output buffer size.");
        return 0;
    }

    if (static_cast<int>(out.size()) !=
        func(bn.get(), reinterpret_cast<unsigned char *>(out.data()), static_cast<int>(out.size())))
    {
        GetLogger()->error("Failed to convert BIGNUM to bytes in int_to_bytes_core.");
        return 0;
    }

    return out.size();
}

BIGNUM_Guard bytes_to_int_big_endian_impl(std::span<const std::byte> in, bool secure)
{
    return bytes_to_int_core(BN_bin2bn, in, secure);
}

BIGNUM_Guard bytes_to_int_little_endian_impl(std::span<const std::byte> in, bool secure)
{
    return bytes_to_int_core(BN_lebin2bn, in, secure);
}

std::size_t int_to_bytes_big_endian_impl(const BIGNUM_Guard &bn, std::span<std::byte> out)
{
    return int_to_bytes_core(BN_bn2binpad, bn, out);
}

std::size_t int_to_bytes_little_endian_impl(const BIGNUM_Guard &bn, std::span<std::byte> out)
{
    return int_to_bytes_core(BN_bn2lebinpad, bn, out);
}

} // namespace

bytes_to_int_ptr_t bytes_to_int_big_endian = &bytes_to_int_big_endian_impl;

bytes_to_int_ptr_t bytes_to_int_little_endian = &bytes_to_int_little_endian_impl;

int_to_bytes_ptr_t int_to_bytes_big_endian = &int_to_bytes_big_endian_impl;

int_to_bytes_ptr_t int_to_bytes_little_endian = &int_to_bytes_little_endian_impl;

} // namespace vrf
