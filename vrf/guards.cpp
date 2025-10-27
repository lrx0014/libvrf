// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/guards.h"
#include "vrf/log.h"

namespace vrf
{

MD_CTX_Guard::MD_CTX_Guard(bool oneshot_only)
{
    mctx_ = EVP_MD_CTX_new();
    if (nullptr != mctx_)
    {
        // Should this context be restricted to one-shot hashing use only?
        const std::uint32_t cond_oneshot =
            (std::uint32_t{0} - static_cast<std::uint32_t>(oneshot_only)) & EVP_MD_CTX_FLAG_ONESHOT;
        const int flags = EVP_MD_CTX_FLAG_FINALISE | static_cast<int>(cond_oneshot);
        EVP_MD_CTX_set_flags(mctx_, flags);
    }
}

EC_GROUP_Guard::EC_GROUP_Guard(Curve curve) : ec_group_{}, curve_{Curve::UNDEFINED}
{
    const int nid = curve_to_nid(curve);
    if (NID_undef == nid)
    {
        Logger()->error("EC_GROUP_Guard constructor called with unsupported curve.");
        return;
    }

    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name_ex(get_libctx(), get_propquery(), nid);
    if (nullptr == ec_group)
    {
        Logger()->error("Failed to create EC_GROUP for curve NID {}.", nid);
        return;
    }

    ec_group_ = ec_group;
    curve_ = curve;
}

void EC_GROUP_Guard::free() noexcept
{
    EC_GROUP_free(ec_group_);
    ec_group_ = nullptr;
    curve_ = Curve::UNDEFINED;
}

EC_GROUP_Guard &EC_GROUP_Guard::operator=(EC_GROUP_Guard &&rhs) noexcept
{
    if (this != &rhs)
    {
        using std::swap;
        swap(ec_group_, rhs.ec_group_);
        swap(curve_, rhs.curve_);
    }
    return *this;
}

EC_GROUP_Guard::EC_GROUP_Guard(const EC_GROUP_Guard &source) : ec_group_{nullptr}, curve_{Curve::UNDEFINED}
{
    EC_GROUP *group_copy = EC_GROUP_dup(source.ec_group_);
    if (nullptr == group_copy)
    {
        Logger()->error("EC_GROUP_Guard copy constructor failed to clone the given group.");
    }

    ec_group_ = group_copy;
    curve_ = source.curve_;
}

BIGNUM_Guard::BIGNUM_Guard(bool secure) : bn_{}, owned_{false}
{
    BIGNUM *bn = secure ? BN_secure_new() : BN_new();
    if (nullptr == bn)
    {
        Logger()->error("Failed to create ({}) BIGNUM.", secure ? "secure" : "non-secure");
    }
    else
    {
        bn_ = bn;
        owned_ = true;
    }
}

BIGNUM **BIGNUM_Guard::free_and_get_addr(bool owned) noexcept
{
    free();
    owned_ = owned;
    return &bn_;
}

void BIGNUM_Guard::free() noexcept
{
    if (owned_ && nullptr != bn_)
    {
        BN_clear_free(bn_);
    }
    bn_ = nullptr;
    owned_ = true;
}

bool BIGNUM_Guard::is_secure() const noexcept
{
    return (nullptr != bn_) ? (BN_get_flags(bn_, BN_FLG_SECURE) != 0) : false;
}

BIGNUM_Guard &BIGNUM_Guard::operator=(BIGNUM_Guard &&rhs) noexcept
{
    if (this != &rhs)
    {
        using std::swap;
        swap(bn_, rhs.bn_);
        swap(owned_, rhs.owned_);
    }
    return *this;
}

BN_CTX_Guard::BN_CTX_Guard(bool secure)
{
    OSSL_LIB_CTX *libctx = get_libctx();
    BN_CTX *bcg = secure ? BN_CTX_secure_new_ex(libctx) : BN_CTX_new_ex(libctx);
    if (nullptr == bcg)
    {
        Logger()->error("Failed to create ({}) BN_CTX.", secure ? "secure" : "non-secure");
    }
    else
    {
        bcg_ = bcg;
        secure_ = secure;
    }
}

void BN_CTX_Guard::free() noexcept
{
    BN_CTX_free(bcg_);
    bcg_ = nullptr;
    secure_ = false;
}

BN_CTX_Guard &BN_CTX_Guard::operator=(BN_CTX_Guard &&rhs) noexcept
{
    if (this != &rhs)
    {
        using std::swap;
        swap(bcg_, rhs.bcg_);
        swap(secure_, rhs.secure_);
    }
    return *this;
}

bool ensure_bcg_set(BN_CTX_Guard &bcg, bool secure)
{
    // Ensure the BN_CTX_Guard is secure, if requested.
    if (bcg.has_value() && (!secure || bcg.is_secure()))
    {
        return true;
    }

    bcg = BN_CTX_Guard{secure};
    if (!bcg.has_value())
    {
        Logger()->error("Failed to create BN_CTX in try_set_bcg.");
        return false;
    }

    return true;
}

EC_POINT_Guard::EC_POINT_Guard(Curve curve, EC_POINT *ec_pt, BN_CTX_Guard &bcg) : ec_pt_{}, curve_(Curve::UNDEFINED)
{
    const EC_GROUP_Guard group{curve};
    if (!group.has_value() || nullptr == ec_pt)
    {
        Logger()->error("EC_POINT_Guard constructor called with invalid curve or null EC_POINT.");
        return;
    }

    // Check that the point is actually on the curve.
    if (!ensure_bcg_set(bcg, false))
    {
        Logger()->error("EC_POINT_Guard constructor failed to obtain BN_CTX.");
        return;
    }

    if (1 != EC_POINT_is_on_curve(group.get(), ec_pt, bcg.get()))
    {
        Logger()->error("EC_POINT_Guard constructor called with EC_POINT not on the specified curve.");
        return;
    }

    // All good. Set the data.
    ec_pt_ = ec_pt;
    curve_ = curve;
}

EC_POINT_Guard::EC_POINT_Guard(const EC_GROUP_Guard &group)
{
    if (!group.has_value())
    {
        Logger()->error("EC_POINT_Guard constructor called with uninitialized EC_GROUP_Guard.");
        return;
    }

    EC_POINT *pt = EC_POINT_new(group.get());
    if (nullptr == pt || 1 != EC_POINT_set_to_infinity(group.get(), pt))
    {
        Logger()->error("Failed to create or initialize EC_POINT.");
        EC_POINT_free(pt);
        return;
    }

    ec_pt_ = pt;
    curve_ = group.get_curve();
}

void EC_POINT_Guard::free() noexcept
{
    EC_POINT_clear_free(ec_pt_);
    ec_pt_ = nullptr;
    curve_ = Curve::UNDEFINED;
}

EC_POINT_Guard &EC_POINT_Guard::operator=(EC_POINT_Guard &&rhs) noexcept
{
    if (this != &rhs)
    {
        using std::swap;
        swap(ec_pt_, rhs.ec_pt_);
        swap(curve_, rhs.curve_);
    }
    return *this;
}

} // namespace vrf
