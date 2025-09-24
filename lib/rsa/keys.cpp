#include "rsa/keys.h"
#include "common.h"
#include "log.h"
#include "rsa/params.h"
#include <cstdint>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/params.h>
#include <span>

namespace rsavrf
{

namespace
{

bool set_rsa_keygen_params(EVP_PKEY_CTX *pctx, vrf::Type type)
{
    RSAVRFParams params = get_rsavrf_params(type);
    const OSSL_PARAM params_to_set[] = {OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &params.bits),
                                        OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_PRIMES, &params.primes),
                                        OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_E, &params.e), OSSL_PARAM_END};

    return (1 == EVP_PKEY_CTX_set_params(pctx, params_to_set));
}

std::vector<std::byte> generate_mgf1_salt(EVP_PKEY *pkey)
{
    // We need OSSL_PKEY_PARAM_RSA_N to generate the salt.
    BIGNUM *bn_n = nullptr;
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n))
    {
        vrf::Logger()->error("Failed to retrieve RSA modulus from EVP_PKEY for MGF1 salt generation.");
        return {};
    }

    // In the salt, first we have a 4-byte big-endian representation of the length of the RSA modulus.
    const int n_len = BN_num_bytes(bn_n);
    const std::uint32_t n_len_u32 = static_cast<std::uint32_t>(n_len);
    std::vector<std::byte> salt(4 + n_len_u32);
    salt[0] = static_cast<std::byte>((n_len_u32 >> 24) & 0xFF);
    salt[1] = static_cast<std::byte>((n_len_u32 >> 16) & 0xFF);
    salt[2] = static_cast<std::byte>((n_len_u32 >> 8) & 0xFF);
    salt[3] = static_cast<std::byte>(n_len_u32 & 0xFF);

    // Next, convert bn_n to a byte array with I2OSP and append to the salt.
    if (n_len != BN_bn2binpad(bn_n, reinterpret_cast<unsigned char *>(salt.data() + 4), n_len))
    {
        vrf::Logger()->error("Failed to convert RSA modulus to byte array for MGF1 salt generation.");
        BN_free(bn_n);
        return {};
    }

    BN_free(bn_n);

    return salt;
}

bool check_rsa_params(vrf::Type type, EVP_PKEY *pkey, bool check_pk, bool check_sk)
{
    if (!vrf::is_rsa_type(type) || nullptr == pkey)
    {
        return false;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(vrf::common::get_libctx(), pkey, vrf::common::get_propquery());
    if (nullptr == pctx || 1 != EVP_PKEY_param_check(pctx))
    {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    // Retrieve n and check that it has the expected size.
    RSAVRFParams params = get_rsavrf_params(type);
    BIGNUM *n = nullptr;
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n))
    {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    unsigned bits = static_cast<unsigned>(BN_num_bits(n));
    if (bits != params.bits)
    {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    // We are done with n.
    BN_free(n);

    if (check_pk)
    {
        // Check that the public key is present.
        BIGNUM *e = nullptr;
        bool ret = false;
        if (1 == EVP_PKEY_public_check(pctx) && 1 == EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e))
        {
            // Public key was retrieved. Check that it matches the expected value.
            BN_ULONG ew = BN_get_word(e);
            if (ew != ~(BN_ULONG){})
            {
                // Does the exponent match what we expected?
                ret = (ew == params.e);
            }
        }

        if (!ret)
        {
            BN_free(e);
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    // Check that the secret key is present without actually retrieving it.
    if (check_sk)
    {
        if (1 != EVP_PKEY_private_check(pctx))
        {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    // Finally, if both keys are checked, verify that their relationship is valid.
    if (check_pk && check_sk)
    {
        if (1 != EVP_PKEY_pairwise_check(pctx))
        {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
    }

    EVP_PKEY_CTX_free(pctx);
    return true;
}

} // namespace

RSA_SK_Guard &RSA_SK_Guard::operator=(RSA_SK_Guard &&rhs) noexcept
{
    if (this != &rhs)
    {
        reset();
        type_ = rhs.type_;
        pkey_ = rhs.pkey_;
        rhs.type_ = vrf::Type::UNKNOWN_VRF_TYPE;
        rhs.pkey_ = nullptr;
    }
    return *this;
}

EVP_PKEY *RSA_SK_Guard::generate_rsa_key(vrf::Type type)
{
    if (!vrf::is_rsa_type(type))
    {
        vrf::Logger()->warn("generate_rsa_key called with non-RSA VRF type: {}", vrf::type_to_string(type));
        return nullptr;
    }

    RSAVRFParams params = get_rsavrf_params(type);
    const char *algorithm_name = params.algorithm_name;
    EVP_PKEY_CTX *pctx =
        EVP_PKEY_CTX_new_from_name(vrf::common::get_libctx(), algorithm_name, vrf::common::get_propquery());
    if (nullptr == pctx)
    {
        vrf::Logger()->error("Failed to create EVP_PKEY_CTX for RSA key generation.");
        return nullptr;
    }

    if (0 >= EVP_PKEY_keygen_init(pctx))
    {
        vrf::Logger()->error("Failed to initialize RSA key generation; EVP_PKEY_keygen_init failed");
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    if (!set_rsa_keygen_params(pctx, type))
    {
        vrf::Logger()->error("Failed to set RSA key generation parameters; set_rsa_keygen_params failed");
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    EVP_PKEY *pkey = nullptr;
    if (1 != EVP_PKEY_generate(pctx, &pkey))
    {
        vrf::Logger()->error("Failed to generate RSA key pair; EVP_PKEY_generate failed}");
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(pctx);

    return pkey;
}

RSA_SK_Guard::RSA_SK_Guard(vrf::Type type) : type_(vrf::Type::UNKNOWN_VRF_TYPE), pkey_(nullptr)
{
    EVP_PKEY *pkey = generate_rsa_key(type);
    if (nullptr == pkey)
    {
        vrf::Logger()->warn("RSA_PKEY_Guard constructor failed to generate RSA key.");
    }
    else
    {
        type_ = type;
        pkey_ = pkey;
    }
}

RSA_SK_Guard RSA_SK_Guard::clone() const
{
    return {type_, vrf::common::evp_pkey_upref(pkey_)};
}

std::vector<std::byte> RSA_SK_Guard::get_mgf1_salt() const
{
    if (nullptr == pkey_)
    {
        vrf::Logger()->warn("get_mgf1_salt called on uninitialized RSA_SK_Guard.");
        return {};
    }

    return generate_mgf1_salt(pkey_);
}

RSA_PK_Guard &RSA_PK_Guard::operator=(RSA_PK_Guard &&rhs) noexcept
{
    if (this != &rhs)
    {
        reset();
        type_ = rhs.type_;
        pkey_ = rhs.pkey_;
        rhs.type_ = vrf::Type::UNKNOWN_VRF_TYPE;
        rhs.pkey_ = nullptr;
    }
    return *this;
}

RSA_PK_Guard::RSA_PK_Guard(vrf::Type type, std::span<const std::byte> der_spki)
    : type_(vrf::Type::UNKNOWN_VRF_TYPE), pkey_(nullptr)
{
    RSAVRFParams params = get_rsavrf_params(type);
    EVP_PKEY *pkey = vrf::common::decode_public_key_from_der_spki(params.algorithm_name, der_spki);
    if (nullptr == pkey)
    {
        vrf::Logger()->warn("RSA_PK_Guard constructor failed to load EVP_PKEY from provided DER SPKI.");
        return;
    }

    // We need to still check that the loaded public key matches the expected parameters.
    if (!check_rsa_params(type, pkey, true /* check_pk */, false /* check_sk */))
    {
        EVP_PKEY_free(pkey);
        vrf::Logger()->warn(
            "RSA_PK_Guard constructor found mismatched or invalid RSA parameters in provided DER SPKI.");
        return;
    }

    // Everything OK. Store the pkey and set the type.
    pkey_ = pkey;
    type_ = type;
}

RSA_PK_Guard RSA_PK_Guard::clone() const
{
    return {type_, vrf::common::evp_pkey_upref(pkey_)};
}

std::vector<std::byte> RSA_PK_Guard::get_mgf1_salt() const
{
    if (nullptr == pkey_)
    {
        vrf::Logger()->warn("get_mgf1_salt called on uninitialized RSA_PK_Guard.");
        return {};
    }

    return generate_mgf1_salt(pkey_);
}

} // namespace rsavrf
