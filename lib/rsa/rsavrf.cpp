#include "rsa/rsavrf.h"
#include "common.h"
#include "log.h"
#include "rsa/params.h"
#include "vrf/type.h"
#include <algorithm>
#include <cstdint>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>

namespace rsavrf
{

namespace
{

/**
 * Verifies that the byte sequence `test` represents a non-negative integer
 * that is less than the RSA modulus `n` contained in the provided `pkey`.
 *
 * Logs an error (and returns false) if any of the following conditions are met:
 *   - `test` is empty.
 *   - `guard` does not hold a valid RSA public or secret key.
 *   - The length of `test` does not match the RSA modulus size.
 *   - The modulus `n` cannot be retrieved from the `pkey`.
 *   - The byte sequence `test` cannot be converted to a BIGNUM.
 */
template <RSAGuard T> bool check_bytes_in_modulus_range(std::span<const std::byte> test, const T &guard)
{
    if (test.empty())
    {
        vrf::Logger()->error("Input to check_bytes_in_modulus_range is empty.");
        return false;
    }
    if (!guard.has_value())
    {
        vrf::Logger()->error("Guard object is uninitialized in call to check_bytes_in_modulus_range.");
        return false;
    }

    const RSAVRFParams params = get_rsavrf_params(guard.get_type());
    std::size_t n_len = (params.bits + 7) / 8;
    if (n_len != test.size())
    {
        vrf::Logger()->error("Input to check_bytes_in_modulus_range has incorrect size: expected {} bytes, got {}",
                             n_len, test.size());
        return false;
    }

    BIGNUM *n = nullptr;
    EVP_PKEY *pkey = guard.get();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n))
    {
        vrf::Logger()->error("Failed to retrieve RSA modulus from EVP_PKEY for range check.");
        BN_free(n);
        return false;
    }

    BIGNUM *bn_test =
        BN_bin2bn(reinterpret_cast<const unsigned char *>(test.data()), static_cast<int>(test.size()), nullptr);
    if (nullptr == bn_test)
    {
        vrf::Logger()->error("Failed to convert test input to BIGNUM for range check.");
        BN_free(n);
        return false;
    }

    // Test condition: 0 <= bn_test < n
    bool ret = !BN_is_negative(bn_test) && BN_ucmp(n, bn_test) > 0;

    BN_free(n);
    BN_free(bn_test);

    return ret;
}

/**
 * Computes a raw RSA signature on the provided data using the given RSA secret key.
 * The data to be signed must be the same length as the RSA modulus and must represent
 * a non-negative integer less than the modulus.
 *
 * Logs an error (and returns an empty vector) if any of the following conditions are met:
 *   - `tbs` or `sk_guard` are out of range or invalid.
 *   - Any of the OpenSSL signature operations failed.
 */
std::vector<std::byte> rsa_signing_primitive(std::span<const std::byte> tbs, const RSA_SK_Guard &sk_guard)
{
    if (!check_bytes_in_modulus_range(tbs, sk_guard))
    {
        vrf::Logger()->warn("Inputs to rsa_signing_primitive are out of range or invalid.");
        return {};
    }

    RSAVRFParams params = get_rsavrf_params(sk_guard.get_type());
    if (RSA_NO_PADDING != params.pad_mode)
    {
        vrf::Logger()->error("rsa_signing_primitive called with non-raw RSA VRF type: {}",
                             vrf::type_to_string(sk_guard.get_type()));
        return {};
    }

    // Create the signing context for raw RSA (no padding).
    EVP_PKEY *pkey = sk_guard.get();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(vrf::common::get_libctx(), pkey, vrf::common::get_propquery());
    if (1 != EVP_PKEY_sign_init(pctx))
    {
        vrf::Logger()->error("Failed to initialize signing context for raw RSA; EVP_PKEY_sign_init failed.");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    if (0 >= EVP_PKEY_CTX_set_rsa_padding(pctx, params.pad_mode))
    {
        vrf::Logger()->error("Failed to configure RSA (no padding) for signing.");
        return {};
    }

    // Determine the length of the required signature buffer.
    std::size_t siglen = 0;
    if (0 >= EVP_PKEY_sign(pctx, nullptr, &siglen, reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    {
        vrf::Logger()->error("Failed to generate raw RSA signature; EVP_PKEY_sign failed.");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    // Actually sign.
    std::vector<std::byte> signature(siglen);
    if (0 >= EVP_PKEY_sign(pctx, reinterpret_cast<unsigned char *>(signature.data()), &siglen,
                           reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    {
        vrf::Logger()->error("Failed to generate raw RSA signature; EVP_PKEY_sign failed.");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    EVP_PKEY_CTX_free(pctx);

    // Resize the signature to the actual size.
    signature.resize(siglen);
    return signature;
}

/**
 * Computes the RSA verification primitive on the provided signature using the given
 * RSA public key. The signature must be the same length as the RSA modulus and must
 * represent a non-negative integer less than the modulus.
 *
 * Logs an error (and returns an empty vector) if any of the following conditions are met:
 *   - `signature` or `pk_guard` are out of range or invalid.
 *   - Any of the OpenSSL verification operations failed.
 */
std::vector<std::byte> rsa_verification_primitive(std::span<const std::byte> signature, const RSA_PK_Guard &pk_guard)
{
    if (!check_bytes_in_modulus_range(signature, pk_guard))
    {
        vrf::Logger()->error("Inputs to rsa_verification_primitive are out of range or invalid.");
        return {};
    }

    RSAVRFParams params = get_rsavrf_params(pk_guard.get_type());
    if (RSA_NO_PADDING != params.pad_mode)
    {
        vrf::Logger()->error("rsa_verification_primitive called with non-raw RSA VRF type: {}",
                             vrf::type_to_string(pk_guard.get_type()));
        return {};
    }

    EVP_PKEY *pkey = pk_guard.get();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(vrf::common::get_libctx(), pkey, vrf::common::get_propquery());
    if (nullptr == pctx)
    {
        vrf::Logger()->error("Failed to create EVP_PKEY_CTX for RSA verification primitive.");
        return {};
    }

    if (0 >= EVP_PKEY_encrypt_init(pctx) || 0 >= EVP_PKEY_CTX_set_rsa_padding(pctx, params.pad_mode))
    {
        vrf::Logger()->error("Failed to initialize RSA verification primitive; EVP_PKEY_encrypt_init failed.");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    std::size_t m_len = 0;
    if (0 >= EVP_PKEY_encrypt(pctx, nullptr, &m_len, reinterpret_cast<const unsigned char *>(signature.data()),
                              signature.size()))
    {
        vrf::Logger()->error("Failed to determine output length for RSA verification primitive.");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    std::vector<std::byte> message(m_len);
    if (0 >= EVP_PKEY_encrypt(pctx, reinterpret_cast<unsigned char *>(message.data()), &m_len,
                              reinterpret_cast<const unsigned char *>(signature.data()), signature.size()))
    {
        vrf::Logger()->error("Failed to perform RSA verification primitive; EVP_PKEY_encrypt failed.");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    EVP_PKEY_CTX_free(pctx);

    // Resize the message to the actual size.
    message.resize(m_len);
    return message;
}

/**
 * Performs RSA-PSS signing with zero-length salt on the provided data using the given RSA secret key.
 * The data to be signed can be of any length.
 *
 * Logs an error (and returns an empty vector) if any of the following conditions are met:
 *   - `tbs` is empty or `sk_guard` is invalid.
 *   - The VRF type in `sk_guard` is not an RSA-PSS type.
 *   - Any of the OpenSSL operations failed.
 */
std::vector<std::byte> rsa_pss_nosalt_sign(std::span<const std::byte> tbs, const RSA_SK_Guard &sk_guard)
{
    if (!sk_guard.has_value())
    {
        vrf::Logger()->error("rsa_pss_nosalt_sign called with invalid RSA secret key.");
        return {};
    }
    if (tbs.empty())
    {
        vrf::Logger()->error("rsa_pss_nosalt_sign called with empty data to sign.");
        return {};
    }

    vrf::Type type = sk_guard.get_type();
    const RSAVRFParams params = get_rsavrf_params(type);
    if (RSA_PKCS1_PSS_PADDING != params.pad_mode)
    {
        vrf::Logger()->error("rsa_pss_nosalt_sign called with non-PSS RSA VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    vrf::common::MD_CTX_Guard mctx{true /* oneshot only */};
    if (!mctx.has_value())
    {
        vrf::Logger()->error("Failed to get EVP_MD_CTX.");
        return {};
    }

    // Create the signing context. Note that `pctx` does *not* need to be freed manually, as mctx will own it.
    EVP_PKEY *pkey = sk_guard.get();
    EVP_PKEY_CTX *pctx = nullptr;
    if (1 != EVP_DigestSignInit_ex(mctx.get(), &pctx, params.digest, vrf::common::get_libctx(),
                                   vrf::common::get_propquery(), pkey, nullptr))
    {
        vrf::Logger()->error("Failed to initialize signing context for RSA-PSS; EVP_DigestSignInit_ex failed.");
        return {};
    }

    // Configure the PSS padding. We set the salt length to 0. This is necessary for the VRF
    // since we need the signature to be deterministic (but unpredictable).
    if (0 >= EVP_PKEY_CTX_set_rsa_padding(pctx, params.pad_mode) || 0 >= EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 0))
    {
        vrf::Logger()->error("Failed to configure PSS padding for signing.");
        return {};
    }

    // We don't need to call EVP_PKEY_CTX_set_rsa_mgf1_md because it defaults to the same digest
    // as the signature digest.

    // One-shot digest-sign. Get the signature length first.
    std::size_t siglen = 0;
    if (0 >=
        EVP_DigestSign(mctx.get(), nullptr, &siglen, reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    {
        vrf::Logger()->error("Failed to determine signature length for RSA-PSS; EVP_DigestSign failed.");
        return {};
    }

    std::vector<std::byte> signature(siglen);
    if (0 >= EVP_DigestSign(mctx.get(), reinterpret_cast<unsigned char *>(signature.data()), &siglen,
                            reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    {
        vrf::Logger()->error("Failed to generate RSA-PSS signature; EVP_DigestSign failed.");
        return {};
    }

    // Resize the signature to the actual size.
    signature.resize(siglen);
    return signature;
}

/**
 * Performs RSA-PSS verification with zero-length salt on the provided signature and data using
 * the given RSA public key. The data to be verified can be of any length.
 *
 * Logs an error (and returns false) if any of the following conditions are met:
 *   - `signature`, `tbs`, or `pk_guard` are out of range or invalid.
 *   - The VRF type in `pk_guard` is not an RSA-PSS type.
 *   - Any of the OpenSSL operations failed.
 */
bool rsa_pss_nosalt_verify(std::span<const std::byte> signature, std::span<const std::byte> tbs,
                           const RSA_PK_Guard &pk_guard)
{
    if (!check_bytes_in_modulus_range(signature, pk_guard))
    {
        vrf::Logger()->warn("Inputs to rsa_pss_nosalt_verify are out of range or invalid.");
        return false;
    }
    if (tbs.empty())
    {
        vrf::Logger()->error("rsa_pss_nosalt_sign called with empty data to sign.");
        return {};
    }

    vrf::Type type = pk_guard.get_type();
    const RSAVRFParams params = get_rsavrf_params(type);
    if (RSA_PKCS1_PSS_PADDING != params.pad_mode)
    {
        vrf::Logger()->error("rsa_pss_nosalt_verify called with non-PSS RSA VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    vrf::common::MD_CTX_Guard mctx{true /* oneshot only */};
    if (!mctx.has_value())
    {
        vrf::Logger()->error("Failed to get EVP_MD_CTX.");
        return false;
    }

    // Create the verification context.
    EVP_PKEY *pkey = pk_guard.get();
    EVP_PKEY_CTX *pctx = nullptr;
    if (1 != EVP_DigestVerifyInit_ex(mctx.get(), &pctx, params.digest, vrf::common::get_libctx(),
                                     vrf::common::get_propquery(), pkey, nullptr))
    {
        vrf::Logger()->error("Failed to initialize verification context for RSA-PSS; EVP_DigestVerifyInit_ex failed.");
        return false;
    }

    // Configure the PSS padding. We set the salt length to 0. This is necessary for the VRF
    // since we need the signature to be deterministic (but unpredictable).
    if (0 >= EVP_PKEY_CTX_set_rsa_padding(pctx, params.pad_mode) || 0 >= EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 0))
    {
        vrf::Logger()->error("Failed to configure RSA-PSS padding for verification.");
        return false;
    }

    // We don't need to call EVP_PKEY_CTX_set_rsa_mgf1_md because it defaults to the same digest
    // as the signature digest.

    // One-shot digest-verify.
    bool success = EVP_DigestVerify(mctx.get(), reinterpret_cast<const unsigned char *>(signature.data()),
                                    signature.size(), reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size());
    return success;
}

bool mgf1(std::span<std::byte> mask, std::span<const std::byte> seed, const EVP_MD *dgst)
{
    if (mask.empty() || nullptr == dgst)
    {
        return false;
    }

    std::size_t len = mask.size();
    std::size_t seedlen = seed.size();
    std::size_t outlen = 0;

    std::array<std::byte, 4> ctr{};
    std::array<std::byte, EVP_MAX_MD_SIZE> md;

    vrf::common::MD_CTX_Guard mctx{false /* oneshot only */};
    if (!mctx.has_value())
    {
        vrf::Logger()->error("Failed to get EVP_MD_CTX for MGF1.");
        return false;
    }

    int mdlen = EVP_MD_get_size(dgst);
    if (mdlen <= 0)
    {
        vrf::Logger()->error("Invalid digest size for MGF1.");
        return false;
    }

    for (std::uint32_t i = 0; outlen < len; i++)
    {
        // Set the counter value for this iteration.
        ctr[0] = static_cast<std::byte>((i >> 24) & 0xFF);
        ctr[1] = static_cast<std::byte>((i >> 16) & 0xFF);
        ctr[2] = static_cast<std::byte>((i >> 8) & 0xFF);
        ctr[3] = static_cast<std::byte>(i & 0xFF);

        if (!EVP_DigestInit_ex(mctx.get(), dgst, nullptr) || !EVP_DigestUpdate(mctx.get(), seed.data(), seedlen) ||
            !EVP_DigestUpdate(mctx.get(), ctr.data(), ctr.size()))
        {
            vrf::Logger()->error("Failed to compute MGF1 digest; EVP_Digest* operations failed.");
            return false;
        }

        if (outlen + mdlen <= len)
        {
            if (!EVP_DigestFinal_ex(mctx.get(), reinterpret_cast<unsigned char *>(mask.data()) + outlen, nullptr))
            {
                vrf::Logger()->error("Failed to finalize MGF1 digest; EVP_DigestFinal_ex failed.");
                return false;
            }
            outlen += mdlen;
        }
        else
        {
            if (!EVP_DigestFinal_ex(mctx.get(), reinterpret_cast<unsigned char *>(md.data()), nullptr))
            {
                vrf::Logger()->error("Failed to finalize MGF1 digest; EVP_DigestFinal_ex failed.");
                return false;
            }

            std::copy_n(md.begin(), len - outlen, mask.begin() + outlen);
            outlen = len;
        }
    }

    // Set the highest-order byte of mask to zero.
    mask[0] = std::byte{0x00};

    return true;
}

std::vector<std::byte> construct_rsa_fdh_tbs(vrf::Type type, std::span<const std::byte> mgf1_salt,
                                             std::span<const std::byte> data)
{
    // We need to evaluate the MGF1 function on suite_string || 0x01 || mgf1_salt || data.
    // The output must have length k-1, where k is the length in bytes of the RSA modulus.

    if (!vrf::is_rsa_type(type))
    {
        vrf::Logger()->warn("construct_rsa_fdh_tbs called with non-RSA VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    const RSAVRFParams params = get_rsavrf_params(type);
    if (RSA_NO_PADDING != params.pad_mode)
    {
        vrf::Logger()->error("construct_rsa_fdh_tbs called with non-FDH RSA VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    const std::size_t suite_string_len = params.suite_string_len;
    std::size_t n_len = (params.bits + 7) / 8;

    // Set up the seed to MGF1.
    std::vector<std::byte> tbs;
    tbs.reserve(suite_string_len + 1 /* domain separator */ + mgf1_salt.size() + data.size());
    std::copy_n(reinterpret_cast<const std::byte *>(params.suite_string), suite_string_len, std::back_inserter(tbs));
    tbs.push_back(std::byte{0x01});
    std::copy(mgf1_salt.begin(), mgf1_salt.end(), std::back_inserter(tbs));
    std::copy(data.begin(), data.end(), std::back_inserter(tbs));

    // Evaluate MGF1. The output *must* have size `n_len` bytes. Otherwise, raw RSA signing will fail.
    std::vector<std::byte> ret(n_len);
    const EVP_MD *md = EVP_MD_fetch(vrf::common::get_libctx(), params.digest, vrf::common::get_propquery());
    if (nullptr == md)
    {
        vrf::Logger()->error("Failed to get EVP_MD for VRF type: {}", vrf::type_to_string(type));
        return {};
    }
    if (!mgf1(ret, tbs, md))
    {
        vrf::Logger()->error("Failed to compute MGF1 output for RSA-FDH.");
        return {};
    }

    return ret;
}

std::vector<std::byte> construct_rsa_pss_tbs(vrf::Type type, std::span<const std::byte> mgf1_salt,
                                             std::span<const std::byte> data)
{
    if (!vrf::is_rsa_type(type))
    {
        vrf::Logger()->error("construct_rsa_pss_tbs called with non-RSA VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    const RSAVRFParams params = get_rsavrf_params(type);
    if (RSA_PKCS1_PSS_PADDING != params.pad_mode)
    {
        vrf::Logger()->error("construct_rsa_pss_tbs called with non-PSS RSA VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    const std::size_t suite_string_len = params.suite_string_len;

    std::vector<std::byte> tbs;
    tbs.reserve(suite_string_len + 1 /* domain separator */ + mgf1_salt.size() + data.size());

    std::copy_n(reinterpret_cast<const std::byte *>(params.suite_string), suite_string_len, std::back_inserter(tbs));
    tbs.push_back(std::byte{0x01});
    std::copy(mgf1_salt.begin(), mgf1_salt.end(), std::back_inserter(tbs));
    std::copy(data.begin(), data.end(), std::back_inserter(tbs));

    return tbs;
}

} // namespace

void RSAProof::from_bytes(vrf::Type type, std::span<const std::byte> data)
{
    RSAProof rsa_proof(type, std::vector<std::byte>(data.begin(), data.end()));
    if (!rsa_proof.is_initialized())
    {
        vrf::Logger()->warn("RSAProof::from_bytes called with invalid proof data for VRF type: {}",
                            vrf::type_to_string(type));
        return;
    }

    *this = std::move(rsa_proof);
}

RSAProof::RSAProof(const RSAProof &source)
{
    RSAProof proof_copy(source.get_type(), source.proof_);
    *this = std::move(proof_copy);
}

RSAProof &RSAProof::operator=(RSAProof &&rhs) noexcept
{
    if (this != &rhs)
    {
        set_type(rhs.get_type());
        proof_ = std::move(rhs.proof_);
        rhs.set_type(vrf::Type::UNKNOWN_VRF_TYPE);
    }
    return *this;
}

bool RSAProof::is_initialized() const
{
    return !proof_.empty() && is_rsa_type(get_type());
}

std::vector<std::byte> RSAProof::get_vrf_value() const
{
    if (!is_initialized())
    {
        vrf::Logger()->warn("RSAProof::get_vrf_value called on an incorrectly initialized proof.");
        return {};
    }

    const vrf::Type type = get_type();
    const RSAVRFParams params = get_rsavrf_params(type);

    const std::size_t suite_string_len = params.suite_string_len;

    std::vector<std::byte> tbh;
    tbh.reserve(suite_string_len + 1 /* domain separator */ + proof_.size());

    std::copy_n(reinterpret_cast<const std::byte *>(params.suite_string), suite_string_len, std::back_inserter(tbh));
    tbh.push_back(std::byte{0x02});
    std::copy(proof_.begin(), proof_.end(), std::back_inserter(tbh));

    return vrf::common::compute_hash(params.digest, tbh);
}

std::unique_ptr<vrf::Proof> RSASecretKey::get_vrf_proof(std::span<const std::byte> in) const
{
    if (!is_initialized())
    {
        vrf::Logger()->warn("RSASecretKey::get_vrf_proof called on invalid RSASecretKey.");
        return nullptr;
    }

    const vrf::Type type = get_type();
    const RSAVRFParams params = get_rsavrf_params(type);

    std::unique_ptr<vrf::Proof> ret = nullptr;
    switch (params.pad_mode)
    {
    case RSA_NO_PADDING: {
        std::vector<std::byte> tbs = construct_rsa_fdh_tbs(type, mgf1_salt_, in);
        std::vector<std::byte> signature = rsa_signing_primitive(tbs, sk_guard_);
        if (signature.empty())
        {
            vrf::Logger()->error("RSASecretKey::get_vrf_proof failed to generate raw RSA signature.");
            return nullptr;
        }

        ret.reset(new RSAProof(type, std::move(signature)));
        break;
    }
    case RSA_PKCS1_PSS_PADDING: {
        std::vector<std::byte> tbs = construct_rsa_pss_tbs(type, mgf1_salt_, in);
        std::vector<std::byte> signature = rsa_pss_nosalt_sign(tbs, sk_guard_);
        if (signature.empty())
        {
            vrf::Logger()->error("RSASecretKey::get_vrf_proof failed to generate RSA-PSS signature.");
            return nullptr;
        }

        ret.reset(new RSAProof(type, std::move(signature)));
        break;
    }
    default:
        vrf::Logger()->error("RSASecretKey::get_vrf_proof called with unsupported padding mode: {}", params.pad_mode);
        break;
    }

    return ret;
}

RSASecretKey::RSASecretKey(vrf::Type type) : vrf::SecretKey{vrf::Type::UNKNOWN_VRF_TYPE}, sk_guard_{}, mgf1_salt_{}
{
    RSA_SK_Guard sk_guard(type);
    if (!sk_guard.has_value())
    {
        vrf::Logger()->warn("RSASecretKey constructor failed to generate RSA key for VRF type: {}",
                            vrf::type_to_string(type));
        return;
    }

    std::vector<std::byte> mgf1_salt = sk_guard.get_mgf1_salt();
    if (mgf1_salt.empty())
    {
        vrf::Logger()->error("RSASecretKey constructor failed to generate MGF1 salt.");
        return;
    }

    sk_guard_ = std::move(sk_guard);
    mgf1_salt_ = std::move(mgf1_salt);
    set_type(type);
}

RSASecretKey &RSASecretKey::operator=(RSASecretKey &&rhs) noexcept
{
    if (this != &rhs)
    {
        set_type(rhs.get_type());
        sk_guard_ = std::move(rhs.sk_guard_);
        mgf1_salt_ = std::move(rhs.mgf1_salt_);

        rhs.set_type(vrf::Type::UNKNOWN_VRF_TYPE);
        rhs.sk_guard_.reset();
        rhs.mgf1_salt_.clear();
    }
    return *this;
}

RSASecretKey::RSASecretKey(const RSASecretKey &source) : sk_guard_{}, mgf1_salt_{}
{
    RSA_SK_Guard sk_guard_copy = source.sk_guard_.clone();
    if (sk_guard_copy.has_value() != source.sk_guard_.has_value())
    {
        // Log an error if the cloning failed.
        vrf::Logger()->error("RSASecretKey copy constructor failed to clone the given secret key.");
        return;
    }

    std::vector<std::byte> mgf1_salt_copy(source.mgf1_salt_);

    sk_guard_ = std::move(sk_guard_copy);
    mgf1_salt_ = std::move(mgf1_salt_copy);
    set_type(source.get_type());
}

bool RSASecretKey::is_initialized() const
{
    return sk_guard_.has_value() && !mgf1_salt_.empty() && get_type() == sk_guard_.get_type();
}

RSAPublicKey::RSAPublicKey(const RSAPublicKey &source)
    : vrf::PublicKey{vrf::Type::UNKNOWN_VRF_TYPE}, pk_guard_{}, mgf1_salt_{}
{
    RSA_PK_Guard pk_guard_copy = source.pk_guard_.clone();
    if (pk_guard_copy.has_value() != source.pk_guard_.has_value())
    {
        // Log an error if the cloning failed.
        vrf::Logger()->error("RSAPublicKey copy constructor failed to clone the given public key.");
        return;
    }

    std::vector<std::byte> mgf1_salt_copy(source.mgf1_salt_);

    pk_guard_ = std::move(pk_guard_copy);
    mgf1_salt_ = std::move(mgf1_salt_copy);
    set_type(source.get_type());
}

RSAPublicKey &RSAPublicKey::operator=(RSAPublicKey &&rhs) noexcept
{
    if (this != &rhs)
    {
        set_type(rhs.get_type());
        pk_guard_ = std::move(rhs.pk_guard_);
        mgf1_salt_ = std::move(rhs.mgf1_salt_);

        rhs.set_type(vrf::Type::UNKNOWN_VRF_TYPE);
        rhs.pk_guard_.reset();
        rhs.mgf1_salt_.clear();
    }
    return *this;
}

RSAPublicKey::RSAPublicKey(vrf::Type type, std::span<const std::byte> der_spki)
    : vrf::PublicKey{vrf::Type::UNKNOWN_VRF_TYPE}, pk_guard_{}, mgf1_salt_{}
{
    RSA_PK_Guard pk_guard(type, der_spki);
    if (!pk_guard.has_value())
    {
        vrf::Logger()->warn("RSAPublicKey constructor failed to load EVP_PKEY from provided DER SPKI.");
        return;
    }

    std::vector<std::byte> mgf1_salt = pk_guard.get_mgf1_salt();
    if (mgf1_salt.empty())
    {
        vrf::Logger()->error("RSAPublicKey constructor failed to generate MGF1 salt from loaded EVP_PKEY.");
        return;
    }

    pk_guard_ = std::move(pk_guard);
    mgf1_salt_ = std::move(mgf1_salt);
    set_type(type);
}

bool RSAPublicKey::is_initialized() const
{
    return pk_guard_.has_value() && !mgf1_salt_.empty();
}

std::vector<std::byte> RSAPublicKey::to_bytes() const
{
    if (!is_initialized())
    {
        vrf::Logger()->warn("RSAPublicKey::to_bytes called on invalid RSAPublicKey.");
        return {};
    }

    std::vector<std::byte> der_spki = vrf::common::encode_public_key_to_der_spki(pk_guard_.get());
    if (der_spki.empty())
    {
        vrf::Logger()->error("RSAPublicKey::to_bytes failed to encode EVP_PKEY to DER SPKI.");
    }

    return der_spki;
}

void RSAPublicKey::from_bytes(vrf::Type type, std::span<const std::byte> data)
{
    RSAPublicKey public_key(type, data);
    if (!public_key.is_initialized())
    {
        vrf::Logger()->warn("RSAPublicKey::from_bytes called with invalid public key DER for VRF type: {}",
                            vrf::type_to_string(type));
        return;
    }

    *this = std::move(public_key);
}

std::unique_ptr<vrf::PublicKey> RSASecretKey::get_public_key() const
{
    if (!is_initialized())
    {
        vrf::Logger()->warn("RSASecretKey::get_public_key called on invalid RSASecretKey.");
        return nullptr;
    }

    // Serialize the public key first and then load back to a fresh EVP_PKEY.
    std::vector<std::byte> der_spki = vrf::common::encode_public_key_to_der_spki(sk_guard_.get());
    std::unique_ptr<RSAPublicKey> public_key(new RSAPublicKey(get_type(), der_spki));
    if (nullptr == public_key || !public_key->is_initialized())
    {
        vrf::Logger()->error("RSASecretKey::get_public_key failed to decode public key from DER SPKI");
        return nullptr;
    }

    return public_key;
}

std::pair<bool, std::vector<std::byte>> RSAPublicKey::verify_vrf_proof(std::span<const std::byte> in,
                                                                       const std::unique_ptr<vrf::Proof> &proof) const
{
    if (!is_initialized())
    {
        vrf::Logger()->warn("RSAPublicKey::verify_vrf_proof called on invalid RSAPublicKey.");
        return {false, {}};
    }

    // Downcast the proof type to RSAProof.
    const RSAProof *rsa_proof = dynamic_cast<const RSAProof *>(proof.get());
    if (nullptr == rsa_proof)
    {
        vrf::Logger()->warn("RSAPublicKey::verify_vrf_proof called with proof that is not of type RSAProof.");
        return {false, {}};
    }

    const vrf::Type type = get_type();
    if (!rsa_proof->is_initialized() || rsa_proof->get_type() != type)
    {
        vrf::Logger()->warn("RSAPublicKey::verify_vrf_proof called with invalid or mismatched proof type.");
        return {false, {}};
    }

    const RSAVRFParams params = get_rsavrf_params(type);

    bool success = false;
    switch (params.pad_mode)
    {
    case RSA_NO_PADDING: {
        std::vector<std::byte> tbs_expected = rsa_verification_primitive(rsa_proof->proof_, pk_guard_);
        if (tbs_expected.empty())
        {
            success = false;
            break;
        }
        std::vector<std::byte> tbs = construct_rsa_fdh_tbs(type, mgf1_salt_, in);
        success = (tbs_expected == tbs);
        break;
    }
    case RSA_PKCS1_PSS_PADDING: {
        std::vector<std::byte> tbs = construct_rsa_pss_tbs(type, mgf1_salt_, in);
        success = rsa_pss_nosalt_verify(rsa_proof->proof_, tbs, pk_guard_);
        break;
    }
    default:
        vrf::Logger()->error("RSASecretKey::get_vrf_proof called with unsupported padding mode: {}", params.pad_mode);
        break;
    }

    if (!success)
    {
        return {false, {}};
    }

    return {true, rsa_proof->get_vrf_value()};
}

} // namespace rsavrf
