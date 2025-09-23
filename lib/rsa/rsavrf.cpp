#include "rsa/rsavrf.h"
#include "log.h"
#include "rsa/params.h"
#include "vrf/type.h"
#include <algorithm>
#include <cstdint>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>

namespace rsavrf
{

namespace
{

OSSL_LIB_CTX *libctx = nullptr;

constexpr char *propquery = nullptr;

bool set_rsa_keygen_params(EVP_PKEY_CTX *pctx, vrf::Type type)
{
    // This should only be called when EVP_PKEY_CTX has keygen op type. The parameter OSSL_PKEY_PARAM_RSA_PRIMES
    // is only valid in this case. For example, the function check_rsa_params cannot verify the correctness of this.

    if (!vrf::is_rsa_type(type) || nullptr == pctx)
    {
        return false;
    }

    RSAVRFParams params = get_rsavrf_params(type);
    const OSSL_PARAM params_to_set[] = {OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &params.bits),
                                        OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_PRIMES, &params.primes),
                                        OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_E, &params.e), OSSL_PARAM_END};

    return (1 == EVP_PKEY_CTX_set_params(pctx, params_to_set));
}

bool check_rsa_params(vrf::Type type, EVP_PKEY *pkey)
{
    if (!vrf::is_rsa_type(type) || nullptr == pkey)
    {
        return false;
    }

    // Check that pkey is for RSA and can sign.
    RSAVRFParams params = get_rsavrf_params(type);
    if (1 != EVP_PKEY_is_a(pkey, params.algorithm_name) || 1 != EVP_PKEY_can_sign(pkey))
    {
        return false;
    }

    // Get the parameter values from the given pkey.
    unsigned bits = 0;
    unsigned e = 0;
    OSSL_PARAM pkey_params[] = {OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &bits),
                                OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_E, &e), OSSL_PARAM_END};
    if (1 != EVP_PKEY_get_params(pkey, pkey_params))
    {
        return false;
    }

    // Check that the parameters match the expected values for the given VRF type.
    return (bits == params.bits && e == params.e);
}

class MD_CTX_Guard
{
  public:
    MD_CTX_Guard(bool oneshot_only)
    {
        mctx_ = EVP_MD_CTX_new();
        if (nullptr != mctx_)
        {
            std::uint32_t cond_oneshot =
                (std::uint32_t{0} - static_cast<std::uint32_t>(oneshot_only)) & EVP_MD_CTX_FLAG_ONESHOT;
            int flags = EVP_MD_CTX_FLAG_FINALISE | static_cast<int>(cond_oneshot);
            EVP_MD_CTX_set_flags(mctx_, flags);
        }
    }

    ~MD_CTX_Guard()
    {
        EVP_MD_CTX_free(mctx_);
        mctx_ = nullptr;
    }

    MD_CTX_Guard(const MD_CTX_Guard &) = delete;

    MD_CTX_Guard(MD_CTX_Guard &&) = delete;

    MD_CTX_Guard &operator=(const MD_CTX_Guard &) = delete;

    MD_CTX_Guard &operator=(MD_CTX_Guard &&) = delete;

    EVP_MD_CTX *get() const noexcept
    {
        return mctx_;
    }

    bool has_value() const noexcept
    {
        return nullptr != mctx_;
    }

  private:
    EVP_MD_CTX *mctx_ = nullptr;
};

// MD_CTX_Guard get_md_ctx(vrf::Type type)
// {
// class MDCTXManager
// {
//   public:
//     MDCTXManager() : mctx_(nullptr)
//     {
//     }
//
//     MDCTXManager(EVP_MD_CTX *mctx) : mctx_(mctx)
//     {
//     }
//
//     void release()
//     {
//         if (nullptr != mctx_)
//         {
//             EVP_MD_CTX_free(mctx_);
//             mctx_ = nullptr;
//         }
//     }
//
//     ~MDCTXManager()
//         release();
//     }
//
//     EVP_MD_CTX *reset_and_get()
//     {
//         if (nullptr == mctx_)
//         {
//             mctx_ = New();
//         }
//         else
//         {
//             reset();
//         }
//         return mctx_;
//     }
//
//   private:
//     void reset()
//     {
//         if (nullptr != mctx_ && 1 != EVP_MD_CTX_reset(mctx_))
//         {
//             release();
//             mctx_ = New();
//         }
//     }
//
//     static EVP_MD_CTX *New()
//     {
//         EVP_MD_CTX *mctx = EVP_MD_CTX_new();
//         EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_ONESHOT | EVP_MD_CTX_FLAG_FINALISE);
//         return mctx;
//     }
//
//     EVP_MD_CTX *mctx_;
// };
//
//     if (!vrf::is_rsa_type(type))
//     {
//         return nullptr;
//     }
//
//     // constexpr std::size_t vrf_type_count = static_cast<std::size_t>(vrf::Type::UNKNOWN_VRF_TYPE);
//     // thread_local static std::array<MDCTXManager, vrf_type_count> mctx_array{};
//     // const std::size_t type_index = static_cast<std::size_t>(type);
//
//     const RSAVRFParams params = get_rsavrf_params(type);
//     // EVP_MD_CTX *mctx = mctx_array[type_index].reset_and_get();
//     EVP_MD_CTX *mctx = EVP_MD_CTX_new();
//     if (nullptr != mctx)
//     {
//         EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_ONESHOT | EVP_MD_CTX_FLAG_FINALISE);
//     }
//     else
//     {
//         vrf::Logger()->error("Failed to fetch EVP_MD_CTX for digest: {}", params.digest);
//     }
//
//     return mctx;
// }

EVP_PKEY *generate_rsa_key(vrf::Type type)
{
    if (!vrf::is_rsa_type(type))
    {
        vrf::Logger()->warn("generate_rsa_key called with non-RSA VRF type: {}", vrf::type_to_string(type));
        return nullptr;
    }

    RSAVRFParams params = get_rsavrf_params(type);
    const char *algorithm_name = params.algorithm_name;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, algorithm_name, propquery);
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

EVP_PKEY *evp_pkey_upref(EVP_PKEY *source)
{
    if (source == nullptr)
    {
        return nullptr;
    }

    if (1 != EVP_PKEY_up_ref(source))
    {
        vrf::Logger()->error("Failed to increment reference count for EVP_PKEY.");
        return nullptr;
    }

    return source;
}

std::vector<std::byte> generate_mgf1_salt(EVP_PKEY *pkey, vrf::Type type)
{
    if (!vrf::is_rsa_type(type))
    {
        vrf::Logger()->warn("generate_mgf1_salt called with non-RSA VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    if (nullptr == pkey)
    {
        vrf::Logger()->warn("generate_mgf1_salt called with null EVP_PKEY.");
        return {};
    }

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

EVP_PKEY *load_evp_pkey_from_der_spki(const std::vector<std::byte> &der_spki, vrf::Type type)
{
    RSAVRFParams params = get_rsavrf_params(type);

    EVP_PKEY *pkey = nullptr;
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", "SubjectPublicKeyInfo", params.algorithm_name,
                                                           EVP_PKEY_PUBLIC_KEY, libctx, propquery);
    if (nullptr == dctx)
    {
        vrf::Logger()->error("Failed to create OSSL_DECODER_CTX for loading public key.");
        return nullptr;
    }

    const unsigned char *der_data = reinterpret_cast<const unsigned char *>(der_spki.data());
    std::size_t der_data_len = der_spki.size();
    if (1 != OSSL_DECODER_from_data(dctx, &der_data, &der_data_len))
    {
        vrf::Logger()->error("Failed to decode DER SPKI into EVP_PKEY using OSSL_DECODER_from_data.");
        EVP_PKEY_free(pkey);
        OSSL_DECODER_CTX_free(dctx);
        return nullptr;
    }

    // Verify that the loaded EVP_PKEY has the expected parameters for the given VRF type.
    if (!check_rsa_params(type, pkey))
    {
        vrf::Logger()->error("Loaded EVP_PKEY does not match expected RSA parameters for VRF type: {}",
                             vrf::type_to_string(type));
        EVP_PKEY_free(pkey);
        OSSL_DECODER_CTX_free(dctx);
        return nullptr;
    }

    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

bool check_bytes_in_modulus_range(std::span<const std::byte> test, const EVP_PKEY *pkey)
{
    BIGNUM *n = nullptr;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n))
    {
        vrf::Logger()->error("Failed to retrieve RSA modulus from EVP_PKEY for range check.");
        return false;
    }

    BIGNUM *bn_test = BN_bin2bn(reinterpret_cast<const unsigned char *>(test.data()),
                                     static_cast<int>(test.size()), nullptr);
    if (nullptr == bn_test)
    {
        vrf::Logger()->error("Failed to convert test input to BIGNUM for range check.");
        BN_free(n);
        return false;
    }

    // Test condition: 0 <= bn_test < n
    if (BN_is_negative(bn_test) || 0 >= BN_ucmp(n, bn_test))
    {
        // Print both n and bn_test in hex.
        // char *n_hex = BN_bn2hex(n);
        // char *test_hex = BN_bn2hex(bn_test);
        // vrf::Logger()->error("Input is out of range [0, n) for the given RSA public key. n = {}, test = {}",
        //                      n_hex ? n_hex : "(null)", test_hex ? test_hex : "(null)");
        // OPENSSL_free(n_hex);
        // OPENSSL_free(test_hex);

        BN_free(n);
        BN_free(bn_test);
        return false;
    }

    BN_free(n);
    BN_free(bn_test);
    return true;
}

std::vector<std::byte> rsa_raw_sign(EVP_PKEY *pkey, vrf::Type type, std::span<const std::byte> tbs)
{
    // WARNING:
    // - Not checking here that `pkey` is actually compatible with `type`.
    // - Not checking that `type` is a "no-padding" type.
    // Basically, these checks should be done by the caller.
    //
    // TODO: Remove unnecessary checks from here and make it clear what caller is expected to verify.

    if (tbs.empty())
    {
        vrf::Logger()->warn("rsa_raw_sign called with empty data to sign.");
        return {};
    }

    if (!vrf::is_rsa_type(type))
    {
        vrf::Logger()->warn("rsa_raw_sign called with non-RSA VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    if (nullptr == pkey)
    {
        vrf::Logger()->warn("rsa_raw_sign called with null EVP_PKEY.");
        return {};
    }

    // Need to verify that the input has the correct length.
    const RSAVRFParams params = get_rsavrf_params(type);
    int modlen = EVP_PKEY_get_size(pkey);
    if (modlen != params.bits / 8)
    {
        vrf::Logger()->error("EVP_PKEY input to rsa_raw_sign has incorrect size: expected {}, got {} for VRF type: {}",
                             params.bits / 8, modlen, vrf::type_to_string(type));
        return {};
    }
    if (modlen != tbs.size())
    {
        vrf::Logger()->error("Input to rsa_raw_sign has incorrect size: expected {}, got {} for VRF type: {}",
                             modlen, tbs.size(), vrf::type_to_string(type));
        return {};
    }
    if (!check_bytes_in_modulus_range(tbs, pkey))
    {
        vrf::Logger()->error("Input to rsa_raw_sign is out of range [0, n) for the given RSA public key.");
        return {};
    }

    // MD_CTX_Guard mctx = MD_CTX_Guard(true /* oneshot only */);
    // if (!mctx.has_value())
    // {
    //     vrf::Logger()->error("Failed to get EVP_MD_CTX.");
    //     return {};
    // }

    // ***************************************** //
    // * TODO: CAN mctx BE ACTUALLY NULL HERE? * //
    // ***************************************** //

    // Create the signing context.
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propquery);
    if (1 != EVP_PKEY_sign_init(pctx))
    {
        vrf::Logger()->error("Failed to initialize signing context for raw RSA; EVP_PKEY_sign_init failed.");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    // if (1 != EVP_DigestSignInit_ex(mctx.get(), &pctx, nullptr /* no digest */, libctx, propquery, pkey, nullptr))
    // {
    //     vrf::Logger()->error("Failed to initialize signing context for raw RSA; EVP_DigestSignInit_ex failed.");
    //     return {};
    // }

    // Configure the padding to be RSA_NO_PADDING.
    if (0 >= EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_NO_PADDING))
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

    // // One-shot digest-sign. Get the signature length first, although this should be the same as modlen.
    // std::size_t siglen = 0;
    // if (0 >=
    //     EVP_DigestSign(mctx.get(), nullptr, &siglen, reinterpret_cast<const unsigned char *>(tbs.data()),
    //     tbs.size()))
    // {
    //     vrf::Logger()->error("Failed to determine signature length for raw RSA; EVP_DigestSign failed.");
    //     return {};
    // }

    // std::vector<std::byte> signature(siglen);
    // if (0 >= EVP_DigestSign(mctx.get(), reinterpret_cast<unsigned char *>(signature.data()), &siglen,
    //                         reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    // {
    //     vrf::Logger()->error("Failed to generate raw RSA signature; EVP_DigestSign failed.");
    //     return {};
    // }

    // Resize the signature to the actual size.
    signature.resize(siglen);

    return signature;
}

std::vector<std::byte> rsa_verification_primitive(std::span<const std::byte> signature, EVP_PKEY *pkey)
{
    // WARNING: THIS FUNCTION ASSUMES THAT `pkey` IS A VALID RSA PUBLIC KEY!!! THIS MUST BE VERIFIED BY CALLER!

    if (signature.empty())
    {
        vrf::Logger()->warn("rsa_verification_primitive called with empty signature.");
        return {};
    }
    if (nullptr == pkey)
    {
        vrf::Logger()->warn("rsa_verification_primitive called with null EVP_PKEY.");
        return {};
    }

    // Get the modulus length.
    int modlen = EVP_PKEY_get_size(pkey);
    if (modlen <= 0)
    {
        vrf::Logger()->error("Failed to get RSA modulus length for verification primitive.");
        return {};
    }
    if (signature.size() != static_cast<std::size_t>(modlen))
    {
        vrf::Logger()->error("Signature length does not match RSA modulus length: expected {}, got {}.", modlen,
                             signature.size());
        return {};
    }

    // Verify that the signature representative is in range.
    if (!check_bytes_in_modulus_range(signature, pkey))
    {
        vrf::Logger()->warn("Signature representative is out of range for RSA verification primitive.");
        return {};
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propquery);
    if (nullptr == pctx)
    {
        vrf::Logger()->error("Failed to create EVP_PKEY_CTX for RSA verification primitive.");
        return {};
    }

    if (0 >= EVP_PKEY_encrypt_init(pctx) || 0 >= EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_NO_PADDING))
    {
        vrf::Logger()->error("Failed to initialize RSA verification primitive; EVP_PKEY_encrypt_init failed.");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    std::size_t mlen = 0;
    if (0 >= EVP_PKEY_encrypt(pctx, nullptr, &mlen, reinterpret_cast<const unsigned char *>(signature.data()),
                              signature.size()))
    {
        vrf::Logger()->error("Failed to determine output length for RSA verification primitive.");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    if (mlen != static_cast<std::size_t>(modlen))
    {
        vrf::Logger()->error("Unexpected output length from RSA verification primitive: expected {}, got {}.", modlen,
                             mlen);
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    std::vector<std::byte> message(mlen);
    if (0 >= EVP_PKEY_encrypt(pctx, reinterpret_cast<unsigned char *>(message.data()), &mlen,
                              reinterpret_cast<const unsigned char *>(signature.data()), signature.size()))
    {
        vrf::Logger()->error("Failed to perform RSA verification primitive; EVP_PKEY_encrypt failed.");
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    EVP_PKEY_CTX_free(pctx);
    return message;
}

std::vector<std::byte> rsassa_pss_nosalt_sign(EVP_PKEY *pkey, vrf::Type type, std::span<const std::byte> tbs)
{
    // WARNING:
    // - Not checking here that `pkey` is actually compatible with `type`.
    // - Not checking that `type` is a PSS type.
    // Basically, these checks should be done by the caller.
    //
    // TODO: Remove unnecessary checks from here and make it clear what caller is expected to verify.

    if (tbs.empty())
    {
        vrf::Logger()->warn("rsassa_pss_nosalt_sign called with empty data to sign.");
        return {};
    }

    if (!vrf::is_rsa_type(type))
    {
        vrf::Logger()->warn("rsassa_pss_nosalt_sign called with non-RSA VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    if (nullptr == pkey)
    {
        vrf::Logger()->warn("rsassa_pss_nosalt_sign called with null EVP_PKEY.");
        return {};
    }

    MD_CTX_Guard mctx = MD_CTX_Guard(true /* oneshot only */);
    if (!mctx.has_value())
    {
        vrf::Logger()->error("Failed to get EVP_MD_CTX.");
        return {};
    }

    // Create the signing context.
    const RSAVRFParams params = get_rsavrf_params(type);
    EVP_PKEY_CTX *pctx = nullptr;
    if (1 != EVP_DigestSignInit_ex(mctx.get(), &pctx, params.digest, libctx, propquery, pkey, nullptr))
    {
        vrf::Logger()->error("Failed to initialize signing context for RSASSA-PSS; EVP_DigestSignInit_ex failed.");
        return {};
    }

    // Configure the PSS padding. We set the salt length to 0. This is necessary for the VRF
    // since we need the signature to be deterministic (but unpredictable).
    if (0 >= EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) ||
        0 >= EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 0))
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
        vrf::Logger()->error("Failed to determine signature length for RSASSA-PSS; EVP_DigestSign failed.");
        return {};
    }

    std::vector<std::byte> signature(siglen);
    if (0 >= EVP_DigestSign(mctx.get(), reinterpret_cast<unsigned char *>(signature.data()), &siglen,
                            reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    {
        vrf::Logger()->error("Failed to generate RSASSA-PSS signature; EVP_DigestSign failed.");
        return {};
    }

    // Resize the signature to the actual size.
    signature.resize(siglen);

    return signature;
}

bool rsassa_pss_nosalt_verify(EVP_PKEY *pkey, vrf::Type type, std::span<const std::byte> sig,
                              std::span<const std::byte> tbs)
{
    if (sig.empty())
    {
        vrf::Logger()->warn("rsassa_pss_nosalt_verify called with empty signature to verify.");
        return false;
    }

    if (tbs.empty())
    {
        vrf::Logger()->warn("rsassa_pss_nosalt_verify called with empty data to verify against.");
        return false;
    }

    if (!vrf::is_rsa_type(type))
    {
        vrf::Logger()->warn("rsassa_pss_nosalt_verify called with non-RSA VRF type: {}", vrf::type_to_string(type));
        return false;
    }

    if (nullptr == pkey)
    {
        vrf::Logger()->warn("rsassa_pss_nosalt_verify called with null EVP_PKEY.");
        return false;
    }

    MD_CTX_Guard mctx = MD_CTX_Guard(true /* oneshot only */);
    if (!mctx.has_value())
    {
        vrf::Logger()->error("Failed to get EVP_MD_CTX.");
        return false;
    }

    // Create the verification context.
    const RSAVRFParams params = get_rsavrf_params(type);
    EVP_PKEY_CTX *pctx = nullptr;
    if (1 != EVP_DigestVerifyInit_ex(mctx.get(), &pctx, params.digest, libctx, propquery, pkey, nullptr))
    {
        vrf::Logger()->error(
            "Failed to initialize verification context for RSASSA-PSS; EVP_DigestVerifyInit_ex failed.");
        return false;
    }

    // Configure the PSS padding. We set the salt length to 0. This is necessary for the VRF
    // since we need the signature to be deterministic (but unpredictable).
    if (0 >= EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) ||
        0 >= EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 0))
    {
        vrf::Logger()->error("Failed to configure RSA PSS padding for verification.");
        return false;
    }

    // We don't need to call EVP_PKEY_CTX_set_rsa_mgf1_md because it defaults to the same digest
    // as the signature digest.

    // One-shot digest-verify.
    bool success = EVP_DigestVerify(mctx.get(), reinterpret_cast<const unsigned char *>(sig.data()), sig.size(),
                                    reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size());

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

    MD_CTX_Guard mctx = MD_CTX_Guard(false /* oneshot only */);
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

    // Set up the seed to MGF1.
    const RSAVRFParams params = get_rsavrf_params(type);
    const std::size_t suite_string_len = params.suite_string_len;
    std::vector<std::byte> tbs;
    tbs.reserve(suite_string_len + 1 /* domain separator */ + mgf1_salt.size() + data.size());
    std::copy_n(reinterpret_cast<const std::byte *>(params.suite_string), suite_string_len, std::back_inserter(tbs));
    tbs.push_back(std::byte{0x01});
    std::copy(mgf1_salt.begin(), mgf1_salt.end(), std::back_inserter(tbs));
    std::copy(data.begin(), data.end(), std::back_inserter(tbs));

    // Evaluate MGF1. The output MUST have size params.bits / 8 bytes. Otherwise, raw RSA signing will fail.
    std::vector<std::byte> ret(params.bits / 8);
    const EVP_MD *md = EVP_MD_fetch(libctx, params.digest, propquery);
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

std::vector<std::byte> construct_rsassa_pss_tbs(vrf::Type type, std::span<const std::byte> mgf1_salt,
                                                std::span<const std::byte> data)
{
    if (!vrf::is_rsa_type(type))
    {
        vrf::Logger()->warn("construct_rsassa_pss_tbs called with non-RSA VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    if (mgf1_salt.empty())
    {
        vrf::Logger()->warn("construct_rsassa_pss_tbs called with empty MGF1 salt.");
        return {};
    }

    const RSAVRFParams params = get_rsavrf_params(type);
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
        vrf::Logger()->warn("RSAProof::get_vrf_value called on invalid proof.");
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

    // Get an EVP_MD for the specified VRF type.
    const EVP_MD *md = EVP_MD_fetch(libctx, params.digest, propquery);
    if (nullptr == md)
    {
        vrf::Logger()->error("Failed to get EVP_MD for VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    MD_CTX_Guard mctx = MD_CTX_Guard(true /* oneshot only */);
    if (!mctx.has_value())
    {
        vrf::Logger()->error("Failed to get EVP_MD_CTX.");
        return {};
    }

    std::array<std::byte, EVP_MAX_MD_SIZE> md_out;
    unsigned md_outlen = 0;
    if (1 != EVP_DigestInit(mctx.get(), md) || 1 != EVP_DigestUpdate(mctx.get(), tbh.data(), tbh.size()) ||
        1 != EVP_DigestFinal_ex(mctx.get(), reinterpret_cast<unsigned char *>(md_out.data()), &md_outlen))
    {
        vrf::Logger()->error("Failed to compute VRF value digest; EVP_Digest* operations failed.");
        return {};
    }

    return std::vector<std::byte>(md_out.begin(), md_out.begin() + md_outlen);
}

std::unique_ptr<vrf::Proof> RSASecretKey::get_vrf_proof(std::span<const std::byte> in) const
{
    if (!is_initialized())
    {
        vrf::Logger()->warn("RSASecretKey::get_vrf_proof called on invalid RSASecretKey.");
        return nullptr;
    }

    const vrf::Type type = get_type();

    std::unique_ptr<vrf::Proof> ret = nullptr;

    const RSAVRFParams params = get_rsavrf_params(type);
    switch (params.pad_mode)
    {
    case RSA_NO_PADDING: {
        std::vector<std::byte> tbs = construct_rsa_fdh_tbs(type, mgf1_salt_, in);
        std::vector<std::byte> signature = rsa_raw_sign(pkey_, type, tbs);
        if (signature.empty())
        {
            vrf::Logger()->error("RSASecretKey::get_vrf_proof failed to generate raw RSA signature.");
            return nullptr;
        }

        ret.reset(new RSAProof(type, std::move(signature)));
        break;
    }
    case RSA_PKCS1_PSS_PADDING: {
        std::vector<std::byte> tbs = construct_rsassa_pss_tbs(type, mgf1_salt_, in);
        std::vector<std::byte> signature = rsassa_pss_nosalt_sign(pkey_, type, tbs);
        if (signature.empty())
        {
            vrf::Logger()->error("RSASecretKey::get_vrf_proof failed to generate RSASSA-PSS signature.");
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

RSASecretKey::RSASecretKey(vrf::Type type)
{
    if (!vrf::is_rsa_type(type))
    {
        vrf::Logger()->warn("RSASecretKey constructor called with non-RSA VRF type: {}", vrf::type_to_string(type));
        return;
    }

    EVP_PKEY *pkey = generate_rsa_key(type);
    if (nullptr == pkey)
    {
        vrf::Logger()->error("RSASecretKey constructor failed to generate RSA key.");
        return;
    }

    std::vector<std::byte> mgf1_salt = generate_mgf1_salt(pkey, type);
    if (mgf1_salt.empty())
    {
        vrf::Logger()->error("RSASecretKey constructor failed to generate MGF1 salt.");
        return;
    }

    RSASecretKey secret_key(type, pkey, std::move(mgf1_salt));
    *this = std::move(secret_key);
}

RSASecretKey::~RSASecretKey()
{
    EVP_PKEY_free(pkey_);
    pkey_ = nullptr;
}

RSASecretKey &RSASecretKey::operator=(RSASecretKey &&rhs) noexcept
{
    if (this != &rhs)
    {
        set_type(rhs.get_type());
        mgf1_salt_ = std::move(rhs.mgf1_salt_);
        pkey_ = rhs.pkey_;

        rhs.set_type(vrf::Type::UNKNOWN_VRF_TYPE);
        rhs.pkey_ = nullptr;
    }
    return *this;
}

RSASecretKey::RSASecretKey(const RSASecretKey &source)
{
    EVP_PKEY *pkey = evp_pkey_upref(source.pkey_);
    if (nullptr == pkey)
    {
        vrf::Logger()->error("RSASecretKey copy constructor failed to upref EVP_PKEY from source.");
        return;
    }

    RSASecretKey secret_key_copy(source.get_type(), pkey, source.mgf1_salt_);
    *this = std::move(secret_key_copy);
}

bool RSASecretKey::is_initialized() const
{
    // Trivial validity checks.
    if (get_type() == vrf::Type::UNKNOWN_VRF_TYPE || nullptr == pkey_)
    {
        return false;
    }

    // Check that the salt is valid.
    if (mgf1_salt_.empty())
    {
        return false;
    }

    return check_rsa_params(get_type(), pkey_);
}

RSAPublicKey::~RSAPublicKey()
{
    EVP_PKEY_free(pkey_);
    pkey_ = nullptr;
}

RSAPublicKey::RSAPublicKey(const RSAPublicKey &source)
{
    EVP_PKEY *pkey = evp_pkey_upref(source.pkey_);
    if (nullptr == pkey)
    {
        vrf::Logger()->error("RSAPublicKey copy constructor failed to upref EVP_PKEY from source.");
        return;
    }

    RSAPublicKey public_key_copy(source.get_type(), source.der_spki_, source.mgf1_salt_, pkey);
    *this = std::move(public_key_copy);
}

RSAPublicKey &RSAPublicKey::operator=(RSAPublicKey &&rhs) noexcept
{
    if (this != &rhs)
    {
        set_type(rhs.get_type());
        der_spki_ = std::move(rhs.der_spki_);
        mgf1_salt_ = std::move(rhs.mgf1_salt_);
        pkey_ = rhs.pkey_;

        rhs.set_type(vrf::Type::UNKNOWN_VRF_TYPE);
        rhs.pkey_ = nullptr;
    }
    return *this;
}

RSAPublicKey::RSAPublicKey(vrf::Type type, std::vector<std::byte> der_spki, std::vector<std::byte> mgf1_salt)
{
    if (!vrf::is_rsa_type(type))
    {
        vrf::Logger()->warn("RSAPublicKey constructor called with non-RSA VRF type: {}", vrf::type_to_string(type));
        return;
    }

    if (der_spki.empty())
    {
        vrf::Logger()->warn("RSAPublicKey constructor called with empty DER SPKI.");
        return;
    }

    EVP_PKEY *pkey = load_evp_pkey_from_der_spki(der_spki, type);
    if (nullptr == pkey)
    {
        vrf::Logger()->error("RSAPublicKey constructor failed to load EVP_PKEY from provided DER SPKI.");
        return;
    }

    RSAPublicKey public_key(type, std::move(der_spki), std::move(mgf1_salt), pkey);
    *this = std::move(public_key);
}

RSAPublicKey::RSAPublicKey(vrf::Type type, std::vector<std::byte> der_spki)
{
    RSAPublicKey public_key(type, std::move(der_spki), {});
    public_key.mgf1_salt_ = generate_mgf1_salt(public_key.pkey_, type);
    if (public_key.mgf1_salt_.empty())
    {
        vrf::Logger()->error("RSAPublicKey constructor failed to generate MGF1 salt from loaded EVP_PKEY.");
        return;
    }

    *this = std::move(public_key);
}

bool RSAPublicKey::is_initialized() const
{
    vrf::Type type = get_type();
    if (!vrf::is_rsa_type(type) || der_spki_.empty() || mgf1_salt_.empty())
    {
        return false;
    }

    EVP_PKEY *pkey = load_evp_pkey_from_der_spki(der_spki_, type);
    if (nullptr == pkey)
    {
        return false;
    }

    bool valid = check_rsa_params(type, pkey);
    EVP_PKEY_free(pkey);

    return valid;
}

void RSAPublicKey::from_bytes(vrf::Type type, std::span<const std::byte> data)
{
    RSAPublicKey public_key(type, std::vector<std::byte>(data.begin(), data.end()));
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

    OSSL_ENCODER_CTX *ectx =
        OSSL_ENCODER_CTX_new_for_pkey(pkey_, EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo", propquery);

    unsigned char *der_data = nullptr;
    std::size_t der_data_len = 0;
    if (1 != OSSL_ENCODER_to_data(ectx, &der_data, &der_data_len))
    {
        vrf::Logger()->error("Failed to encode to DER SPKI using OSSL_ENCODER_to_data.");
        OSSL_ENCODER_CTX_free(ectx);
        return nullptr;
    }

    const std::byte *der_data_begin = reinterpret_cast<const std::byte *>(der_data);
    const std::byte *der_data_end = der_data_begin + der_data_len;
    std::vector<std::byte> der_spki(der_data_begin, der_data_end);

    OPENSSL_free(der_data);
    OSSL_ENCODER_CTX_free(ectx);

    return std::unique_ptr<RSAPublicKey>(new RSAPublicKey(get_type(), std::move(der_spki), mgf1_salt_));
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
    if (!rsa_proof->is_initialized() || rsa_proof->get_type() != type || !vrf::is_rsa_type(type))
    {
        vrf::Logger()->warn("RSAPublicKey::verify_vrf_proof called with invalid or mismatched proof type.");
        return {false, {}};
    }

    bool success = false;

    const RSAVRFParams params = get_rsavrf_params(type);
    switch (params.pad_mode)
    {
    case RSA_NO_PADDING: {
        std::vector<std::byte> tbs_expected = rsa_verification_primitive(rsa_proof->proof_, pkey_);
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
        std::vector<std::byte> tbs = construct_rsassa_pss_tbs(type, mgf1_salt_, in);
        success = rsassa_pss_nosalt_verify(pkey_, type, rsa_proof->proof_, tbs);
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
