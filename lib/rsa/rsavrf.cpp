#include "rsa/rsavrf.h"
#include "log.h"
#include "rsa/params.h"
#include "vrf/type.h"
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

EVP_MD_CTX *get_md_ctx(vrf::Type type)
{
    class MDCTXManager
    {
      public:
        MDCTXManager() : mctx_(nullptr)
        {
        }

        MDCTXManager(EVP_MD_CTX *mctx) : mctx_(mctx)
        {
        }

        void release()
        {
            if (nullptr != mctx_)
            {
                EVP_MD_CTX_free(mctx_);
                mctx_ = nullptr;
            }
        }

        ~MDCTXManager()
        {
            release();
        }

        EVP_MD_CTX *reset_and_get()
        {
            if (nullptr == mctx_)
            {
                mctx_ = New();
            }
            else
            {
                reset();
            }
            return mctx_;
        }

      private:
        void reset()
        {
            if (nullptr != mctx_ && 1 != EVP_MD_CTX_reset(mctx_))
            {
                release();
                mctx_ = New();
            }
        }

        static EVP_MD_CTX *New()
        {
            EVP_MD_CTX *mctx = EVP_MD_CTX_new();
            EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_ONESHOT | EVP_MD_CTX_FLAG_FINALISE);
            return mctx;
        }

        EVP_MD_CTX *mctx_;
    };

    if (!vrf::is_rsa_type(type))
    {
        return nullptr;
    }

    constexpr std::size_t vrf_type_count = static_cast<std::size_t>(vrf::Type::UNKNOWN_VRF_TYPE);
    thread_local static std::array<MDCTXManager, vrf_type_count> mctx_array{};
    const std::size_t type_index = static_cast<std::size_t>(type);

    const RSAVRFParams params = get_rsavrf_params(type);
    EVP_MD_CTX *mctx = mctx_array[type_index].reset_and_get();
    if (nullptr == mctx)
    {
        vrf::Logger()->error("Failed to fetch EVP_MD_CTX for digest: {}", params.digest);
    }

    return mctx;
}

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

std::vector<std::byte> rsassa_pss_nosalt_sign(EVP_PKEY *pkey, vrf::Type type, std::span<const std::byte> tbs)
{
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

    // Get an EVP_MD_CTX for the specified VRF type. This does *not* need to be freed by the caller.
    EVP_MD_CTX *mctx = get_md_ctx(type);
    if (nullptr == mctx)
    {
        vrf::Logger()->error("Failed to get EVP_MD_CTX for VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    // Create the signing context.
    const RSAVRFParams params = get_rsavrf_params(type);
    EVP_PKEY_CTX *pctx = nullptr;
    if (1 != EVP_DigestSignInit_ex(mctx, &pctx, params.digest, libctx, propquery, pkey, nullptr))
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
    if (0 >= EVP_DigestSign(mctx, nullptr, &siglen, reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    {
        vrf::Logger()->error("Failed to determine signature length for RSASSA-PSS; EVP_DigestSign failed.");
        EVP_MD_CTX_free(mctx);
        return {};
    }

    std::vector<std::byte> signature(siglen);
    if (0 >= EVP_DigestSign(mctx, reinterpret_cast<unsigned char *>(signature.data()), &siglen,
                            reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    {
        vrf::Logger()->error("Failed to generate RSASSA-PSS signature; EVP_DigestSign failed.");
        EVP_MD_CTX_free(mctx);
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

    // Get an EVP_MD_CTX for the specified VRF type. This does *not* need to be freed by the caller.
    EVP_MD_CTX *mctx = get_md_ctx(type);
    if (nullptr == mctx)
    {
        vrf::Logger()->error("Failed to get EVP_MD_CTX for VRF type: {}", vrf::type_to_string(type));
        return false;
    }

    // Create the verification context.
    const RSAVRFParams params = get_rsavrf_params(type);
    EVP_PKEY_CTX *pctx = nullptr;
    if (1 != EVP_DigestVerifyInit_ex(mctx, &pctx, params.digest, libctx, propquery, pkey, nullptr))
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
    bool success = EVP_DigestVerify(mctx, reinterpret_cast<const unsigned char *>(sig.data()), sig.size(),
                                    reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size());

    return success;
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

    // Get an EVP_MD_CTX for the specified VRF type. This does *not* need to be freed by the caller.
    EVP_MD_CTX *mctx = get_md_ctx(type);
    if (nullptr == mctx)
    {
        vrf::Logger()->error("Failed to get EVP_MD_CTX for VRF type: {}", vrf::type_to_string(type));
        return {};
    }

    std::array<std::byte, EVP_MAX_MD_SIZE> md_out;
    unsigned md_outlen = 0;
    if (1 != EVP_DigestInit(mctx, md) || 1 != EVP_DigestUpdate(mctx, tbh.data(), tbh.size()) ||
        1 != EVP_DigestFinal_ex(mctx, reinterpret_cast<unsigned char *>(md_out.data()), &md_outlen))
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
    case RSA_NO_PADDING:
        vrf::Logger()->error("Not implemented!");
        break;
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
    case RSA_NO_PADDING:
        vrf::Logger()->error("Not implemented!");
        break;
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
