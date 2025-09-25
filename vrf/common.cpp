#include "vrf/common.h"
#include "vrf/log.h"
#include <array>
#include <cstdint>
#include <openssl/decoder.h>
#include <openssl/encoder.h>

namespace vrf::common
{

OSSL_LIB_CTX *get_libctx()
{
    // For a custom libctx, create a RAII wrapper here instead and return
    // a pointer to the underlying OSSL_LIB_CTX.
    static OSSL_LIB_CTX *libctx = nullptr;
    return libctx;
}

const char *get_propquery()
{
    // Set a custom propquery here.
    static const char *propquery = nullptr;
    return propquery;
}

EVP_PKEY *decode_public_key_from_der_spki(const char *algorithm_name, std::span<const std::byte> der_spki)
{
    if (nullptr == algorithm_name || der_spki.empty())
    {
        vrf::Logger()->warn("decode_public_key_from_der_spki called with null algorithm name or empty DER data.");
        return nullptr;
    }

    EVP_PKEY *pkey = nullptr;
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", "SubjectPublicKeyInfo", algorithm_name,
                                                           EVP_PKEY_PUBLIC_KEY, get_libctx(), get_propquery());
    if (nullptr == dctx)
    {
        vrf::Logger()->error("Failed to create OSSL_DECODER_CTX for loading public key.");
        return nullptr;
    }

    const unsigned char *der_data = reinterpret_cast<const unsigned char *>(der_spki.data());
    std::size_t der_data_len = der_spki.size();
    if (1 != OSSL_DECODER_from_data(dctx, &der_data, &der_data_len))
    {
        vrf::Logger()->warn("Failed to decode DER SPKI into EVP_PKEY using OSSL_DECODER_from_data.");
        EVP_PKEY_free(pkey);
        OSSL_DECODER_CTX_free(dctx);
        return nullptr;
    }

    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

std::vector<std::byte> encode_public_key_to_der_spki(EVP_PKEY *pkey)
{
    if (nullptr == pkey)
    {
        vrf::Logger()->warn("encode_public_key_from_der_spki called with null key.");
        return {};
    }

    OSSL_ENCODER_CTX *ectx =
        OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo", get_propquery());

    unsigned char *der_data = nullptr;
    std::size_t der_data_len = 0;
    if (1 != OSSL_ENCODER_to_data(ectx, &der_data, &der_data_len))
    {
        vrf::Logger()->error("Failed to encode to DER SPKI using OSSL_ENCODER_to_data.");
        OSSL_ENCODER_CTX_free(ectx);
        return {};
    }

    const std::byte *der_data_begin = reinterpret_cast<const std::byte *>(der_data);
    const std::byte *der_data_end = der_data_begin + der_data_len;
    std::vector<std::byte> der_spki(der_data_begin, der_data_end);

    OPENSSL_free(der_data);
    OSSL_ENCODER_CTX_free(ectx);

    return der_spki;
}

EVP_PKEY *evp_pkey_upref(EVP_PKEY *pkey)
{
    if (nullptr == pkey)
    {
        return nullptr;
    }

    if (1 != EVP_PKEY_up_ref(pkey))
    {
        vrf::Logger()->error("Failed to increment reference count for EVP_PKEY.");
        return nullptr;
    }

    return pkey;
}

MD_CTX_Guard::MD_CTX_Guard(bool oneshot_only)
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

std::vector<std::byte> compute_hash(const char *md_name, std::span<const std::byte> tbh)
{
    // Get an EVP_MD for the specified VRF type.
    const EVP_MD *md = EVP_MD_fetch(get_libctx(), md_name, get_propquery());
    if (nullptr == md)
    {
        vrf::Logger()->error("Failed to get EVP_MD for digest: {}", md_name);
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
        vrf::Logger()->error("Failed to compute digest; EVP_Digest* operations failed.");
        return {};
    }

    return std::vector<std::byte>(md_out.begin(), md_out.begin() + md_outlen);
}

} // namespace vrf::common
