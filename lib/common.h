#pragma once

#include <cstddef>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <span>
#include <vector>

namespace vrf::common
{

OSSL_LIB_CTX *get_libctx();

const char *get_propquery();

EVP_PKEY *decode_public_key_from_der_spki(const char *algorithm_name, std::span<const std::byte> der_spki);

std::vector<std::byte> encode_public_key_to_der_spki(EVP_PKEY *pkey);

EVP_PKEY *evp_pkey_upref(EVP_PKEY *pkey);

class MD_CTX_Guard
{
  public:
    MD_CTX_Guard(bool oneshot_only);

    ~MD_CTX_Guard()
    {
        EVP_MD_CTX_free(mctx_);
        mctx_ = nullptr;
    }

    MD_CTX_Guard(const MD_CTX_Guard &) = delete;

    MD_CTX_Guard(MD_CTX_Guard &&) = delete;

    MD_CTX_Guard &operator=(const MD_CTX_Guard &) = delete;

    MD_CTX_Guard &operator=(MD_CTX_Guard &&) = delete;

    [[nodiscard]] EVP_MD_CTX *get() const noexcept
    {
        return mctx_;
    }

    [[nodiscard]] bool has_value() const noexcept
    {
        return nullptr != mctx_;
    }

  private:
    EVP_MD_CTX *mctx_ = nullptr;
};

std::vector<std::byte> compute_hash(const char *md_name, std::span<const std::byte> tbh);

} // namespace vrf::common
