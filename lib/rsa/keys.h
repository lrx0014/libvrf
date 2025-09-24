#pragma once

#include "vrf/type.h"
#include <concepts>
#include <openssl/evp.h>
#include <span>
#include <vector>

namespace rsavrf
{

class RSA_SK_Guard
{
  public:
    RSA_SK_Guard() = default;

    RSA_SK_Guard(vrf::Type type);

    ~RSA_SK_Guard()
    {
        reset();
    }

    RSA_SK_Guard &operator=(const RSA_SK_Guard &) = delete;

    RSA_SK_Guard &operator=(RSA_SK_Guard &&) noexcept;

    RSA_SK_Guard(const RSA_SK_Guard &) = delete;

    RSA_SK_Guard(RSA_SK_Guard &&rhs) noexcept
    {
        *this = std::move(rhs);
    }

    [[nodiscard]] EVP_PKEY *get() const noexcept
    {
        return pkey_;
    }

    [[nodiscard]] bool has_value() const noexcept
    {
        return nullptr != pkey_;
    }

    [[nodiscard]] vrf::Type get_type() const noexcept
    {
        return type_;
    }

    [[nodiscard]] RSA_SK_Guard clone() const;

    [[nodiscard]] std::vector<std::byte> get_mgf1_salt() const;

    void reset()
    {
        EVP_PKEY_free(pkey_);
        pkey_ = nullptr;
        type_ = vrf::Type::UNKNOWN_VRF_TYPE;
    }

  private:
    RSA_SK_Guard(vrf::Type type, EVP_PKEY *pkey) : type_(type), pkey_(pkey) {};

    static EVP_PKEY *generate_rsa_key(vrf::Type type);

    vrf::Type type_ = vrf::Type::UNKNOWN_VRF_TYPE;

    EVP_PKEY *pkey_ = nullptr;
};

class RSA_PK_Guard
{
  public:
    RSA_PK_Guard() = default;

    RSA_PK_Guard(vrf::Type type, std::span<const std::byte> der_spki);

    ~RSA_PK_Guard()
    {
        reset();
    }

    RSA_PK_Guard &operator=(const RSA_PK_Guard &) = delete;

    RSA_PK_Guard &operator=(RSA_PK_Guard &&) noexcept;

    RSA_PK_Guard(const RSA_PK_Guard &) = delete;

    RSA_PK_Guard(RSA_PK_Guard &&rhs) noexcept
    {
        *this = std::move(rhs);
    }

    [[nodiscard]] EVP_PKEY *get() const noexcept
    {
        return pkey_;
    }

    [[nodiscard]] bool has_value() const noexcept
    {
        return nullptr != pkey_;
    }

    [[nodiscard]] vrf::Type get_type() const noexcept
    {
        return type_;
    }

    [[nodiscard]] RSA_PK_Guard clone() const;

    [[nodiscard]] std::vector<std::byte> get_mgf1_salt() const;

    void reset()
    {
        EVP_PKEY_free(pkey_);
        pkey_ = nullptr;
        type_ = vrf::Type::UNKNOWN_VRF_TYPE;
    }

  private:
    RSA_PK_Guard(vrf::Type type, EVP_PKEY *pkey) : type_(type), pkey_(pkey) {};

    vrf::Type type_ = vrf::Type::UNKNOWN_VRF_TYPE;

    EVP_PKEY *pkey_ = nullptr;
};

template <typename T>
concept RSAGuard = std::same_as<T, RSA_PK_Guard> || std::same_as<T, RSA_SK_Guard>;

} // namespace rsavrf
