#pragma once

#include "vrf/type.h"
#include "vrf/vrf_base.h"
#include <cstddef>
#include <memory>
#include <openssl/evp.h>
#include <span>
#include <utility>
#include <vector>

namespace rsavrf
{

class RSASecretKey;

class RSAProof : public vrf::Proof
{
  public:
    RSAProof() = default;

    ~RSAProof() override = default;

    [[nodiscard]] std::vector<std::byte> get_vrf_value() const override;

    [[nodiscard]] std::unique_ptr<vrf::Proof> clone() const override
    {
        return std::unique_ptr<RSAProof>(new RSAProof(*this));
    }

    [[nodiscard]] std::vector<std::byte> to_bytes() const override
    {
        return proof_;
    }

    void from_bytes(vrf::Type type, std::span<const std::byte> data) override;

    [[nodiscard]] bool is_initialized() const override;

  private:
    RSAProof(const RSAProof &source);

    RSAProof(vrf::Type type, std::vector<std::byte> proof) : vrf::Proof(type), proof_(std::move(proof))
    {
        // Assumes all inputs are valid and consistent.
    }

    RSAProof &operator=(const RSAProof &) = delete;

    RSAProof &operator=(RSAProof &&) noexcept;

    RSAProof(RSAProof &&source) noexcept
    {
        *this = std::move(source);
    }

    std::vector<std::byte> proof_{};

    friend class RSASecretKey;

    friend class RSAPublicKey;
};

class RSAPublicKey;

class RSASecretKey : public vrf::SecretKey
{
  public:
    RSASecretKey() = default;

    ~RSASecretKey() override;

    RSASecretKey(vrf::Type type);

    [[nodiscard]] std::unique_ptr<vrf::Proof> get_vrf_proof(std::span<const std::byte> in) const override;

    [[nodiscard]] bool is_initialized() const override;

    [[nodiscard]] std::unique_ptr<vrf::SecretKey> clone() const override
    {
        return std::unique_ptr<RSASecretKey>(new RSASecretKey(*this));
    }

    [[nodiscard]] std::unique_ptr<vrf::PublicKey> get_public_key() const override;

  private:
    RSASecretKey(vrf::Type type, EVP_PKEY *pkey, std::vector<std::byte> mgf1_salt)
        : vrf::SecretKey(type), pkey_(pkey), mgf1_salt_(std::move(mgf1_salt))
    {
        // Assumes all inputs are valid and consistent.
    }

    RSASecretKey &operator=(RSASecretKey &&) noexcept;

    RSASecretKey(RSASecretKey &&source) noexcept
    {
        *this = std::move(source);
    }

    RSASecretKey &operator=(const RSASecretKey &) = delete;

    RSASecretKey(const RSASecretKey &);

    EVP_PKEY *pkey_ = nullptr;

    std::vector<std::byte> mgf1_salt_{};
};

class RSAPublicKey : public vrf::PublicKey
{
  public:
    RSAPublicKey() = default;

    ~RSAPublicKey() override;

    [[nodiscard]] std::pair<bool, std::vector<std::byte>> verify_vrf_proof(
        std::span<const std::byte> in, const std::unique_ptr<vrf::Proof> &proof) const override;

    [[nodiscard]] bool is_initialized() const override;

    [[nodiscard]] std::vector<std::byte> to_bytes() const override
    {
        return der_spki_;
    }

    void from_bytes(vrf::Type type, std::span<const std::byte> data) override;

    [[nodiscard]] std::unique_ptr<vrf::PublicKey> clone() const override
    {
        return std::unique_ptr<RSAPublicKey>(new RSAPublicKey(*this));
    }

  private:
    RSAPublicKey(vrf::Type type, std::vector<std::byte> der_spki);

    RSAPublicKey(vrf::Type type, std::vector<std::byte> der_spki, std::vector<std::byte> mgf1_salt);

    RSAPublicKey(vrf::Type type, std::vector<std::byte> der_spki, std::vector<std::byte> mgf1_salt, EVP_PKEY *pkey)
        : vrf::PublicKey(type), der_spki_(std::move(der_spki)), mgf1_salt_(std::move(mgf1_salt)), pkey_(pkey)
    {
        // Assumes all inputs are valid and consistent.
    }

    RSAPublicKey &operator=(const RSAPublicKey &) = delete;

    RSAPublicKey(const RSAPublicKey &);

    RSAPublicKey &operator=(RSAPublicKey &&) noexcept;

    RSAPublicKey(RSAPublicKey &&source) noexcept
    {
        *this = std::move(source);
    }

    std::vector<std::byte> der_spki_{};

    std::vector<std::byte> mgf1_salt_{};

    EVP_PKEY *pkey_ = nullptr;

    friend class RSASecretKey;
};

} // namespace rsavrf
