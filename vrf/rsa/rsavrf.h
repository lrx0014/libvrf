#pragma once

#include "vrf/rsa/keys.h"
#include "vrf/type.h"
#include "vrf/vrf_base.h"
#include <cstddef>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace vrf::rsavrf
{

class RSASecretKey;

class RSAProof : public Proof
{
  public:
    RSAProof() = default;

    ~RSAProof() override = default;

    [[nodiscard]] std::vector<std::byte> get_vrf_value() const override;

    [[nodiscard]] std::unique_ptr<Proof> clone() const override
    {
        return std::unique_ptr<RSAProof>(new RSAProof(*this));
    }

    [[nodiscard]] std::vector<std::byte> to_bytes() const override
    {
        return proof_;
    }

    void from_bytes(Type type, std::span<const std::byte> data) override;

    [[nodiscard]] bool is_initialized() const override;

  private:
    RSAProof(const RSAProof &source);

    RSAProof(Type type, std::vector<std::byte> proof) : Proof{type}, proof_{std::move(proof)}
    {
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

class RSASecretKey : public SecretKey
{
  public:
    RSASecretKey() = default;

    ~RSASecretKey() override = default;

    RSASecretKey(Type type);

    [[nodiscard]] std::unique_ptr<Proof> get_vrf_proof(std::span<const std::byte> in) const override;

    [[nodiscard]] bool is_initialized() const override;

    [[nodiscard]] std::unique_ptr<SecretKey> clone() const override
    {
        return std::unique_ptr<RSASecretKey>(new RSASecretKey(*this));
    }

    [[nodiscard]] std::unique_ptr<PublicKey> get_public_key() const override;

  private:
    RSASecretKey &operator=(RSASecretKey &&) noexcept;

    RSASecretKey(RSASecretKey &&source) noexcept
    {
        *this = std::move(source);
    }

    RSASecretKey &operator=(const RSASecretKey &) = delete;

    RSASecretKey(const RSASecretKey &);

    RSA_SK_Guard sk_guard_{};

    std::vector<std::byte> mgf1_salt_{};
};

class RSAPublicKey : public PublicKey
{
  public:
    RSAPublicKey() = default;

    ~RSAPublicKey() override = default;

    [[nodiscard]] std::pair<bool, std::vector<std::byte>> verify_vrf_proof(
        std::span<const std::byte> in, const std::unique_ptr<Proof> &proof) const override;

    [[nodiscard]] bool is_initialized() const override;

    [[nodiscard]] std::vector<std::byte> to_bytes() const override;

    void from_bytes(Type type, std::span<const std::byte> data) override;

    [[nodiscard]] std::unique_ptr<PublicKey> clone() const override
    {
        return std::unique_ptr<RSAPublicKey>{new RSAPublicKey(*this)};
    }

  private:
    RSAPublicKey(Type type, std::span<const std::byte> der_spki);

    RSAPublicKey &operator=(const RSAPublicKey &) = delete;

    RSAPublicKey(const RSAPublicKey &);

    RSAPublicKey &operator=(RSAPublicKey &&) noexcept;

    RSAPublicKey(RSAPublicKey &&source) noexcept
    {
        *this = std::move(source);
    }

    RSA_PK_Guard pk_guard_{};

    std::vector<std::byte> mgf1_salt_{};

    friend class RSASecretKey;
};

} // namespace vrf::rsavrf
