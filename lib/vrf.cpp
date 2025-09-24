#include "vrf/vrf.h"
#include "log.h"

namespace vrf
{

VRF &VRF::operator=(VRF &&rhs) noexcept
{
    if (this != &rhs)
    {
        set_type(rhs.get_type());
        sk_ = std::move(rhs.sk_);
        pk_ = std::move(rhs.pk_);

        rhs.set_type(Type::UNKNOWN_VRF_TYPE);
    }
    return *this;
}

template <typename T> VRF VRF::make_vrf(Type type)
{
    VRF vrf{};

    std::unique_ptr<SecretKey> sk(new T{type});
    if (nullptr == sk)
    {
        spdlog::error("Failed to generate secret key for VRF type {}", type_to_string(type));
        return VRF{};
    }

    std::unique_ptr<PublicKey> pk = sk->get_public_key();

    vrf.set_type(type);
    vrf.sk_ = std::move(sk);
    vrf.pk_ = std::move(pk);

    if (!vrf.is_initialized())
    {
        spdlog::error("VRF object is not properly initialized for VRF type {}", type_to_string(type));
        return VRF{};
    }

    return vrf;
}

VRF::VRF(Type type)
{
    if (is_rsa_type(type))
    {
        *this = make_vrf<rsavrf::RSASecretKey>(type);
    }
    else if (is_ec_type(type))
    {
        // Not implemented.
        spdlog::error("VRF type {} is not supported", type_to_string(type));
        return;
    }
    else
    {
        spdlog::error("VRF type {} is not supported", type_to_string(type));
        return;
    }
}

std::unique_ptr<PublicKey> VRF::get_public_key() const
{
    return pk_ == nullptr ? nullptr : pk_->clone();
}

std::unique_ptr<SecretKey> VRF::get_secret_key() const
{
    return sk_ == nullptr ? nullptr : sk_->clone();
}

bool VRF::is_initialized() const
{
    bool type_valid = get_type() != Type::UNKNOWN_VRF_TYPE;
    bool keys_set = type_valid && (sk_ != nullptr && pk_ != nullptr);
    bool type_matches = keys_set && (sk_->get_type() == get_type() && pk_->get_type() == get_type());
    bool keys_valid = type_matches && (sk_->is_initialized() && pk_->is_initialized());

    return keys_valid;
}

std::unique_ptr<Proof> VRF::proof_from_bytes(Type type, std::span<std::byte> data)
{
    std::unique_ptr<Proof> proof = nullptr;

    if (is_rsa_type(type))
    {
        proof.reset(new rsavrf::RSAProof{});
    }
    else if (is_ec_type(type))
    {
        // Not implemented.
        spdlog::warn("VRF type {} is not supported", type_to_string(type));
    }
    else
    {
        spdlog::warn("VRF type {} is not supported", type_to_string(type));
    }

    if (nullptr == proof)
    {
        spdlog::error("Failed to allocate memory for VRF proof of type {}", type_to_string(type));
        return nullptr;
    }

    proof->from_bytes(type, data);
    if (!proof->is_initialized())
    {
        spdlog::warn("Failed to deserialize VRF proof for type {}", type_to_string(type));
        return nullptr;
    }

    return proof;
}

std::unique_ptr<PublicKey> VRF::public_key_from_bytes(Type type, std::span<std::byte> data)
{
    std::unique_ptr<PublicKey> pk = nullptr;

    if (is_rsa_type(type))
    {
        pk.reset(new rsavrf::RSAPublicKey{});
    }
    else if (is_ec_type(type))
    {
        // Not implemented.
        spdlog::warn("VRF type {} is not supported", type_to_string(type));
    }
    else
    {
        spdlog::warn("VRF type {} is not supported", type_to_string(type));
    }

    if (nullptr == pk)
    {
        spdlog::error("Failed to allocate memory for VRF public key of type {}", type_to_string(type));
        return nullptr;
    }

    pk->from_bytes(type, data);
    if (!pk->is_initialized())
    {
        spdlog::warn("Failed to deserialize VRF public key for type {}", type_to_string(type));
        return nullptr;
    }

    return pk;
}

} // namespace vrf
