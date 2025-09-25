#include "vrf/vrf.h"
#include "vrf/log.h"
#include "vrf/rsa/rsavrf.h"

namespace vrf
{

std::unique_ptr<SecretKey> VRF::Create(Type type)
{
    if (is_rsa_type(type))
    {
        return std::unique_ptr<SecretKey>(new rsavrf::RSASecretKey{type});
    }
    else if (is_ec_type(type))
    {
        // Not implemented.
        Logger()->error("VRF type {} is not supported", type_to_string(type));
        return nullptr;
    }
    else
    {
        Logger()->error("VRF type {} is not supported", type_to_string(type));
        return nullptr;
    }
}

std::unique_ptr<Proof> VRF::proof_from_bytes(Type type, std::span<const std::byte> data)
{
    std::unique_ptr<Proof> proof = nullptr;

    if (is_rsa_type(type))
    {
        proof.reset(new rsavrf::RSAProof{});
    }
    else if (is_ec_type(type))
    {
        // Not implemented.
        Logger()->warn("VRF type {} is not supported", type_to_string(type));
    }
    else
    {
        Logger()->warn("VRF type {} is not supported", type_to_string(type));
    }

    if (nullptr == proof)
    {
        Logger()->error("Failed to allocate memory for VRF proof of type {}", type_to_string(type));
        return nullptr;
    }

    proof->from_bytes(type, data);
    if (!proof->is_initialized())
    {
        Logger()->warn("Failed to deserialize VRF proof for type {}", type_to_string(type));
        return nullptr;
    }

    return proof;
}

std::unique_ptr<PublicKey> VRF::public_key_from_bytes(Type type, std::span<const std::byte> data)
{
    std::unique_ptr<PublicKey> pk = nullptr;

    if (is_rsa_type(type))
    {
        pk.reset(new rsavrf::RSAPublicKey{});
    }
    else if (is_ec_type(type))
    {
        // Not implemented.
        Logger()->warn("VRF type {} is not supported", type_to_string(type));
    }
    else
    {
        Logger()->warn("VRF type {} is not supported", type_to_string(type));
    }

    if (nullptr == pk)
    {
        Logger()->error("Failed to allocate memory for VRF public key of type {}", type_to_string(type));
        return nullptr;
    }

    pk->from_bytes(type, data);
    if (!pk->is_initialized())
    {
        Logger()->warn("Failed to deserialize VRF public key for type {}", type_to_string(type));
        return nullptr;
    }

    return pk;
}

} // namespace vrf
