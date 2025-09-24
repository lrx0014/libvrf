#pragma once

#include "rsa/rsavrf.h"
#include "vrf/vrf_base.h"

namespace vrf
{

/**
 * The main VRF class that encapsulates VRF operations including key generation, proof generation,
 * and proof verification. This class can be used with all of the supported VRF types defined in
 * vrf::Type.
 */
class VRF : public VRFObject<VRF>
{
  public:
    ~VRF() = default;

    VRF(Type type);

    /**
     * Checks whether this VRF object is properly initialized with both a secret key and a public key.
     */
    [[nodiscard]] bool is_initialized() const override;

    /**
     * Returns the public key associated with this VRF object.
     */
    [[nodiscard]] std::unique_ptr<PublicKey> get_public_key() const;

    /**
     * Returns the secret key associated with this VRF object.
     */
    [[nodiscard]] std::unique_ptr<SecretKey> get_secret_key() const;

    /**
     * Deserializes a VRF proof from a span of bytes for the specified VRF type. Returns a unique
     * pointer to the deserialized proof object, or nullptr if deserialization fails.
     */
    [[nodiscard]] static std::unique_ptr<Proof> proof_from_bytes(Type type, std::span<std::byte> data);

    /**
     * Deserializes a VRF public key from a span of bytes for the specified VRF type. Returns a unique
     * pointer to the deserialized public key object, or nullptr if deserialization fails.
     */
    [[nodiscard]] static std::unique_ptr<PublicKey> public_key_from_bytes(Type type, std::span<std::byte> data);

    VRF &operator=(VRF &&) noexcept;

  private:
    VRF() = default;

    VRF(const VRF &) = delete;

    VRF &operator=(const VRF &) = delete;

    VRF(VRF &&source) noexcept
    {
        *this = std::move(source);
    }

    template <typename T> static VRF make_vrf(Type type);

    std::unique_ptr<SecretKey> sk_ = nullptr;

    std::unique_ptr<PublicKey> pk_ = nullptr;
};

} // namespace vrf
