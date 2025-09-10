#pragma once

#include "rsa/rsavrf.h"
#include "vrf/vrf_base.h"

namespace vrf
{

class VRF : public VRFObject<VRF>
{
  public:
    ~VRF() = default;

    VRF(Type type);

    [[nodiscard]] bool is_initialized() const override;

    [[nodiscard]] std::unique_ptr<PublicKey> get_public_key() const;

    [[nodiscard]] std::unique_ptr<SecretKey> get_secret_key() const;

    [[nodiscard]] static std::unique_ptr<Proof> proof_from_bytes(Type type, std::span<std::byte> data);

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
