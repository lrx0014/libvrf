#ifndef FRAMEWORK_VRF_WRAPPER_H
#define FRAMEWORK_VRF_WRAPPER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

// libvrf
#include "vrf/type.h"
#include "vrf/vrf.h"
#include "base64.h"

namespace node_vrf {

struct EvalResult {
    // VRF output ("hash") bytes, Base64 encoded.
    std::string output_b64;
    // Proof bytes, Base64 encoded.
    std::string proof_b64;
};

// Wrapper around Microsoft/libvrf
class Vrf {
public:

    static constexpr ::vrf::Type kDefaultType = ::vrf::Type::RSA_FDH_VRF_RSA2048_SHA256;

    static Vrf Create(::vrf::Type type = kDefaultType);

    Vrf(const Vrf&) = delete;
    Vrf& operator=(const Vrf&) = delete;

    Vrf(Vrf&&) noexcept = default;
    Vrf& operator=(Vrf&&) noexcept = default;

    ::vrf::Type type() const noexcept { return type_; }

    // Return public key as Base64.
    std::string get_public_key_b64() const;

    // Evaluate VRF on arbitrary bytes.
    EvalResult evaluate(std::span<const std::byte> data) const;

    // evaluate on uint64 view (big-endian 8 bytes).
    EvalResult evaluate(std::uint64_t view) const;

    static bool verify(::vrf::Type type,
                       std::span<const std::byte> public_key_der_spki,
                       std::span<const std::byte> data,
                       std::span<const std::byte> expected_output,
                       std::span<const std::byte> proof_bytes);

    // Base64-based verify.
    static bool verify_b64(::vrf::Type type,
                           const std::string& public_key_b64,
                           std::span<const std::byte> data,
                           const std::string& expected_output_b64,
                           const std::string& proof_b64);

    // verify for the same encoding used by evaluate(view).
    static bool verify_view_b64(::vrf::Type type,
                                const std::string& public_key_b64,
                                std::uint64_t view,
                                const std::string& expected_output_b64,
                                const std::string& proof_b64);

private:
    ::vrf::Type type_;
    std::unique_ptr<::vrf::SecretKey> sk_;

    explicit Vrf(::vrf::Type type, std::unique_ptr<::vrf::SecretKey> sk);

    static std::array<std::byte, 8> u64_be(std::uint64_t x);

};

} // namespace node_vrf

#endif // FRAMEWORK_VRF_WRAPPER_H
