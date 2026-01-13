#include "vrf_wrapper.h"

#include <stdexcept>

namespace node_vrf {

Vrf::Vrf(::vrf::Type type, std::unique_ptr<::vrf::SecretKey> sk)
    : type_(type), sk_(std::move(sk)) {}

Vrf Vrf::Create(::vrf::Type type) {
    std::unique_ptr<::vrf::SecretKey> sk = ::vrf::VRF::Create(type);
    if (!sk || !sk->is_initialized()) {
        throw std::runtime_error("libvrf: secret key creation failed");
    }
    return Vrf(type, std::move(sk));
}

std::string Vrf::get_public_key_b64() const {
    auto pk = sk_->get_public_key();
    if (!pk || !pk->is_initialized()) {
        throw std::runtime_error("libvrf: public key creation failed");
    }
    const std::vector<std::byte> der_spki = pk->to_bytes();
    if (der_spki.empty()) {
        throw std::runtime_error("libvrf: failed to serialize public key");
    }
    return base64::encode(der_spki);
}

EvalResult Vrf::evaluate(std::span<const std::byte> data) const {
    auto proof = sk_->get_vrf_proof(data);
    if (!proof || !proof->is_initialized()) {
        throw std::runtime_error("libvrf: proof creation failed");
    }

    const std::vector<std::byte> proof_bytes = proof->to_bytes();
    if (proof_bytes.empty()) {
        throw std::runtime_error("libvrf: failed to serialize proof");
    }

    const std::vector<std::byte> output = proof->get_vrf_value();
    if (output.empty()) {
        throw std::runtime_error("libvrf: failed to extract VRF value");
    }

    return EvalResult{
        .output_b64 = base64::encode(output),
        .proof_b64  = base64::encode(proof_bytes),
    };
}

EvalResult Vrf::evaluate(std::uint64_t view) const {
    const auto bytes = u64_be(view);
    return evaluate(std::span<const std::byte>(bytes.data(), bytes.size()));
}

bool Vrf::verify(::vrf::Type type,
                 std::span<const std::byte> public_key_der_spki,
                 std::span<const std::byte> data,
                 std::span<const std::byte> expected_output,
                 std::span<const std::byte> proof_bytes) {
    auto pk = ::vrf::VRF::public_key_from_bytes(type, public_key_der_spki);
    if (!pk || !pk->is_initialized()) {
        return false;
    }

    auto proof = ::vrf::VRF::proof_from_bytes(type, proof_bytes);
    if (!proof || !proof->is_initialized()) {
        return false;
    }

    auto res = pk->verify_vrf_proof(data, proof);
    return res.first && res.second == std::vector<std::byte>(expected_output.begin(), expected_output.end());
}

bool Vrf::verify_b64(::vrf::Type type,
                     const std::string& public_key_b64,
                     std::span<const std::byte> data,
                     const std::string& expected_output_b64,
                     const std::string& proof_b64) {
    try {
        const auto pk    = base64::decode(public_key_b64);
        const auto out   = base64::decode(expected_output_b64);
        const auto proof = base64::decode(proof_b64);
        if (pk.empty() || out.empty() || proof.empty()) {
            return false;
        }
        return verify(type, pk, data, out, proof);
    } catch (...) {
        return false;
    }
}

bool Vrf::verify_view_b64(::vrf::Type type,
                          const std::string& public_key_b64,
                          std::uint64_t view,
                          const std::string& expected_output_b64,
                          const std::string& proof_b64) {
    const auto bytes = u64_be(view);
    return verify_b64(type, public_key_b64,
                      std::span<const std::byte>(bytes.data(), bytes.size()),
                      expected_output_b64,
                      proof_b64);
}

std::array<std::byte, 8> Vrf::u64_be(std::uint64_t x) {
    std::array<std::byte, 8> b{};
    for (int i = 7; i >= 0; --i) {
        b[static_cast<std::size_t>(i)] = static_cast<std::byte>(x & 0xFFu);
        x >>= 8;
    }
    return b;
}

} // namespace node_vrf
