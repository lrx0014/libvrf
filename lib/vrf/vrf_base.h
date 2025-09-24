#pragma once

#include "vrf/type.h"
#include <cstddef>
#include <memory>
#include <span>
#include <vector>

namespace vrf
{

template <typename T> class VRFObject
{
  public:
    virtual ~VRFObject() = default;

    /**
     * Checks whether this object is properly initialized.
     */
    [[nodiscard]] virtual bool is_initialized() const = 0;

    /**
     * Returns the VRF type associated with this object. For the full list of supported types,
     * see vrf::Type in vrf/type.h.
     */
    [[nodiscard]] Type get_type() const noexcept
    {
        return type_;
    }

  protected:
    VRFObject() = default;

    VRFObject(Type type) : type_(type) {};

    VRFObject(const VRFObject<T> &) = default;

    VRFObject &operator=(const VRFObject<T> &) = delete;

    VRFObject(VRFObject<T> &&) = delete;

    VRFObject &operator=(VRFObject<T> &&) = delete;

    void set_type(Type type) noexcept
    {
        type_ = type;
    }

  private:
    Type type_ = Type::UNKNOWN_VRF_TYPE;
};

template <typename T> class Clonable
{
  public:
    virtual ~Clonable() = default;

    [[nodiscard]] virtual std::unique_ptr<T> clone() const = 0;
};

class Serializable
{
  public:
    virtual ~Serializable() = default;

    /**
     * Serializes the object into a vector of bytes.
     */
    [[nodiscard]] virtual std::vector<std::byte> to_bytes() const = 0;

    /**
     * Deserializes an object from a span of bytes for the specified VRF type. Deserialization
     * failure is indicated by checking the output of VRFObject::is_initialized().
     */
    virtual void from_bytes(Type type, std::span<const std::byte> data) = 0;
};

/**
 * Abstract base class representing a VRF proof object. The proof object can be serialized
 * to and deserialized from a byte array. It can also be used to extract the VRF value itself.
 */
class Proof : public VRFObject<Proof>, public Clonable<Proof>, public Serializable
{
  public:
    virtual ~Proof() = default;

    /**
     * Returns the VRF value associated with this proof as a vector of bytes. The length of
     * the returned vector depends on the VRF type.
     */
    [[nodiscard]] virtual std::vector<std::byte> get_vrf_value() const = 0;

  protected:
    using VRFObject<Proof>::VRFObject;
};

class PublicKey;

/**
 * Abstract base class representing a VRF secret key object. The secret key can be used to
 * generate VRF proofs for given inputs, and it can also provide the corresponding public key.
 * The secret key can be cloned but cannot be serialized or deserialized.
 */
class SecretKey : public VRFObject<SecretKey>, public Clonable<SecretKey>
{
  public:
    virtual ~SecretKey() = default;

    /**
     * Generates a VRF proof for the given input data using this secret key. The input data is
     * provided as a span of bytes.
     */
    [[nodiscard]] virtual std::unique_ptr<Proof> get_vrf_proof(std::span<const std::byte> in) const = 0;

    /**
     * Returns the public key corresponding to this secret key.
     */
    [[nodiscard]] virtual std::unique_ptr<PublicKey> get_public_key() const = 0;

  protected:
    using VRFObject<SecretKey>::VRFObject;
};

class PublicKey : public VRFObject<PublicKey>, public Clonable<PublicKey>, public Serializable
{
  public:
    virtual ~PublicKey() = default;

    /**
     * Verifies the given VRF proof against the provided input data using this public key.
     * If the proof is valid, the function returns a pair where the first element is true
     * and the second element is the VRF value as a vector of bytes. If the proof is invalid,
     * the function returns a pair where the first element is false and the second element
     * is an empty vector.
     */
    [[nodiscard]] virtual std::pair<bool, std::vector<std::byte>> verify_vrf_proof(
        std::span<const std::byte> in, const std::unique_ptr<Proof> &proof) const = 0;

  protected:
    using VRFObject<PublicKey>::VRFObject;
};

} // namespace vrf
