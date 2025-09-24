# libvrf

## Verifiable Random Functions

A Verifiable Random Function (VRF) is a cryptographic primitive that produces a pseudorandom output ("VRF value") together with a proof that the output was correctly computed from a given input and a secret key.
Only the secret key holder can generate the output–proof pair, but anyone with the corresponding public key can verify that the output is valid.
They are useful when you need a publicly verifiable source of randomness that cannot be biased by the party generating, ensuring that the output is both unpredictable before it is revealed and provably correct after it is.

`libvrf` is a C++ implementation of several VRFs, mostly following the specification in [https://datatracker.ietf.org/doc/rfc9381](https://datatracker.ietf.org/doc/rfc9381).
It comes with a CMake based build system, unit tests, and benchmarks.

### Build

`libvrf` depends on [OpenSSL](https://github.com/openssl/openssl) and [spdlog](https://github.com/gabime/spdlog).
To build, ensure [vcpkg](https://GitHub.com/Microsoft/vcpkg) is installed and run
```bash
cmake -B build -S . -GNinja -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" -DCMAKE_BUILD_TYPE=<Debug|Release>
cmake --build build -j
```

After this, the unit test and benchmark executables are available in your build directory.

## Implemented VRFs

The library implements the RSA-FDH based VRF ([https://datatracker.ietf.org/doc/rfc9381](https://datatracker.ietf.org/doc/rfc9381)), as well as a variant based on standard RSA-PSS signatures, for multiple parameter sets.
An elliptic curve-based EC-VRF implementation is in progress.

## Usage

This library exposes a simple, type-safe API for creating VRF keypairs, producing proofs, verifying them, and (de)serializing keys and proofs.
These functionalities are illustrated in the examples below.

### 1) Choosing the VRF type and key generation

All supported VRF implementations are listed in [vrf/type.h](vrf/type.h).
They are described by the following enum values:

- `vrf::Type::RSA_FDH_VRF_RSA2048_SHA256`
- `vrf::Type::RSA_FDH_VRF_RSA3072_SHA256`
- `vrf::Type::RSA_FDH_VRF_RSA4096_SHA384`
- `vrf::Type::RSA_FDH_VRF_RSA8192_SHA512`
- `vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256`
- `vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256`
- `vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384`
- `vrf::Type::RSA_PSS_NOSALT_VRF_RSA8192_SHA512`

The following code snippet creates an RSA-FDH VRF with a 2048-bit key and uses SHA-256 as a hash function.
The `vrf::VRF` constructor creates the required asymmetric key pair and stores both in memory.
The `vrf::VRF::is_initialized` member function can be used to test whether the VRF instance was set up successfully for use.
```cpp
#include "vrf/vrf.h"

vrf::Type type = vrf::Type::RSA_FDH_VRF_RSA2048_SHA256;
vrf::VRF vrf(type);
if (!vrf.is_initialized()) {
    throw std::runtime_error("VRF initialization failed");
}
```

### 2) Accessing keys

Once a `vrf::VRF` instance has been successfully created, the public and secret key can be retrieved as follows:
```cpp
std::unique_ptr<vrf::SecretKey> sk = vrf.get_secret_key();
std::unique_ptr<vrf::PublicKey> pk = vrf.get_public_key();
```

The secret key cannot be serialized, although we may add this capability in the future.
The public key can be serialized (to a DER-encoded SPKI struct) and deserialized as follows:
```cpp
// To serialize
std::vector<std::byte> der_spki = pk->to_bytes();

// To deserialize, the caller is responsible for providing the correct type as input.
// If a type for which the deserialized key is not valid is provided, pk2->is_initialized()
// will return false.
std::unique_ptr<vrf::PublicKey> pk2 = vrf::VRF::public_key_from_bytes(type, der_spki);
if (!pk2->is_initialized()) {
    throw std::runtime_error("Deserialization failed");
}
```

### 3) Prove and verify

Given an input `data`, the secret key can produce a VRF proof.
The public key verifies the proof and returns whether the verification succeeded, and if so, the VRF "hash" value.
```cpp
std::vector<std::byte> data = /* your bytes */;

// The proof is sent to the verifier (who has the public key).
std::unique_ptr<vrf::Proof> proof = sk->get_vrf_proof(data);
if (!proof) {
    throw std::runtime_error("Proof creation failed");
}

// Verify the proof with the public key.
std::pair<bool, std::vector<std::byte>> res = pk->verify_vrf_proof(data, proof);
if (!res.first) {
    throw std::runtime_error("Proof verification failed");
}

// The proof verified successfully and hash is a byte array that holds the VRF value.
// The VRF value can also be obtained directly from the proof object as follows.
// However, this does *not* verify the proof!
std::vector<std::byte> hash2 = res.second->get_vrf_value();
```

The proof can be serialized and deserialized as follows:
```cpp
// To serialize
std::vector<std::byte> proof_bytes = proof->to_bytes();

// To deserialize
std::unique_ptr<vrf::Proof> proof2 = vrf::VRF::proof_from_bytes(type, proof_bytes);
if (!proof2) {
    throw std::runtime_error("Deserialization failed");
}
```

### 4) Other functions

All of the VRF objects above (`vrf::VRF`, `vrf::SecretKey`, `vrf::PublicKey`, `vrf::Proof`) store their `vrf::Type`.
This can retrieved using the member function `get_type()`.

