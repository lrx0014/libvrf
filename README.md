# libvrf

## Verifiable Random Functions

A Verifiable Random Function (VRF) is a cryptographic primitive that produces a pseudorandom output ("VRF value") together with a proof that the output was correctly computed from a given input and a secret key.
Only the secret key holder can generate the output–proof pair, but anyone with the corresponding public key can verify that the output is valid.
They are useful when you need a publicly verifiable source of randomness that cannot be biased by the party generating, ensuring that the output is both unpredictable before it is revealed and provably correct after it is.

## libvrf

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

The library implements an RSA VRF based on RSASSA-PSS signatures; however, note that while this uses a standard RSA signature, this exact method is not described in the RFC cited above.
Instead, the RFC uses an FDH (Full Domain Hash) type RSA signature, which itself is non-standard, but results in a far simpler VRF implementation.

Both RSA-FDH VRF as well as an elliptic curve based EC-VRF are in progress.

