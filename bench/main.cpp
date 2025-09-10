#include "vrf/vrf.h"
#include <benchmark/benchmark.h>

static void BM_VRF_GenerateKeys(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    for (auto _ : state)
    {
        vrf::VRF vrf(type);
        benchmark::DoNotOptimize(vrf);
    }
    state.SetLabel(vrf::type_to_string(type));
}

BENCHMARK(BM_VRF_GenerateKeys)
    ->Unit(benchmark::kMillisecond)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512));

static void BM_VRF_GenerateProof(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    vrf::VRF vrf(type);
    auto secret_key = vrf.get_secret_key();
    std::vector<std::byte> data(512, std::byte{0}); // Fixed 512-bit input for benchmarking
    for (auto _ : state)
    {
        auto proof = secret_key->get_vrf_proof(data);
        benchmark::DoNotOptimize(proof);
    }
    state.SetLabel(vrf::type_to_string(type));
}

BENCHMARK(BM_VRF_GenerateProof)
    ->Unit(benchmark::kMillisecond)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512));

static void BM_VRF_VerifyProof(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    vrf::VRF vrf(type);
    auto secret_key = vrf.get_secret_key();
    auto public_key = vrf.get_public_key();
    std::vector<std::byte> data(512, std::byte{0}); // Fixed 512-bit input for benchmarking
    auto proof = secret_key->get_vrf_proof(data);
    for (auto _ : state)
    {
        auto [success, hash] = public_key->verify_vrf_proof(data, proof);
        benchmark::DoNotOptimize(success);
        benchmark::DoNotOptimize(hash);
    }
    state.SetLabel(vrf::type_to_string(type));
}

BENCHMARK(BM_VRF_VerifyProof)
    ->Unit(benchmark::kMicrosecond)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512));

static void BM_VRF_ProofToBytes(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    vrf::VRF vrf(type);
    auto secret_key = vrf.get_secret_key();
    std::vector<std::byte> data(512, std::byte{0}); // Fixed 512-bit input for benchmarking
    auto proof = secret_key->get_vrf_proof(data);
    for (auto _ : state)
    {
        auto proof_bytes = proof->to_bytes();
        benchmark::DoNotOptimize(proof_bytes);
    }
    state.SetLabel(vrf::type_to_string(type));
}

BENCHMARK(BM_VRF_ProofToBytes)
    ->Unit(benchmark::kNanosecond)
    ->Iterations(1000)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512));

static void BM_VRF_ProofFromBytes(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    vrf::VRF vrf(type);
    auto secret_key = vrf.get_secret_key();
    std::vector<std::byte> data(512, std::byte{0}); // Fixed 512-bit input for benchmarking
    auto proof = secret_key->get_vrf_proof(data);
    auto proof_bytes = proof->to_bytes();
    for (auto _ : state)
    {
        auto proof_from_bytes = vrf::VRF::proof_from_bytes(type, proof_bytes);
        benchmark::DoNotOptimize(proof_from_bytes);
    }
    state.SetLabel(vrf::type_to_string(type));
}

BENCHMARK(BM_VRF_ProofFromBytes)
    ->Unit(benchmark::kNanosecond)
    ->Iterations(1000)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512));

static void BM_VRF_PublicKeyToBytes(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    vrf::VRF vrf(type);
    auto public_key = vrf.get_public_key();
    for (auto _ : state)
    {
        auto der_spki = public_key->to_bytes();
        benchmark::DoNotOptimize(der_spki);
    }
    state.SetLabel(vrf::type_to_string(type));
}

BENCHMARK(BM_VRF_PublicKeyToBytes)
    ->Unit(benchmark::kNanosecond)
    ->Iterations(1000)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512));

static void BM_VRF_PublicKeyFromBytes(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    vrf::VRF vrf(type);
    auto public_key = vrf.get_public_key();
    auto der_spki = public_key->to_bytes();
    for (auto _ : state)
    {
        auto public_key_from_string = vrf::VRF::public_key_from_bytes(type, der_spki);
        benchmark::DoNotOptimize(public_key_from_string);
    }
    state.SetLabel(vrf::type_to_string(type));
}

BENCHMARK(BM_VRF_PublicKeyFromBytes)
    ->Unit(benchmark::kMicrosecond)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512));

BENCHMARK_MAIN();
