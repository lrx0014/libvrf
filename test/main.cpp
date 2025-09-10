#include "vrf/vrf.h"
#include <gtest/gtest.h>
#include <random>

namespace
{
std::vector<std::byte> random_bytes(std::size_t length)
{
    std::vector<std::byte> bytes(length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned char> dis(0, 255);

    for (std::size_t i = 0; i < length; ++i)
    {
        bytes[i] = static_cast<std::byte>(dis(gen));
    }

    return bytes;
}
} // namespace

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

class VRFTest : public testing::TestWithParam<vrf::Type>
{
};

TEST_P(VRFTest, Create)
{
    vrf::Type type = GetParam();
    vrf::VRF vrf(type);
    ASSERT_TRUE(vrf.is_initialized());
    ASSERT_EQ(vrf.get_type(), type);
}

TEST_P(VRFTest, GetPublicKey)
{
    vrf::Type type = GetParam();
    vrf::VRF vrf(type);

    auto public_key = vrf.get_public_key();
    ASSERT_NE(public_key, nullptr);
    ASSERT_TRUE(public_key->is_initialized());
    ASSERT_EQ(public_key->get_type(), type);

    auto der_spki = public_key->to_bytes();
    ASSERT_FALSE(der_spki.empty());

    // Get the public key again and compare.
    auto public_key2 = vrf.get_public_key();
    ASSERT_NE(public_key2, nullptr);
    ASSERT_TRUE(public_key2->is_initialized());
    ASSERT_EQ(public_key2->get_type(), type);
    auto der_spki2 = public_key2->to_bytes();
    ASSERT_EQ(der_spki, der_spki2);
}

TEST_P(VRFTest, GetSecretKey)
{
    vrf::Type type = GetParam();
    vrf::VRF vrf(type);

    auto secret_key = vrf.get_secret_key();
    ASSERT_NE(secret_key, nullptr);
    ASSERT_TRUE(secret_key->is_initialized());
    ASSERT_EQ(secret_key->get_type(), type);

    // Get the secret key again.
    auto secret_key2 = vrf.get_secret_key();
    ASSERT_NE(secret_key2, nullptr);
    ASSERT_TRUE(secret_key2->is_initialized());
    ASSERT_EQ(secret_key2->get_type(), type);
}

TEST_P(VRFTest, CreateVerifyProof)
{
    vrf::Type type = GetParam();
    vrf::VRF vrf(type);
    auto secret_key = vrf.get_secret_key();
    auto public_key = vrf.get_public_key();

    auto prove_and_verify = [&](std::vector<std::byte> data) {
        auto proof = secret_key->get_vrf_proof(data);
        ASSERT_NE(proof, nullptr);
        ASSERT_EQ(proof->get_type(), type);
        auto [success, hash] = public_key->verify_vrf_proof(data, proof);
        ASSERT_TRUE(success);
        ASSERT_FALSE(hash.empty());
    };

    prove_and_verify({});
    prove_and_verify({std::byte{0x00}});
    prove_and_verify({std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{0x05}});
    prove_and_verify(random_bytes(32));
    prove_and_verify(random_bytes(128));
    prove_and_verify(random_bytes(16384));
}

TEST_P(VRFTest, ProofToBytesFromBytes)
{
    vrf::Type type = GetParam();
    vrf::VRF vrf(type);
    auto secret_key = vrf.get_secret_key();
    auto public_key = vrf.get_public_key();

    std::vector<std::byte> data = random_bytes(32);
    auto proof = secret_key->get_vrf_proof(data);

    std::vector<std::byte> proof_bytes = proof->to_bytes();
    ASSERT_FALSE(proof_bytes.empty());

    auto proof_from_bytes = vrf::VRF::proof_from_bytes(type, proof_bytes);
    ASSERT_NE(proof_from_bytes, nullptr);
    ASSERT_EQ(proof_from_bytes->get_type(), type);

    auto [success, hash] = public_key->verify_vrf_proof(data, proof_from_bytes);
    ASSERT_TRUE(success);
    ASSERT_FALSE(hash.empty());
}

TEST_P(VRFTest, PublicKeyEncodeDecode)
{
    vrf::Type type = GetParam();
    vrf::VRF vrf(type);
    auto public_key = vrf.get_public_key();

    std::vector<std::byte> der_spki = public_key->to_bytes();
    ASSERT_FALSE(der_spki.empty());

    auto public_key_from_string = vrf::VRF::public_key_from_bytes(type, der_spki);
    ASSERT_NE(public_key_from_string, nullptr);
    ASSERT_EQ(public_key_from_string->get_type(), type);

    std::vector<std::byte> data = random_bytes(32);
    auto secret_key = vrf.get_secret_key();
    auto proof = secret_key->get_vrf_proof(data);

    auto [success, hash] = public_key_from_string->verify_vrf_proof(data, proof);
    ASSERT_TRUE(success);
    ASSERT_FALSE(hash.empty());
}

TEST_P(VRFTest, ValueIsDeterministic)
{
    vrf::Type type = GetParam();
    vrf::VRF vrf(type);
    auto secret_key = vrf.get_secret_key();
    auto public_key = vrf.get_public_key();

    std::vector<std::byte> data = random_bytes(32);
    auto proof1 = secret_key->get_vrf_proof(data);
    auto proof2 = secret_key->get_vrf_proof(data);

    auto [success1, hash1] = public_key->verify_vrf_proof(data, proof1);
    auto [success2, hash2] = public_key->verify_vrf_proof(data, proof2);
    ASSERT_TRUE(success1);
    ASSERT_TRUE(success2);
    ASSERT_FALSE(hash1.empty());
    ASSERT_FALSE(hash2.empty());
    ASSERT_EQ(proof1->to_bytes(), proof2->to_bytes());
    ASSERT_EQ(hash1, hash2);

    // Invert all bits in data.
    std::vector<std::byte> different_data(data.size());
    for (std::size_t i = 0; i < data.size(); ++i)
    {
        different_data[i] = ~data[i];
    }
    auto proof3 = secret_key->get_vrf_proof(different_data);
    auto [success3, hash3] = public_key->verify_vrf_proof(different_data, proof3);
    ASSERT_TRUE(success3);
    ASSERT_FALSE(hash3.empty());
    ASSERT_NE(proof1->to_bytes(), proof3->to_bytes());
}

TEST_P(VRFTest, InvalidProof)
{
    vrf::Type type = GetParam();
    vrf::VRF vrf(type);
    auto secret_key = vrf.get_secret_key();
    auto public_key = vrf.get_public_key();

    std::vector<std::byte> data = random_bytes(32);
    auto proof = secret_key->get_vrf_proof(data);
    std::vector<std::byte> proof_bytes = proof->to_bytes();

    // Modify the proof to make it invalid: modification in the beginning.
    {
        std::vector<std::byte> invalid_proof_data = proof_bytes;
        invalid_proof_data[0] ^= std::byte{0xFF};
        auto invalid_proof = vrf::VRF::proof_from_bytes(type, invalid_proof_data);
        auto [success, hash] = public_key->verify_vrf_proof(data, invalid_proof);
        ASSERT_FALSE(success);
        ASSERT_TRUE(hash.empty());
    }

    // Modify the proof to make it invalid: modification in the middle.
    {
        std::vector<std::byte> invalid_proof_data = proof_bytes;
        invalid_proof_data[invalid_proof_data.size() / 2] ^= std::byte{0xFF};
        auto invalid_proof = vrf::VRF::proof_from_bytes(type, invalid_proof_data);
        auto [success, hash] = public_key->verify_vrf_proof(data, invalid_proof);
        ASSERT_FALSE(success);
        ASSERT_TRUE(hash.empty());
    }

    // Modify the proof to make it invalid: modification in the end.
    {
        std::vector<std::byte> invalid_proof_data = proof_bytes;
        invalid_proof_data[invalid_proof_data.size() - 1] ^= std::byte{0xFF};
        auto invalid_proof = vrf::VRF::proof_from_bytes(type, invalid_proof_data);
        auto [success, hash] = public_key->verify_vrf_proof(data, invalid_proof);
        ASSERT_FALSE(success);
        ASSERT_TRUE(hash.empty());
    }

    // Empty proof.
    {
        std::vector<std::byte> invalid_proof_data = {};
        auto invalid_proof = vrf::VRF::proof_from_bytes(type, invalid_proof_data);
        ASSERT_EQ(invalid_proof, nullptr);
    }

    // Totally wrong size proof.
    {
        std::vector<std::byte> invalid_proof_data(proof_bytes.begin(), proof_bytes.begin() + proof_bytes.size() / 2);
        auto invalid_proof = vrf::VRF::proof_from_bytes(type, invalid_proof_data);
        auto [success, hash] = public_key->verify_vrf_proof(data, invalid_proof);
        ASSERT_FALSE(success);
        ASSERT_TRUE(hash.empty());
    }

    // Very large size proof.
    {
        std::vector<std::byte> invalid_proof_data = proof_bytes;
        invalid_proof_data.insert(invalid_proof_data.end(), proof_bytes.begin(), proof_bytes.end());
        auto invalid_proof = vrf::VRF::proof_from_bytes(type, invalid_proof_data);
        auto [success, hash] = public_key->verify_vrf_proof(data, invalid_proof);
        ASSERT_FALSE(success);
        ASSERT_TRUE(hash.empty());
    }
}

TEST_P(VRFTest, InvalidPublicKey)
{
    vrf::Type type = GetParam();
    vrf::VRF vrf(type);
    auto secret_key = vrf.get_secret_key();

    std::vector<std::byte> data = random_bytes(32);
    auto proof = secret_key->get_vrf_proof(data);

    // Create an invalid public key by modifying the DER SPKI: modification in the beginning.
    {
        auto public_key = vrf.get_public_key();
        auto der_spki = public_key->to_bytes();
        der_spki[0] ^= std::byte{1};
        auto invalid_public_key = vrf::VRF::public_key_from_bytes(type, der_spki);
        ASSERT_TRUE(invalid_public_key == nullptr || !invalid_public_key->is_initialized() ||
                    !invalid_public_key->verify_vrf_proof(data, proof).first);
    }

    // Create an invalid public key by modifying the DER SPKI: modification in the middle.
    {
        auto public_key = vrf.get_public_key();
        auto der_spki = public_key->to_bytes();
        der_spki[der_spki.size() / 2] ^= std::byte{1};
        auto invalid_public_key = vrf::VRF::public_key_from_bytes(type, der_spki);
        ASSERT_TRUE(invalid_public_key == nullptr || !invalid_public_key->is_initialized() ||
                    !invalid_public_key->verify_vrf_proof(data, proof).first);
    }

    // Create an invalid public key by modifying the DER SPKI: modification in the end.
    {
        auto public_key = vrf.get_public_key();
        auto der_spki = public_key->to_bytes();
        der_spki[der_spki.size() - 1] ^= std::byte{1};
        auto invalid_public_key = vrf::VRF::public_key_from_bytes(type, der_spki);
        ASSERT_TRUE(invalid_public_key == nullptr || !invalid_public_key->is_initialized() ||
                    !invalid_public_key->verify_vrf_proof(data, proof).first);
    }
}

INSTANTIATE_TEST_SUITE_P(RSAVRFTypes, VRFTest,
                         testing::Values(vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA2048_SHA256,
                                         vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA3072_SHA256,
                                         vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA4096_SHA512,
                                         vrf::Type::RSASSA_PSS_NOSALT_VRF_RSA8192_SHA512));
