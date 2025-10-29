// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// These test vectors are from https://datatracker.ietf.org/doc/rfc9381.

#pragma once

#define EC_VRF_P256_SHA256_TAI_SK                                                                                      \
    {"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",                                               \
     "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",                                               \
     "2CA1411A41B17B24CC8C3B089CFD033F1920202A6C0DE8ABB97DF1498D50D2C8"}

#define EC_VRF_P256_SHA256_TAI_M                                                                                       \
    {"73616D706C65", "74657374",                                                                                       \
     "4578616D706C65207573696E67204543445341206B65792066726F6D20"                                                      \
     "417070656E646978204C2E342E32206F6620414E53492E58392D36322D32303035"}

#define EC_VRF_P256_SHA256_TAI_PROOF                                                                                   \
    {"035B5C726E8C0E2C488A107C600578EE75CB702343C153CB1EB8DEC77F4B5"                                                   \
     "071B4A53F0A46F018BC2C56E58D383F2305E0975972C26FEEA0EB122FE789"                                                   \
     "3C15AF376B33EDF7DE17C6EA056D4D82DE6BC02F",                                                                       \
     "034DAC60ABA508BA0C01AA9BE80377EBD7562C4A52D74722E0ABAE7DC3080"                                                   \
     "DDB56C19E067B15A8A8174905B13617804534214F935B94C2287F797E393EB0816"                                              \
     "969D864F37625B443F30F1A5A33F2B3C854",                                                                            \
     "03D03398BF53AA23831D7D1B2937E005FB0062CBEFA06796579F2A1FC7E7B"                                                   \
     "8C667D091C00B0F5C3619D10ECEA44363B5A599CADC5B2957E223FEC62E81F7B48"                                              \
     "25FC799A771A3D7334B9186BDBEE87316B1"}

#define EC_VRF_P256_SHA256_TAI_VALUE                                                                                   \
    {"A3AD7B0EF73D8FC6655053EA22F9BEDE8C743F08BBED3D38821F0E16474B505E",                                               \
     "A284F94CEEC2FF4B3794629DA7CBAFA49121972671B466CAB4CE170AA365F26D",                                               \
     "90871E06DA5CAA39A3C61578EBB844DE8635E27AC0B13E829997D0D95DD98C19"}

#define EC_VRF_P256_SHA256_TAI_PARAMS                                                                                  \
    {EC_VRF_P256_SHA256_TAI_SK, EC_VRF_P256_SHA256_TAI_M, EC_VRF_P256_SHA256_TAI_PROOF, EC_VRF_P256_SHA256_TAI_VALUE}
