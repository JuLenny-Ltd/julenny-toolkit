#ifndef FHE_TOOLKIT_CRYPTO_INTERNAL_H
#define FHE_TOOLKIT_CRYPTO_INTERNAL_H

#include <cstdint>
#include <map>
#include <memory>

#include <openfhe.h>

#include "crypto/context.h"
#include "crypto/keys.h"
#include "crypto/ciphertext.h"
#include "crypto/eval_keys.h"

namespace fhe_toolkit::crypto {

using OpenFheContext       = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;
using OpenFhePublicKey     = lbcrypto::PublicKey<lbcrypto::DCRTPoly>;
using OpenFhePrivateKey    = lbcrypto::PrivateKey<lbcrypto::DCRTPoly>;
using OpenFheCiphertext    = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using OpenFhePlaintext     = lbcrypto::Plaintext;
using OpenFheEvalKey       = lbcrypto::EvalKey<lbcrypto::DCRTPoly>;
using OpenFheSumKeyMap     = std::shared_ptr<std::map<uint32_t, OpenFheEvalKey>>;

struct Context::Impl         { OpenFheContext    cc; };
struct PublicKey::Impl       { OpenFhePublicKey  key; };
struct SecretKey::Impl       { OpenFhePrivateKey key; };
struct PlaintextPacked::Impl { OpenFhePlaintext  pt; };
struct Ciphertext::Impl      { OpenFheCiphertext ct; };
struct EvalKey::Impl         { OpenFheEvalKey    key; };
struct SumKeyMap::Impl       { OpenFheSumKeyMap  keys; };
struct RotationKeyMap::Impl  { OpenFheSumKeyMap  keys; };  // same shape as SumKeyMap

}  // namespace fhe_toolkit::crypto

#endif
