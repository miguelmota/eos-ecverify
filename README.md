# EOS ECDSA Verify

> EOS smart contract for doing ECDSA verification (ecrecover/ecverify).

## Contract

`ecverify.cpp` - smart contract

```cpp
#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>
#include <eosiolib/crypto.h>

using namespace eosio;

// ...

class ec: public eosio::contract {
  public:
      using contract::contract;

  ///@abi action
  void ecrecover(std::string data, const signature &sig)
  {
    std::string tmp;
    checksum256 digest;
    sha256(&data[0], data.size(), &digest);

    char pub[34]; // public key without checksum
    auto n = recover_key(&digest, (char *)&sig, sizeof(sig), pub, 34);
    assert(n == 34);

    std::string pubhex = to_hex(pub, sizeof(pub)).substr(2); // remove leading '00'
    tmp = hex_to_string(pubhex.c_str());
    strcpy(pub, tmp.c_str());

    checksum160 chksm;
    ripemd160(pub, 33, &chksm);

    tmp = hex_to_string(pubhex + to_hex(&chksm, 20).substr(0,8)); // append checksum

    unsigned char encoded[37  * 137 / 100];
    base58encode(tmp, 37, encoded);
    tmp = "EOS" + std::string(reinterpret_cast<char*>(encoded));
    assert(tmp.length() == 53);
    print(tmp);
  }

  ///@abi action
  void ecverify(std::string data, const signature &sig, const public_key &pk)
  {
    checksum256 digest;
    sha256(&data[0], data.size(), &digest);

    assert_recover_key(&digest, (const char *)&sig, sizeof(sig), (const char *)&pk, sizeof(pk));
    print("VALID");
  }
};

EOSIO_ABI( ec, (ecrecover)(ecverify) )
```

## Example usage

`sign.js` - signing message and generating signature


```js
const ecc = require('eosjs-ecc')

const wif = '5J5twkfSgL3SgWNKDsD5bjvevdmbXD5faBGcybJVAmYjCJXvpbJ'
const sig = ecc.sign('hello', wif)

console.log(sig) // SIG_K1_KcB1jGNsjYEE7Gby6X7KZ9z6BFVfHPey6DUayYtDagXsbzr4Tbfpq5TS2JvYzs3oMg9QGAugTyGXoTVe7DujeXpDX5KYfJ
```

`action_ecrecover.sh` - call action method `ecrecover` to recover signing public key of signature

```bash
cleos push action ecverify1234 ecrecover '["hello", "SIG_K1_K3c9eTFA34HwqN1xNxr4ngbTzckSoDYWz2cYMneyMTTJLqfQ1yAQS1M4EYUJDqhVgzC1cN65mwBRqau2EhDBirWodhW8xb"]' -p myaccount123@active
```

Result

```bash
>> EOS68vRVaNgCvStaUmxQsKoHANU1Uypo4BQLWSNEM8KBiCAWW8deh
```

`action_ecverify.sh` - call action method `ecverify` to verify signature signer

```bash
cleos push action ecverify1234 ecverify '["hello", "SIG_K1_KcB1jGNsjYEE7Gby6X7KZ9z6BFVfHPey6DUayYtDagXsbzr4Tbfpq5TS2JvYzs3oMg9QGAugTyGXoTVe7DujeXpDX5KYfJ", "EOS68vRVaNgCvStaUmxQsKoHANU1Uypo4BQLWSNEM8KBiCAWW8deh"]' -p myaccount123@active
```

Result

```bash
>> VALID
```

## License

MIT
