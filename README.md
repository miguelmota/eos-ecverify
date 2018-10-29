# EOS ECDSA Verify

> EOS smart contract that does ECDSA verification.

## Contract

`ecverify.cpp` - smart contract

```cpp
#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>
#include <eosiolib/crypto.h>
using namespace eosio;

class ec: public eosio::contract {
  public:
      using contract::contract;

  ///@abi action
  void ecverify(std::string data, const signature &sig, const public_key &pk)
  {
    checksum256 digest;
    sha256(&data[0], data.size(), &digest);

    assert_recover_key(&digest, (const char *)&sig, sizeof(sig), (const char *)&pk, sizeof(pk));
    print("VALID");
  }
};

EOSIO_ABI( ec, (ecverify) )
```

## Example usage

`sign.js` - signing message and generating signature


```js
const ecc = require('eosjs-ecc')

const wif = '5J5twkfSgL3SgWNKDsD5bjvevdmbXD5faBGcybJVAmYjCJXvpbJ'
const sig = ecc.sign('hello', wif)

console.log(sig) // SIG_K1_KcB1jGNsjYEE7Gby6X7KZ9z6BFVfHPey6DUayYtDagXsbzr4Tbfpq5TS2JvYzs3oMg9QGAugTyGXoTVe7DujeXpDX5KYfJ
```

`action.sh` - call action method `ecverify`

```bash
cleos push action ecverify1234 ecverify '["hello", "SIG_K1_KcB1jGNsjYEE7Gby6X7KZ9z6BFVfHPey6DUayYtDagXsbzr4Tbfpq5TS2JvYzs3oMg9QGAugTyGXoTVe7DujeXpDX5KYfJ", "EOS5nKgVwRvRnjf4tyViZ61iydQ6CiFMoURta36RUk9hxi5wpAkLb"]' -p myaccount123@active
```

Result

```bash
>> VALID
```

## License

MIT
