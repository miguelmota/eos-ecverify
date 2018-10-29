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
