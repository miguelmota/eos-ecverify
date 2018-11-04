#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>
#include <eosiolib/crypto.h>

using namespace eosio;

template<typename CharT>
static std::string to_hex(const CharT* d, uint32_t s) {
  std::string r;
  const char* to_hex="0123456789abcdef";
  uint8_t* c = (uint8_t*)d;
  for( uint32_t i = 0; i < s; ++i ) {
    (r += to_hex[(c[i] >> 4)]) += to_hex[(c[i] & 0x0f)];
  }
  return r;
}

std::string hex_to_string(const std::string& input) {
  static const char* const lut = "0123456789abcdef";
  size_t len = input.length();
  if (len & 1) abort();
  std::string output;
  output.reserve(len / 2);
  for (size_t i = 0; i < len; i += 2) {
    char a = input[i];
    const char* p = std::lower_bound(lut, lut + 16, a);
    if (*p != a) abort();
    char b = input[i + 1];
    const char* q = std::lower_bound(lut, lut + 16, b);
    if (*q != b) abort();
    output.push_back(((p - lut) << 4) | (q - lut));
  }
  return output;
}

const char * const ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const char ALPHABET_MAP[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
    -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
    -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
};

int base58encode(const std::string input, int len, unsigned char result[]) {
    unsigned char const* bytes = (unsigned const char*)(input.c_str());
    unsigned char digits[len * 137 / 100];
    int digitslen = 1;
    for (int i = 0; i < len; i++) {
        unsigned int carry = (unsigned int) bytes[i];
        for (int j = 0; j < digitslen; j++) {
            carry += (unsigned int) (digits[j]) << 8;
            digits[j] = (unsigned char) (carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            digits[digitslen++] = (unsigned char) (carry % 58);
            carry /= 58;
        }
    }
    int resultlen = 0;
    // leading zero bytes
    for (; resultlen < len && bytes[resultlen] == 0;)
        result[resultlen++] = '1';
    // reverse
    for (int i = 0; i < digitslen; i++)
        result[resultlen + i] = ALPHABET[digits[digitslen - 1 - i]];
    result[digitslen + resultlen] = 0;
    return digitslen + resultlen;
}

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
