const ecc = require('eosjs-ecc')

const wif = '5J5twkfSgL3SgWNKDsD5bjvevdmbXD5faBGcybJVAmYjCJXvpbJ'
const sig = ecc.sign('hello', wif)

console.log(sig) // SIG_K1_KcB1jGNsjYEE7Gby6X7KZ9z6BFVfHPey6DUayYtDagXsbzr4Tbfpq5TS2JvYzs3oMg9QGAugTyGXoTVe7DujeXpDX5KYfJ
