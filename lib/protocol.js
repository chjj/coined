/**
 * coined - a high-level wrapper around bcoin
 * Copyright (c) 2014, Christopher Jeffrey. (MIT Licensed)
 * https://github.com/chjj/coined
 */

var bcoin = require('bcoin');
var constants = bcoin.protocol.constants;
var wallet = bcoin.wallet;
var utils = require('./utils');

/**
 * Normal Protocol
 */

// Reference:
// ~/bitcoin/src/chainparams.cpp

var protocol = exports;

protocol.type = process.env.USE_TESTNET
  ? 'testnet'
  : 'normal';

var normal = protocol.normal = {};

normal.type = 'normal';

normal.seeds = [
  'seed.bitcoin.sipa.be',
  'dnsseed.bluematt.me',
  'dnsseed.bitcoin.dashjr.org',
  'seed.bitcoinstats.com',
  'seed.bitnodes.io',
  'bitseed.xf2.org'
];

normal.port = 8333;

normal.alertKey = utils.toArray(''
  + '04fc9702847840aaf195de8442ebecedf5b095c'
  + 'dbb9bc716bda9110971b28a49e0ead8564ff0db'
  + '22209e0374782c093bb899692d524e9d6a6956e'
  + '7c5ecbcd68284',
  'hex');

normal.seeds.ips = [
  0x7e6a692e, 0x7d04d1a2, 0x6c0c17d9, 0xdb330ab9, 0xc649c7c6, 0x7895484d,
  0x047109b0, 0xb90ca5bc, 0xd130805f, 0xbd074ea6, 0x578ff1c0, 0x286e09b0,
  0xd4dcaf42, 0x529b6bb8, 0x635cc6c0, 0xedde892e, 0xa976d9c7, 0xea91a4b8,
  0x03fa4eb2, 0x6ca9008d, 0xaf62c825, 0x93f3ba51, 0xc2c9efd5, 0x0ed5175e,
  0x487028bc, 0x7297c225, 0x8af0c658, 0x2e57ba1f, 0xd0098abc, 0x46a8853e,
  0xcc92dc3e, 0xeb6f1955, 0x8cce175e, 0x237281ae, 0x9d42795b, 0x4f4f0905,
  0xc50151d0, 0xb1ba90c6, 0xaed7175e, 0x204de55b, 0x4bb03245, 0x932b28bc,
  0x2dcce65b, 0xe2708abc, 0x1b08b8d5, 0x12a3dc5b, 0x8a884c90, 0xa386a8b8,
  0x18e417c6, 0x2e709ac3, 0xeb62e925, 0x6f6503ae, 0x05d0814e, 0x8a9ac545,
  0x946fd65e, 0x3f57495d, 0x4a29c658, 0xad454c90, 0x15340905, 0x4c3f3b25,
  0x01fe19b9, 0x5620595b, 0x443c795b, 0x44f24ac8, 0x0442464e, 0xc8665882,
  0xed3f3ec3, 0xf585bf5d, 0x5dd141da, 0xf93a084e, 0x1264dd52, 0x0711c658,
  0xf12e7bbe, 0x5b02b740, 0x7d526dd5, 0x0cb04c90, 0x2abe1132, 0x61a39f58,
  0x044a0618, 0xf3af7dce, 0xb994c96d, 0x361c5058, 0xca735d53, 0xeca743b0,
  0xec790905, 0xc4d37845, 0xa1c4a2b2, 0x726fd453, 0x625cc6c0, 0x6c20132e,
  0xb7aa0c79, 0xc6ed983d, 0x47e4cbc0, 0xa4ac75d4, 0xe2e59345, 0x4d784ad0,
  0x18a5ec5e, 0x481cc85b, 0x7c6c2fd5, 0x5e4d6018, 0x5b4b6c18, 0xd99b4c90,
  0xe63987dc, 0xb817bb25, 0x141cfeb2, 0x5f005058, 0x0d987f47, 0x242a496d,
  0x3e519bc0, 0x02b2454b, 0xdfaf3dc6, 0x888128bc, 0x1165bb25, 0xabfeca5b,
  0x2ef63540, 0x5773c7c6, 0x1280dd52, 0x8ebcacd9, 0x81c439c6, 0x39fcfa45,
  0x62177d41, 0xc975ed62, 0x05cff476, 0xdabda743, 0xaa1ac24e, 0xe255a22e,
  0x88aac705, 0xe707c658, 0xa9e94b5e, 0x2893484b, 0x99512705, 0xd63970ca,
  0x45994f32, 0xe519a8ad, 0x92e25f5d, 0x8b84a9c1, 0x5eaa0a05, 0xa74de55b,
  0xb090ff62, 0x5eee326c, 0xc331a679, 0xc1d9b72e, 0x0c6ab982, 0x7362bb25,
  0x4cfedd42, 0x1e09a032, 0xa4c34c5e, 0x3777d9c7, 0x5edcf260, 0x3ce2b548,
  0xd2ac0360, 0x2f80b992, 0x3e4cbb25, 0x3995e236, 0xd03977ae, 0x953cf054,
  0x3c654ed0, 0x74024c90, 0xa14f1155, 0x14ce0125, 0xc15ebb6a, 0x2c08c452,
  0xc7fd0652, 0x7604f8ce, 0xffb38332, 0xa4c2efd5, 0xe9614018, 0xab49e557,
  0x1648c052, 0x36024047, 0x0e8cffad, 0x21918953, 0xb61f50ad, 0x9b406b59,
  0xaf282218, 0x7f1d164e, 0x1f560da2, 0xe237be58, 0xbdeb1955, 0x6c0717d9,
  0xdaf8ce62, 0x0f74246c, 0xdee95243, 0xf23f1a56, 0x61bdf867, 0xd254c854,
  0xc4422e4e, 0xae0563c0, 0xbdb9a95f, 0xa9eb32c6, 0xd9943950, 0x116add52,
  0x73a54c90, 0xb36b525e, 0xd734175e, 0x333d7f76, 0x51431bc6, 0x084ae5cf,
  0xa60a236c, 0x5c67692e, 0x0177cf45, 0xa6683ac6, 0x7ff4ea47, 0x2192fab2,
  0xa03a0f46, 0xfe3e39ae, 0x2cce5fc1, 0xc8a6c148, 0x96fb7e4c, 0x0a66c752,
  0x6b4d2705, 0xeba0c118, 0x3ba0795b, 0x1dccd23e, 0x6912f3a2, 0x22f23c41,
  0x65646b4a, 0x8b9f8705, 0xeb9b9a95, 0x79fe6b4e, 0x0536f447, 0x23224d61,
  0x5d952ec6, 0x0cb4f736, 0xdc14be6d, 0xb24609b0, 0xd3f79b62, 0x6518c836,
  0x83a3cf42, 0x9b641fb0, 0x17fef1c0, 0xd508cc82, 0x91a4369b, 0x39cb4a4c,
  0xbbc9536c, 0xaf64c44a, 0x605eca50, 0x0c6a6805, 0xd07e9d4e, 0x78e6d3a2,
  0x1b31eb6d, 0xaa01feb2, 0x4603c236, 0x1ecba3b6, 0x0effe336, 0xc3fdcb36,
  0xc290036f, 0x4464692e, 0x1aca7589, 0x59a9e52e, 0x19aa7489, 0x2622c85e,
  0xa598d318, 0x438ec345, 0xc79619b9, 0xaf570360, 0x5098e289, 0x36add862,
  0x83c1a2b2, 0x969d0905, 0xcf3d156c, 0x49c1a445, 0xbd0b7562, 0x8fff1955,
  0x1e51fe53, 0x28d6efd5, 0x2837cc62, 0x02f42d42, 0x070e3fb2, 0xbcb18705,
  0x14a4e15b, 0x82096844, 0xcfcb1c2e, 0x37e27fc7, 0x07923748, 0x0c14bc2e,
  0x26100905, 0xcb7cd93e, 0x3bc0d2c0, 0x97131b4c, 0x6f1e5c17, 0xa7939f43,
  0xb7a0bf58, 0xafa83a47, 0xcbb83f32, 0x5f321cb0, 0x52d6c3c7, 0xdeac5bc7,
  0x2cf310cc, 0x108a2bc3, 0x726fa14f, 0x85bad2cc, 0x459e4c90, 0x1a08b8d8,
  0xcd7048c6, 0x6d5b4c90, 0xa66cfe7b, 0xad730905, 0xdaac5bc7, 0x8417fd9f,
  0x41377432, 0x1f138632, 0x295a12b2, 0x7ac031b2, 0x3a87d295, 0xe219bc2e,
  0xf485d295, 0x137b6405, 0xcfffd9ad, 0xafe20844, 0x32679a5f, 0xa431c644,
  0x0e5fce8c, 0x305ef853, 0xad26ca32, 0xd9d21a54, 0xddd0d736, 0xc24ec0c7,
  0x4aadcd5b, 0x49109852, 0x9d6b3ac6, 0xf0aa1e8b, 0xf1bfa343, 0x8a30c0ad,
  0x260f93d4, 0x2339e760, 0x8869959f, 0xc207216c, 0x29453448, 0xb651ec36,
  0x45496259, 0xa23d1bcc, 0xb39bcf43, 0xa1d29432, 0x3507c658, 0x4a88dd62,
  0x27aff363, 0x7498ea6d, 0x4a6785d5, 0x5e6d47c2, 0x3baba542, 0x045a37ae,
  0xa24dc0c7, 0xe981ea4d, 0xed6ce217, 0x857214c6, 0x6b6c0464, 0x5a4945b8,
  0x12f24742, 0xf35f42ad, 0xfd0f5a4e, 0xfb081556, 0xb24b5861, 0x2e114146,
  0xb7780905, 0x33bb0e48, 0x39e26556, 0xa794484d, 0x4225424d, 0x3003795b,
  0x31c8cf44, 0xd65bad59, 0x127bc648, 0xf2bc4d4c, 0x0273dc50, 0x4572d736,
  0x064bf653, 0xcdcd126c, 0x608281ae, 0x4d130087, 0x1016f725, 0xba185fc0,
  0x16c1a84f, 0xfb697252, 0xa2942360, 0x53083b6c, 0x0583f1c0, 0x2d5a2441,
  0xc172aa43, 0xcd11cf36, 0x7b14ed62, 0x5c94f1c0, 0x7c23132e, 0x39965a6f,
  0x7890e24e, 0xa38ec447, 0xc187f1c0, 0xef80b647, 0xf20a7432, 0x7ad1d8d2,
  0x869e2ec6, 0xccdb5c5d, 0x9d11f636, 0x2161bb25, 0x7599f889, 0x2265ecad,
  0x0f4f0e55, 0x7d25854a, 0xf857e360, 0xf83f3d6c, 0x9cc93bb8, 0x02716857,
  0x5dd8a177, 0x8adc6cd4, 0xe5613d46, 0x6a734f50, 0x2a5c3bae, 0x4a04c3d1,
  0xe4613d46, 0x8426f4bc, 0x3e1b5fc0, 0x0d5a3c18, 0xd0f6d154, 0x21c7ff5e,
  0xeb3f3d6c, 0x9da5edc0, 0x5d753b81, 0x0d8d53d4, 0x2613f018, 0x4443698d,
  0x8ca1edcd, 0x10ed3f4e, 0x789b403a, 0x7b984a4b, 0x964ebc25, 0x7520ee60,
  0x4f4828bc, 0x115c407d, 0x32dd0667, 0xa741715e, 0x1d3f3532, 0x817d1f56,
  0x2f99a552, 0x6b2a5956, 0x8d4f4f05, 0xd23c1e17, 0x98993748, 0x2c92e536,
  0x237ebdc3, 0xa762fb43, 0x32016b71, 0xd0e7cf79, 0x7d35bdd5, 0x53dac3d2,
  0x31016b71, 0x7fb8f8ce, 0x9a38c232, 0xefaa42ad, 0x876b823d, 0x18175347,
  0xdb46597d, 0xd2c168da, 0xcd6fe9dc, 0x45272e4e, 0x8d4bca5b, 0xa4043d47,
  0xaab7aa47, 0x202881ae, 0xa4aef160, 0xecd7e6bc, 0x391359ad, 0xd8cc9318,
  0xbbeee52e, 0x077067b0, 0xebd39d62, 0x0cedc547, 0x23d3e15e, 0xa5a81318,
  0x179a32c6, 0xe4d3483d, 0x03680905, 0xe8018abc, 0xdde9ef5b, 0x438b8705,
  0xb48224a0, 0xcbd69218, 0x9075795b, 0xc6411c3e, 0x03833f5c, 0xf33f8b5e,
  0x495e464b, 0x83c8e65b, 0xac09cd25, 0xdaabc547, 0x7665a553, 0xc5263718,
  0x2fd0c5cd, 0x22224d61, 0x3e954048, 0xfaa37557, 0x36dbc658, 0xa81453d0,
  0x5a941f5d, 0xa598ea60, 0x65384ac6, 0x10aaa545, 0xaaab795b, 0xdda7024c,
  0x0966f4c6, 0x68571c08, 0x8b40ee59, 0x33ac096c, 0x844b4c4b, 0xd392254d,
  0xba4d5a46, 0x63029653, 0xf655f636, 0xbe4c4bb1, 0x45dad036, 0x204bc052,
  0x06c3a2b2, 0xf31fba6a, 0xb21f09b0, 0x540d0751, 0xc7b46a57, 0x6a11795b,
  0x3d514045, 0x0318aa6d, 0x30306ec3, 0x5c077432, 0x259ae46d, 0x82bbd35f,
  0xae4222c0, 0x254415d4, 0xbd5f574b, 0xd8fd175e, 0x0a3f38c3, 0x2dce6bb8,
  0xc201d058, 0x17fca5bc, 0xe8453cca, 0xd361f636, 0xa0d9edc0, 0x2f232e4e,
  0x134e116c, 0x61ddc058, 0x05ba7283, 0xe1f7ed5b, 0x040ec452, 0x4b672e4e,
  0xe4efa36d, 0x47dca52e, 0xe9332e4e, 0xa3acb992, 0x24714c90, 0xa8cc8632,
  0x26b1ce6d, 0x264e53d4, 0xd3d2718c, 0x225534ad, 0xe289f3a2, 0x87341717,
  0x9255ad4f, 0x184bbb25, 0x885c7abc, 0x3a6e9ac6, 0x1924185e, 0xb73d4c90,
  0x946d807a, 0xa0d78e3f, 0x5a16bb25, 0xcb09795b, 0x8d0de657, 0x630b8b25,
  0xe572c6cf, 0x2b3f1118, 0x4242a91f, 0x32990905, 0x058b0905, 0xe266fc60,
  0xbe66c5b0, 0xcc98e46d, 0x698c943e, 0x44bd0cc3, 0x865c7abc, 0x771764d3,
  0x4675d655, 0x354e4826, 0xb67ac152, 0xaeccf285, 0xea625b4e, 0xbcd6031f,
  0x5e81eb18, 0x74b347ce, 0x3ca56ac1, 0x54ee4546, 0x38a8175e, 0xa3c21155,
  0x2f01576d, 0x5d7ade50, 0xa003ae48, 0x2bc1d31f, 0x13f5094c, 0x7ab32648,
  0x542e9fd5, 0x53136bc1, 0x7fdf51c0, 0x802197b2, 0xa2d2cc5b, 0x6b5f4bc0
];

normal.seeds.ips = normal.seeds.ips.map(function(ip) {
  // LE:
  return ((ip >> 0) & 0xff)
    + '.' + ((ip >> 8) & 0xff)
    + '.' + ((ip >> 16) & 0xff)
    + '.' + ((ip >> 24) & 0xff);
});

normal.seeds.push.apply(normal.seeds, normal.seeds.ips);

/**
 * Checkpoints
 */

// Reference:
// ~/bitcoin/src/checkpoints.cpp

normal.checkpoints = [
  { height: 11111,  hash: '0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d' },
  { height: 33333,  hash: '000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6' },
  { height: 74000,  hash: '0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20' },
  { height: 105000, hash: '00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97' },
  { height: 134444, hash: '00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe' },
  { height: 168000, hash: '000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763' },
  { height: 193000, hash: '000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317' },
  { height: 210000, hash: '000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e' },
  { height: 216116, hash: '00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e' },
  { height: 225430, hash: '00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932' },
  { height: 250000, hash: '000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214' },
  { height: 279000, hash: '0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40' }
];

// * UNIX timestamp of last checkpoint block
normal.checkpoints.tsLastCheckpoint = 1389047471;
// * total number of transactions between genesis and last checkpoint
//   (the tx=... number in the SetBestChain debug.log lines)
normal.checkpoints.txsLastCheckpoint = 30549816;
// * estimated number of transactions per day after checkpoint
normal.checkpoints.txsPerDay = 60000.0;

/**
 * Genesis Block
 * http://blockexplorer.com/b/0
 * http://blockexplorer.com/rawblock/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
 */

normal.genesis = {
  version: 1,
  _hash: utils.toArray(
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
    'hex'
  ).reverse(),
  prevBlock: [ 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0 ],
  merkleRoot: utils.toArray(
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
    'hex'
  ).reverse(),
  ts: 1231006505,
  bits: 0x1d00ffff,
  nonce: 2083236893
};

normal.magic = 0xd9b4bef9;
normal.addressVersion = 0;

/**
 * Use Normal
 */

protocol.__proto__ = normal;

/**
 * Testnet Protocol (v3)
 * https://en.bitcoin.it/wiki/Testnet
 */

// Reference:
// ~/bitcoin/src/chainparams.cpp

var testnet = protocol.testnet = {};

testnet.type = 'testnet';

testnet.seeds = [
  'testnet-seed.bitcoin.petertodd.org',
  'testnet-seed.bluematt.me'
];

testnet.port = 18333;

testnet.alertKey = utils.toArray(''
  + '04302390343f91cc401d56d68b123028bf52e5f'
  + 'ca1939df127f63c6467cdf9c8e2c14b61104cf8'
  + '17d0b780da337893ecc4aaff1309e536162dabb'
  + 'db45200ca2b0a',
  'hex');

/**
 * Testnet Checkpoints
 */

// Reference:
// ~/bitcoin/src/checkpoints.cpp

testnet.checkpoints = [
  { height: 546, hash: '000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70' }
];

testnet.checkpoints.tsLastCheckpoint = 1338180505;
testnet.checkpoints.txsLastCheckpoint = 16341;
testnet.checkpoints.txsPerDay = 300;

/**
 * Genesis Block
 * http://blockexplorer.com/testnet/b/0
 * http://blockexplorer.com/testnet/rawblock/000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943
 */

testnet.genesis =  {
  version: 1,
  _hash: utils.toArray(
    '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943',
    'hex'
  ).reverse(),
  prevBlock: [ 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0 ],
  merkleRoot: utils.toArray(
    '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
    'hex'
  ).reverse(),
  ts: 1296688602,
  bits: 0x1d00ffff,
  nonce: 414098458
};

testnet.magic = 0x0709110b;
testnet.addressVersion = 111;

/**
 * Use Testnet
 */

if (protocol.type === 'testnet') {
  protocol.__proto__ = testnet;

  constants.genesis = protocol.genesis;
  constants.magic = protocol.magic;
  constants.addressVersion = protocol.addressVersion;

  utils.merge(bcoin.protocol.preload, {
    'v': 1,
    'type': 'chain',
    'hashes': [utils.toHex(protocol.genesis._hash)],
    'ts': [protocol.genesis.ts],
    'heights': [0]
  });

  wallet.hash2addr = function hash2addr(hash) {
    hash = utils.toArray(hash, 'hex');

    // Add version
    hash = [ constants.addressVersion ].concat(hash);

    var addr = hash.concat(utils.checksum(hash));
    return utils.toBase58(addr);
  };
}
