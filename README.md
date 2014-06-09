# coined

**coined** is a high-level wrapper around [BCoin][bcoin], making it easy to
send transactions and deal with wallets/accounts. Some of the original code was
based on Fedor Indutny's [BThread][bthread].

## Install

``` bash
$ npm install coined
```

## Usage

The primary feature of Coined is a wallet similar to the way bitcoin-qt handles
wallets (a collection of accounts, stored by label).

```js
var coined = require('coined');
var utils = coined.utils;
var bcoin = coined.bcoin;
var bn = coined.bn;

var coin = coined({
  // DB type, can be `tiny` or `leveldown`.
  db: {
    type: 'tiny',
    path: process.env.HOME + '/.my-app/db'
  },
  wallet: process.env.HOME + '/.my-app/wallet.json'
});

// Add a key+pair/account to our wallet, under the label "main".
coin.addAccount({ label: 'main' });

// Send
coin.on('balance', function() {
  if (coin._sentIt) return;

  var address = '1Lzcrow4haAm6j4vyKhMeFQdHcaE1VbjTc';
  var amount = 100000; // satoshis!

  // `coin.balance()` will tell you the *entire* cumulative
  // balance of every account in your wallet.
  if (coin.balance().cmpn(amount) < 0) {
    return;
  }

  return coin.sendTo(address, amount, function(err) {
    if (err) {
      console.error('sendTo failed');
      console.error(err.message);
      return;
    }
    coin._sentIt = true;
    console.log('Sending of %s satoshis to %s succeeded.', amount, address);
  });
});

// List our addresses and their associated labels.
console.log('My wallet\'s addresses:');
coin.accounts.forEach(function(account) {
  console.log(account.label + ': ' + account.getAddress());
});
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

Copyright (c) 2014, Christopher Jeffrey. (MIT License)

See LICENSE for more info.

[bcoin]: https://github.com/indutny/bcoin
[bthread]: https://github.com/indutny/bthread
