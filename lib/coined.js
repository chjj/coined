/**
 * coined - a high-level wrapper around bcoin
 * Copyright (c) 2014, Christopher Jeffrey. (MIT Licensed)
 * https://github.com/chjj/coined
 */

/**
 * Modules
 */

var net = require('net')
  , path = require('path')
  , EventEmitter = require('events').EventEmitter
  , fs = require('fs')
  , crypto = require('crypto')
  , util = require('util')
  , assert = require('assert');

var setImmediate = typeof global.setImmediate !== 'function'
  ? process.nextTick.bind(proccess)
  : global.setImmediate;

/**
 * Dependencies
 */

var bcoin = require('bcoin')
  , bn = require('bcoin/node_modules/bn.js')
  , async = require('bcoin/node_modules/async');

/**
 * Load
 */

var utils = require('./utils')
  , protocol = require('./protocol')
  , seeds = protocol.seeds;

/**
 * Coined
 */

function Coined(options) {
  var self = this
    , dbType
    , dbDir
    , dbPath;

  if (!(this instanceof Coined)) {
    return new Coined(options);
  }

  EventEmitter.call(this);

  options = options || {};
  options.db = options.db || {};

  dbType = options.db.type || 'tiny';
  dbDir = dbType === 'level'
    ? '.coined.level'
    : '.coined';
  dbPath = dbType === 'level'
    ? path.resolve(process.env.HOME, dbDir)
    : path.resolve(process.env.HOME, dbDir, 'db');

  options.db.type = options.db.type || dbType;
  options.db.path = options.db.path || dbPath;

  if (options.db.clear) {
    cleanup(options.db.path);
  }

  if (options.db.type === 'level') {
    mkdirp(options.db.path);
    this.db = require('levelup')(options.db.path, {
      db: require('leveldown'),
      valueEncoding: 'json'
    });
  } else if (options.db.type === 'tiny') {
    mkdirp(path.resolve(options.db.path, '..'));
    this.db = require('tiny').json({
      file: options.db.path,
      saveIndex: false,
      initialCache: false
    });
  } else {
    throw new Error('Invalid DB type.');
  }

  this.options = options;

  this.socketIndex = 0;

  this.crypto = options.crypto;
  this.compressed = options.compressed != null
    ? options.compressed
    : true;

  this.walletPath = options.walletPath || options.wallet
    || process.env.HOME + '/.coined/wallet.json';

  this.addr = null;
  this.dust = 5460;
  this.fee = 10000;

  mkdirp(path.dirname(this.walletPath));

  this.account = null;
  this.accounts = [];
  this.aaccounts = {};
  this.laccounts = {};
  this.recipients = {};

  if (options.noPreload) {
    this._clearPreload();
  }

  this.pool = options.pool || bcoin.pool({
    size: options.size,
    createConnection: function() {
      if (self.socketIndex >= seeds.length) {
        self.socketIndex = 0;
      }

      if (seeds.length > 3000) {
        seeds = seeds.slice(0, 1500);
        self.socketIndex = 0;
      }

      var addr = seeds[self.socketIndex++]
        , parts = addr.split(':')
        , host = parts[0]
        , port = +parts[1] || protocol.port
        , socket;

      socket = net.connect(port, host);

      socket.on('connect', function() {
        var peers = [].concat(
          self.pool.peers.pending,
          self.pool.peers.block,
          self.pool.peers.load
        ).filter(Boolean);

        for (var i = 0; i < peers.length; i++) {
          var peer = peers[i];

          if (peer.socket !== socket) {
            continue;
          }

          if (peer.version) {
            return self.emit('peer', peer, socket);
          }

          return peer.parser.on('packet', function callee(payload) {
            if (payload.cmd !== 'version') return;
            peer.removeListener('packet', callee);
            return setImmediate(function() {
              self.emit('peer', peer, socket);
            });
          });
        }

        self._log('Connected to %s:%d', host, port);
      });

      return socket;
    },
    storage: this.db,
    startHeight: options.startHeight,
    relay: options.relay
  });

  this.blockHeight = 0;
  this.on('peer', function(peer) {
    if (!peer.version || !peer.socket) {
      return;
    }
    if (peer.version.height > self.blockHeight) {
      self.blockHeight = peer.version.height;
    }
    self._log('Connected to %s:%d (%s v%s) height=%d relay=%d',
      peer.socket.remoteAddress,
      peer.socket.remotePort,
      peer.version.agent,
      peer.version.v,
      peer.version.height,
      peer.version.relay);
  });

  if (options.noPreload) {
    bcoin.protocol.preload = bcoin.protocol._preload;
  }

  this.pool.on('error', function(err) {
    self._error(err);
  });

  this.salt = 'coined:';

  this.pending = {};

  this.loadWallet(null, this.passphrase);

  if (!this.account) {
    this.createAccount(options);
  }

  // Keep track of version, handle upgrades.
  this.version = Coined.version;
  this.previousVersion = '0.0.0';
  this.db.get('meta/version', function(err, data) {
    if (data) {
      self.previousVersion = data.version;
    }
    return self.db.set('meta/version', { version: self.version }, function(err) {
      if (err) return self._error(err);
      self._log('Version written: %s, previous: %s',
        self.version, self.previousVersion);
    });
  });

  // Listeners to remove on .destroy();
  this.pool._poolOnTX = null;
  this.pool._poolOnReject = null;
  this.pool._poolOnceFull = null;
  this.closed = false;

  this.init();
}

Coined.prototype.__proto__ = EventEmitter.prototype;

Coined.version = require('../package.json').version;

Coined.prototype.init = function() {
  var self = this;

  this.pool.setMaxListeners(Number.MAX_VALUE);
  this.pool.chain.setMaxListeners(Number.MAX_VALUE);

  this.pool.on('addr', function(data, peer) {
    var host = data.ipv4 + ':' + data.port;
    if (!~seeds.indexOf(host)) {
      self._log('Found new peer: %s', host);
      seeds.push(host);
    }
  });

  if (this.options.noPreload || this.options.neverFull) {
    this.pool.chain.isFull = function() { return false; };
    this.pool.isFull = function() { return false; };
  }

  this.db.on('error', function(err) {
    self._log('\x1b[41m' + err.message + '\x1b[m');
  });

  setImmediate(function() {
    self.addr = self.account.getAddress();
    self.emit('account', self.addr);
  });

  this.pool.on('tx', this._poolOnTX = function(tx) {
    var hash = tx.hash('hex');

    if (!tx.block) {
      if (!self.pending[hash]) {
        self.pending[hash] = tx;
        self.pool.watch(tx.hash('hex'));
      }
      return;
    }

    if (self.pending[hash]) {
      delete self.pending[hash];
    }

    for (var i = 0; i < self.accounts.length; i++) {
      // if (self.accounts[i].ownInput(tx) || self.accounts[i].ownOutput(tx)) {
      //   self.accounts[i].addTX(tx);
      // }
      self.accounts[i].addTX(tx);
    }
  });

  this.pool.on('reject', this._poolOnReject = function(msg) {
    self._log('Transaction rejected %j', msg);
  });

  this.pool.once('full', this._poolOnceFull = function() {
    self._log('Blockchain is full and up-to-date');
    self.emit('full');
  });

  this.pool.on('debug', function() {
    self._log.apply(self, arguments);
  });

  if (this.pool.isFull()) {
    this._poolOnceFull();
  }
};

Coined.prototype._log = function(msg) {
  if (typeof msg === 'string') {
    msg = util.format.apply(util, arguments);
  } else {
    msg = util.inspect(msg, null, 20, true);
  }
  this.emit('log', msg);
};

Coined.prototype._error = function(msg) {
  if (typeof msg === 'string') {
    msg = new Error(util.format.apply(util, arguments));
  }
  this.emit('error', msg);
  return msg;
};

Coined.prototype.close = function() {
  if (this.closed) return;
  this.closed = true;

  this.pool.destroy();
  this.db.close();

  for (var i = 0; i < this.accounts.length; i++) {
    this.pool.removeWallet(this.accounts[i]);
  }

  this.pool.removeListener('tx', this._poolOnTX);
  this.pool.removeListener('reject', this._poolOnReject);
  this.pool.removeListener('full', this._poolOnceFull);
};

Coined.prototype._clearPreload = function() {
  utils.merge(bcoin.protocol._preload = {}, bcoin.protocol.preload);
  utils.merge(bcoin.protocol.preload, {
    'v': 1,
    'type': 'chain',
    'hashes': bcoin.protocol._preload.hashes.slice(0, 1),
    'ts': bcoin.protocol._preload.ts.slice(0, 1),
    'heights': bcoin.protocol._preload.heights.slice(0, 1)
  });
  if (this.pool) {
    utils.merge(this.pool.chain.index, {
      'hashes': bcoin.protocol._preload.hashes.slice(0, 1),
      'ts': bcoin.protocol._preload.ts.slice(0, 1),
      'heights': bcoin.protocol._preload.heights.slice(0, 1)
    });
  }
};

Coined.prototype.loadWallet = function(path, passphrase, time) {
  var self = this;
  var path = path || this.walletPath;
  var time = time || this.options.lockTime;

  if (!path || !fs.existsSync(path)) {
    return;
  }

  var data = Coined._readJSON(path);

  this.clearWallet();

  this.crypto = !!data.encrypted;
  this.encrypted = this.crypto;

  this.passphrase = this.timeKey(passphrase || this.passphrase);
  if (passphrase) passphrase = null;

  data.accounts.forEach(function(account) {
    var priv = account.priv;

    if (data.encrypted) {
      if (!self.passphrase) {
        // NOTE: priv and pub can be hex strings,
        // or arrays. priv alone can be a bn().
        var account = self.createAccount({
          label: account.label,
          pub: account.pub
            ? utils.fromBase58(account.pub)
            : null
        }, true);
        if (account.key) {
          delete account.key.priv;
        }
        account._priv = priv;
        return;
      }
      priv = self._decrypt(priv, self.passphrase);
      priv = utils.toArray(priv, 'hex');
    } else {
      priv = Coined.fromKeyBase58(priv, self.compressed);
    }

    self.createAccount({
      label: account.label,
      priv: priv
    });
  });

  this.recipients = data.recipients || {};

  return this.accounts;
};

Coined.prototype.saveWallet = function(path, passphrase) {
  var self = this;
  var path = path || this.walletPath;
  var noSave = false;

  if (!path) return this.accounts;

  var passphrase = passphrase || this.passphrase;
  if (typeof passphrase === 'string') {
    passphrase = new Buffer(passphrase);
  }

  var accounts = this.accounts.map(function(account) {
    var priv;
    if (self.crypto) {
      if (account._priv) {
        priv = account._priv;
      } else {
        if (!self.passphrase) {
          noSave = true;
          return;
        }
        priv = utils.toHex(account.key.priv.toArray());
        priv = self._encrypt(priv, passphrase);
      }
    } else {
      priv = Coined.toKeyBase58(account.getPrivateKey(), self.compressed);
    }
    return {
      address: account.getAddress(),
      label: account.label || '',
      priv: priv,
      pub: utils.toBase58(account.getPublicKey()),
      balance: utils.toBTC(account.balance()),
      tx: account.tx.all().length
    };
  });

  if (noSave) return this.accounts;

  var data = JSON.stringify({
    version: 1,
    ts: Date.now() / 1000 | 0,
    encrypted: this.crypto,
    compressed: this.compressed,
    balance: utils.toBTC(this.balance()),
    accounts: accounts,
    recipients: this.recipients
  }, null, 2);

  this._writeWallet(path, data);

  return this.accounts;
};

Coined.prototype._writeWallet = function(path, data) {
  this._walletBackups = this._walletBackups || 3;
  this._walletLastWrite = this._walletLastWrite || 0;

  if (this._walletLastWrite + 60 * 60 * 1000 > Date.now()) {
    return fs.writeFileSync(path, data);
  }

  if (fs.existsSync(path)) {
    for (var i = 0; i < this._walletBackups; i++) {
      if (!fs.existsSync(path + '.bak' + i)) {
        break;
      }
    }

    if (i === this._walletBackups) {
      for (var i = 0; i < this._walletBackups; i++) {
        fs.unlinkSync(path + '.bak' + i);
      }
    }

    for (var i = 0; i < this._walletBackups; i++) {
      if (!fs.existsSync(path + '.bak' + i)) {
        fs.renameSync(path, path + '.bak' + i);
        break;
      }
    }
  }

  this._walletLastWrite = Date.now();

  return fs.writeFileSync(path, data);
};

Coined.prototype.clearWallet = function(options) {
  if (this.passphrase) {
    this.passphrase.fill(0);
    this.passphrase = null;
  }
  this.account = null;
  this.accounts = [];
  this.aaccounts = {};
  this.laccounts = {};
  this.recipients = {};
};

Coined.prototype.createAccount = function(options, ignoreCrypt) {
  var self = this;

  options = options || {};

  if (this.encrypted && !ignoreCrypt) {
    return this._error('Encrypted.');
  }

  options.label = options.label || '';

  var account = bcoin.wallet({
    scope: options.scope,
    passphrase: options.passphrase,
    pub: options.pub,
    priv: options.priv,
    compressed: this.compressed,
    storage: this.db
  });

  account.label = options.label;

  account.on('balance', function(balance) {
    self.emit('balance', self.balance(), account, balance);
  });

  account.once('load', function(ts) {
    self._log(account.getAddress() + ' is loaded');
  });

  this.pool.addWallet(account);

  if (!this.account) {
    this.account = account;
  }

  this.accounts.push(account);
  this.aaccounts[account.getAddress()] = account;
  this.laccounts[account.label] = this.laccounts[account.label] || [];
  this.laccounts[account.label].push(account);

  setImmediate(function() {
    return self.saveWallet();
  });

  return account;
};

Coined.prototype.deleteAccount = function(address) {
  if (this.encrypted) {
    return this._error('Encrypted.');
  }

  var account = this.accountByAddress(address);
  if (!account) return;

  this.pool.removeWallet(account);

  var i = this.accounts.indexOf(account);
  this.accounts.splice(i, 1);

  var laccounts = this.accountByLabel(account.label);
  var i = laccounts.indexOf(account);
  laccounts.splice(i, 1);

  delete this.aaccounts[address];

  if (this.account === account) {
    this.account = this.accounts[0] || this.createAccount();
  }

  this.saveWallet();
};

Coined.prototype.accountByAddress = function(address) {
  return this.aaccounts[address];
};

Coined.prototype.accountByLabel = function(label) {
  return this.laccounts[label] || (this.laccounts[label] = []);
};

Coined.prototype.createRecipient = function(address, label) {
  this.recipients[address] = label || '';
  this.saveWallet();
};

Coined.prototype.deleteRecipient = function(address) {
  delete this.recipients[address];
  this.saveWallet();
};

Coined.prototype.balance = function() {
  return this.accounts.reduce(function(total, account) {
    return total.iadd(account.balance());
  }, new bn(0));
};

Coined.prototype.ubalance = function balance() {
  var self = this
    , confirmed = new bn(0)
    , unconfirmed = new bn(0)
    , total = new bn(0);

  this.accounts.forEach(function(account) {
    account.unspent().forEach(function(item) {
      var value = item.tx.outputs[item.index].value;
      if (item.tx.block) {
        confirmed.iadd(value);
      }
      total.iadd(value);
    });
  });

  var noValues = false;
  Object.keys(this.pending).forEach(function(hash) {
    var tx = self.pending[hash];
    self.accounts.forEach(function(account) {
      if (noValues) return;

      var ownInput = account.ownInput(tx) || [];
      var ownOutput = account.ownOutput(tx) || [];

      for (var i = 0; i < ownInput.length; i++) {
        var input = ownInput[i];
        var prev = input.out.tx || account.tx._all[input.out.hash];
        if (prev) {
          var value = prev.outputs[input.out.index].value;
          total.isub(value);
        } else {
          noValues = true;
          return;
        }
      }

      for (var i = 0; i < ownOutput.length; i++) {
        var output = ownOutput[i];
        total.iadd(output.value);
      }
    });
  });

  if (total.cmp(confirmed) > 0) {
    unconfirmed = total.isub(confirmed);
  }

  return {
    confirmed: confirmed,
    unconfirmed: unconfirmed
  };
};

Coined.prototype.encryptWallet = function(passphrase) {
  var self = this;
  var passphrase = passphrase || this.passphrase;
  if (typeof passphrase === 'string') {
    passphrase = new Buffer(passphrase);
  }
  this.passphrase = null;
  if (this.encrypted) {
    return this._error('Encrypted.');
  }
  this.crypto = true;
  this.encrypted = true;
  this.accounts.forEach(function(account) {
    if (!account.key.priv) {
      return;
    }
    var priv = account.key.priv.toArray();
    priv = utils.toHex(priv);
    account._priv = self._encrypt(priv, passphrase);
    delete account.key.priv;
  });
  this.saveWallet(null, passphrase);
};

Coined.prototype.decryptWallet = function(passphrase, time) {
  var self = this;

  if (!this.crypto) {
    return this._error('Not encrypted');
  }

  this.passphrase = this.timeKey(passphrase || this.passphrase);
  if (passphrase) passphrase = null;

  this.encrypted = false;
  this.accounts.forEach(function(account) {
    var priv = self._decrypt(account._priv, self.passphrase);
    priv = utils.toArray(priv, 'hex');
    account.key.priv = new bn(priv, 10);
  });
};

Coined.prototype.unencryptWallet = function(passphrase) {
  this.decryptWallet(passphrase);
  this.crypto = false;
  this.saveWallet();
};

Coined.prototype.timeKey = function(passphrase, time) {
  this.passphrase = passphrase = passphrase || this.passphrase;
  if (!passphrase) return;

  if (typeof passphrase === 'string') {
    this.passphrase = passphrase = new Buffer(passphrase);
  }

  if (this._keyTimer) {
    clearTimeout(this._keyTimer);
    this._keyTimer = null;
  }

  var locker = this.lockWallet.bind(this);
  var timeout = (time || (60 * 60)) * 1000;

  this._keyTimer = setTimeout(locker, timeout);

  return passphrase;
};

Coined.prototype.lockWallet = function() {
  if (!this.passphrase) return;
  this.encryptWallet(this.passphrase);
  if (this.passphrase) {
    this.passphrase.fill(0);
  }
  this.passphrase = null;
  this.encrypted = true;
};

Coined.prototype._encrypt = function(data, passphrase) {
  var cipher = crypto.createCipher('aes-256-cbc', passphrase);

  var out = '';
  out += cipher.update(this.salt + data, 'utf8', 'hex');
  out += cipher.final('hex');

  return ':' + out;
};

Coined.prototype._decrypt = function(data, passphrase) {
  if (data[0] !== ':') {
    return this._error('Not encrypted.');
  }
  data = data.substring(1);

  var decipher = crypto.createDecipher('aes-256-cbc', passphrase);

  var out = '';
  out += decipher.update(data, 'hex', 'utf8');
  out += decipher.final('utf8');

  if (out.indexOf(this.salt) !== 0) {
    return this._error('Decrypt failed.');
  }
  out = out.substring(this.salt.length);

  return out;
};

Coined._readJSON = function(path, callback) {
  if (!callback) {
    return JSON.parse(fs.readFileSync(path, 'utf8'));
  }
  return fs.readFile(path, 'utf8', function(err, data) {
    if (err) return callback(err);
    try {
      data = JSON.parse(data);
    } catch (e) {
      return callback(e);
    }
    return callback(null, data);
  });
};

// ~/work/node_modules/bcoin/lib/bcoin/wallet.js
// wallet.getPrivateKey('base58')
Coined.toKeyBase58 = function(key, compressed) {
  key = bcoin.utils.toArray(key, 'hex');

  // We'll be using ncompressed public key as an address
  var out = [128];

  // 0-pad key
  while (out.length + key.length < 33) {
    out.push(0);
  }

  out = out.concat(key);
  if (compressed) {
    out.push(1);
  }

  var chk = bcoin.utils.checksum(out);
  return bcoin.utils.toBase58(out.concat(chk));
};

Coined.fromKeyBase58 = function(key, compressed) {
  if (!Array.isArray(key)) {
    key = bcoin.utils.fromBase58(key);
  }

  if (compressed) {
    if (key[key.length - 5] !== 1) {
      throw new Error('Bad key compression.');
    }
    key.splice(key.length - 5, 1);
  }

  if (key.length !== 37) {
    throw new Error('Bad key length.');
  }

  if (key[0] !== 128) {
    throw new Error('Bad key prefix.');
  }

  var chk = key.slice(0, -4);
  if (compressed) chk = chk.concat(1);
  chk = bcoin.utils.checksum(chk);

  if (bcoin.utils.readU32(chk, 0) !== bcoin.utils.readU32(key, 33)) {
    throw new Error('Bad key checksum.');
  }

  return key.slice(1, -4);
};

Coined.isAddress = function(address) {
  var hash = bcoin.wallet.addr2hash(address);
  return hash.length > 0;
};

Coined.dumpToJSON = function(file, dump) {
  var dump = dump || fs.readFileSync(file, 'utf8')
    , dump = dump.replace(/^# [^\n]+/gm, '').trim()
    , lines = dump.split(/\n+/);

  var accounts = lines.reduce(function(accounts, line) {
    var parts = line.trim().split(/\s+/)
      , account = {}
      , name;

    account.priv = parts.shift() || '';
    account.ts = parts.shift() || '';

    while (parts.length) {
      part = parts.shift();
      if (part === '#') {
        continue;
      } else if (/^\w+=/.test(part)) {
        name = part.split('=')[0];
        account[name] = part.split('=').slice(1).join('=');
      } else {
        account[name] += parts.shift();
      }
    }

    account.ts = +new Date(account.ts) / 1000 | 0;

    accounts.push(account);

    return accounts;
  }, []);

  var json = {
    version: 1,
    ts: accounts.length
      ? accounts[accounts.length-1].ts
      : Date.now() / 1000 | 0,
    encrypted: false,
    compressed: true,
    balance: 0,
    accounts: accounts.map(function(account) {
      return {
        address: account.addr || '',
        label: account.label || '',
        priv: account.priv || '',
        pub: '',
        balance: 0,
        tx: 0
      };
    }),
    recipients: {}
  };

  return JSON.stringify(json, null, 2);
};

Coined.jsonToDump = function(file, data) {
  var data = data || Coined._readJSON(file);

  var header = [
    '# Wallet dump created by coined',
    '# * Created on ' + new Date().toISOString(),
    ''
  ];

  var body = data.accounts.reduce(function(body, account) {
    body.push(
      account.priv + ' ' + new Date(data.ts * 1000).toISOString()
      + ' ' + 'label=' + (account.label || '')
      + ' # ' + 'addr=' + account.address
    );
    return body;
  }, []);

  var footer = [
    '',
    '# End of dump'
  ];

  return header.concat(body).concat(footer).join('\n');
};

Coined.prototype.importWallet = function(file, callback) {
  var self = this;

  if (!callback) {
    callback = file;
    file = process.env.HOME + '/wallet.dump';
  }

  function _dump(callback) {
    return callback();

    if (fs.existsSync(file)) {
      return callback();
    }

    var exec = require('child_process').execFile
      , args = ['dumpwallet', file];

    return exec('bitcoind', args, function(err, stdout, stderr) {
      if (err) return callback(err);
      if (stderr && stderr.trim()) {
        return callback(new Error(stderr));
      }
      return callback();
    });
  }

  return _dump(function(err) {
    if (err) return callback(err);
    var json = Coined.dumpToJSON(file);
    return fs.writeFile(self.walletPath, json, function(err) {
      if (err) return callback(err);
      return fs.unlink(file, function() {
        self.loadWallet();
        return callback();
      });
    });
  });
};

Coined.prototype.dumpWallet = function(file, callback) {
  var self = this;

  if (!callback) {
    callback = file;
    file = process.env.HOME + '/wallet.dump';
  }

  function _import(callback) {
    return callback();

    var exec = require('child_process').execFile
      , args = ['importwallet', file];

    return exec('bitcoind', args, function(err, stdout, stderr) {
      if (err) return callback(err);
      if (stderr && stderr.trim()) {
        return callback(new Error(stderr));
      }
      return fs.unlink(file, function() {
        return callback();
      });
    });
  }

  var dump = Coined.jsonToDump(this.walletPath);

  return fs.writeFile(file, dump, function(err) {
    if (err) return callback(err);
    return _import(function(err) {
      if (err) return callback(err);
      return callback();
    });
  });
};

Coined.prototype.sendFrom = function(from, address, amount, callback) {
  return this.sendTo(address, amount, callback, from);
};

Coined.prototype.sendTo = function(address, amount, callback, from) {
  var self = this;
  var target = from || this;

  if (!amount || !amount.cmp) {
    amount = new bn(Math.floor(+amount || 0).toString(16), 16);
  }

  if (target.balance().cmp(amount) < 0) {
    return callback(new Error('Not enough funds.'));
  }

  function done(err, status, hash) {
    if (err && err.minBalance) {
      return retry(err.minBalance);
    }

    if (err) {
      return callback(err);
    }

    self._log('Messages %s posted, the TX hash is %s',
      status ? 'successfully' : 'not', hash);

    self.pool.unwatch(bcoin.wallet.addr2hash(address));

    // Ensure that enough acks will be acquired
    setTimeout(callback.bind(null, err, status, hash), 5000);
  }

  function retry(balance) {
    self._log('You don\'t have enough bitcoins to send a transaction.');
    self._log('Minimum required value is %s satoshi (~%d BTC).',
      balance.toString(10), balance.toString(10) / 10000000);

    var req = balance.sub(target.balance());

    self._log(
      'Please send %d satoshi (~%d BTC) to your address: %s to continue',
      req.toString(10),
      req.toString(10) / 10000000,
      target.getAddress()
    );

    // Retry later
    target.once('balance', function() {
      if (target.balance().cmp(balance) >= 0) {
        self._sendTo(address, amount, done, from);
      }
    });
  }

  this.pool.watch(bcoin.wallet.addr2hash(address));

  return this._sendTo(address, amount, done, from);
};

Coined.prototype._sendTo = function(address, amount, callback, from) {
  var self = this;

  if (this.encrypted) {
    return callback(new Error('Encrypted.'));
  }

  if (amount.cmpn(0) !== 0 && amount.cmpn(this.dust) < 0) {
    var dust = utils.toBTC(new bn(this.dust));
    return callback(new Error('Amount should be at least ' + dust + ' or zero.'));
  }

  var tx = bcoin.tx();

  // Additional money to author
  if (amount.cmpn(0) !== 0) {
    // tx.out({ address: address, value: amount });
    tx.out(address, amount);
  }

  // Add enough inputs to cover both outputs and fee
  this._fill(from, tx, function(err) {
    if (err) return callback(err);

    self._log('Filled TX:');
    self._log({
      hash: tx.hash('hex'),
      cost: utils.toBTC(amount.add(new bn(self.fee))),
      totalIn: utils.toBTC(tx.funds('in')),
      inputs: tx.inputs.map(function(input) {
        return {
          prev: input.out.hash,
          value: utils.toBTC(input.out.tx.outputs[input.out.index].value),
          script: [
            utils.toHex(input.script[0]),
            utils.toHex(input.script[1])
          ]
        };
      }),
      totalOut: utils.toBTC(tx.funds('out')),
      outputs: tx.outputs.map(function(output) {
        return {
          value: utils.toBTC(output.value),
          script: JSON.stringify(output.script)
        };
      })
    });

    // This gives a fee for some reason.
    var totalIn = tx.funds('in');
    var totalOut = tx.funds('out');
    var fee = totalIn.sub(totalOut);
    var hash = utils.revHex(tx.hash('hex'));

    self._log('TX amount: %s BTC. Fee: %s BTC.',
      utils.toBTC(amount), utils.toBTC(fee));

    self._log('Sending TX with id %s', hash);

    var broadcast = self.pool.sendTX(tx);

    var timeout = setTimeout(function() {
      timeout = null;
      return callback(new Error('No transaction ACKs in 30 seconds.'));
    }, 30 * 1000);

    broadcast.once('ack', function(peer) {
      if (!timeout) return;
      clearTimeout(timeout);
      self.accounts.forEach(function(account) {
        // account.tx.add(tx, true);
        self.pending[tx.hash('hex')] = tx;
        self.pool.watch(tx.hash('hex'));
      });
      return callback(null, true, hash);
    });

    broadcast.on('ack', function(peer) {
      self._log('Got ACK for TX %s', hash);
    });
  });
};

Coined.prototype._fill = function(from, tx, callback) {
  if (!callback) {
    callback = tx;
    tx = from;
    from = null;
  }

  // if (from) {
  //   return from.fill(tx, callback);
  // }

  var account;

  // NOTE: tx should be prefilled with all outputs
  var cost = tx.funds('out');

  // Use initial fee for starters
  var fee;

  // total = cost + fee
  var total = cost.add(new bn(this.fee));

  var lastAdded;
  function addInput(unspent, i) {
    // Add new inputs until TX will have enough funds to cover both
    // minimum post cost and fee
    tx.input(unspent);
    account._toSign.push(tx.inputs[tx.inputs.length - 1]);
    lastAdded++;
    return tx.funds('in').cmp(total) < 0;
  }

  // Add dummy output (for `left`) to calculate maximum TX size
  var change;
  if (this.options.change === 'new') {
    change = this.createAccount();
  } else if (this.options.change === 'random') {
    var tried = [];
    for (;;) {
      change = this.accounts[(this.accounts.length - 1) * Math.random() | 0];
      // Try not to send change to the same address as the real outputs.
      if (this.accounts.length > 1 && change.ownOutput(tx)) {
        if (tried.length === this.accounts.length) {
          change = this.account;
          break;
        }
        if (!~tried.indexOf(change)) {
          tried.push(change);
        }
        continue;
      }
      break;
    }
  } else {
    change = this.account;
  }
  tx.out(change, new bn(0));

  for (var i = 0; i < this.accounts.length; i++) {
    account = this.accounts[i];
    account._toSign = [];
  }

  for (var i = 0; i < this.accounts.length; i++) {
    account = this.accounts[i];

    if (from && account !== from) {
      continue;
    }

    lastAdded = 0;

    // Transfer `total` funds maximum
    var unspent = account.unspent();
    if (!unspent.length) continue;
    unspent.every(addInput, account);

    fee = 1;
    // Change fee value if it is more than 1024 bytes
    // (10000 satoshi for every 1024 bytes)
    do {
      // Calculate maximum possible size after signing
      var byteSize = tx.maxSize();

      var addFee = Math.ceil(byteSize / 1024) - fee;
      total.iadd(new bn(addFee * account.fee));
      fee += addFee;

      // Failed to get enough funds, add more inputs
      if (tx.funds('in').cmp(total) < 0)
        unspent.slice(lastAdded).every(addInput, account);
    } while (tx.funds('in').cmp(total) < 0 && lastAdded < unspent.length);

    // Still failing to get enough funds, notify caller
    if (tx.funds('in').cmp(total) >= 0) {
      // How much money is left after sending outputs
      var left = tx.funds('in').sub(total);

      // Not enough money, transfer everything to owner
      if (left.cmpn(account.dust) < 0) {
        // NOTE: that account output is either `postCost` or one of the `dust` values
        tx.outputs[tx.outputs.length - 2].value.iadd(left);
        left = new bn(0);
      }

      // Change or remove last output if there is some money left
      if (left.cmpn(0) === 0)
        tx.outputs.pop();
      else
        tx.outputs[tx.outputs.length - 1].value = left;

      break;
    }

    if (from) {
      var err = new Error('Not enough funds');
      err.minBalance = total;
      return setImmediate(function() {
        return callback(err);
      });
    }
  }

  // NOTE: the offset has to be passed into
  // wallet.sign() to keep track of the input index.
  var off = 0;
  for (var i = 0; i < this.accounts.length; i++) {
    account = this.accounts[i];
    if (!account._toSign.length) {
      delete account._toSign;
      continue;
    }
    account.sign(tx, 'all', account._toSign, off);
    off += account._toSign.length;
    delete account._toSign;
  }

  if (this.options.change === 'new' && !change.ownOutput(tx)) {
    this.deleteAccount(change.getAddress());
  }

  if (tx.funds('in').cmp(total) < 0) {
    return callback(new Error('Not enough funds.'));
  }

  if (!tx.verify()) {
    return callback(new Error('TX does not verify.'));
  }

  return setImmediate(function() {
    return callback(null, tx);
  });
};

Coined.prototype.ownInput = function(tx, index) {
  return this.accounts.filter(function(account) {
    return account.ownInput(tx, index);
  })[0];
};

Coined.prototype.ownOutput = function(tx, index) {
  return this.accounts.filter(function(account) {
    return account.ownOutput(tx, index);
  })[0];
};

Coined.prototype.ownTX = function(tx, index) {
  return this.ownInput(tx, index) || this.ownOutput(tx, index);
};

Coined.prototype.setFee = function(fee) {
  var self = this;
  this.fee = +fee.toString(10);
  this.accounts.forEach(function(account) {
    account.fee = self.fee;
  });
};

Coined.prototype.getAddress = function() {
  return this.account.getAddress();
};

Coined.prototype.sign = function(msg, account) {
  if (this.crypto && this.encrypted) {
    return this._error('Encrypted.');
  }
  var account = account || this.account;
  sig = bcoin.ecdsa.sign(msg, account.key).toDER('hex');
  sig = new Buffer(sig, 'hex').toString('base64');
  return sig;
};

Coined.prototype.verify = function(msg, sig, account) {
  if (this.crypto && this.encrypted) {
    return this._error('Encrypted.');
  }
  var account = account || this.account;
  sig = new Buffer(sig, 'base64').toString('hex');
  return bcoin.ecdsa.verify(msg, sig, account.key);
};

Coined.prototype.getInputKeys = function(input) {
  if (!input || !input.script) return;

  var script = input.script;

  // if (script.length === 2
  //     && Array.isArray(script[0])
  //     && Array.isArray(script[1])) {
  if (bcoin.script.isPubkeyhashInput(script)) {
    var scriptSig = utils.toHex(script[0]);
    var pubKey = script[1];
    var hash = utils.ripesha(pubKey);
    var addr = bcoin.wallet.hash2addr(hash);
    return {
      sig: scriptSig,
      pub: pubKey,
      hash: hash,
      addr: addr
    };
  }
};

Coined.prototype.getOutputKeys = function(output) {
  if (!output || !output.script) return;

  var script = output.script;

  // if (script.length === 5
  //     && script[0] === 'dup'
  //     && script[1] === 'hash160'
  //     && Array.isArray(script[2])
  //     && script[3] === 'eqverify'
  //     && script[4] === 'checksig') {
  if (bcoin.script.isPubkeyhash(script)) {
    var hash = script[2];
    var addr = bcoin.wallet.hash2addr(hash);
    return {
      hash: hash,
      addr: addr
    };
  }

  // if (bcoin.script.isSimplePubkeyhash(script)) {
  if (script.length === 2
      && Array.isArray(script[0])
      && script[1] === 'checksig') {
    var pubKey = script[0];
    var hash = utils.ripesha(pubKey);
    var addr = bcoin.wallet.hash2addr(hash);
    return {
      pub: pubKey,
      hash: hash,
      addr: addr
    };
  }

  var pubKeys;
  if (pubKeys = bcoin.script.isMultisig(script)) {
    var pubKey = pubKeys[0];
    var hash = utils.ripesha(pubKeys[0]);
    var addr = bcoin.wallet.hash2addr(hash);
    return {
      pub: pubKey,
      hash: hash,
      addr: addr,
      pubs: pubKeys,
      multi: true
    };
  }
};

Coined.prototype.getScriptPubKey = function(output) {
  // Derive scriptPubKey notation from output Script
  var script = output.script
    , code = []
    , i
    , val
    , op;

  for (i = 0; i < script.length; i++) {
    val = script[i];
    if (Array.isArray(val)) {
      code.push(utils.toHex(val));
    } else if (typeof val === 'number') {
      op = bcoin.protocol.constants.opcodesByVal[val] || '';
      code.push('OP_' + op.toUpperCase());
    } else if (typeof val === 'string') {
      code.push('OP_' + val.toUpperCase());
    }
  }

  code = code.join(' ');

  return code;
};

Coined.prototype.getCoinbase = function(tx) {
  var coinbase = utils.toHex(tx.inputs[0].script[0])
    , scriptPubKey = utils.toHex(tx.inputs[0].script[1])
    , scriptSig_ = tx.inputs[0].script.slice(2)
    , scriptSig = util.toHex(tx.inputs[0].script[2]);

  var start = coinbase[4]
    + (coinbase[5] - 1)
    + coinbase.slice(0, 4)
    + coinbase.slice(4, 6)
    + coinbase.slice(4, 6);

  var mid = coinbase[5] + coinbase[0];

  var coinbaseNotation = start + scriptPubKey + mid + scriptSig
    , decodedSig = String.fromCharCode.apply(String, tx.inputs[0].script[2]);

  return {
    coinbase: coinbaseNotation,
    decoded: decodedSig
  };
};

/**
 * Methods
 */

// bt/block/[block]
// bt/full-block/[block]
Coined.prototype.saveBlock = function(block, full, callback) {
  if (!callback) {
    callback = full;
    full = null;
  }

  var self = this;
  var prefix = 'bt/block/';
  var hash = block.hash('hex');
  var txs = block.txs ? block.txs.slice() : [];
  var errs = [];

  if (!full) {
    if (block.subtype == 'block') {
      block.txs = [];
    } else if (block.subtype === 'merkleblock') {
      block.hashes = [];
      block.flags = [];
      block.txs = [];
      block.subtype = 'block';
    }
  } else {
    prefix = 'bt/full-block/';
  }

  return this.db.put(prefix + hash, block.toJSON(), function(err) {
    if (err) return callback(err);
    return async.forEach(txs, function(tx, next) {
      return self.saveTX(tx, function(err) {
        if (err) {
          errs.push(err);
          return next();
        }
        return next();
      });
    }, function() {
      var err = errs.length ? new Error(errs.join('\n')) : null;
      if (err) return callback(err);
      return callback();
    });
  });
};

// bt/tx/[tx]
Coined.prototype.saveTX = function(tx, callback) {
  var self = this;
  var prefix = 'bt/tx/';
  var hash = tx.hash('hex');
  var suffix = '';

  if (!tx.block) {
    suffix = '/' + '[unconfirmed]';
  }

  return this.db.put(prefix + hash + suffix, tx.toJSON(), function(err1) {
    return self._saveBlockTX(tx, function(err2) {
      return self._saveAddrTX(tx, function(err3) {
        if (err1) return callback(err1);
        if (err2) return callback(err2);
        if (err3) return callback(err3);
        return callback();
      });
    });
  });
};

// bt/block-tx/[block]/[tx]
Coined.prototype._saveBlockTX = function(tx, callback) {
  var self = this
    , hash = tx.hash('hex')
    , prefix = 'bt/block-tx/'
    , block = tx.block || '[unconfirmed]';

  return self.db.put(prefix + block + '/' + hash, {}, callback);
};

// bt/addr-tx/[addr]/[block]/[tx]
Coined.prototype._saveAddrTX = function(tx, callback) {
  var self = this
    , hash = tx.hash('hex')
    , ptx = this.parseTX(tx)
    , prefix = 'bt/addr-tx/'
    , block = tx.block || '[unconfirmed]'
    , errs = []
    , addrs;

  addrs = ptx.inputs.addresses.slice();

  ptx.outputs.addresses.forEach(function(addr) {
    if (!~addrs.indexOf(addr)) {
      addrs.push(addr);
    }
  });

  return async.forEach(addrs, function(addr, next) {
    return self.db.put(prefix + addr + '/' + block + '/' + hash, {}, function(err) {
      if (err) {
        errs.push(err);
        return next();
      }
      return next();
    });
  }, function() {
    var err = errs.length ? new Error(errs.join('\n')) : null;
    if (err) return callback(err);
    return callback();
  });
};

Coined.prototype.getBlock = function(hash, callback) {
  var self = this;
  var prefix = 'bt/block/';
  return this.db.get(prefix + hash, function(err, data) {
    if (err) return callback(err);

    var block = bcoin.block.fromJSON(data);
    block.txs = [];

    return self.db.createKeyStream({
      start: 'bt/block-tx/' + hash + '/',
      end: 'bt/block-tx/' + hash + '/z'
    }).on('data', function(key) {
      var parts = key.split('/');
      var tx = parts[3];
      return self.getTX(tx, function(err, tx) {
        if (err) return;
        block.txs.push(tx);
      });
    }).on('error', function(err) {
      return callback(err);
    }).on('end', function() {
      bcoin.block.call(block, block, 'block');
      return callback(null, block);
    });
  });
};

Coined.prototype.getUnconfirmedTransactions = function(calback) {
  var self = this
    , txs = [];

  var stream = this.db.createKeyStream({
    start: 'bt/block-tx/[unconfirmed]/',
    end: 'bt/block-tx/[unconfirmed]/z'
  }).on('data', function(key) {
    var parts = key.split('/');
    var tx = parts[3];
    return self.getTX(tx, function(err, tx) {
      if (err) return self._error(err);
      if (callback) {
        txs.push(tx);
      } else {
        stream.emit('tx', tx);
      }
    });
  }).on('error', function(err) {
    if (callback) {
      return callback(err);
    } else {
      self._error(err);
    }
  }).on('end', function() {
    if (!callback) return;
    return callback(null, txs);
  });

  return stream;
};

Coined.prototype.getTransaction =
Coined.prototype.getTX = function(hash, block, callback) {
  var self = this;
  var prefix = 'bt/tx/';

  if (!callback) {
    callback = block;
    block = null;
  }

  return this.db.get(prefix + hash, function(err, data) {
    if (err) return callback(err);

    var tx = bcoin.tx.fromJSON(data);

    return callback(null, tx);
  });
};

Coined.prototype.getLatest = function(num, callback) {
  var self = this;
  var blocks = [];
  var latest = this.pool.chain.index.hashes.slice(-num);
  return utils.forEach(latest, function(hash, next) {
    return self.getBlock(hash, function(err, block) {
      if (err) {
        self._error('Block not found: %s.', hash);
      }
      if (block) blocks.push(block);
      return next();
    });
  }, function() {
    return callback(null, blocks);
  });
};

Coined.prototype.getLastBlock = function(callback) {
  var hashes = this.pool.chain.index.hashes;
  return this.getBlock(hashes[hashes.length-1], callback);
};

Coined.prototype.getBlockHeight = function(callback) {
  var heights = this.pool.chain.index.heights;
  return callback(null, heights[heights.length-1]);
};

Coined.prototype.getAddressTransactions = function(address, callback) {
  var self = this;
  var txs = [];
  return this.db.createKeyStream({
    start: 'bt/addr-tx/' + address + '/',
    end: 'bt/addr-tx/' + address + '/z'
  }).on('data', function(key) {
    var parts = key.split('/');
    var tx = parts[4];
    return self.getTX(tx, function(err, tx) {
      if (err) return self._error(err);
      txs.push(tx);
    });
  }).on('error', function(err) {
    return callback(err);
  }).on('end', function() {
    return callback(null, {
      address: address,
      txs: txs
    });
  });
};

Coined.prototype.search = function(range, callback) {
  var self = this;
  var last = -1;
  var search = this.pool.search(range);

  search.on('progress', function(current, total) {
    if (current !== last) {
      self._log('Search progressing: %d/%d.', current, total);
      last = current;
    }
  });

  search.on('end', function(empty) {
    self._log('Search ended.');
    if (!callback) return;
    return callback();
  });

  return search;
};

Coined.prototype.parseBlock = function(block) {
  var self = this;

  if (!block || typeof block !== 'object' || !block.verify || block.rhash) {
    return block;
  }

  if (!block.verify()) {
    return block;
  }

  var hash = block.hash('hex');

  // START CONSTRUCTOR
  // var pblock = utils.deepMerge({}, block);
  // var pblock = block;
  var pblock = {};
  pblock.type = 'block';
  pblock.subtype = block.subtype;
  pblock.version = block.version;
  pblock.prevBlock = block.prevBlock;
  pblock.merkleRoot = block.merkleRoot;
  pblock.ts = block.ts;
  pblock.bits = block.bits;
  pblock.nonce = block.nonce;
  pblock.totalTX = block.totalTX;
  pblock.hashes = block.hashes.slice();
  pblock.flags = block.flags.slice();

  pblock.tx = block.tx.slice();
  pblock.invalid = block.invalid;

  if (pblock.subtype === 'block') {
    pblock.txs = block.txs.slice();
    // pblock.txs = pblock.txs.map(function(tx) {
    //   return self.parseTX(tx);
    // });
    pblock.merkleTree = pblock.merkleTree.slice();
  }

  pblock._hash = null;
  // END CONSTRUCTOR

  pblock._hash = hash;
  pblock.rhash = utils.revHex(hash);

  var index = this.pool.chain.index;

  var i = index.hashes.indexOf(hash);
  var height = index.heights[i];
  pblock.height = height || -1;

  if (pblock.height === -1) {
    var prevProbe = this.pool.chain._probeIndex(pblock.prevBlock, pblock.ts);
    if (prevProbe) {
      // this.pool.chain._addIndex(pblock._hash, pblock.ts, prevProbe.height + 1);
      pblock.height = prevProbe.height + 1;
    }
  }

  pblock.verified = true;

  if (pblock.height !== -1) {
    var currentHeight = index.heights[index.heights.length-1];
    pblock.confirmations = currentHeight - pblock.height + 1;
  } else {
    pblock.confirmations = -1;
  }

  if (pblock.ts) {
    pblock.date = new Date(pblock.ts * 1000).toISOString()
  }

  utils.hideProperty(pblock, '_raw');

  utils.hideProperty(block, 'd', pblock);
  utils.hideProperty(pblock, 'o', block);

  return pblock;
};

Coined.prototype.parseTX = function(tx, block) {
  var self = this;

  if (!tx || typeof tx !== 'object' || !tx.verify || tx.rhash) {
    if (tx && tx.rhash && block && block.confirmations && !tx.confirmations) {
      tx.confirmations = block.confirmations;
      tx.unconfirmed = true;
    }
    return tx;
  }

  var hash = tx.hash('hex');

  // START CONSTRUCTOR
  // var ptx = utils.deepMerge({}, tx);
  // var ptx = tx;
  var ptx = {};

  ptx.type = 'tx';

  ptx.version = tx.version;
  ptx.inputs = [];
  ptx.outputs = [];
  ptx.lock = tx.lock;
  ptx.ts = tx.ts;
  ptx.block = tx.block;

  ptx._hash = null;
  ptx._raw = tx._raw || null;

  tx.inputs.forEach(function(input) {
    ptx.inputs.push({
      out: {
        tx: null,
        // tx: self.parseTX(input.out.tx),
        hash: input.out.hash,
        index: input.out.index
      },
      script: input.script ? input.script.slice() : [],
      seq: input.seq
    });
  });

  tx.outputs.forEach(function(output) {
    ptx.outputs.push({
      value: output.value ? output.value.clone() : new bn(0),
      script: output.script ? output.script.slice() : []
    });
  });

  if (!tx.ts && block) {
    ptx.ts = block.ts;
    ptx.block = block._hash || block.hash('hex');
  }

  ptx.ps = ptx.ps;
  // END CONSTRUCTOR

  ptx._hash = hash;
  ptx.rhash = utils.revHex(hash);
  ptx.rblock = ptx.block ? utils.revHex(ptx.block) : null;
  ptx.verified = tx.verify();

  // Derive input addresses and sig code from input Script
  ptx.inputs.addresses = [];
  ptx.inputs.forEach(function(input, i) {
    var keys = self.getInputKeys(input);
    if (!keys) return;

    ptx.inputs.addresses.push(keys.addr);
    input.out.scriptSig = keys.sig;
    input.out.address = keys.addr;

    var prev = tx.inputs[i].out.tx;

    if (!prev) {
      prev = self.accounts.map(function(account) {
        return account.tx._all[input.out.hash];
      }).filter(Boolean)[0];
    }

    input.out.value = prev
      ? prev.outputs[input.out.index].value.clone()
      : null;
  });

  // Grab other info from inputs
  ptx.inputs.forEach(function(input) {
    var previous = input.out.hash;
    input.out.rhash = utils.revHex(previous);

    // TODO: Find previous and the addresses outputs
    // there. Check this `index` in the previous transaction's
    // outputs array.
    if (ptx.inputs.length === 0 && +input.out.hash === 0) {
      ptx.coinbase = true;
    }

    if (ptx.lock > 0 && input.seq !== 0xffffffff) {
      ptx.finalBlockHeight = input.seq;
      ptx.finalTimestamp = ptx.lock;
    }
  });

  // Derive output addresses from output Script
  ptx.outputs.addresses = [];
  ptx.outputs.forEach(function(output) {
    var keys = self.getOutputKeys(output);
    if (!keys) return;
    ptx.outputs.addresses.push(keys.addr);
    output.address = keys.addr;
  });

  // Derive scriptPubKey notation from output Script
  ptx.outputs.scriptPubKeys = [];
  ptx.outputs.forEach(function(output) {
    var code = self.getScriptPubKey(output);
    if (!code) return;
    ptx.outputs.scriptPubKeys.push(code);
    output.scriptPubKey = code;
  });

  // Convert output values to BTC
  ptx.outputs.bvalues = [];
  ptx.outputs.total = new bn(0);
  ptx.outputs.forEach(function(output) {
    ptx.outputs.total = ptx.outputs.total.add(output.value);
    var bvalue = utils.toBTC(output.value);
    ptx.outputs.bvalues.push(bvalue);
    output.bvalue = bvalue;
  });
  ptx.outputs.btotal = utils.toBTC(ptx.outputs.total);

  // Grab confirmations from block
  if (!ptx.block || !ptx.verified) {
    ptx.confirmations = 0;
    ptx.unconfirmed = true;
  } else if (block && block.confirmations) {
    ptx.confirmations = block.confirmations;
    ptx.unconfirmed = false;
  } else {
    ptx.confirmations = 1;
    ptx.unconfirmed = false;
  }

  // Just initialize balance and fee (unknown)
  ptx.balance = ptx.outputs.total.clone();
  ptx.bbalance = utils.toBTC(ptx.balance);
  ptx.fee = new bn(0);
  ptx.bfee = utils.toBTC(ptx.fee);
  ptx.feeUncertain = true;

  // Estimate how much the sender was actually sending. This is really only
  // easy if there are two senders or less (as far as I know).
  if (ptx.outputs.length <= 2) {
    ptx.estimated = ptx.outputs[0].value.clone();
    ptx.bestimated = utils.toBTC(ptx.estimated);
    ptx.sender = ptx.inputs.addresses[0];
    ptx.recipient = ptx.outputs.addresses[0];
  } else {
    ptx.estimated = ptx.balance.clone();
    ptx.bestimated = utils.toBTC(ptx.balance);
    ptx.estimateUncertain = true;
    ptx.sender = null;
    ptx.recipient = null;
  }

  // Timestamp
  if (ptx.ts) {
    ptx.date = new Date(ptx.ts * 1000).toISOString()
  }

  if (ptx.coinbase) {
    delete ptx.coinbase;
    ptx.coinbase = true;
  }

  ptx.inputs.forEach(function(input) {
    utils.hideProperty(input, 'script');
  });

  ptx.outputs.forEach(function(output) {
    utils.hideProperty(output, 'script');
  });

  utils.hideProperty(ptx, '_raw');

  utils.hideProperty(tx, 'd', ptx);
  utils.hideProperty(ptx, 'o', tx);

  return ptx;
};

Coined.prototype.findBlock = function(hash, callback) {
  var self = this;
  this.pool.on('block', function callee(block) {
    if (block.hash('hex') === hash) {
      self.pool.removeListener('block', callee);
      clearInterval(timer);
      return callback(null, block);
    }
  });
  var timer = setInterval(function callee() {
    if (!self.pool.peers.load) {
      self.pool._addLoader();
    }
    if (self.pool.peers.load) {
      self.pool.peers.load.loadBlocks([hash], 0);
      self.pool.peers.load.getData([{ type: 'block', hash: hash }]);
    }
    for (var i = 0; i < self.pool.peers.block.length; i++) {
      self.pool.peers.block[i].loadBlocks([hash], 0);
      self.pool.peers.block[i].getData([{ type: 'block', hash: hash }]);
    }
    return callee;
  }(), 5 * 1000);
};

Coined.prototype.downloadBlockchain = function(callback) {
  var self = this;

  var counts = {
    blocks: {},
    interval: 250
  };

  this.pool.on('block', function(block, peer) {
    var ip = peer.socket && peer.socket.remoteAddress || '0.0.0.0';
    var count = counts.blocks;
    if (!count[ip]) count[ip] = 0;
    if (++count[ip] % counts.interval === 0) {
      self._log('Found %d more blocks. Total: %d. (%s)',
        counts.interval, count[ip], ip);
      self._log('Total blocks: %s', self.pool.chain.index.hashes.length);
      self._log('Total orphans: %s', Object.keys(self.pool.chain.orphan.map).length);
    }
    // return self.saveBlock(block, function(err) {
    //   if (err) return self._error(err);
    // });
  });

  var feed = bcoin.protocol.parser.prototype.feed;
  bcoin.protocol.parser.prototype.feed = function(chunk) {
    var self = this;
    setImmediate(function() {
      feed.call(self, chunk);
    });
  };
};

/**
 * Hooks
 */

bcoin.chain.prototype.isFull = function isFull() {
  // < 10m since last block
  if (this.request.count)
    return false;

  var delta = (+new Date() / 1000) - this.index.ts[this.index.ts.length - 1];
  return delta < 10 * 60;
};

/**
 * Helpers
 */

// Copyright 2010 James Halliday (mail@substack.net)
// This project is free software released under the MIT/X11 license.

function mkdirp(dir, made) {
  var mode = 0777 & (~process.umask());
  if (!made) made = null;

  dir = path.resolve(dir);

  try {
    fs.mkdirSync(dir, mode);
    made = made || dir;
  } catch (err0) {
    switch (err0.code) {
      case 'ENOENT':
        made = mkdirp(path.dirname(dir), made);
        mkdirp(dir, made);
        break;
      default:
        var stat;
        try {
          stat = fs.statSync(dir);
        } catch (err1) {
          throw err0;
        }
        if (!stat.isDirectory()) throw err0;
        break;
    }
  }

  return made;
}

function cleanup(p) {
  // If we were a directory:
  try {
    fs.readdirSync(p).forEach(function(file) {
      fs.unlinkSync(path.resolve(p, file));
    });
  } catch (e) {
    ;
  }

  try {
    fs.rmdirSync(p);
  } catch (e) {
    ;
  }

  // If we were a file:
  try {
    fs.unlinkSync(p);
    fs.unlinkSync(p + '.idx');
  } catch (e) {
    ;
  }

  // Remove outer directory:
  try {
    fs.rmdirSync(path.resolve(p, '..'));
  } catch (e) {
    ;
  }
}

/**
 * Exports
 */

exports = Coined;
exports.protocol = protocol;
exports.utils = utils;
exports.bcoin = bcoin;
exports.bn = bn;
exports.async = async;

module.exports = exports;
