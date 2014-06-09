/**
 * coined - a high-level wrapper around bcoin
 * Copyright (c) 2014, Christopher Jeffrey. (MIT Licensed)
 * https://github.com/chjj/coined
 */

var util = require('util')
  , bcoin = require('bcoin')
  , bn = require('bcoin/node_modules/bn.js')
  , crypto = require('crypto');

var setImmediate = typeof global.setImmediate !== 'function'
  ? process.nextTick.bind(proccess)
  : global.setImmediate;

var utils = exports;

utils.__proto__ = bcoin.utils;

utils.hash = function(type, data, enc) {
  return crypto
    .createHash(type)
    .update(data)
    .digest(enc || 'hex');
};

utils.sha1 = function(data) {
  return utils.hash('sha1', data, 'hex');
};

utils.merge = function(target) {
  var args = Array.prototype.slice.call(arguments, 1);
  args.forEach(function(obj) {
    Object.keys(obj).forEach(function(key) {
      target[key] = obj[key];
    });
  });
  return target;
};

utils.uniq = function(obj) {
  var out = [];
  for (var i = 0; i < obj.length; i++) {
    if (!~out.indexOf(obj[i])) {
      out.push(obj[i]);
    }
  }
  return out;
};

utils.inspect = function(obj, level) {
  return typeof obj !== 'string'
    ? util.inspect(obj, null, level || 2, true)
    : obj;
};

utils.print = function(msg) {
  return typeof msg === 'object'
    ? process.stdout.write(utils.inspect(msg) + '\n')
    : console.log.apply(console, arguments);
};

utils.printl = function(msg, level) {
  return process.stdout.write(utils.inspect(msg, level) + '\n');
};

utils.printc = function() {
  var args = Array.prototype.slice.call(arguments);
  args[0] = '\x1b[34m' + args[0] + '\x1b[m';
  return utils.print.apply(null, args);
};

utils.error = function() {
  var args = Array.prototype.slice.call(arguments);
  args[0] = '\x1b[31m' + args[0] + '\x1b[m';
  return utils.print.apply(null, args);
};

utils.serial = function(obj, iter, done) {
  var i = 0, l = obj.length;
  if (!l) return done();
  (function next() {
    if (i === l) return done();
    var j = i++;
    return setImmediate(function() {
      return iter(obj[j], next, j);
    });
  })();
};

utils.forEach = function(obj, iter, done) {
  var pending = obj.length;
  if (!pending) return done();
  function next() {
    --pending || done();
  }
  return obj.forEach(function(item, i) {
    return iter(item, next, i);
  });
};

utils.parallel = function(obj, done) {
  var keys = Object.keys(obj)
    , pending = keys.length
    , results = []
    , errs = [];

  function next(key, err, result) {
    if (err) {
      errs.push(err.message);
    } else {
      results[key] = result;
    }
    if (--pending) return;
    return errs.length
      ? done(new Error(errs.join('\n')))
      : done(null, results);
  }

  if (!pending) {
    return done(null, results);
  }

  return keys.forEach(function(key) {
    return obj[key](next.bind(null, key));
  });
};

utils.hideProperty = function(obj, key, value) {
  var value = value || obj[key];
  if (value) {
    delete obj[key];
    Object.defineProperty(obj, key, {
      value: value,
      enumerable: false,
      configurable: true
    });
  }
};

utils.fromBTC = function(btc) {
  return new bn(Math.floor(((+btc || 0) * 100000000)).toString(16), 16);
};

utils.ntoBTC = function(satoshi) {
  satoshi = new bn(Math.floor(+satoshi || 0).toString(16), 16);
  return bcoin.utils.toBTC(satoshi);
};

/**
 * Deep merge, shamelessly taken from jQuery
 */

utils.isObject = function(obj) {
  return obj && typeof obj === 'object' && !Array.isArray(obj);
};

utils.hasOwnProperty = function(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
};

utils.deepMerge = function() {
  var args = Array.prototype.slice.call(arguments);
  args.unshift(true);
  return utils._deepMerge.apply(utils, args);
};

utils._deepMerge = function merge() {
  var options
    , name
    , src
    , copy
    , copyIsArray
    , clone
    , target = arguments[0] || {}
    , i = 1
    , length = arguments.length
    , deep = false;

  // Handle a deep copy situation
  if (typeof target === 'boolean') {
    deep = target;

    // skip the boolean and the target
    target = arguments[i] || {};
    i++;
  }

  // Handle case when target is a string or something (possible in deep copy)
  if (typeof target !== 'object' && typeof target !== 'function') {
    target = {};
  }

  // extend jQuery itself if only one argument is passed
  if (i === length) {
    target = this;
    i--;
  }

  for (; i < length; i++) {
    // Only deal with non-null/undefined values
    if ((options = arguments[i]) != null) {
      // Extend the base object
      for (name in options) {
        src = target[name];
        copy = options[name];

        if (!utils.hasOwnProperty(options, name)) {
          continue;
        }

        // Prevent never-ending loop
        if (target === copy) {
          continue;
        }

        // Recurse if we're merging plain objects or arrays
        if (deep && copy && (utils.isObject(copy) || (copyIsArray = Array.isArray(copy)))) {
          // Handle bn.js:
          if (copy.ishln) {
            target[name] = copy.clone();
            continue;
          }

          if (copyIsArray) {
            copyIsArray = false;
            clone = src && Array.isArray(src) ? src : [];
          } else {
            clone = src && utils.isObject(src) ? src : {};
          }

          // Never move original objects, clone them
          target[name] = merge(deep, clone, copy);

        // Don't bring in undefined values
        } else if (copy !== undefined) {
          target[name] = copy;
        }
      }
    }
  }

  // Return the modified object
  return target;
};
