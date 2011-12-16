#!/usr/bin/env node

const
http = require('http'),
https = require('https'),
jwk = require('jwcrypto/jwk.js'),
jwt = require('jwcrypto/jwt.js'),
vep = require('jwcrypto/vep.js'),
querystring = require('querystring'),
urlparse = require('urlparse');

var argv = require('optimist')
.usage('Get an assertion and bounce it off of mozillians\nUsage: $0')
.alias('h', 'help')
.describe('h', 'display this usage message')
.alias('s', 'server')
.describe('s', 'server url to stage on')
.default('s', 'https://browserid.org')
.alias('d', 'domain')
.describe('d', 'domain that assertion is generated for')
.default('d', "http://50-57-227-85.static.cloud-ips.com")
.alias('e', 'email')
.describe('e', 'email address to use')
.demand('e')
.alias('i', 'iterations')
.describe('i', 'the number of distinct assertions to bounce off the server')
.default('i', 10)
.demand('e')
.alias('p', 'password')
.describe('p', 'password')
.demand('p');

var args = argv.argv;

if (args.h) {
  argv.showHelp();
  process.exit(0);
}

try {
  var url = urlparse(args.d).originOnly();
} catch(e) {
  process.stderr.write("Invalid url: " + e.toString() + "\n");
  pocess.exit(1);
}

function genAssertion(cert, secretKey) {
  // XXX: expiration date should really be based on current server time.
  var expirationDate = new Date(new Date().getTime() + (2 * 60 * 1000));
  var tok = new jwt.JWT(null, expirationDate, args.d);
  var assertion = vep.bundleCertsAndAssertion([cert], tok.sign(secretKey));

  return {
    audience: args.d,
    assertion: assertion,
    expirationDate: expirationDate
  };
}

function sendAssertion(assertion) {
  var body = querystring.stringify({
    assertion: assertion,
    mode: 'register'
  });

  var method = url.scheme === 'http' ? http : https;

  var req = method.request({
    host: url.host,
    path: '/en-US/browserid-login',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': body.length
    },
    method: "POST",
    agent: false
  }, function(res) {
    console.log('CODE:', res.statusCode);
    console.log('location:', res.headers['location']);
    var body = "";
    res.on('data', function(chunk) {
      body += chunk;
    });
    res.on('end', function() {
      console.log(body);
    });
  }).on('error', function(e) {
    console.log("Got error: " + e.message);
    process.exit(1);
  });

  req.write(body);
  req.end();
}

const
wcli = require("./lib/wsapi_client.js");

var args = argv.argv;

// request context (cookie jar, etc)
var ctx = {};

// generate a keypair
var keypair = jwk.KeyPair.generate("DS", 256)

var cfg = { browserid: args.s };

wcli.post(cfg, '/wsapi/authenticate_user', ctx, {
  email: args.e,
  pass: args.p
}, function(response) {
  wcli.post(cfg, '/wsapi/cert_key', ctx, {
    email: args.e,
    pubkey: keypair.publicKey.serialize()
  }, function(resp) {
    var cert = resp.body;
    for (var i = 0; i < args.i; i++) {
      var assertion = genAssertion(cert, keypair.secretKey)
      sendAssertion(assertion.assertion);
    }
  });
});
