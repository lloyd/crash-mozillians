const http = require('http'),
https = require('https'),
querystring = require('querystring'),
wsapi = require('./wsapi_client.js'),
uuid = require('node-uuid');

function _parseCSRF(body) {
  var m = /.*csrfmiddlewaretoken' value='([^']*)'/.exec(body);
  if (m && m.length > 1) {
    return m[1];
  } else {
    console.error("Unable to parse CSRF token...");
    return "";
  }
}
var ctx = {};

exports.login = login = function login(assertion, url) {
  var method = url.scheme === 'http' ? http : https,
      homeBody = "";

  var req = method.request({
    host: url.host,
    path: '/en-US/?' + uuid.v4()
  }, function (res) {
    res.on('data', function (chunk) {
      homeBody += chunk;
    });
    res.on('end', function () {
      //console.info(homeBody);
      if (res.headers['set-cookie']) {
        wsapi.extractCookies(ctx, res);
      } else {
        console.error("Server didn't start a session.");
        console.log('res.headers', res.headers);
      }

      var csrf = _parseCSRF(homeBody);
      sendAssertion(ctx, csrf, assertion, method, url);
    });
  });
  req.end();
};

exports.sendAssertion = sendAssertion = function sendAssertion(ctx, csrf, assertion, method, url) {
  var body = querystring.stringify({
    assertion: assertion,
    mode: 'register',
    csrfmiddlewaretoken: csrf
  });

  var headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': body.length
  };
  wsapi.injectCookies(ctx, headers);
  var req = method.request({
    host: url.host,
    path: '/en-US/browserid-login',
    headers: headers,
    method: "POST"
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
};