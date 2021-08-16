#!/usr/bin/env node
//npm install express body-parser and navigate to http://127.0.0.1:8080/index.html
var express = require('express');
var bodyParser = require('body-parser');
var crypto = require('crypto');

var app = express();
console.log(require('path').join( __dirname + '/../'));
app.use(express.static(require('path').join( __dirname + '/../')));

// Add simple logging middleware
app.use(function(req, res, next) {
  console.log(req.method + ' ' + req.originalUrl);
  next();
});

app.use(express.json());

app.use(bodyParser.urlencoded({
	extended: true
}));

app.listen(8080, '127.0.0.1', function () {
	console.log('Listening on 127.0.0.1:8080');
});

function hmac(key, string){
  const hmac = crypto.createHmac('sha256', key);
  hmac.end(string);
  return hmac.read();
}


function sign(stringToSign, dateString) {
  const timestamp = dateString.substr(0, 8);

  const dateKey = hmac('AWS4' + process.env.AWS_SECRET, timestamp);
  console.log('dateKey', dateKey);
  const dateRegionKey = hmac(dateKey, process.env.AWS_REGION);
  console.log('dateRegionKey', dateRegionKey);
  const dateRegionServiceKey = hmac(dateRegionKey, 's3');
  const signingKey = hmac(dateRegionServiceKey, 'aws4_request');

  var signature = hmac(signingKey, stringToSign).toString('hex');

	console.log('Created signature "' + signature + '" from ' + stringToSign);
  return signature;
}

app.use('/sign_auth', function (req, res) {

  const timestamp = req.query.datetime.substr(0, 8);

  const dateKey = hmac('AWS4' + process.env.AWS_SECRET, timestamp);
  const dateRegionKey = hmac(dateKey, process.env.AWS_REGION);
  const dateRegionServiceKey = hmac(dateRegionKey, 's3');
  const signingKey = hmac(dateRegionServiceKey, 'aws4_request');

  var signature = hmac(signingKey, req.query.to_sign).toString('hex');

	console.log('Created signature "' + signature + '" from ' + req.query.to_sign);
	res.send(signature);

  // ===========

  function hmac(key, string){
    const hmac = crypto.createHmac('sha256', key);
    hmac.end(string);
    return hmac.read();
  }
});

app.use('/backend_sign', function (req, res) {
  console.log(req.body);

  const { headersToSign, requestDate, canonicalRequest } = req.body;
  
  const requestSha256Hex = function () {
    return crypto.createHash('sha256').update(canonicalRequest).digest('hex');
  }

  const credentialString = function () {
    var credParts = [];

    credParts.push(requestDate.slice(0, 8));
    credParts.push(process.env.AWS_REGION);
    credParts.push('s3');
    credParts.push('aws4_request');
    return credParts.join('/');
  }

  const stringToSign = function () {
    var signParts = [];
    signParts.push('AWS4-HMAC-SHA256');
    signParts.push(requestDate);
    signParts.push(credentialString());
    signParts.push(requestSha256Hex());
    var result = signParts.join('\n');

    return result;
  };

  const authorizationString = function () {
    var authParts = [];

    var credentials = credentialString();
    authParts.push(['AWS4-HMAC-SHA256 Credential=', process.env.AWS_KEY_ID, '/', credentials].join(''));
    authParts.push('SignedHeaders=' + headersToSign);
    authParts.push('Signature=' + sign(stringToSign(), requestDate));

    return authParts.join(', ');
  }

  const authString = authorizationString();

  console.log('authorization string', authString);
  res.send(authString);
});

app.get('/session_token', function (req, res) {
  if (process.env.AWS_SESSION_TOKEN) {
    res.send(process.env.AWS_SESSION_TOKEN);
  } else {
    res.send();
  }
});

app.get('/index.html', function (req, res) {
	res.redirect(301, '/example/evaporate_example_awsv4_signature.html');
});
