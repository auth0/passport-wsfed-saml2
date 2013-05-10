var express = require('express');
var http = require('http');
var samlp = require('samlp');
var xtend = require('xtend');
var fs = require('fs');
var path = require('path');

var passport = require('passport');
var Strategy = require('../../lib/passport-wsfed-saml2').Strategy;

var identityProviderUrl = 'http://localhost:5051/samlp';
var relayState = 'somestate';

passport.use('samlp', new Strategy(
  {
    validateSignature: true,
    path: '/callback',
    realm: 'urn:fixture-test',
    identityProviderUrl: identityProviderUrl,
    thumbprint: '5ca6e1202eafc0a63a5b93a43572eb2376fed309'
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signedresponse', new Strategy(
  {
    validateSignature: false,
    validateResponse: true,
    path: '/callback',
    realm: 'urn:fixture-test',
    identityProviderUrl: identityProviderUrl,
    thumbprint: '5ca6e1202eafc0a63a5b93a43572eb2376fed309'
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signedresponse-invalidcert', new Strategy(
  {
    validateSignature: false,
    validateResponse: true,
    path: '/callback',
    realm: 'urn:fixture-test',
    identityProviderUrl: identityProviderUrl,
    thumbprint: '11111111111111111a5b93a43572eb2376fed309'
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-invalidcert', new Strategy(
  {
    validateSignature: true,
    validateResponse: false,
    path: '/callback',
    realm: 'urn:fixture-test',
    identityProviderUrl: identityProviderUrl,
    thumbprint: '11111111111111111a5b93a43572eb2376fed309'
  },
  function(profile, done) {
    return done(null, profile);
  })
);

var fakeUser = {
  id: '12345678',
  displayName: 'John Foo',
  name: {
    familyName: 'Foo',
    givenName: 'John'
  },
  emails: [
    {
      type: 'work',
      value: 'jfoo@gmail.com'
    }
  ]
};

var credentials = {
  cert:     fs.readFileSync(path.join(__dirname, '../test-auth0.pem')),
  key:      fs.readFileSync(path.join(__dirname, '../test-auth0.key'))
};

module.exports.options = {};

module.exports.start = function(options, callback){
  module.exports.options = options;
  if (typeof options === 'function') {
    callback = options;
    module.exports.options = {};
  }

  var app = express();

  app.configure(function(){
    this.use(express.bodyParser());
    this.use(passport.initialize());
    this.use(passport.session());
    this.use(function(req,res,next){
      req.user = fakeUser;
      next();
    });
  });

  function getPostURL (audience, samlRequestDom, req, callback) {
    callback(null, 'http://localhost:5051/callback');
  }

  //configure samlp middleware
  app.get('/samlp', function(req, res, next) { 
    samlp.auth(xtend({}, {
        issuer:             'urn:fixture-test',
        getPostURL:         getPostURL,
        cert:               credentials.cert,
        key:                credentials.key
      }, module.exports.options))(req, res);
  });

  app.get('/login', passport.authenticate('samlp', { protocol: 'samlp', RelayState: relayState }));

  app.post('/callback', 
    function(req, res, next) {
      //console.log('req.body');
      next();
    },
    passport.authenticate('samlp', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-signedresponse', 
    passport.authenticate('samlp-signedresponse', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-signedresponse-invalidcert', 
    passport.authenticate('samlp-signedresponse-invalidcert', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-invalidcert', 
    passport.authenticate('samlp-invalidcert', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  var server = http.createServer(app).listen(5051, callback);
  module.exports.close = server.close.bind(server);
};

module.exports.relayState = relayState;
module.exports.identityProviderUrl = identityProviderUrl;
module.exports.fakeUser = fakeUser;
module.exports.credentials = credentials;
