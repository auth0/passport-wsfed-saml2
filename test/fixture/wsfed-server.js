var bodyParser = require('body-parser');
var express = require('express');
var http = require('http');
var wsfed = require('wsfed');
var xtend = require('xtend');
var fs = require('fs');
var path = require('path');

var passport = require('passport');
var Strategy = require('../../lib/passport-wsfed-saml2').Strategy;

passport.use(new Strategy(
  {
    path: '/callback',
    realm: 'urn:fixture-test',
    identityProviderUrl: 'http://localhost:5050/login',
    thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309']
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

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

module.exports.options = {};

module.exports.start = function(options, callback){
  module.exports.options = options;
  if (typeof options === 'function') {
    callback = options;
    module.exports.options = {};
  }

  var app = express();

  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(function(req,res,next){
    req.user = fakeUser;
    next();
  });

  function getPostURL (wtrealm, wreply, req, callback) {
    callback(null, 'http://localhost:5050/callback');
  }

  app.get('/login',
    wsfed.auth(xtend({}, {
      issuer:             'fixture-test',
      getPostURL:         getPostURL,
      cert:               credentials.cert,
      key:                credentials.key
  }, options)));

  app.post('/callback/wresult-with-invalid-xml',
    function (req, res, next) {
      passport.authenticate('wsfed-saml2', function(err, user, info) {
        res.status(400).json({ message: err.message });
      })(req, res, next);
    },
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback',
    passport.authenticate('wsfed-saml2'),
    function(req, res) {
      res.json(req.user);
    });

  var server = http.createServer(app).listen(5050, callback);
  module.exports.close = function(callback) {
    server.close.bind(server);
    callback();
  }
};

module.exports.fakeUser = fakeUser;
module.exports.credentials = credentials;
