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

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use('samlp', new Strategy({
    path: '/callback',
    realm: 'https://auth0-dev-ed.my.salesforce.com',
    identityProviderUrl: identityProviderUrl,
    thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
    recipientUrl: 'https://auth0-dev-ed.my.salesforce.com',
    destinationUrl: 'https://auth0-dev-ed.my.salesforce.com'
  }, function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-http-post', new Strategy({
    protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    path: '/callback',
    realm: 'https://auth0-dev-ed.my.salesforce.com',
    identityProviderUrl: identityProviderUrl,
    thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309']
  }, function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-custom-request-template', new Strategy({
    path: '/callback',
    realm: 'https://auth0-dev-ed.my.salesforce.com',
    identityProviderUrl: identityProviderUrl,
    thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
    requestTemplate: '<AuthnRequest Issuertico="@@Issuer@@" Version="3.0" Protocol="@@ProtocolBinding@@" Foo="@@Foo.Test@@"></AuthnRequest>',
    requestContext: {
      Foo: {
        Test: 123
      }
    }
  }, function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-idpurl-with-querystring', new Strategy(
  {
    path: '/callback',
    realm: 'https://auth0-dev-ed.my.salesforce.com',
    identityProviderUrl: identityProviderUrl + '?foo=bar',
    thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309']
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signedrequest-without-deflate', new Strategy({
    path: '/callback',
    realm: 'https://auth0-dev-ed.my.salesforce.com',
    identityProviderUrl: identityProviderUrl,
    thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
    signingKey: {
      key: fs.readFileSync(path.join(__dirname, '../test-auth0.key')),
      cert: fs.readFileSync(path.join(__dirname, '../test-auth0.pem')),
    },
    deflate: false
  }, function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signedrequest-with-deflate', new Strategy({
    path: '/callback',
    realm: 'https://auth0-dev-ed.my.salesforce.com',
    identityProviderUrl: identityProviderUrl,
    thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
    signingKey: {
      key: fs.readFileSync(path.join(__dirname, '../test-auth0.key')),
      cert: fs.readFileSync(path.join(__dirname, '../test-auth0.pem')),
    },
    deflate: true
  }, function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signedrequest-post', new Strategy({
    protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    path: '/callback',
    realm: 'https://auth0-dev-ed.my.salesforce.com',
    identityProviderUrl: identityProviderUrl,
    thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
    signingKey: {
      key: fs.readFileSync(path.join(__dirname, '../test-auth0.key')),
      cert: fs.readFileSync(path.join(__dirname, '../test-auth0.pem')),
    },
    deflate: false
  }, function(profile, done) {
    return done(null, profile);
  })
);


passport.use('samlp-signedresponse', new Strategy(
  {
    path: '/callback',
    realm: 'https://auth0-dev-ed.my.salesforce.com',
    identityProviderUrl: identityProviderUrl,
    thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
    recipientUrl: 'https://auth0-dev-ed.my.salesforce.com',
    destinationUrl: 'https://auth0-dev-ed.my.salesforce.com'
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signedresponse-invalidcert', new Strategy(
  {
    path: '/callback',
    realm: 'urn:fixture-test',
    identityProviderUrl: identityProviderUrl,
    thumbprints: ['11111111111111111a5b93a43572eb2376fed309'],
    recipientUrl: 'https://auth0-dev-ed.my.salesforce.com',
    destinationUrl: 'https://auth0-dev-ed.my.salesforce.com'
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-invalidcert', new Strategy(
  {
    path: '/callback',
    realm: 'urn:fixture-test',
    identityProviderUrl: identityProviderUrl,
    thumbprints: ['11111111111111111a5b93a43572eb2376fed309']
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-signedresponse-signedassertion', new Strategy(
  {
    path: '/callback',
    realm: 'urn:auth0:login-dev3',
    thumbprints: ['C9ED4DFB07CAF13FC21E0FEC1572047EB8A7A4CB'],
    destinationUrl: 'https://login-dev3.auth0.com:3000/login/callback',
    recipientUrl: 'https://login-dev3.auth0.com:3000/login/callback',
    checkExpiration: false // we are using a precomputed assertion generated from a sample idp feide
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-ping', new Strategy(
  {
    path: '/callback',
    realm: 'urn:auth0:login-dev3',
    thumbprints: ['44340220770a348444be34970939cff8a2d74f08'],
    destinationUrl: 'https://login-dev3.auth0.com:3000/login/callback',
    recipientUrl: 'https://login-dev3.auth0.com:3000/login/callback',
    checkExpiration: false // we are using a precomputed assertion generated from a sample idp feide
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-okta', new Strategy(
  {
    path: '/callback',
    realm: 'https://auth0145.auth0.com',
    thumbprints: ['a0c7dbb790e3476d3c5dd236f9f2060b1fd6e253'],
    destinationUrl: 'https://auth0145.auth0.com',
    recipientUrl: 'https://auth0145.auth0.com',
    checkExpiration: false // we are using a precomputed assertion generated from a sample idp feide
  },
  function(profile, done) {
    return done(null, profile);
  })
);

function pemToCert(pem) {
  // if certificate doesn't have ---- begin cert --- just return the pem
  if (!/-----BEGIN CERTIFICATE-----/.test(pem.toString())) {
    return pem.toString();
  }

  var cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(pem.toString());
  if (cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }

  return null;
}

passport.use('samlp-with-utf8', new Strategy(
  {
    path: '/callback',
    thumbprints: ['119B9E027959CDB7C662CFD075D9E2EF384E445F'],
    decryptionKey: fs.readFileSync(path.join(__dirname, '../test-auth0.key')),
    recipientUrl: 'https://login0.myauth0.com/login/callback',
    destinationUrl: 'https://login0.myauth0.com/login/callback',
    checkExpiration: false, // we are using a precomputed assertion generated from a sample idp feide
    checkSPNameQualifier: false,
    checkAudience: false
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-with-ISO', new Strategy(
  {
    path: '/callback',
    cert: pemToCert(fs.readFileSync(path.join(__dirname, '../test-auth0.pem'))),
    checkExpiration: false, // we are using a precomputed assertion generated from a sample idp feide
    checkAudience: false,
    checkDestination: false,
    checkRecipient: false
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-with-ISO-explicit', new Strategy(
  {
    path: '/callback',
    cert: pemToCert(fs.readFileSync(path.join(__dirname, '../test-auth0.pem'))),
    checkExpiration: false, // we are using a precomputed assertion generated from a sample idp feide
    checkAudience: false,
    default_encoding: 'ISO-8859-1',
    checkDestination: false,
    checkRecipient: false
  },
  function(profile, done) {
    return done(null, profile);
  })
);

passport.use('samlp-with-dsig-at-root', new Strategy(
  {
    path: '/callback',
    checkExpiration: false, // we are using a precomputed assertion generated from a sample idp
    checkAudience: false,
    checkDestination: false,
    cert: pemToCert(fs.readFileSync(path.join(__dirname, '../test-auth0.pem')))
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
        key:                credentials.key,
        recipient:          'https://auth0-dev-ed.my.salesforce.com'
      }, module.exports.options))(req, res);
  });

  app.get('/login', passport.authenticate('samlp', { protocol: 'samlp', RelayState: relayState }));
  app.get('/login-http-post', passport.authenticate('samlp-http-post', { protocol: 'samlp', RelayState: relayState }));
  app.get('/login-idp-with-querystring', passport.authenticate('samlp-idpurl-with-querystring', { protocol: 'samlp', RelayState: relayState }));

  app.get('/login-signed-request-without-deflate', passport.authenticate('samlp-signedrequest-without-deflate', { protocol: 'samlp', RelayState: relayState }));
  app.get('/login-signed-request-post', passport.authenticate('samlp-signedrequest-post', { protocol: 'samlp', RelayState: relayState }));
  app.get('/login-signed-request-with-deflate', passport.authenticate('samlp-signedrequest-with-deflate', { protocol: 'samlp', RelayState: relayState }));

  app.get('/login-custom-request-template',
      passport.authenticate('samlp-custom-request-template', { protocol: 'samlp', RelayState: relayState }));

  app.post('/callback',
    function(req, res, next) {
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

  app.post('/callback/samlp-signedresponse-signedassertion',
    passport.authenticate('samlp-signedresponse-signedassertion', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-ping',
    passport.authenticate('samlp-ping', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-okta',
    passport.authenticate('samlp-okta', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-with-utf8',
    passport.authenticate('samlp-with-utf8', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-with-ISO',
    passport.authenticate('samlp-with-ISO', { protocol: 'samlp' }),
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-with-ISO-explicit',
  passport.authenticate('samlp-with-ISO-explicit', { protocol: 'samlp' }),
  function(req, res) {
    res.json(req.user);
  }
);

  app.post('/callback/samlp-with-invalid-xml',
    function (req, res, next) {
      passport.authenticate('samlp-with-utf8', { protocol: 'samlp' }, function(err, user, info) {
        res.send(400, { message: err.message });
      })(req, res, next);
    },
    function(req, res) {
      res.json(req.user);
    }
  );

  app.post('/callback/samlp-with-dsig-at-root',
    passport.authenticate('samlp-with-dsig-at-root', { protocol: 'samlp' }),
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
