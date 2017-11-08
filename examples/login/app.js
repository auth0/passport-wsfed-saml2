// var express = require('express')
//   , passport = require('passport')
//   , util = require('util')
//   , wsfedsaml2 = require('../../lib/passport-wsfed-saml2/index').Strategy
//   , fs = require('fs');

var express = require('express')
  , passport = require('passport')
  , util = require('util')
  , wsfedsaml2 = require('../../lib/passport-wsfed-saml2/index').Strategy
  , fs = require('fs')
  , morgan = require('morgan')
  , cookieParser = require('cookie-parser')
  , bodyParser = require('body-parser')
  , methodOverride = require('method-override')
  , session = require('express-session');

var users = [
    { id: 1, givenName: 'matias', email: 'matias@auth10.com' }
  , { id: 2, givenName: 'foo', email: 'foo@gmail.com' }
];

function findByEmail(email, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    if (user.email === email) {
      return fn(null, user);
    }
  }
  return fn(null, null);
}


// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.
passport.serializeUser(function(user, done) {
  done(null, user.email);
});

passport.deserializeUser(function(id, done) {
  findByEmail(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new wsfedsaml2(
  {
    path: '/login/callback',
    realm: 'urn:node:app',
    homeRealm: '', // specify an identity provider to avoid showing the idp selector
    identityProviderUrl: 'https://auth10-dev.accesscontrol.windows.net/v2/wsfederation',
    // setup either a certificate base64 encoded (cer) or just the thumbprint of the certificate if public key is embedded in the signature

    //cert: 'MIIDFjCCAf6gAwIBAgIQDRRprj9lv5RBvaQdlFltDzANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDEyRhdXRoMTAtZGV2LmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTEwOTIxMDMzMjMyWhcNMTIwOTIwMDkzMjMyWjAvMS0wKwYDVQQDEyRhdXRoMTAtZGV2LmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCEIAEB/KKT3ehNMy2MQEyJIQ14CnZ8DC2FZgL5Gw3UBSdRb9JinK/gw7yOQtwKfJUqeoZaUSAAdcdbgqwVxOnMBfWiYX7DGlEznSfqYVnjOWjqqjpoe0h6RaOkdWovDtoidmqVV1tWRJFjkj895clPxkLpnqqcycfXtSdZen0SroGyirD2mhMc9ccLbJ3zRnBNjlvpo5zow1zYows09tNC2EhGROL/OS4JNRQnJRICZC+WkA7Igf3xb4btJOzIPYhFiqCGrd/81CHmAyEuNzyc60I5yomDQfZ91Eb5Uk3F7mlfAlYB2aZwDwldLSOlVE8G1E5xFexF/5KyPC4ShNodAgMBAAGjLjAsMAsGA1UdDwQEAwIE8DAdBgNVHQ4EFgQUyYfx/r0czsPgTzitqey+fGMQpkcwDQYJKoZIhvcNAQEFBQADggEBAB5dgQlM3tKS+/cjlvMCPjZH0Iqo/Wxecri3YWi2iVziZ/TQ3dSV+J/iTyduN7rJmFQzTsNERcsgyAwblwnEKXXvlWo8G/+VDIMh3zVPNQFKns5WPkfkhoSVlnZPTQ8zdXAcWgDXbCgvdqIPozdgL+4l0W0XVL1ugA4/hmMXh4TyNd9Qj7MWvlmwVjevpSqN4wG735jAZFHb/L/vvc91uKqP+JvLNj8tPFVxatzi56X1V8jBM61Hx1Z9D0RCDjtmcQVysVEylW9O6mNy6ZrhLm0q5yecWudfBbTKDqRoCHQRjrMU2c5q/ZFDtgjLim7FaNxFbgTyjeRCPclEhfemYVg='
    thumbprints: ['a3cff17cbf7e793a97861390eb698d00e9598537']
  },
  function(profile, done) {
    console.log("Auth with", profile);
    if (!profile.email) {
      return done(new Error("No email found"), null);
    }
    // asynchronous verification, for effect...
    process.nextTick(function () {
      findByEmail(profile.email, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          // "Auto-registration"
          users.push(profile);
          return done(null, profile);
        }
        return done(null, user);
      })
    });
  }
));

var app = express();
var router = express.Router();

// configure Express
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(morgan('combined'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(methodOverride());
app.use(session({
  secret: 'keyboard cat',
  resave: false,
 saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());
app.use('', router);
app.use(express.static(__dirname + '/../../public'));


app.get('/', function(req, res){
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login',
  passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post('/login/callback',
  passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.listen(3000, function () {
  console.log("Server listening in http://localhost:3000");
});

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}