var express = require('express');
var passport = require('passport');
var Strategy = require('../../lib/passport-wsfed-saml2/index').Strategy;
var http = require('http');

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(id, done) {
  done(null, id);
});

passport.use(new Strategy(
  {
    protocol: 'samlp',
    path: '/login/callback',
    realm: 'urn:saml-example',
    homeRealm: '',
    // identityProviderUrl: 'https://mdocs.auth0.com/samlp/dVrQZOG4gkBhzcLartSgW2v7kSnvW5XR?connection=github',
    // thumbprint: 'c5b930896e3f4e2cc1d6d1ceb68f4d3de90deee6'
    identityProviderUrl: 'https://login0.myauth0.com/samlp/wklezTET2P3iYA54Sraju8qFN0ohdI0G',
    thumbprints: ['dba77ba142ff38d5076b4310700709c470d53790']
  }, function(profile, done) {
    console.log("Auth with", profile);
    if (!profile.email) {
      return done(new Error("No email found"), null);
    }
    done(null, profile);
  }
));

var app = express();

// configure Express
app.configure(function() {
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(express.logger());
  app.use(express.cookieParser());
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.session({ secret: 'keyboard cat' }));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(app.router);
  app.use(express.static(__dirname + '/../../public'));
});


app.get('/', function(req, res){
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login',
  passport.authenticate('wsfed-saml2', { failureRedirect: '/', forceAuthn: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post('/login/callback',
  passport.authenticate('wsfed-saml2', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

http.createServer(app).listen(3000, function () {
  console.log("Server listening in http://localhost:3000");
});

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login');
}