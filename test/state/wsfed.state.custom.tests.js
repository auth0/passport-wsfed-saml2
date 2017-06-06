var chai      = require('chai');
var expect    = require('chai').expect;
var passport  = require('chai-passport-strategy');
var Strategy  = require('../../lib/passport-wsfed-saml2').Strategy;

chai.use(passport);

describe('wsfed - using custom session state store', function() {
  
  describe('that accepts meta argument', function() {
    function CustomStore() {}

    CustomStore.prototype.store = function(req, meta, cb) {
      if (req.url === '/error') { return cb(new Error('something went wrong storing state')); }
      if (req.url === '/exception') { throw new Error('something went horribly wrong storing state'); }
      
      if (req.url !== '/me') { return cb(new Error('incorrect req argument')); }
      if (meta.identityProviderUrl !== 'http://www.example.com/login') { return cb(new Error('incorrect meta.identityProviderUrl argument')); }
      
      req.customStoreStoreCalled = req.customStoreStoreCalled ? req.customStoreStoreCalled++ : 1;
      return cb(null, 'foos7473');
    };
    
    CustomStore.prototype.verify = function(req, state, meta, cb) {
      if (req.url === '/error') { return cb(new Error('something went wrong verifying state')); }
      if (req.url === '/exception') { throw new Error('something went horribly wrong verifying state'); }
      
      if (state !== 'foos7473') { return cb(new Error('incorrect state argument')); }
      if (meta.identityProviderUrl !== 'http://www.example.com/login') { return cb(new Error('incorrect meta.identityProviderUrl argument')); }
      
      req.customStoreVerifyCalled = req.customStoreVerifyCalled ? req.customStoreVerifyCalled++ : 1;
      return cb(null, true);
    };
    
    describe('issuing authorization request', function() {
      var strategy = new Strategy({
        path: '/callback',
        realm: 'urn:fixture-test',
        identityProviderUrl: 'http://www.example.com/login',
        thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
        store: new CustomStore()
      },
      function() {});
      
      describe('that redirects to service provider', function() {
        var request, url;
  
        before(function (done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.url = '/me';
            })
            .authenticate({});
        });
  
        it('should be redirected', function() {
          expect(url).to.equal('http://www.example.com/login?wctx=foos7473&wtrealm=urn%3Afixture-test&wa=wsignin1.0&whr=');
        });
      
        it('should serialize state using custom store', function() {
          expect(request.customStoreStoreCalled).to.equal(1);
        });
      });
      
      describe('that errors due to custom store supplying error', function() {
        var request, err;
  
        before(function (done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              request = req;
              req.url = '/error';
            })
            .authenticate({});
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('something went wrong storing state');
        });
      });
      
      describe('that errors due to custom store throwing error', function() {
        var request, err;
  
        before(function (done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              request = req;
              req.url = '/exception';
            })
            .authenticate({});
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('something went horribly wrong storing state');
        });
      });
    });
    
    describe('processing response to authorization request', function() {
      var strategy = new Strategy({
        path: '/callback',
        realm: 'urn:fixture-test',
        identityProviderUrl: 'http://www.example.com/login',
        thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
        store: new CustomStore()
      },
      function (profile, done) {
        return done(null, profile, { message: 'Hello' });
      });

      strategy._wsfed.extractToken = function(req) {
        expect(req).to.be.an.object;
        return '<trust:RequestedSecurityToken>...</trust:RequestedSecurityToken>';
      };

      strategy._saml.validateSamlAssertion = function(token, options, done) {
        expect(token).to.equal('<trust:RequestedSecurityToken>...</trust:RequestedSecurityToken>');
        done(null, { id: '1234' });
      };
      
      describe('that was approved', function() {
        var request, user, info;

        before(function (done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              request = req;
          
              req.url = '/login';
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'foos7473';
              req.method = 'POST';
              req.get = function(){
                return '';
              };
            })
            .authenticate({});
        });

        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });

        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Hello');
        });
    
        it('should verify state using custom store', function() {
          expect(request.customStoreVerifyCalled).to.equal(1);
        });
      });
      
      describe('that errors due to custom store supplying error', function() {
        var request, err;

        before(function (done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              request = req;
          
              req.url = '/error';
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'foos7473';
              req.method = 'POST';
            })
            .authenticate({});
        });

        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('something went wrong verifying state');
        });
      });
      
      describe('that errors due to custom store throwing error', function() {
        var request, err;

        before(function (done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              request = req;
          
              req.url = '/exception';
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'foos7473';
              req.method = 'POST';
            })
            .authenticate({});
        });

        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('something went horribly wrong verifying state');
        });
      });
    });
  });
  
  describe('that accepts meta argument and supplies state', function() {
    function CustomStore() {}
    
    CustomStore.prototype.verify = function(req, state, meta, cb) {
      req.customStoreVerifyCalled = req.customStoreVerifyCalled ? req.customStoreVerifyCalled++ : 1;
      return cb(null, true, { returnTo: 'http://www.example.com/' });
    };
    
    describe('processing response to authorization request', function() {
      
      describe('that was approved without info', function() {
        var strategy = new Strategy({
          path: '/callback',
          realm: 'urn:fixture-test',
          identityProviderUrl: 'http://www.example.com/login',
          thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
          store: new CustomStore()
        },
        function (profile, done) {
          return done(null, profile);
        });

        strategy._wsfed.extractToken = function(req) {
          expect(req).to.be.an.object;
          return '<trust:RequestedSecurityToken>...</trust:RequestedSecurityToken>';
        };

        strategy._saml.validateSamlAssertion = function(token, options, done) {
          expect(token).to.equal('<trust:RequestedSecurityToken>...</trust:RequestedSecurityToken>');
          done(null, { id: '1234' });
        };
        
        var request, user, info;

        before(function (done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              request = req;
        
              req.url = '/login';
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'foos7473';
              req.method = 'POST';
              req.get = function(){
                return '';
              };
            })
            .authenticate({});
        });

        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });

        it('should supply info with state', function() {
          expect(info).to.be.an.object;
          expect(Object.keys(info)).to.have.length(1);
          expect(info.state).to.be.an.object;
          expect(info.state.returnTo).to.equal('http://www.example.com/');
        });
  
        it('should verify state using custom store', function() {
          expect(request.customStoreVerifyCalled).to.equal(1);
        });
      });
      
      describe('that was approved with info', function() {
        var strategy = new Strategy({
          path: '/callback',
          realm: 'urn:fixture-test',
          identityProviderUrl: 'http://www.example.com/login',
          thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
          store: new CustomStore()
        },
        function (profile, done) {
          return done(null, profile, { message: 'Hello' });
        });

        strategy._wsfed.extractToken = function(req) {
          expect(req).to.be.an.object;
          return '<trust:RequestedSecurityToken>...</trust:RequestedSecurityToken>';
        };

        strategy._saml.validateSamlAssertion = function(token, options, done) {
          expect(token).to.equal('<trust:RequestedSecurityToken>...</trust:RequestedSecurityToken>');
          done(null, { id: '1234' });
        };

        var request, user, info;

        before(function (done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              request = req;
        
              req.url = '/login';
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'foos7473';
              req.method = 'POST';
              req.get = function(){
                return '';
              };
            })
            .authenticate({});
        });

        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });

        it('should supply info with state', function() {
          expect(info).to.be.an.object;
          expect(Object.keys(info)).to.have.length(2);
          expect(info.message).to.equal('Hello');
          expect(info.state).to.be.an.object;
          expect(info.state.returnTo).to.equal('http://www.example.com/');
        });
  
        it('should verify state using custom store', function() {
          expect(request.customStoreVerifyCalled).to.equal(1);
        });
      });
    });
  });
});
