var chai      = require('chai');
var uri       = require('url');
var expect    = require('chai').expect;
var passport  = require('chai-passport-strategy');
var Strategy  = require('../../lib/passport-wsfed-saml2').Strategy;

chai.use(passport);

describe('wsfed - using default session state store', function() {
  
  describe('without session key option', function() {
    
    describe('issuing authorization request', function() {
      var strategy = new Strategy({
        path: '/callback',
        realm: 'urn:fixture-test',
        identityProviderUrl: 'http://www.example.com/login',
        thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
        state: true
      }, function () {});
      
      describe('that redirects to service provider', function() {
        var request, url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate({});
        });
  
        it('should be redirected', function() {
          var u = uri.parse(url, true);
          expect(u.query.wctx).to.have.length(24);
        });
      
        it('should save state in session', function() {
          var u = uri.parse(url, true);
          expect(request.session['wsfed:www.example.com'].state).to.have.length(24);
          expect(request.session['wsfed:www.example.com'].state).to.equal(u.query.wctx);
        });
      });
      
      describe('that redirects to service provider with other data in session', function() {
        var request, url;
  
        before(function(done) {
          chai.passport.use(strategy)
            .redirect(function(u) {
              url = u;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
              req.session['wsfed:www.example.com'] = {};
              req.session['wsfed:www.example.com'].foo = 'bar';
            })
            .authenticate({});
        });
  
        it('should be redirected', function() {
          var u = uri.parse(url, true);
          expect(u.query.wctx).to.have.length(24);
        });
      
        it('should save state in session', function() {
          var u = uri.parse(url, true);
        
          expect(request.session['wsfed:www.example.com'].state).to.have.length(24);
          expect(request.session['wsfed:www.example.com'].state).to.equal(u.query.wctx);
        });
        
        it('should preserve other data in session', function() {
          expect(request.session['wsfed:www.example.com'].foo).to.equal('bar');
        });
      });
      
      describe('that errors due to lack of session support in app', function() {
        var request, err;
  
        before(function(done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              request = req;
            })
            .authenticate({});
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('Authentication requires session support when using state. Did you forget to use express-session middleware?');
        });
      });
    });
    
    describe('processing response to authorization request', function() {
      var strategy = new Strategy({
        path: '/callback',
        realm: 'urn:fixture-test',
        identityProviderUrl: 'http://www.example.com/login',
        thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
        state: true
      },
      function (profile, done) {
        return done(null, profile, { message: 'Hello' });
      });

      strategy._wsfed.extractToken = function(req) {
        expect(req).to.be.an.object;
        return '<trust:RequestedSecurityToken>...</trust:RequestedSecurityToken>';
      };

      strategy._saml.validateSamlAssertion = function(token, done) {
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
            
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.method = 'POST';
              req.session = {};
              req.session['wsfed:www.example.com'] = {};
              req.session['wsfed:www.example.com']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
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
      
        it('should remove state from session', function() {
          expect(request.session['wsfed:www.example.com']).to.be.undefined;
        });
      });
      
      describe('that was approved with other data in the session', function() {
        var request, user, info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.method = 'POST';
              req.session = {};
              req.session['wsfed:www.example.com'] = {};
              req.session['wsfed:www.example.com']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.session['wsfed:www.example.com'].foo = 'bar';
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
      
        it('should preserve other data from session', function() {
          expect(request.session['wsfed:www.example.com'].state).to.be.undefined;
          expect(request.session['wsfed:www.example.com'].foo).to.equal('bar');
        });
      });
      
      describe('that fails due to state being invalid', function() {
        var request, info, status;
  
        before(function (done) {
          chai.passport.use(strategy)
            .fail(function(i, s) {
              info = i;
              status = s;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'DkbychwKu8kBaJoLE5yeR5NK-WRONG';
              req.method = 'POST';
              req.session = {};
              req.session['wsfed:www.example.com'] = {};
              req.session['wsfed:www.example.com']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
            })
            .authenticate({});
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Invalid authorization request state.');
        });
      
        it('should supply status', function() {
          expect(status).to.equal(403);
        });
      
        it('should remove state from session', function() {
          expect(request.session['wsfed:www.example.com']).to.be.undefined;
        });
      });
      
      describe('that fails due to provider-specific state not found in session', function() {
        var request, info, status;
  
        before(function(done) {
          chai.passport.use(strategy)
            .fail(function(i, s) {
              info = i;
              status = s;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'DkbychwKu8kBaJoLE5yeR5NK-WRONG';
              req.method = 'POST';
              req.session = {};
            })
            .authenticate({});
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Unable to verify authorization request state.');
        });
      
        it('should supply status', function() {
          expect(status).to.equal(403);
        });
      });
      
      describe('that fails due to provider-specific state lacking state value', function() {
        var request, info, status;
  
        before(function(done) {
          chai.passport.use(strategy)
            .fail(function(i, s) {
              info = i;
              status = s;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'DkbychwKu8kBaJoLE5yeR5NK-WRONG';
              req.method = 'POST';
              req.session = {};
              req.session['wsfed:www.example.com'] = {};
            })
            .authenticate({});
        });
  
        it('should supply info', function() {
          expect(info).to.be.an.object;
          expect(info.message).to.equal('Unable to verify authorization request state.');
        });
      
        it('should supply status', function() {
          expect(status).to.equal(403);
        });
      });
      
      describe('that errors due to lack of session support in app', function() {
        var request, err;
  
        before(function (done) {
          chai.passport.use(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              request = req;
            
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'DkbychwKu8kBaJoLE5yeR5NK-WRONG';
              req.method = 'POST';
            })
            .authenticate({});
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('Authentication requires session support when using state. Did you forget to use express-session middleware?');
        });
      });
    });
  });
  
  describe('with session key option', function() {
    var strategy = new Strategy({
      path: '/callback',
      realm: 'urn:fixture-test',
      identityProviderUrl: 'http://www.example.com/login',
      thumbprints: ['5ca6e1202eafc0a63a5b93a43572eb2376fed309'],
      state: true,
      sessionKey: 'wsfed:example'
    },
    function (profile, done) {
      return done(null, profile, { message: 'Hello' });
    });

    strategy._wsfed.extractToken = function(req) {
      expect(req).to.be.an.object;
      return '<trust:RequestedSecurityToken>...</trust:RequestedSecurityToken>';
    };

    strategy._saml.validateSamlAssertion = function(token, done) {
      expect(token).to.equal('<trust:RequestedSecurityToken>...</trust:RequestedSecurityToken>');
      done(null, { id: '1234' });
    };
    
    describe('issuing authorization request', function() {
      
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
              req.session = {};
            })
            .authenticate({});
        });
  
        it('should be redirected', function() {
          var u = uri.parse(url, true);
          expect(u.query.wctx).to.have.length(24);
        });
      
        it('should save state in session', function() {
          var u = uri.parse(url, true);
        
          expect(request.session['wsfed:example'].state).to.have.length(24);
          expect(request.session['wsfed:example'].state).to.equal(u.query.wctx);
        });
      });
    });
    
    describe('processing response to authorization request', function() {
      
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
            
              req.body = {};
              req.body.wresult = '<trust:RequestSecurityTokenResponseCollection>...</trust:RequestSecurityTokenResponseCollection>';
              req.body.wctx = 'DkbychwKu8kBaJoLE5yeR5NK';
              req.method = 'POST';
              req.session = {};
              req.session['wsfed:example'] = {};
              req.session['wsfed:example']['state'] = 'DkbychwKu8kBaJoLE5yeR5NK';
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
      
        it('should remove state from session', function() {
          expect(request.session['wsfed:example']).to.be.undefined;
        });
      });
    });
  });
});
