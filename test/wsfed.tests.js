var expect = require('chai').expect;
var server = require('./fixture/wsfed-server');
var request = require('request');
var cheerio = require('cheerio');

describe('wsfed', function () {
  before(function (done) {
    server.start(done);
  });
  
  after(function (done) {
    server.close(done);
  });

  describe('normal flow', function () {
    var user, r, bod, $;

    before(function (done) {
      request.get({
        jar: request.jar(), 
        uri: 'http://localhost:5050/login?wa=wsignin1.0&wtrealm=urn:fixture-test'
      }, function (err, response, b){
        if(err) return done(err);
        expect(response.statusCode)
          .to.equal(200);


        $ = cheerio.load(b);
        var wresult = $('input[name="wresult"]').attr('value');
        var wa = $('input[name="wa"]').attr('value');

        request.post({
          jar: request.jar(), 
          uri: 'http://localhost:5050/callback',
          form: { wresult: wresult, wa: wa }
        }, function(err, response, body) {
          if(err) return done(err);

          r = response;
          bod = body;
          done();
        });
      });
    });

    it('should be valid signature', function(){
      expect(r.statusCode)
            .to.equal(200);
    });

    it('should return a valid user', function(){
      var user = JSON.parse(bod);
      expect(user['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'])
          .to.equal(server.fakeUser.id);
      expect(user['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'])
          .to.equal(server.fakeUser.emails[0].value);
    });

  });

  describe('wresult without RequestedSecurityToken', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5050/callback',
        form: { wresult: '<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"></t:RequestSecurityTokenResponse>' }
      }, function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should return a 400', function(){
      expect(r.statusCode)
            .to.equal(400);
    });
  });

  describe('missing wresult in POST', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(), 
        uri: 'http://localhost:5050/callback'
      }, function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should redirect to idp', function(){
      expect(r.statusCode)
            .to.equal(302);
    });
  });

  describe('invalid wresult in POST', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(), 
        uri: 'http://localhost:5050/callback',
        form: { wresult: 'foo' }
      }, function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should return a 400', function(){
      expect(r.statusCode)
            .to.equal(400);
    });
  });
});