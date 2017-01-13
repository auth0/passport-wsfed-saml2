var expect  = require('chai').expect;
var request = require('request');
var qs      = require('querystring');
var cheerio = require('cheerio');
var xmldom  = require('xmldom');
var fs      = require('fs');
var zlib    = require('zlib');
var crypto  = require('crypto');
var utils   = require('./utils');
var server  = require('./fixture/samlp-server');
var Samlp   = require('../lib/passport-wsfed-saml2/samlp');
var Saml    = require('../lib/passport-wsfed-saml2/saml').SAML;

describe('samlp (functional tests)', function () {
  before(function (done) {
    server.start(done);
  });

  after(function (done) {
    server.close(done);
  });

  describe('samlp flow with assertion signed', function () {
    var r, bod;

    before(function (done) {
      // this samlp request comes from Salesforce
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
                  'http://localhost:5051/callback', function(err, resp) {
        if (err) return done(err);
        if (resp.response.statusCode !== 200) return done(new Error(resp.body));
        r = resp.response;
        bod = resp.body;
        done();
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

  describe('samlp flow with assertion signed with different cert', function () {
    var r, bod;

    before(function (done) {
      server.options = { signResponse: true };
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
            'http://localhost:5051/callback/samlp-invalidcert', function(err, resp) {
        if (err) return done(err);
        r = resp.response;
        bod = resp.body;
        done();
      });
    });

    it('should return 400 (invalid signature)', function(){
      expect(r.statusCode)
            .to.equal(400);
    });
  });

  describe('samlp flow with response signed', function () {
    var r, bod;

    before(function (done) {
      server.options = { signResponse: true };
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
            'http://localhost:5051/callback/samlp-signedresponse', function(err, resp) {
        if (err) return done(err);
        if (resp.response.statusCode !== 200) return done(new Error(resp.body));
        r = resp.response;
        bod = resp.body;
        done();
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

  describe('samlp flow with response signed with different cert', function () {
    var r, bod;

    before(function (done) {
      server.options = { signResponse: true };
      doSamlpFlow('http://localhost:5051/samlp?SAMLRequest=fZJbc6owFIX%2FCpN3EAEVMmIHEfDaqlCP%2BtKJELkUEkqCl%2F76Uj3O9JyHPmay9l4r%2BVb%2F6VLkwglXLKXEBG1JBgImIY1SEpvgNXBFHTwN%2BgwVeQmtmidkjT9qzLjQzBEGbxcmqCsCKWIpgwQVmEEeQt9azKEiybCsKKchzYFgMYYr3hjZlLC6wJWPq1Ma4tf13AQJ5yWDrVZO45RIDOWYHWkVYimkBRBGjWVKEL%2BlfEhDSjhlVEJNLvlb1%2FqOA4TJyARvynPH80qFFJPAdg%2Fh1fNnGVqpKO3OLkZonUfJ0Nu2Y2t6PdlVPj1RZxVlThywI8rihVH0MuksTQz3sx1Fm2xv5LO9nYSs5KXxfnm364%2FwfMDPWMqn182qHOqpjzR0dncsM6xO1Vs7h860HI97yrB7xHE9dt2loy%2FQu1prie%2FMcuNNL2i6nUdWp%2Fdnk3yekb7dXYhWjFjil%2Br2IC%2Bd%2FexlNF7wS77Zomvo7epFbCuyVx5tq3klYzWeEMYR4SZQ5LYqypqo6IGiQE2FmiKpencPhOXf%2Fx%2Bm5E71N1iHu4jBcRAsxeWLHwBh82hHIwD3LsCbefWjBL%2BvRQ%2FyYPCAd4MmRvgk4kgqrv8R77d%2B2Azup38LOPgC&RelayState=123',
            'http://localhost:5051/callback/samlp-signedresponse-invalidcert', function(err, resp) {
        if (err) return done(err);
        r = resp.response;
        bod = resp.body;
        done();
      });
    });

    it('should return 400 (invalid signature)', function(){
      expect(r.statusCode)
            .to.equal(400);
    });
  });

  describe('missing SAMLResponse in POST', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5051/callback'
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
      expect(r.headers.location.split('?')[0])
            .to.equal('http://localhost:5051/samlp');
      var querystring = qs.parse(r.headers.location.split('?')[1]);
      expect(querystring).to.have.property('SAMLRequest');
      expect(querystring).to.have.property('RelayState');
    });
  });

  describe('SAMLResponse with utf8 chars', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5051/callback/samlp-with-utf8',
        form: { SAMLResponse: 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9mbWktdGVzdC5hdXRoMC5jb20vbG9naW4vY2FsbGJhY2siIElEPSJfNzY4NjU5OGUzNDk4YjcxOGM3MjcyNmZlMjVhZDU3Y2MiIEluUmVzcG9uc2VUbz0iXzM3ZjAyNjJkYWZlNmJhZWFmYThiIiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDQtMTFUMTE6MzU6MjQuMDYwWiIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cHM6Ly9hYWktbG9nb24uZXRoei5jaC9pZHAvc2hpYmJvbGV0aDwvc2FtbDI6SXNzdWVyPjxzYW1sMnA6U3RhdHVzPjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PC9zYW1sMnA6U3RhdHVzPjxzYW1sMjpFbmNyeXB0ZWRBc3NlcnRpb24geG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjx4ZW5jOkVuY3J5cHRlZERhdGEgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIiBJZD0iX2M4ZjVjZDJlMDBjZTIzOTBhMmQyN2UzNGNmNDBlYjZhIiBUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNFbGVtZW50Ij48eGVuYzpFbmNyeXB0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjYWVzMTI4LWNiYyIgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIi8+PGRzOktleUluZm8geG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjx4ZW5jOkVuY3J5cHRlZEtleSBJZD0iXzBmNzM0OTg1MWQyNjQ0OTY1YTQ3YzZmNTY5NzUwOTUxIiB4bWxuczp4ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiPjx4ZW5jOkVuY3J5cHRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNyc2Etb2FlcC1tZ2YxcCIgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIj48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIi8+PC94ZW5jOkVuY3J5cHRpb25NZXRob2Q+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRE96Q0NBaU9nQXdJQkFnSUpBUFBvSHJFcGI3b3VNQTBHQ1NxR1NJYjNEUUVCQlFVQU1CMHhHekFaQmdOVkJBTVRFbVp0YVMxMApaWE4wTG1GMWRHZ3dMbU52YlRBZUZ3MHhNekExTURZeU16QXpNVGRhRncweU56QXhNVE15TXpBek1UZGFNQjB4R3pBWkJnTlZCQU1UCkVtWnRhUzEwWlhOMExtRjFkR2d3TG1OdmJUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQUtiOUdpZmYKK0t2UVB3bzllb09iU1c3Tk5ZWkZyVW94Um43NHFNY2RmWndrdXdHM084RUdpOFgrVXNOdE5nd1FsTVZmWXQ5bEtCNzFpSlNsS09CaQpCUFNGUDd6UDlqRnRUbmZKY2FSdmR2WVBvSUM0WTgxdHU2TGtOTjNlMS8zMU5wK1I2cGQ3RjZMZkhXcXVmK0IraHlISkNYYXNkZDZKCmxHb2ViOTQrZW1wajlsbTh3SE5iM3NyLzg4Mzk0S0ozRlVCZXhQelE1cnBLTGU3ZDVmbTRFS08vaXlFcFdIVWxmN2RmOXlHRDZtNzEKUHhvKzhyOERxcTdBNUVoR1gvems2U3V3WjRqL3N6aXp5bi9jWHVsbEdnM1BBc2M5WFhMVDQ1NUExS0VCeDVlVEdyTWM3SlEzdURVcQpxZkRmNHZqd2xOQmNJanhnMlgzZE0wc0pWay81cjAwQ0F3RUFBYU4rTUh3d0hRWURWUjBPQkJZRUZCczVscGZ2ZXlPU29wbU5WZWVoClhQK1BHdGszTUUwR0ExVWRJd1JHTUVTQUZCczVscGZ2ZXlPU29wbU5WZWVoWFArUEd0azNvU0drSHpBZE1Sc3dHUVlEVlFRREV4Sm0KYldrdGRHVnpkQzVoZFhSb01DNWpiMjJDQ1FEejZCNnhLVys2TGpBTUJnTlZIUk1FQlRBREFRSC9NQTBHQ1NxR1NJYjNEUUVCQlFVQQpBNElCQVFBMlprM1NtU0dUT2gvNnJhemVtL0ZpOEd6RW9wY0tkSUUxdWVDaFRzQXpoNi9taW01cTVsSDBQVzFiODVzUTMvYzMxU1lVClN4VlpCODRLMk1QNitod0MwV1p4a3E4eTBpTUVFQXhXeUMzWjNpOXBTbEdkdzdzdi9OV0p2NFlQam8yc1NOSHVaODBPMTFhM2NYb3UKWXhMTzhEQlJNcTlWVHM3UmI3cUtGQldsNUl4K2NaeFZnbHJ4SXY2VzA4T3JybXFQZW9EanVpSmlCajI4Y3NqaGVoWUVsS1ljblU0TApSZElqQmxaRm4xQW9USlJCRkF5akw4QnZTTUlNUmt6RXJvL0dwM0l6ajYwM1JCVEdPa3ZuaWFsS0hjd0xuVkZGRTB4ZVpaVXE3S3cwCkx2TzBYOHVTM0RYN2RUYzJvcXpYT1R4NDIvT2o1cTl4VXVhaXVYME1SWlQwPC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PHhlbmM6Q2lwaGVyRGF0YSB4bWxuczp4ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiPjx4ZW5jOkNpcGhlclZhbHVlPlBtN2dVRDI5d1AwMTdLUnZKTmdmVzUxRkQ0eHlUTGJ5RDdXbElNRVZUR2xzWnc5K3ZNbUdzL2VkdXJoT2ZVZEV2SGZBV04vdUYzYkxCOTl1Q1pFN0dHLzJ0aDVBS2pLejFaN1NvZWZuUU54dnFvbXUyNUNmWTEwUzFpbitNMU13N3ZrcTZlS0c4bndEQjBDc3JsOXJ6ZUMyekNQRFc1TG81N0x2NDNNbUVpM1dYZkVhbkQwZDJZT2NRVFppaHIzUlpnajl0SDJUQmVKZjhNN28yY1BrOXFBWk40aU56dk1oWE5OV0RDR256SGxIdXNxVk9RNWM4d2l5MmwzdWlUZlk3aEIvTVhpUDVmemRPYitEbWw4NlJrT2MyUVd3RHUwQ0t1ZHBveVRxQW90OUhFZ1JoL25tVXVSQkVKQ3NtWEdyN3FOM3ZSWW5HTXRmdEswZG9VYzN6QT09PC94ZW5jOkNpcGhlclZhbHVlPjwveGVuYzpDaXBoZXJEYXRhPjwveGVuYzpFbmNyeXB0ZWRLZXk+PC9kczpLZXlJbmZvPjx4ZW5jOkNpcGhlckRhdGEgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIj48eGVuYzpDaXBoZXJWYWx1ZT4xY1JHdFhpWFZMYXRhSHFTMWVLM3JtTjlQcnJyZ0laR25XM0xPT25aektuU2w2dWFKWnRENXFyQkRURE5zaXg2ek15cHJPOU5KQVlQYlJEQ21CbWNaVStMSm5aSVdtT3IrQ29SdWJBUGdIT2Q3Q0VoQVB6RGVJZFh0S0V3R29hNHNKbXJRMjlCR3VSejBYS3ljTlJhU2lJa0toRm40dTZCRzV0a2dzS0RRT3Q3dmd0RzhuV21pczZqM0lYSVdrWGpXT2tKWjBHbktXajJqd3EwL3ArdEo1OXM1R3lTQi9uVy9nQW1PcjlLelhJMllQWm5CTk1xSUl6ZTZPNDBaaDRtaXpmUmdTSzM4dE5XQ3NCRlB6Q1krZjJWZVlsMzVORythdUhEZU9BRGtkQkR4d2xqRTJCV0Q2MXBKaFhuRzBTRVBIcnV1b1k3YldjWGpoNDVYLzhiM1hNcHF4ZDFjRFJPZkZMdFRMb0syVjVqcnhiRGRvcVh2TFR2NnZ5NDZGVkZYRVNEV0xmSGFxTjBOTlNsY2hORXJmcFV3SDRNUXNVOGU1UW1yeEw1QUVDVldmQytEYnNOZTVjZFhZcS8wVTBkcWJPV1ZlQkdVL3h0KzJEWmVhSFBTZVpweGhCb3diZ0FKejRlTlpQdnhIWVRGZHducXZhemRneWo4VUdHbEQvZjFoSXFHWHFja3BNbTJ2OEplZUd1akV6SDNnMXNOcEluWG40eVBaTUFLSEtOaVhIZTF3aWk1V2V5Ty9tMHlCUGZreGRrMll1S3NPMy9KWDlOcXltNXV6WUIzbmZZN1JkR21pdXBDV2tpb05aL1hidG5Bb1dDSENyc210am1kdm5rM2NBTVAvdmNSWmluQm9pSjgxdnBLdTNtSm5FdGV6cEVqaUMxY1dnTUxoLzZRK29MbXZOL1dyNVZWZmxjSFJYMWNhTEQrWURncnkybTVCbHBTRjhVKy9KYXR6NjR3Y0V2aXlqVFgwelN6VlRtakptZG44a3FvSEN0V3RvVCtWQUt0MG9CcGRMdHg5eDUzUTVTVG1rUG5xOXdnc3FWRXBGZGFHK25qM1RiZkY5K1FBMHFCVk1BVmxpZmNyb01YTzZRZlpFZUwwNWpFZWFSUGZpK0t5K2tVNUUvMFduTWFVUU1ZZE1kUFh5NW1XenZuZHMzVE5DczRjMWhYc1c2SXFoeTRnQjFPdEFVdjhIeEtPWVhrT0ZMMVN4TEs4Ty80UUUwVEFGd0hvZ0hEY3NVTEIvNDJHZ3IxZjZJVWcyTGNjOTMvN3JOUkhOV21OK21ienBJdUUvT0lRTEM5RW5yM1ErSkdURFJKajJsR0Fidzk4MnlsUzYyS2ZETDlKMWEzdzdtb0ZKM3ZubTdTUmZ4K25CREw2YzFBSDJTS0s1SmsrT3VDOWVSWllwMDdXMy9TQnJOWFVUUzhpbnpRaERLSWwvOVJ0b1Bzbyt3K3RnaCtIY2svNERaQnV0cmtpY3BGejBWZm5pK0VGZXBEZVJLT1ZwY1JNclVFeHdvWFZ3SitBUldMRnBIdDFJQjh4TmJTeFU4WUpzeDlMdWxGeXhUQzVOYWFqU0N4WFhkRENFajE5U2o2MFRYZGcwOHNRY0NYdGxUS1dLVDdQQXl1cGo5dFZtdVg2NkEweGQwdWt3MmhjbSs1bnB4REtEbUhKdWFMSUlzSDB4WDFyQVE0a3VqVHg1aGNGZnEyMDZIK2JBUE1xTEYyTjFDSnlkYUJMd2xoejRwa0tPczhMRXVzTGtySGVUK3hFeHBETnk4MzBZQ3M1SUpnTkY2R3dFcFdiaklGbVNIMlpzSnBycnB4b3h6eGtuZ29DSzYvSlRkYUVoM0diWkVmaFNlSW5kTGFnUktFcjZ5azNFMS9sNzlxTmxCbzlpUndTRE5UVXdkMmVHOENhZVpyYjJQZEIweDk2L3Z4L2lkUXNwQjNCQjkrbzBRaFhndVp5c0pDMmtIdmZUSndZZjRWVDBoL01TQnk1dGVWYU1kUWZxUmpCVm9pbGZncnFaVjlPTHZOOUw3TzUxVGFqVE1EcmdleGxIV3VNNVhMczZUK3pNdXM3WisrNys2aGNEUGg4UXpxY2ljVyt6TGpOTHN3OXhZS09CNlJ4T1NHTy9CekkxcExhbmRHSnJ5bXVsWlBicUJyZEQ1MXFWNUxwWjVBcUU2MHg5RGc0NDNJRkpPeWIxUzN3VCsyb3BBVEFDVDZQV3o0blJsNHZJc2J1M1RlVGdGTXZiUHdKdmV0U1d2ZjNwckdRNDlqVHpMaXhlSUlRTmUyOXdYamZROE1TKzJSUGppMnlpQVFCcllITWo2UzBiWFloYUVCRmFGN1kxNTRxMVJORk5rTmpmN2tVQjBTbVlnaVU4em83QjdLNzRwTm1SbWxIcitMcGtFcHVyVEU5Lzgvd1hhRWFzSitIb0UyNVlTYnFZRitxKzQ1L1NFcEJQdWpCa2ZQdkQwR0pqVCtnbGxiNzFWQU9nMTk2dGN2RFU4TUduSUN6SGM0ajJRaWVhZkF2YzZMNElvMEJRQXhnNDZXTTlIWVJyOGhZeURQNzFCMC95Sm5CV1R5QzUvWFNsRmsrQWFQeXpxdFZpMk5GeFh3bnRldzA1R1NjU2F2NDdKSEFRVFZaRlJsd2k4RkNtaUpKZWVQVWRrb2FlZExOT21oUXFMN0hmZ000RDRmOE9MaHhxdng3Ym5QQkRPMmlBcndYbHFrdy9Lc3l4dlQvZVd3NUZMOW41KzVDTWxiYnJCTEpNM2o2WkVxM3RJOWZuYk1vNmFHUERRb2RURUMwaEY2ZHdJYm02VG5tdFlLcDFZSTR5UWlzMUFURmIxbTY4R0htS0tidXNiMGE4N3BKbzRYbDlQdVdLSFRhMXBWdDBVTWw0RWJjNm14aXdyRytIZzNFdDRXUk5qaTJHQXhWMmYyekFaN1ZsNXpGRk02dmdxbFlqQ3NWZWNLekM1emp6T2Y4aDd0UThKdTUxMWJpRjlhN090cFhCWHZqVWdvcVRFV25SM1pyRjI4MkNNV3VvUXJHbjlwNFR2eldORU1iWjd2cGJiQ2tYS0t3cFhhWXNzL3pwcHg2d3JXWTRNOUdoVE45RVhXTTRXUGVpbmZ1MStUQUdDK3dISFVTd2h2TE9Ob0RsaHhqcU94MVVweVZubmxTeTV2QlBIbWRrYXgzT3o4MWhIY3hHVEtvb3N1U0hRYU9hL2xRelY4Sm9sM2RyZURobjlBWkM1bjRsa3hYV0tUOEhuQUNMS3VUTE4rMXpQUVY0UWorSDcxNUloNkZzNkE3bGY0dVloY2pWcWNVdWZrTHFvcjd0NjdOck5FekIyNSs2UVNRSlhMbTNUU2M2UTlCUDNjNUhWOGZzVHJEL043RUdJUkJGL3BTNldSMzY2UjV6WkJiWjZXbFNOek1TcnlwZnlQVDk5ODhJeGtLRFZqYjE1MkZ3Njg4OTZvUS8rckdxY3BxYlB5bmsvYkpVbThWWU1vbzA3U0J4Y2hURncybmtRc1VLT0J2MkdJT01WQ0d0YUVmWDh5YVBlcGZ4UGFxSm5tVjJTQ2U3Q09vVWQ1b3g2SzgrL21uWUZaTXJ6N3RYQ1VIU1MybDdyU3BYTStXZ013VnIwalh5OXdYSkxKK3NLM0dXSDZYVDAzNHZrMk1KZHdmcU9zQnBwTkFjeStNekd5NDlFVlFULytQb2FlT245MzM3aHBibjFnVmNMd2ovWGMzRll4REtkakY1OGNUL2d0dG52aWRhaktUcGNnQ1l4R1F2KzNRUkhidWFEWnRyRXY0L3phNnpiRGZHcEtzbklqeVVhc21HeHpiQ1Q3ZjFMQU1aYlJwaklnYi9ScVRnVnhEQXRhUGNSVU9YTEE3N29ZZm83Y2h2STd5RlJGbk9lMDNURDhHRFFLaGI5VUlzN1JmRXNYS0xVOVZwZVp3NnZ4Q1lNZDhScTlDbG5kOG1jR0FsNDgrOTRVeUFWZUdUelYzMWVCam44QjQ1R0wzWDkxL2JULzExaHZNS05YMjFQbUZ5eVR5YzZNMXhVY3IzN282YWY0SEFzVW5YZ1o4U1VLUXdKUE1WQzkrRW52RHByUjYvWS81S1l5MFVnb1IrR01IRTNaMXl0UUdZWEZZRlVaVW1NVjJVZ3oySW5pVTRhWExYNFlxQjhMRVgvRjVENnUzcVFCekhkSXhPelNTdlRiRXN6dVhuOFd4NStMNW1MVGM1U1JuNmxQZTRIUVZ1U0lLYzg3Ym5UTDFzNHFadjF0KzlaTUxLSVRHc1J4bjM1YXFZdVBMdDVOM053MlBZUkg4ZHFyZkwvWlA5WW5CWXo2aEFlWXZQVG5pYWF2ZVYzU0dNeW1VRVM5YlVtbHRjOUo0NnR3MkNwYkkxT0NDRDJ3dW1ucTlvbkZEam1oQUticENkaVNlSXFyNll4Y09QbzFXTnNVMmR1Z1Z3L1dYbTl5RUJ4S0o1UHJjNHJhdjhPT2Ezc0g0Z0cyYm9KeEMrMTluenZDbnVmTTRiRVQ3WVY5SVdmaDJLOGJacytRYTZPYjBTOXZnUWw1YWhGekpCUGhNUW91NjhKLzNkQm5ScUlPUENUMUhxcDN2aktlR3B4bGQxRDl3azZNYUREakl4aTJvWDQ3azZYREt6UkprUENabnJFTDZSblRodFJ0dzhiRUJCblZvdTdHWlZMZWtmRmw1MGlHTldBTmJpYTFGaDhad0c3SmxGbnhQZkhOdHYwM1QrT0dmOGhnMDV4YVlWQjRtZURKeC8rWmJBQzBKYUpYeUpNMnJmeTVuY3UxTk9BNWdEV1E3Vkp0MlFyQXh2cmQ5TVV4eHRnbHRtek1Nc1FZbDd3QVByMk5QRW1Nck1EeXJCcVRNY0JWbVg2N05sNGhBck44WUQySE9WZW5pZkkzcGFZSXMySTg3eWJ4SVNsMlEvbDFySXdScHFZSFVzRGNqVjBmUzd5c2VVZUdnK2hEMDdZR1RWaVkvT0JHeEswMzJneUtUcFdVMHFibW8rWTYvWkdVdnBqbldCRWJ5QkhkZ0xia0JUL29CNVE0azdLMi9TQXd6N29DZStJWG9OYkxYYkFNSGZIS296WFNxUysxQkN1TUUxSnNsWGpSWFk1WWJnRms2MU8zUndLRFVMaExUNUdmSlVFUVNoU2h2S05naHYzOUlBY1o2YWlFWlp3WVBUK1BudnNpc1hKanFiM2lhaU1yMCs5aEIvR3hrOHN5amRuVU1mL3FJOEpRU0k5UVhIZ0t6UU5pY0dSZFdjNUpXUkZreUIxMzh5dUF6NHQ4eHI1SzFhNStBUHJ6M1JJem1KWExpSlBySkhhcnlTL1ZNclBKaHR4WFpoYVlsYlJPRFptaUJjci9LVGlaVk02OWNlK3ZTa2FtZHFCakxFTThNWHZXQzRUY1poSDUzZXlmblJNUjIyb3hKVEVlQjZDYWJFZ3diNjNtQXlVb2JUSkdabFlvZ2NpbTZXZ3MwWnFDNllhaVR2dzNuLzEwWnhHWE5XRnNMRGhDa08vTGxqQWh2SXo0VElnN2F1UCsybXRNc2pram9IVDRDMG5QcXhGREZHanVRRHJpblRDZU1ZRGtnVTBhRTZtMzNnRGp2UEZDbGNqTEc4bTd4REtKbmwzTDNsVCs1eUNJSTNvY2NqaGxpTGVlN3JzSklkeFFaeEd3aDB0RUtmSThtdGYxbzlOSnllMEc1UnpXOTdiOXk5T0hEaVloTWNtalFHVHA5ZE54a0h2cU9qak9QbkdBL1FYZDcwYWVHVy9PT25MUjdBdkRzS1owbENrZDN6dFh6eVVLZ0VwQWRHK2FSbkNsT1JodG9xZXJwN1VxUHJvTmRGdHVNWStnOTlyWU9XS0RxSEo0ZFBBK3lRTkFRTHVBNTBLMU5RMHgzbEdlSlpaaTQraCthN1RRdDF4UVNqODBWVk4zR0VJc1I3WE02RXRNa0JLa2h0NjZoS1pQejJpT29mSVl1YUl0QkJiUWRZN3RXTW9LMElUL2ttbVMrK25MSmJiOUh2WDdqMGxvVWhqVFdocHF1MDQzcHRVeVBvWlVEaEVicmVsVzJldW9kc2ZuNHhoN1A1VUlaR2FNVU5HZ2k1bnF6a2p6MXVzaDEzU3huN0g1NTdZeGlZV2p2TmVJWmd6ZGJWK0dKdERDczBoVm0xZzhpbDh2MnEyazViLzlRZWh1NVVpTFNVZ3AvYVp6d1hOL0xkajQyVWxpWHM4TWRPOHVRVFRnZzZDb0dEbVcvaGJZZU1BV3NFelBlUGliRENmU0t0c0gzTlNGWWRUU0hFdjJYUU0zOEkvL2JpTlR1VWhSNzYxT0U5Qy9ndVFmd1lnbkRJZ05uV0NPUTdYRXRqSHZ2SDM2OUZiSEtnNlpwVmlzRWlEMk1qYnpCbEJsTm5FTFFBU3dQOVVBME1iWVQ2L0xuS3hYTnJXTDRwYWs5WjA0R3FBTm0ydTVxcFp5WGZFZzVGWXdUODVHbUpmSW9JQ2lCSk1JeHE0bXlwdTZ4dWRPdnhPeVVCZFE2enQ0dDR4MHp0TWQ3KzlNN3YzdjNjTVZOVFh0WG9NUEZLL1NKQWRaSGVxb2ZIS0FtcEJiaWV2ODhWL05XaVR5SVVUT1c3bkxGdWpSYUtPODZmWnB5c01kKyt5Q0crcEJDZyswZFY5d3RuYjhkdnl5d2hENkoxTExoelQydGZhUU5mWHZ3VUw1d255M3R3Zkd6M3NhV1A2YkYrSmpZd000SlltYjdEbUNySTZML3M5WlJ1TWlGclRFa3JqNUJ0T2oyckpObFlwZ1NWZ2Z2WWtLWDhmZFVhdWczRWRzVktheThkNzRwUE11S3gza0g3N0ZWbktUdWNiTEdSS1AyU1FuT1RvbE1ZTHNlQUhOK2phUkNpODJldTRFVzBxbWNmYjJNM2JjNVBzd0s3UUVQSWVnYW02Sm5jMFhOeUVPU2NWU1hmUUZEU3FGME1jSkVjeVUyQmIwaFgvTStNazd3SEFRUjBxa2tOQU5KYXkrbFAvQVliWVJ1dUtPWTdXRUxheHUzM0dhZ3pZeU5scWJFR1BQQnBTU2tTbCtiMXEyZHRXWGhmd3JXV052Z3lnMUQ4eVN5U2pJUXNaTEUyS1pab2RuZ2labUtqUERjd3pDMFBvcENSVXQ2ZFBZM3ExWTJjMk9Bd1BpY2NkN0YrYWlSSjdzNWpPei9BOHp5NlpLdll1ZW8xSDdoaVd2dFlJZ2YrQy9MaFFuQ0UxR21rODNzdURPQ3JQSUxPMDduOEcrMjZoenEvQ3lGKytGdHNyb29XUTErb29TanNmQWpXaDZ1QUR2N29DbmN3OFdmdjJXVk5pcGVHZU13UlJpcTFuVWFGN3BwK3dONGdsU3NVZzZ2V21GdHQ0QURFeXp3ODBMRExPNGszeXpsQURmc3pJeFc0KzNsT3FKN2loaklvSkMzRlB6djRWNXE5VWFlWjB2NWt2bk5YTmZUb3k0eG95dFROcUVTODFZYjZiK3R5R0pqZFRyai9WZ3l1dEU1b2oyN3R4YU9ObGloYzhObDlQbzZZb3ZrK3BFUU1vMEQ4SlVXNi9qL0FKUnVTT0I1MllMN1BJK3FFQXpIY0tYTXg4d3l3bEVHWEdrako5QXBoWTA4MUFyazJWclA3UEJEd2xwcENlQUtjZ1R3dTNtN0lRL1FibzFQMVhwMlB6U1hVbnI2N0xiRmFTT3ZjalNtNGlBQ3FjeXVPaDFVb0pIRGRRZWJ6UTdrWEdiQ1R6bEVPZ1NRazl5RzJMY25mOGVaVHBvRXZTbUpRNGcyTEovRkpjelBheGI5cUZXaTF0cGt2OVFrd04vTTVSVWd6QmNjNjV2ZUZQZE1ES09VRmU0UnNtV3htbFo2ZXBwQmJxVk5CbFhoQVBIWSs1aXRjWVR3eHVLUGJNRUNjcDYwc01xUEEyMDdoOWl1WVdvclRMMmNyMjQxSlBDQ3lvZVR5TDZ6MjhmbisyQXR5akxCVC8ydXpaUm9iejY4dzNDRUpLU1paQVlURG16ZWpaWXdVbmkxQ3BhM2JEcDNZcHd6ZkFIeEtSbmtwblJUS2gvUmFYVy95RElZb0U5eHQrcFBjb0kycXRLWGZpMjcxRXQ5eUMwTElvRllFQ2dQRE1GRGp2dGZlQTlnS2lpbWNiUThSSGdld3c2c1VLRS81L0VJcGlRS2t0UC9oSUtna2VHbmkxSXJHbnJYNU5aRmVlN1R0V3BlK3ozZUhCRFdJNlh4TGx6a3Y4ZzdQS1ltSkpxZzY2Unl5K1UzSlBkbk9pSkxoTWRzSmd2NDRlNm55am5VK1V5RWRpN3VGTUdoaFdOUlFSNWg0Y1JRMTB4MXMyNUdyUzhZWDlOdWVZNk5nMlAzYUJ4R2E0enZMa3YrSzA2czN3dUl2d2piSWxkdmpqdTM5di80eTlWMlo3VGdRWlFVUVMzQUd5NmFmQ296VXNnN3pFQitOZmx5U0ZwUDQ4eGY2U0NHWFcrbXZ6NVVabWlEMUErNkFlRlBmTktFd1lWZFB2OXN2aElaWlJ6cVQ4RTRNNCtaVUlxS202ZGplRHp1QmdGaEV4djNZNzZlNDd6OFhCa1p0SFV6aHptNlZPTW1rT2JualFlekdWTTBVdnlGbzVYWVZQbzhTQlo5TVBqd1NVbm9CUzB2T01Zb3BSdTBDM1BQR2NVSVFuZ1BncGF2WVRlTHpTWXZzU055WEwySnEvRUd4eWJUekYwN01Kek44VDN6SURUcE9FUjRUOGVGMEl6czVLcERSdFV6c1JLQjFwNm5RcnFmRFdTcE9VRDB1cXU1U3pPTE8vZkJrb1V5QWlWaldtMUFiNWxtSjZWMW4zRHJLazQzVVBMeTJ2MmFMWWZsMWR0QXFkSHBqY2dwaVdLQVptVCtBMU8zMFRLQlVQR3lnTlN5bW45ZGI2ZkJFQWphTG9USG9DS0QrR1RzNTgvTThpb3htM1NUd0F3K1FJUjAyV3RYTjJGM0JpQWV2Z1pGR0xRNEk3eVVvZ1RXdzh2VnFiY0pZWEZOclF2NDl0eVRBcjhRWnhpamIyM1p2Y01EM2ptcDBNbURoTGZza212T0d4WkdLeW9ERzk3b0k4cW1mbzFjQjVxMVUzSk1NSDFudEFiZTl6MWZFTVNOeVpCenVMV3QyQk9MTWU3akNQR0pYSThmKzUrcllmVGJEVlRxeldQK3lrN1pFSVF5TW9kcitoSlE2eEQ4Tm83Q255KzFpMlR0cU1wTGF5YlowUDVDRzlNQ0h6eHMwbHp6bjJiRVFyUmUxVlg5TUJ3NHVmNFFCeUZZZ1phUmN2NzdNdis1alV5QnQ0amhVd3dxdWp3eTRjL3VYdytQQU9iMHBsZ2s0SG8yUDcvUm10bmE0bnZBQWo2Rzl2cVBVS3pqTnh3RmRkRWxFb1ZERDUrK3Q3TnhhYVVXZzljRjhLRFJZU0M0enUxbXNXQXVYZFQ4aEd2Q1lmNjd4bTc1SVB1SnRtZ3FCWmpYUjg3b0NKb3h3aXZ5bzh0dHRxbUFaOFp4K0VCY1hqV2pLMzVKMzZvVFZ3U2JOcnFJYjZLbmpHbEZYSVN3clBORWkrUmtMb3RhU3lPU3ZuS251bERjM0doaEVYYXNCY3dEMElPNzNpZEk0YmlnR2F1bW9sSFF4QWVMRytVOUZycUY4dGdRT1dMenY0aHd3SlFHL2NpNE5GYmZISWpEVnM0bXM5WTdzQldUNkI1T1pNTzZyRE1wOUlsZG1Fcm1VUGE4ejU1ZVdqMDQ1YUxEQkt0Q1k5UHpXaHZXWHhqeTQ3SmxCU2ZETVBNVFhReHJ0T1B1SjRLSmo1V05xTlg3WXoxaTJMTm5weG5KbnltOWNsVTdGV1MrT2dUeTNBOWpYaTFCVXg0QjBHZzhXWUl4LzVBd0pzU0RPVC8yV0NpM09jRXhtUVRveVZrQ2p5UE55ZWNOck9GQmRQenowa1NaQjNJaFU4dW5OT1N0YytaNjdOZnF5K0kvRTlaVDczcUNCYVRJN1UxSFZxQzlsSnluUk1zbUZmMUdvbGNROG5DbXZvK0tPVTVtVkVzL2xvQThIZ3pWZWVNR043SkxaOFhJcUVkbnp5NHQyNlNRbTlobVY2ZDRiS2ZjQmk0MG9XNGZRUFdZRG1pWlorR1MrTDhuSnlYdzNBWkRIWkdKWEhFci85S096RFF0OVU0WVdpYS9NMTIrbFNyWmd5QmlrdWxnbnBBYmU0ZERpMUZMQTZMMUQzQjBIUlozRUdHamRRbng1R1hFZXhnNG9CVlQzS2dRbmpweXJrN0YzR0tQOUhGdnFLTUZ6VWJoL2RCV3k5bjRWc2JXUFlkSDdsSDFyVUg0YzdwN0lrWGc0VlREOE11MzV3b3ZORkErWkVBYmR3Z3o2dTR6NXZpZzhIcHNiUVpNVXZFVy91VE83cVU4UW56Z1o1NHRHcGl2YyszbnBhYnhSUTZSMDNpMHZYdDZCb0JJckFBMndxMmxzMTVSTXhleFZWczdYT25ORDRlcHFoMUJzR2pROC91ejZya1dRNVJFenNCeERxbXpZSTA1UXhYZlducUM2WVloWXpON1FQUzh0SGpYbGxsN0VzKzhVYzhzTytjRkE3REM3Y0hRbVZGaVpXN1NZYmFtTmFHc2FpY2VYTHE4Q3YveDJIZ21oUzYveU1qUFVFVkhoOTVZdHdhc25kT0p5NGdBbUlEWkh0d2RsOWxXY1ZDMDl4MUlBakt5UWlpQjRPLy9DcG9qZjFOUmNiUWF3VVBKMGI5ZXJyWDNFVWM3cU5Vc2NGMlpubXZVVThxM1g2UFVpb2p5TDVGMUFNdWJzcThuOTFmaG5FUmwrY2syQUJWYm9yeEhORlpSVXgvVlNYNHRMZzROUG1VcmhlalNoNXJZUkl6S3Q5OG9PNTBsTlEraS9RVkZUbmt6Ym9SUkkrS0NTM1o1bzJZZ0hlOGx2ZGhDeHYxZ3hjVGhRM21pd2dIeDdmR09LV1Myc2psSkxYanMxbm9raVowTEZ0NTIxaWYzKzFSYVZlRHpCU1hYRFFZVCtwbEI1S0M2L0ZOZEpDWW9mZGVTY0gwK0lHN2FyeWRyOUhUOU5SMXNHczZnc2JYQnNnWnViNXFKVmYzSisvQ3kra2FCYzByTEtyZ3UzZmlGUG1uMDdhWGdtK2xRVjBPVlVkaWVoNm5vQ0oxcHczT2VNdWJ0TU9rcmQyUWRFNEQ3T1ZoVithdUM5b1pIc09uQXhDYnZoYXovTTZYOEFaNXducHUvZVdwdDZ2WHBhWHpXVklJcVBET0NFMnRCSTcrNlNmTHdjVXFlYU5ZSVhtUlRwNnRUOGhhcDduZXpDZldqUGZxU2ZMVGljaFpEU1dlR2hYTXZWNTRCODJ2eWJoM1NBNXZCZDdwRnkzWTlxYnNCaHZDbHRKWmwzK044OXNnbTNJWElyeU5MT3JmL3VUMVJ0NDRrVDNleFM5N3FCWVpteGZXZW5PeUxqOHAxZGJlSjd6MlFxeE1xZXRia3FOUHBucnduMUFMV3VkSU5ZOGhLYnJYS0RDQmhWMmNQTkg3VWdTcnZYVFV2T1UxRnVyQ0FGRThSa09vcWxobUZ4SXRRUHUzNWd4MWFqaVFBTkMxQllTdlkvZzZyL2lLMHRlekFoRGNtaW4xVWF3Qk1qMkZHK2M4ZXdCYzVVbzN6ZUNIdERYVnlsSlY3UUdGVGZZR0JOWmlKUXJkYnFXRmEra01tdjRJUWYzSjY5bjBEeVNwRTJVY0h5dlFKQ3d0czlUN3NMU2h6WWFNVFVKUUFmOHhwcjBXKzVac3NHMjhJcXFsSTNkbUFpM0dQa2REblE3c0ZiNXBWSVVFVHRUQm9kMEp3K0U1UGgvY0Evbk9FbHpRYXRXUmUxWCs3NFl0bzdZSWJBRW56NW1YSGlva1hnTkVzbEdUWXhzWUo5QVBWOSt4WjVKTk1VWFl0OGhrVHBwaFBzN0FlazFpOXhsMW5sbm5FYnY0M3hnM2VMYTRySDBBcy8wTE9GK01yV2Z0aDBoWnQxanJCb05ycmNHOG1WWVJyd29YaXFIS3NSZTRVYTQ4a0YvRXVRWFZKeUZPV05KNUJjYW9xOSswa3lJdnVoeVhxNS9UL0tJTG12cFpTMzZINHJ1bFJhRm1Hb29sejBtaUl4V2FrdHFpUjF1VjhYaWtiekZFUzR2cGV5NHVKMWVBZjUyRCszL2NLY0V6V2E2KzU2VGRFQ0VKQWExWDl2Ni83UzFDZlBxaVkwN1lNMXZXdXNHcEhPQ0FSTFBDWGZ5V2ZXQytVSThPM1FkSEhRaC9XNXpzZ3RFWnVhYWhkWk9lY2VsQmtnS0NIZ1o4NTFpN2IvY25EN2VsRHlCVGJuNHFKRWhSWVRLWUNRZW82SEpFd1N5b3NhOVJrU0lpQklBaGVHaTlSRWJYY2xMY1JnR3FoMXp5Qi9JUHFmMUtXOXFMbzhzaU9wRUlUU3BOeks3NSttMlc0L2c4TjJLTGgvb1MyeGEyTXZGU0pTemdZZmpwYjlOK3pVeE5XR0xjZDVQR2J6STdkYW4yY2tKSmE2UkhLRG1WTWtqYW1ZTHh6M0ZKK29SdUFhTzFpcjMzWGViSGV6ZHErQjRKT2FweVhleGs4M1hIbG1kS211UTg1aWdqRmZPVElHMmFJc2FXcTdDL0ppZmdyK0pqdVRoSm55TVdyYkNSRTV2VkZ0MEdJYWlvR1NsYktIM1RYUnhaK0tXdXozZ3ErWXIzSWNrT1RIRUgwR0FERy9pc2lQSWV4bHJHNmRZaW43V20vUGVkRGVzd0t5TFlwVFMxejNzVGVTSXRFbXpZSERNRURzS0FsNVh5anZOalJvNzg5OHVhRW5pMWIraWpCc2p5b01EY0RFaHcxZzhseWpIZldrSjRwRitIWGpuMzJBak9qb0ZuNVIrcWM1ZWpsTVVxV0N1OUU0UWJTZWtWbmcwSW02OG9naWF5WVVDQTlZQklSd0Y5b3l2REZ5WGRJblhFOFFsZDRkYks2dUpwM2xzbERkclNWczBZQTdxRnBQY0MrWWdFZnBEa2NraXVjR2RINTFWaHYrMmJNWEpabmdNMTU0Sm0rcUJ4MGhOd1R0K1AyMGZ6ZlpueDh2TEM5c3RxZUxPVm9lNFhlZzhQS01TdFQ1ei9yRGQrZk1nTVB2MHd5bWVybEM5ajJ4L0tMYnRTQmtNa0hkTXZjWVY0cjhJNkFCV0tvNE50QmhTYk8wdUcreDUwbjdkOTFhb1R1ZmhrM3plajV1dEM0ZElGRmdFMkZXMmdvcldzSTBBT0huVXJadlgrYmJxYmFZUFMyT05XSW9wcW1hVVUrVXZPUzcwM2Q4WWtjSGFyaTdFREE1dVFKVG5xT1I1YkpieFk3U0hjWEVmMFZFeldpcGgrL0FKMmYvSzJUVUhoNjZZMnpqdnM4cHdKZURKRUQ0U080OEZHMEtOTjk3UzN5NEJMdz09PC94ZW5jOkNpcGhlclZhbHVlPjwveGVuYzpDaXBoZXJEYXRhPjwveGVuYzpFbmNyeXB0ZWREYXRhPjwvc2FtbDI6RW5jcnlwdGVkQXNzZXJ0aW9uPjwvc2FtbDJwOlJlc3BvbnNlPg==' }
      }, function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should be valid signature', function(){
      expect(r.statusCode)
            .to.equal(200);
    });

    it('should return a valid user', function(){
      var user = JSON.parse(bod);
      expect(user['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'])
          .to.equal('_89841b346092548fd44097a1e7c426a4');
      expect(user['urn:oid:2.5.4.4'])
          .to.equal('Müller');
    });
  });

  describe.skip('SAMLResponse with signed assertion and "ds" prefix defined only at the root of the SAMLResponse', function () {
    var r, bod;

    // samlResponse was not properly generated
    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5051/callback/samlp-with-dsig-at-root',
        form: { SAMLResponse: 'PHNhbWxwOlJlc3BvbnNlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIiB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBJRD0iX2ViMGQ0MzZkNzQyMTAyMmE0ZWZmIiBJblJlc3BvbnNlVG89Il8yTjVHR3Aybm1JVENGYmN5R1NLamFRM2FpNkt4OWNBd0RoQkdYMWdBSnl2Q3JsSnZvRVFkakVnVHNmYWpnTTltN2oudy5JOUZ6MWRkVmpaOWxLWkNoY3NwdHA5a3hrQ3VxY3diZU5lLmxKeVZRcEI4aVNhNGF3RllzajlBNXI3UkViNUpwSEg3MkI2ZmVndUhGRlBFOE1hazN1NGhTRUtsOV84bW9pWExkQTU3V1ZoendhOFhZeG40bURzaFNwM1hiMFBFWktPREhNdHhsVlhheWNHWXVNZ0MyMEdwZkNBIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNi0wMi0wMVQyMjoyNDo1MloiIERlc3RpbmF0aW9uPSJodHRwczovL2F1dGgwLWRldi1lZC5teS5zYWxlc2ZvcmNlLmNvbSI+PHNhbWw6SXNzdWVyIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPnVybjpmaXh0dXJlLXRlc3Q8L3NhbWw6SXNzdWVyPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBWZXJzaW9uPSIyLjAiIElEPSJfSW40RjVGbmlPNDV5TkxaVTRrTTdibTZOTHRyYVV3c0oiIElzc3VlSW5zdGFudD0iMjAxNi0wMi0wMVQyMjoyNDo1Mi40MzlaIj48c2FtbDpJc3N1ZXI+dXJuOmZpeHR1cmUtdGVzdDwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxkczpSZWZlcmVuY2UgVVJJPSIjX0luNEY1Rm5pTzQ1eU5MWlU0a003Ym02Tkx0cmFVd3NKIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48ZHM6RGlnZXN0VmFsdWU+TGJjL2NSanIxVjBIUzZaQTVWTzR5cTdUTXZIK0g4eURqdzJjU0lHMU9ZYz08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+ZzlibGRydDlVTks0bU5NbEl2bFhQSzFUa2ZZaStHUXlwTThzTHE1Z2VkQmZSMDU2cW1qUnpLckRzOEhYMHdVMXZKaDN6cnNOcHcwR055aVkvamlhOGpQQkJkc3dqTHBDTTUzNDF5aVRyNXFDNzhvRFk0ZGNZOTZCN1N5UCs3VXI2MVNGbTNOUWtrUDd6QnFUYnZycW9vWHU1RVBNUjdSMHozdEptZ25BZnpDbytvS3h3bEE2cmF0d2xXWldQQmtYRzVmYmM5MEtIZnhaS2ZLOGVWTlRRajJUTmlrYzZaaFFsWEI5aG05ekNqMDNoRjNlL29vV1NTaUNlOUwvM0RmSENpbk1jU2ozMjJLc1dOZmNBVEI4dWVwcncvWll3OUFwYmRld2hUcyt5NFlGdGNzQktpei83ZUlmTmJHcERQTUtVN3lxeEFVR2w2WmJ1TmNON2dlN2h3PT08L2RzOlNpZ25hdHVyZVZhbHVlPjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUVEekNDQXZlZ0F3SUJBZ0lKQUxyOUh3Z3JRN0dlTUEwR0NTcUdTSWIzRFFFQkJRVUFNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaREFlRncweE1qRXlNamt4TlRNd05EZGFGdzB4TXpBeE1qZ3hOVE13TkRkYU1HSXhHREFXQmdOVkJBTVREMkYxZEdnd0xtRjFkR2d3TG1OdmJURVNNQkFHQTFVRUNoTUpRWFYwYURBZ1RFeERNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1YyRnphR2x1WjNSdmJqRVFNQTRHQTFVRUJ4TUhVbVZrYlc5dVpEQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1aaVZtTkhpWExsZHJnYlM1ME9OTk9IN3BKMnpnNk9jU01rWVpHRFpKYk9aL1Rxd2F1QzZKT25JNyt4dGtQSnNRSFpTRkpzNFUwc3JqWkt6RENtYXoyakxBSkRTaFAyamFYbHJraTE2bkRMUEUvL0lHQWczQkpndVNtQkNXcERiU205MlY5aFNzRStNaHg2YkRhSml3OHlRK1E4aVNtMGFUUVp0cDZPNElDTXUwMEVTZGg5TkpxSUVDRUx2UDMxQURWMVhoajdJYnl5VlBERnhNdjNvbDVCeVNFOXd3d09GVXEvd3Y3WHo5TFJpVWpVelBPK0xxM09NM28vdUNEYms3akQ3WHJHVXVPeWRBTEQ4VUxzWHA0RXVETytuRmJlWEIvaUtuZFp5bnVWS29raXJ5d2wybkQySVAwL3luY2RMUVo4QnlJeXFQM0c4MmZxL2w4cDdBc0NBd0VBQWFPQnh6Q0J4REFkQmdOVkhRNEVGZ1FVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBZd2daUUdBMVVkSXdTQmpEQ0JpWUFVSEkyclVYZUJqVHYxekFsbGFQR3JIRmNFSzBhaFpxUmtNR0l4R0RBV0JnTlZCQU1URDJGMWRHZ3dMbUYxZEdnd0xtTnZiVEVTTUJBR0ExVUVDaE1KUVhWMGFEQWdURXhETVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNCTUtWMkZ6YUdsdVozUnZiakVRTUE0R0ExVUVCeE1IVW1Wa2JXOXVaSUlKQUxyOUh3Z3JRN0dlTUF3R0ExVWRFd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBRnJYSWhDeTRUNGVHcmlrYjBSMndIdi91UzU0OHIzcFp5QlYwQ0RiY1J3QXRibnBKTXZrR0ZxS1ZwNHBteW9JRFNWTksvaitzTEVzaEIyMFhmdGV6SFp5UkpiQ1VidEt2WFE2RnN4b2VaTWxOMElUWUtUYW9CWktoVXh4ajkwb3RBaE5DNThxd0dVUHF0Mkxld0poSHlMdWNLa0dKMW1RM2I1eEtaNTMyVG91Zm91SDlWTGhpZzNIMUtueFdvL3pNRDZLZThjQ2s2cU85aHR1aEkwNnMzR1FHUzFRV1F0QW1tMTdDNlRmS2dEd1FGWndocUhVVVpud0tSSDhnVTZPZ1pzdmhnVjFCN0g1bWpaY3U1N0tNaURCZWtVOU1FWTBEQ1ZUTjNXa21jVElJNjY4ekxzSnJrTlg2UEVmY2sxQU1CYlZFNnBFVUtjV3dxM3VhTHZsQVVvPTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9kczpLZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxzYW1sOlN1YmplY3Q+PHNhbWw6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6dW5zcGVjaWZpZWQiPjEyMzQ1Njc4PC9zYW1sOk5hbWVJRD48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90T25PckFmdGVyPSIyMDE2LTAyLTAxVDIzOjI0OjUyLjQzOVoiIEluUmVzcG9uc2VUbz0iXzJONUdHcDJubUlUQ0ZiY3lHU0tqYVEzYWk2S3g5Y0F3RGhCR1gxZ0FKeXZDcmxKdm9FUWRqRWdUc2ZhamdNOW03ai53Lkk5RnoxZGRWalo5bEtaQ2hjc3B0cDlreGtDdXFjd2JlTmUubEp5VlFwQjhpU2E0YXdGWXNqOUE1cjdSRWI1SnBISDcyQjZmZWd1SEZGUEU4TWFrM3U0aFNFS2w5Xzhtb2lYTGRBNTdXVmh6d2E4WFl4bjRtRHNoU3AzWGIwUEVaS09ESE10eGxWWGF5Y0dZdU1nQzIwR3BmQ0EiLz48L3NhbWw6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWw6U3ViamVjdD48c2FtbDpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxNi0wMi0wMVQyMjoyNDo1Mi40MzlaIiBOb3RPbk9yQWZ0ZXI9IjIwMTYtMDItMDFUMjM6MjQ6NTIuNDM5WiI+PHNhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48c2FtbDpBdWRpZW5jZT5odHRwczovL2F1dGgwLWRldi1lZC5teS5zYWxlc2ZvcmNlLmNvbTwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIj48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvbmFtZWlkZW50aWZpZXIiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czphbnlUeXBlIj4xMjM0NTY3ODwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czphbnlUeXBlIj5qZm9vQGdtYWlsLmNvbTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6YW55VHlwZSI+Sm9obiBGb288L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZ2l2ZW5uYW1lIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6YW55VHlwZSI+Sm9objwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9zdXJuYW1lIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6YW55VHlwZSI+Rm9vPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9zYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMTYtMDItMDFUMjI6MjQ6NTIuNDM5WiI+PHNhbWw6QXV0aG5Db250ZXh0PjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOnVuc3BlY2lmaWVkPC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPjwvc2FtbDpBdXRobkNvbnRleHQ+PC9zYW1sOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDpBc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4=' }
      }, function(err, response, body) {
        if(err) return done(err);
        r = response;
        bod = body;
        done();
      });
    });

    it('should be valid signature', function(){
      expect(r.statusCode)
            .to.equal(200);
    });
  });

  describe('invalid SAMLResponse in POST', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5051/callback',
        form: { SAMLResponse: 'foo' }
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

  describe('samlp request', function () {
    describe('HTTP-Redirect', function () {
      var r, bod;

      before(function (done) {
        request.get({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5051/login'
        }, function (err, resp, b){
          if(err) return done(err);
          r = resp;
          bod = b;
          done();
        });
      });

      it('should redirect to idp', function(){
        expect(r.statusCode)
              .to.equal(302);
      });

      it('should have SAMLRequest querystring', function(done){
        expect(r.headers.location.split('?')[0])
              .to.equal(server.identityProviderUrl);
        var querystring = qs.parse(r.headers.location.split('?')[1]);
        expect(querystring).to.have.property('SAMLRequest');
        var SAMLRequest = querystring.SAMLRequest;

        zlib.inflateRaw(new Buffer(SAMLRequest, 'base64'), function (err, buffer) {
          if (err) return done(err);
          var request = buffer.toString();
          var doc = new xmldom.DOMParser().parseFromString(request);

          expect(doc.documentElement.getAttribute('ProtocolBinding'))
            .to.equal('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');

          expect(doc.documentElement.getAttribute('Version'))
            .to.equal('2.0');

          expect(doc.documentElement.getElementsByTagName('saml:Issuer')[0]
                                    .getAttribute('xmlns:saml'))
            .to.equal('urn:oasis:names:tc:SAML:2.0:assertion');

          done();
        });
      });

      it('should have RelayState querystring', function(){
        expect(r.headers.location.split('?')[0])
              .to.equal(server.identityProviderUrl);
        var querystring = qs.parse(r.headers.location.split('?')[1]);
        expect(querystring).to.have.property('RelayState');
        expect(querystring.RelayState).to.equal(server.relayState);
      });
    });

    describe('HTTP-POST', function () {
      var r, bod, $;

      before(function (done) {
        request.get({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5051/login-http-post'
        }, function (err, resp, b){
          if (err) return done(err);
          r = resp;
          bod = b;
          $ = cheerio.load(bod);
          done();
        });
      });

      it('should post to idp', function(){
        expect(r.statusCode).to.equal(200);
        expect(r.headers['content-type']).to.equal('text/html');
        expect(r.headers['content-type']).to.equal('text/html');
        expect($('form').attr('action')).to.equal('http://localhost:5051/samlp');
      });

      it('should have SAMLRequest input', function (done) {
        var SAMLRequest = $('form input[name="SAMLRequest"]').val();
        expect(SAMLRequest).to.be.ok;

        var doc = new xmldom.DOMParser().parseFromString(new Buffer(SAMLRequest, 'base64').toString());
        expect(doc.documentElement.getAttribute('ProtocolBinding'))
          .to.equal('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');

        expect(doc.documentElement.getAttribute('Version'))
          .to.equal('2.0');

        expect(doc.documentElement.getElementsByTagName('saml:Issuer')[0]
                                  .getAttribute('xmlns:saml'))
          .to.equal('urn:oasis:names:tc:SAML:2.0:assertion');

        done();
      });

      it('should have RelayState input', function(){
        var RelayState = $('form input[name="RelayState"]').val();
        expect(RelayState).to.be.ok;
        expect(RelayState).to.equal(server.relayState);
      });
    });
  });

  describe('samlp request with custom xml', function () {
    var r, bod;

    before(function (done) {
      request.get({
        jar: request.jar(),
        followRedirect: false,
        uri: 'http://localhost:5051/login-custom-request-template'
      }, function (err, resp, b){
        if(err) return done(err);
        r = resp;
        bod = b;
        done();
      });
    });

    it('should redirect to idp', function(){
      expect(r.statusCode)
            .to.equal(302);
    });

    it('should have SAMLRequest querystring', function(done){
      expect(r.headers.location.split('?')[0])
            .to.equal(server.identityProviderUrl);
      var querystring = qs.parse(r.headers.location.split('?')[1]);
      expect(querystring).to.have.property('SAMLRequest');
      var SAMLRequest = querystring.SAMLRequest;

      zlib.inflateRaw(new Buffer(SAMLRequest, 'base64'), function (err, buffer) {
        if (err) return done(err);
        var request = buffer.toString();
        var doc = new xmldom.DOMParser().parseFromString(request);

        expect(doc.documentElement.getAttribute('Protocol'))
          .to.equal('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');

        expect(doc.documentElement.getAttribute('Version'))
          .to.equal('3.0');

        expect(doc.documentElement.getAttribute('Foo'))
          .to.equal('123');

        expect(doc.documentElement.getAttribute('Issuertico'))
          .to.equal('https://auth0-dev-ed.my.salesforce.com');

        done();
      });

    });

  });

  describe('samlp request with idp url containing querystring', function () {
    var r, bod;

    before(function (done) {
      request.get({
        jar: request.jar(),
        followRedirect: false,
        uri: 'http://localhost:5051/login-idp-with-querystring'
      }, function (err, resp, b){
        if(err) return done(err);
        r = resp;
        bod = b;
        done();
      });
    });

    it('should redirect to idp', function(){
      expect(r.statusCode)
            .to.equal(302);
    });

    it('should have SAMLRequest and foo in querystring', function(){
      expect(r.headers.location.split('?')[0])
            .to.equal(server.identityProviderUrl);
      var querystring = qs.parse(r.headers.location.split('?')[1]);
      expect(querystring).to.have.property('SAMLRequest');
      expect(querystring).to.have.property('foo');
    });

  });

  describe('samlp with signed request', function () {
    describe('POST binding', function () {
      var r, bod, $;

      before(function (done) {
        request.get({
          jar: request.jar(),
          uri: 'http://localhost:5051/login-signed-request-post'
        }, function (err, resp, b){
          if(err) return callback(err);
          r = resp;
          bod = b;
          $ = cheerio.load(bod);          
          done();
        });
      });

      it('should return 200 with form element', function(){
        expect(r.statusCode)
              .to.equal(200);
      });

      it('should have signed SAMLRequest with valid signature', function(done){
        var signedSAMLRequest = $('form input[name="SAMLRequest"]').val();
        var signedRequest = new Buffer(signedSAMLRequest, 'base64').toString();
        var signingCert = fs.readFileSync(__dirname + '/test-auth0.pem');

        expect(utils.isValidSignature(signedRequest, signingCert))
          .to.equal(true);

        done();
      });

      it('should show issuer before signature', function(done){
        var signedSAMLRequest = $('form input[name="SAMLRequest"]').val();
        var signedRequest = new Buffer(signedSAMLRequest, 'base64').toString();
        var doc = new xmldom.DOMParser().parseFromString(signedRequest);
        
        // First child has to be the issuer
        expect(doc.documentElement.childNodes[0].nodeName).to.equal('saml:Issuer');
        // Second child the signature
        expect(doc.documentElement.childNodes[1].nodeName).to.equal('Signature');
        done();
      });
    });

    describe('without deflate', function () {
      var r, bod;

      before(function (done) {
        request.get({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5051/login-signed-request-without-deflate'
        }, function (err, resp, b){
          if(err) return callback(err);
          r = resp;
          bod = b;
          done();
        });
      });

      it('should redirect to idp', function(){
        expect(r.statusCode)
              .to.equal(302);
      });

      it('should have signed SAMLRequest with valid signature', function(done){
        expect(r.headers.location.split('?')[0])
              .to.equal(server.identityProviderUrl);
        var querystring = qs.parse(r.headers.location.split('?')[1]);
        expect(querystring).to.have.property('SAMLRequest');
        expect(querystring.RelayState).to.equal('somestate');

        var signedSAMLRequest = querystring.SAMLRequest;
        var signedRequest = new Buffer(signedSAMLRequest, 'base64').toString();
        var signingCert = fs.readFileSync(__dirname + '/test-auth0.pem');

        expect(utils.isValidSignature(signedRequest, signingCert))
          .to.equal(true);
        done();
      });
    });

    describe('with deflate', function () {
      var r, bod;

      before(function (done) {
        request.get({
          jar: request.jar(),
          followRedirect: false,
          uri: 'http://localhost:5051/login-signed-request-with-deflate'
        }, function (err, resp, b){
          if(err) return callback(err);
          r = resp;
          bod = b;
          done();
        });
      });

      it('should redirect to idp', function(){
        expect(r.statusCode)
              .to.equal(302);
      });

      it('should have signed SAMLRequest with valid signature', function(done){
        expect(r.headers.location.split('?')[0])
              .to.equal(server.identityProviderUrl);
        var querystring = qs.parse(r.headers.location.split('?')[1]);
        expect(querystring).to.have.property('SAMLRequest');
        expect(querystring).to.have.property('Signature');
        expect(querystring.RelayState).to.equal('somestate');
        expect(querystring.SigAlg).to.equal('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');

        var signingCert = fs.readFileSync(__dirname + '/test-auth0.pem');

        var signedParams = {
          SAMLRequest: querystring.SAMLRequest,
          RelayState: querystring.RelayState,
          SigAlg: querystring.SigAlg
        };

        var verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(require('querystring').stringify(signedParams));
        var verified = verifier.verify(signingCert, querystring.Signature, 'base64');

        expect(verified).to.equal(true);
        done();
      });
    });
  });
});

describe('samlp (unit tests)', function () {

  describe('extractAssertion', function () {

    var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_0d2a510bffbb012bbc30" InResponseTo="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_241siKCvX3e3oRGYtkdcV4DfGDtIsVk4" IssueInstant="2014-02-25T15:20:20.535Z"><saml:Issuer>urn:fixture-test</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">12345678</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2014-02-25T16:20:20.535Z" InResponseTo="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2014-02-25T15:20:20.535Z" NotOnOrAfter="2014-02-25T16:20:20.535Z"><saml:AudienceRestriction><saml:Audience>https://auth0-dev-ed.my.salesforce.com</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"><saml:AttributeValue xsi:type="xs:anyType">12345678</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue xsi:type="xs:anyType">jfoo@gmail.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue xsi:type="xs:anyType">John Foo</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"><saml:AttributeValue xsi:type="xs:anyType">John</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"><saml:AttributeValue xsi:type="xs:anyType">Foo</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthnStatement AuthnInstant="2014-02-25T15:20:20.535Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_0d2a510bffbb012bbc30"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>YkV3DdlEa19Gb0eE3jTYTVPalV1kZ88fbIv4blO9T1Y=</DigestValue></Reference></SignedInfo><SignatureValue>ZiINpNlahQlp1JbgFsamI1/pZ+zcPsZboESVayxBMtrUBYNC4IG2VBnqku7paDxJQ7624CvcNzAYWYCv/2/c67Bv6YhQwK1rb4DPEL6OvbI8FNkYAhTNNw5UhUTEMjnJ7AncV/svUTYyIOyktuCvQh3tR4teZJV+BM3IKj9vRQQbCRNSUVHJEe963ma5HcCyo+RhIKU1pm4+ycswOlY9F115roKB4RNRJLs7Z5fyzhbOoCUujR9MMKHHq+CWaYvh5SkjaH1wMorlPlJtq5dhTZtDRhj4HwxYpCG5b4NF2vp+Jpni4dDFKou0Lzk0k6ueCJGcNHfidfEB3RB20Hed2g==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</X509Certificate></X509Data></KeyInfo></Signature></samlp:Response>';
    var samlpReponseWithEncryptedAssertion = '<samlp:Response ID="_66a4b25c-2d88-492e-a730-7ea462cdd9ba" Version="2.0" IssueInstant="2014-02-11T15:44:44.598Z" Destination="https://fmi-test.auth0.com/login/callback" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_d4f0e231c8b038213f27" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" > <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://adfs.fmi.ch/adfs/services/trust</Issuer> <samlp:Status> <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /> </samlp:Status> <EncryptedAssertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"> <xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" > <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" /> <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"> <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#"> <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"> <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /> </e:EncryptionMethod> <KeyInfo> <ds:X509Data xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> <ds:X509IssuerSerial> <ds:X509IssuerName>CN=fmi-test.auth0.com</ds:X509IssuerName> <ds:X509SerialNumber>17575331292066593326</ds:X509SerialNumber> </ds:X509IssuerSerial> </ds:X509Data> </KeyInfo> <e:CipherData> <e:CipherValue>PfbLmL7Eb2NL5lzxyuEuKolgDtHjAuVDV9AaDKp1UqxSKXPGQaF3FTFt7Gl7FRmEdfjMD4xyMII4c6itasV7/N1WIXVw6j9VpvBZ2WPH4lT2gHVXEnCSko+rlk0OfFQN/XFY1HZrPb0PeSYtbuR6Fe2KDLVYYSElrGyn9lbU/zgLB+cV3OiidMamymcTjBYxr3+wv8zhEl2jDYd/04wULeDydhNpA8KFzjy/DQwE4GwlOfuCCtZboai1OXA3++KEuwH2QrC5lRpmnpwV1OJj+ozWDmJrRLA/vpxakQfMzjBcMoBx5wy0dvDaXcjMZk2aaOUhydSC+vd5UYD3npVlog==</e:CipherValue> </e:CipherData> </e:EncryptedKey> </KeyInfo> <xenc:CipherData> <xenc:CipherValue>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</xenc:CipherValue> </xenc:CipherData> </xenc:EncryptedData> </EncryptedAssertion> </samlp:Response>';

    it('should returns assertion', function (done) {
      var samlp = new Samlp({});
      samlp.extractAssertion(samlpResponse, function (err, assertion) {
        if (err) { done(err); }

        var doc = new xmldom.DOMParser().parseFromString(assertion.toString());
        var attributes = doc.documentElement.getElementsByTagName('saml:Attribute');
        expect(attributes.length).to.equal(5);
        expect(attributes[0].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier');
        expect(attributes[0].firstChild.textContent).to.equal('12345678');
        expect(attributes[1].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress');
        expect(attributes[1].firstChild.textContent).to.equal('jfoo@gmail.com');
        expect(attributes[2].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name');
        expect(attributes[2].firstChild.textContent).to.equal('John Foo');
        expect(attributes[3].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname');
        expect(attributes[3].firstChild.textContent).to.equal('John');
        expect(attributes[4].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname');
        expect(attributes[4].firstChild.textContent).to.equal('Foo');
        done();
      });
    });

    it('should throws error if EncryptedAssertion is present but options.encryptionKey was not specified', function (done) {
      var samlp = new Samlp({});
      samlp.extractAssertion(samlpReponseWithEncryptedAssertion, function (err) {
        expect(err.message).to.equal('Assertion is encrypted. Please set options.decryptionKey with your decryption private key.');
        done();
      });
    });

    it('should returns decrypted assertion', function (done) {
      var samlp = new Samlp({
        decryptionKey: fs.readFileSync(__dirname + '/test-decryption.key')
      });

      samlp.extractAssertion(samlpReponseWithEncryptedAssertion, function (err, assertion) {
        if (err) { done(err); }

        var doc = new xmldom.DOMParser().parseFromString(assertion.toString());
        var attributes = doc.documentElement.getElementsByTagName('Attribute');
        expect(attributes.length).to.equal(8);
        expect(attributes[0].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress');
        expect(attributes[1].getAttribute('Name')).to.equal('urn:oid:0.9.2342.19200300.100.1.3');
        expect(attributes[2].getAttribute('Name')).to.equal('urn:oid:2.16.756.1.2.5.1.1.4');
        expect(attributes[2].firstChild.textContent).to.equal('fmi.ch');
        expect(attributes[3].getAttribute('Name')).to.equal('urn:oid:2.16.756.1.2.5.1.1.5');
        expect(attributes[3].firstChild.textContent).to.equal('others');
        expect(attributes[4].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname');
        expect(attributes[4].firstChild.textContent).to.equal('Pan');
        expect(attributes[5].getAttribute('Name')).to.equal('urn:oid:2.5.4.4');
        expect(attributes[5].firstChild.textContent).to.equal('Pan');
        expect(attributes[6].getAttribute('Name')).to.equal('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname');
        expect(attributes[6].firstChild.textContent).to.equal('Peter');
        expect(attributes[7].getAttribute('Name')).to.equal('urn:oid:2.5.4.42');
        expect(attributes[7].firstChild.textContent).to.equal('Peter');
        done();
      });
    });

  });

  describe('validateSamlResponse', function(){
    var samlpResponseWithStatusResponder = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusResponderWithMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/><samlp:StatusMessage>specific error message</samlp:StatusMessage></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusResponderAndAuthnFailed = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" /></samlp:StatusCode></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusResponderAndAuthnFailedWithMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" /></samlp:StatusCode><samlp:StatusMessage>specific error message</samlp:StatusMessage></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusRequesterWithMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"><samlp:StatusMessage>signature required</samlp:StatusMessage></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusRequesterWithoutMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusVersionMismatchWithMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"><samlp:StatusMessage>version mismatch error</samlp:StatusMessage></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusVersionMismatchWithoutMessage = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"></samlp:Status></samlp:Response>';
    var samlpResponseWithStatusNotMappedStatus = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" IssueInstant="2014-02-25T15:20:20Z" Destination="https://auth0-dev-ed.my.salesforce.com"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>';

    it('shuold return error for AuthnFailed status with generic message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderAndAuthnFailed, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('The responding provider was unable to successfully authenticate the principal');
        done();
      });
    });

    it('shuold return error for AuthnFailed status with specific message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderAndAuthnFailedWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('specific error message');
        done();
      });
    });

    it('should return error for Responder status with generic message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusResponder, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('The request could not be performed due to an error on the part of the SAML responder or SAML authority');
        done();
      });
    });

    it('should return error for Responder status with specific message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('specific error message');
        done();
      });
    });

    it('should return error for Requester status with specific message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusRequesterWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('signature required');
        done();
      });
    });

    it('should return error for Requester status with default message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusRequesterWithoutMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('The request could not be performed due to an error on the part of the requester');
        done();
      });
    });

    it('should return error for VersionMismatch status with specific message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusVersionMismatchWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('version mismatch error');
        done();
      });
    });

    it('should return error for VersionMismatch status with default message', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusVersionMismatchWithoutMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('AuthenticationFailedError');
        expect(err.message).to.equal('The SAML responder could not process the request because the version of the request message was incorrect.');
        done();
      });
    });

    it('should return \'saml response does not contain an Assertion element\' error', function(done){
      var samlp = new Samlp({ checkDestination: false });
      samlp.validateSamlResponse(samlpResponseWithStatusNotMappedStatus, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error');
        expect(err.message).to.equal('saml response does not contain an Assertion element (Status: urn:oasis:names:tc:SAML:2.0:status:Success)');
        done();
      });
    });

    it.skip('should return error for Destination does not match', function(done){
      var samlp = new Samlp({ destinationUrl: 'invalid' });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error');
        expect(err.message).to.equal('Destination endpoint https://auth0-dev-ed.my.salesforce.com did not match invalid');
        done();
      });
    });

    it('should return error for if isValidResponseID fails', function(done){
      var samlp = new Samlp({ destinationUrl: 'invalid', isValidResponseID: function(samlResponseID, done) {
        return done(new Error('Invalid response id'))
      } });
      samlp.validateSamlResponse(samlpResponseWithStatusResponderWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error');
        expect(err.message).to.equal('Invalid response id');
        done();
      });
    });

    it('should return error for if isValidInResponseTo fails', function(done){
      var samlp = new Samlp({ destinationUrl: 'invalid', isValidInResponseTo: function(inReponseTo, done) {
        return done(new Error('Invalid inResponseTo'))
      } });

      samlp.validateSamlResponse(samlpResponseWithStatusResponderWithMessage, function (err) {
        expect(err).to.be.ok;
        expect(err.name).to.equals('Error');
        expect(err.message).to.equal('Invalid inResponseTo');
        done();
      });
    });

    it('should return profile even if the namespace is in respsonse element', function(done){
       var cert = fs.readFileSync(__dirname + '/test-auth0.cer');
       var samlResponse = `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:enc="http://www.w3.org/2001/04/xmlenc#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Destination="https://avillachlab.auth0.com/login/callback?connection=CHOP" ID="pfx2ba35038-7fff-f9c0-c9bc-1462e1455a76" IssueInstant="2016-08-10T19:20:28Z" Version="2.0"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://cidmfed.chop.edu/oam/fed</saml:Issuer><ds:Signature>
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx2ba35038-7fff-f9c0-c9bc-1462e1455a76"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>wFK//X7GAw5PBQHntPWb8OThZEE=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>tIb8Z6OWq1T0sws6JFdAbUR6FEBk3I7NkXgk5wCt42tMjPq343j8aj1xwJqsbYvLTvAtxEgmohgxvcJ7oADiqXBgDQ6HJNxe3U6q3NGO6Q7XhmtHMFN+bf+BlT7Hll6Ma11BfYNi6rKnROqJTL6ezm53jLNnqk9En/GYwcAKmGI1C1xlJ9cQDuHzA6w57TexdAOXnBVMi50oAoAG8taUDWtppQwfuuCF+D7Nz5QoUNUKE/ExtTjriBg04RXv6gFTKqYbeb4qDMIqf6hgpVd1xroZipGfQhuHocjoUKQSfSP8BDYDTZoxVIiEBUHP8RRK5Xof45x0+fYj1+O7kg8VpA==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="id-Y-RwHi6RP8jMUR8kr1FVzHuNvburOIeK6wGpNjd-" IssueInstant="2016-08-10T19:20:28Z" Version="2.0"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://cidmfed.chop.edu/oam/fed</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">HankeeJ@email.chop.edu</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2016-08-10T19:25:28Z" Recipient="https://avillachlab.auth0.com/login/callback?connection=CHOP"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2016-08-10T19:20:28Z" NotOnOrAfter="2016-08-10T19:25:28Z"><saml:AudienceRestriction><saml:Audience>urn:auth0:avillachlab:CHOP</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2016-08-10T19:20:28Z" SessionIndex="id-vMW-3rK-vReoeuOd5AtV8Jb-QQ4CmQ0zG45fTYJ1" SessionNotOnOrAfter="2016-08-10T20:20:28Z"><saml:AuthnContext><saml:AuthnContextClassRef>LDAPScheme_GRIN</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>`;
       var options = {
        cert: cert,
        thumbprint: '5CA6E1202EAFC0A63A5B93A43572EB2376FED309',
        checkExpiration: false,
        realm: 'urn:auth0:avillachlab:CHOP'
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });
    
    it('should return profile even if the namespace is in respsonse element and assertion is signed', function(done){
       var cert = fs.readFileSync(__dirname + '/test-auth0.cer');
       var samlResponse = `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:enc="http://www.w3.org/2001/04/xmlenc#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Destination="https://avillachlab.auth0.com/login/callback?connection=CHOP" ID="pfx0bd7e842-6bf5-618a-c910-2e9504eed82f" IssueInstant="2016-08-10T19:20:28Z" Version="2.0"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://cidmfed.chop.edu/oam/fed</saml:Issuer><ds:Signature>
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx0bd7e842-6bf5-618a-c910-2e9504eed82f"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>rbOfDvvLSUqfujYcW1b0L8alwf0=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>MYHsKJvyvkDeA8w485PV4QbQszIQoTeWb+LdRkk9xofVgF325wPnBM7rF+MeZ9ft13nhuW3JpmhKLJnWeQzzpDCxJe8yW1DyE/kHz+FEMOt4d4gKAUBuS5dyh307dhOFYnDOCx9r/oRnFCzsuFXuI4xR8DjRVw9w/8ICCRCFzOK/LZsgpSwmym1Crmm+nXpPuOzkSJl1MUs9UdGAyo0Y0MyXLKybvvZbTyKAIezQFSdr2wz4h1y9IOJvpGrgv3Bu7zN6tjIJQLmEdVk7ugYaQ1ro9jD0Fjk3NgERFnDdEAmo8calIS9VW3pW2g20322Dayky6feumpJYzd4ZrAvoVA==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="pfxd6384c8e-bf0b-d819-9fd2-2163c512ef64" IssueInstant="2016-08-10T19:20:28Z" Version="2.0"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://cidmfed.chop.edu/oam/fed</saml:Issuer><ds:Signature>
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfxd6384c8e-bf0b-d819-9fd2-2163c512ef64"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>zHHFFB4JHVjYEJyJXVk7C4QAnL8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>O9i/ioG9MCc1L13hj2J1ouliDU+oE8TE2OCagGjrn3bZdpST2P3bJtaA1vSZolso1eTjn2gyaP3Va2z8CeRqfhd+flusKQJetVOBhdaLEu5Bvw6nufWhLolfNn1PmGdEDdCUMiY9NC1nwIZ8szvGL54Ca9xvjso+ocY/KGk4jXHygJy27IoLSj18YK3vXPJmC97XzKUmyLOMIBi9wf+hSZRkWTB5ejDFUfnzLP/vBhqRUPYxafv1YSNtjbRPO3IynodsKqtqWgvcuzCGqP/tZKZ185mxtlo2qPRI11Y4x3Mg0bv0HABnIwFqP47a2XYeeMY71c/Er766xjPzIF0QNA==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">HankeeJ@email.chop.edu</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2016-08-10T19:25:28Z" Recipient="https://avillachlab.auth0.com/login/callback?connection=CHOP"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2016-08-10T19:20:28Z" NotOnOrAfter="2016-08-10T19:25:28Z"><saml:AudienceRestriction><saml:Audience>urn:auth0:avillachlab:CHOP</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2016-08-10T19:20:28Z" SessionIndex="id-vMW-3rK-vReoeuOd5AtV8Jb-QQ4CmQ0zG45fTYJ1" SessionNotOnOrAfter="2016-08-10T20:20:28Z"><saml:AuthnContext><saml:AuthnContextClassRef>LDAPScheme_GRIN</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>`;
       var options = {
        cert: cert,
        thumbprint: '5CA6E1202EAFC0A63A5B93A43572EB2376FED309',
        checkExpiration: false,
        realm: 'urn:auth0:avillachlab:CHOP'
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });

    it('should return profile even if the namespace is in respsonse element', function(done){
       var cert = fs.readFileSync(__dirname + '/test-auth0.cer');
       var samlResponse = `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:enc="http://www.w3.org/2001/04/xmlenc#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Destination="https://avillachlab.auth0.com/login/callback?connection=CHOP" ID="pfx2ba35038-7fff-f9c0-c9bc-1462e1455a76" IssueInstant="2016-08-10T19:20:28Z" Version="2.0"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://cidmfed.chop.edu/oam/fed</saml:Issuer><ds:Signature>
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx2ba35038-7fff-f9c0-c9bc-1462e1455a76"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>wFK//X7GAw5PBQHntPWb8OThZEE=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>tIb8Z6OWq1T0sws6JFdAbUR6FEBk3I7NkXgk5wCt42tMjPq343j8aj1xwJqsbYvLTvAtxEgmohgxvcJ7oADiqXBgDQ6HJNxe3U6q3NGO6Q7XhmtHMFN+bf+BlT7Hll6Ma11BfYNi6rKnROqJTL6ezm53jLNnqk9En/GYwcAKmGI1C1xlJ9cQDuHzA6w57TexdAOXnBVMi50oAoAG8taUDWtppQwfuuCF+D7Nz5QoUNUKE/ExtTjriBg04RXv6gFTKqYbeb4qDMIqf6hgpVd1xroZipGfQhuHocjoUKQSfSP8BDYDTZoxVIiEBUHP8RRK5Xof45x0+fYj1+O7kg8VpA==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="id-Y-RwHi6RP8jMUR8kr1FVzHuNvburOIeK6wGpNjd-" IssueInstant="2016-08-10T19:20:28Z" Version="2.0"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://cidmfed.chop.edu/oam/fed</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">HankeeJ@email.chop.edu</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2016-08-10T19:25:28Z" Recipient="https://avillachlab.auth0.com/login/callback?connection=CHOP"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2016-08-10T19:20:28Z" NotOnOrAfter="2016-08-10T19:25:28Z"><saml:AudienceRestriction><saml:Audience>urn:auth0:avillachlab:CHOP</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2016-08-10T19:20:28Z" SessionIndex="id-vMW-3rK-vReoeuOd5AtV8Jb-QQ4CmQ0zG45fTYJ1" SessionNotOnOrAfter="2016-08-10T20:20:28Z"><saml:AuthnContext><saml:AuthnContextClassRef>LDAPScheme_GRIN</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>`;
       var options = {
        cert: cert,
        thumbprint: '5CA6E1202EAFC0A63A5B93A43572EB2376FED309',
        checkExpiration: false,
        realm: 'urn:auth0:avillachlab:CHOP'
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });

    it('should return profile when attribute namespaces are defined in saml response', function(done){
       var samlResponse = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:enc="http://www.w3.org/2001/04/xmlenc#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Destination="https://fireglass.eu.auth0.com/login/callback?connection=putnam" ID="id-TDU5L7ZuUSJteaLg3Wo6ULH-7PHwrjZVoC9ICoah" InResponseTo="_a0f580df04c2eb021735" IssueInstant="2016-08-29T19:33:22Z" Version="2.0">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://oam-stg.putnam.com/oam/fed</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="pfx99f6ce1c-1a46-7c97-5916-34da1efd74b3" IssueInstant="2016-08-29T19:33:22Z" Version="2.0">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://oam-stg.putnam.com/oam/fed</saml:Issuer><ds:Signature>
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx99f6ce1c-1a46-7c97-5916-34da1efd74b3"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>Xf6a3Y0xwjZf921nP20oOVZcOYQ=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>LtqqnXEEiEJoz3CTBbKB43TYo+nuSZqobcfum3a9m/hrrU+6TtIublnTXBHl/55cy0sjAkgC/c71jSmM0CJ0Ucp63MvLhxDgQGik0DEsrBq8RlGhCCxoe3J4zY49wfcvmQWW8yr0n8hnVqkM5et+uRN5va3ZJ3YvG0+Cb4Kc4MBBh1X6JPfaXt/pVSC5SSmU3QkjJBmJ07fhltILrleQoaLfg/8H1bwNx3WDO+1wrw4z40F2LWg/XnsmYK0MfBJ5QkpqHIJjSodmb9C/eKPB6dW4O6fwHKrZ2AR7f9BXNG3w2sQmTsX1swJgwew0jCo52r8mWaGo9CotU7WYRL0AtA==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">Demo_User@putnam.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="_a0f580df04c2eb021735" NotOnOrAfter="2016-08-29T19:38:22Z" Recipient="https://fireglass.eu.auth0.com/login/callback?connection=putnam"/></saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2016-08-29T19:33:22Z" NotOnOrAfter="2016-08-29T19:38:22Z">
      <saml:AudienceRestriction>
        <saml:Audience>urn:auth0:fireglass:putnam</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2016-08-29T19:33:21Z" SessionIndex="id-6hogk8JmWq8hJHewaVCNiSNXmqL0LvfwhyTS96Cu" SessionNotOnOrAfter="2016-08-29T20:33:22Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">Demo_User@putnam.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="sn" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">User</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="givenName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">Demo</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;
       var options = {
        
        thumbprint: '5CA6E1202EAFC0A63A5B93A43572EB2376FED309',
        checkExpiration: false,
        realm: 'urn:auth0:fireglass:putnam'
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });

    it('should return profile for IBM saml response', function(done){
       var cert = fs.readFileSync(__dirname + '/test-auth0.cer');    
       var samlResponse = `<?xml version="1.0"?>
<samlp:Response xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Destination="https://safarijv.auth0.com/login/callback?connection=IBM-Prod" ID="pfx087348d7-544e-b359-704e-0768effc49ef" InResponseTo="_23d347ad32abbd288fbc" IssueInstant="2016-09-06T19:19:46Z" Version="2.0"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://w3id.sso.ibm.com/auth/sps/samlidp/saml20</saml:Issuer><ds:Signature>
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx087348d7-544e-b359-704e-0768effc49ef"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>nKIJagEhY0nwjWf2eTMUpy7B/O8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>nQoLtflrSaVpV6FQEuORo/dzm+vN8qAU4djJOxEXHjszmrQY0TAvPNS76L/f/lmZMbvkfg5Z/pZBlLfrmsiBRqq7EKrHzJpGU39e2frOjY8MaH95dWh0SztH4rvN2cUozqOxFVHMfbKVJTltXgvV1adaiSjTiGiaADSoVT4P1ydyBIldNt7w8tyFYMX0LOkO31FF93XGEyYwRnYFW0XzLX4AnFk5jklkF4pgHlw/43pzRLJcW1F+kpLMba17cg7XAVzwbyc85GrLKW3ijdCWERW1TDm1jcwhCxFgGcFqP0YaLwIlg9Cg05A43WVEBp8VBRjq+k/s4Yus3KznzWlq7w==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="pfxc142a6f7-df8d-2131-5dd1-8b2a285a21eb" IssueInstant="2016-09-06T19:19:46Z" Version="2.0"><saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://w3id.sso.ibm.com/auth/sps/samlidp/saml20</saml:Issuer><ds:Signature>
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfxc142a6f7-df8d-2131-5dd1-8b2a285a21eb"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>UzUVS+6XRPhKUK7cw3diiofYSTg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>uXXEjo8CjqdbDs2MEWooAbufv1hrC5BKXuoYuS/9Z1eqh1vZdgVogqz2yzz2YStzZolB55zL9EbHuHJ8jq8Fw6yDDm7igB2Q6pej08FTrkzBnt7485wKTcTUJdEH7tDJUR5ibm2ESWFTXih7FiAb5Bs9NBX+kK1MJBpKEPOrlqB/IJbwe0bQcQbS6OSfciRiP7Vrw37xB+2tm5Qlgsy7uJXpHaB+jErFT3EdyekaS+KgVmE6f989Ky8n9b+W1p1LbMQJz5+eUsaJVPqt6Sn8SDuKt+uwZWTMNtTJ4tZ5h3kuHAL9spthldfI7sUFAyRr4KI23YE+2lK62pf/vuexaQ==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEDzCCAvegAwIBAgIJALr9HwgrQ7GeMA0GCSqGSIb3DQEBBQUAMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDAeFw0xMjEyMjkxNTMwNDdaFw0xMzAxMjgxNTMwNDdaMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZiVmNHiXLldrgbS50ONNOH7pJ2zg6OcSMkYZGDZJbOZ/TqwauC6JOnI7+xtkPJsQHZSFJs4U0srjZKzDCmaz2jLAJDShP2jaXlrki16nDLPE//IGAg3BJguSmBCWpDbSm92V9hSsE+Mhx6bDaJiw8yQ+Q8iSm0aTQZtp6O4ICMu00ESdh9NJqIECELvP31ADV1Xhj7IbyyVPDFxMv3ol5BySE9wwwOFUq/wv7Xz9LRiUjUzPO+Lq3OM3o/uCDbk7jD7XrGUuOydALD8ULsXp4EuDO+nFbeXB/iKndZynuVKokirywl2nD2IP0/yncdLQZ8ByIyqP3G82fq/l8p7AsCAwEAAaOBxzCBxDAdBgNVHQ4EFgQUHI2rUXeBjTv1zAllaPGrHFcEK0YwgZQGA1UdIwSBjDCBiYAUHI2rUXeBjTv1zAllaPGrHFcEK0ahZqRkMGIxGDAWBgNVBAMTD2F1dGgwLmF1dGgwLmNvbTESMBAGA1UEChMJQXV0aDAgTExDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZIIJALr9HwgrQ7GeMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFrXIhCy4T4eGrikb0R2wHv/uS548r3pZyBV0CDbcRwAtbnpJMvkGFqKVp4pmyoIDSVNK/j+sLEshB20XftezHZyRJbCUbtKvXQ6FsxoeZMlN0ITYKTaoBZKhUxxj90otAhNC58qwGUPqt2LewJhHyLucKkGJ1mQ3b5xKZ532ToufouH9VLhig3H1KnxWo/zMD6Ke8cCk6qO9htuhI06s3GQGS1QWQtAmm17C6TfKgDwQFZwhqHUUZnwKRH8gU6OgZsvhgV1B7H5mjZcu57KMiDBekU9MEY0DCVTN3WkmcTII668zLsJrkNX6PEfck1AMBbVE6pEUKcWwq3uaLvlAUo=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" NameQualifier="https://w3id.sso.ibm.com/auth/sps/samlidp/saml20" SPNameQualifier="urn:auth0:safarijv:IBM-Prod">uuid6dd97435-0154-186a-971f-ee1c8efabdde</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="_23d347ad32abbd288fbc" NotOnOrAfter="2016-09-06T19:29:46Z" Recipient="https://safarijv.auth0.com/login/callback?connection=IBM-Prod"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2016-09-06T19:18:46Z" NotOnOrAfter="2016-09-06T19:29:46Z"><saml:AudienceRestriction><saml:Audience>urn:auth0:safarijv:IBM-Prod</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2016-09-06T19:19:46Z" SessionIndex="uuideeffc0-0157-1b72-aff0-894ab08f84d9" SessionNotOnOrAfter="2016-09-07T08:19:46Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="EmailAddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">cornel.popa@ro.ibm.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="UserID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xsi:type="xs:string">Y9C4BM826</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`;
       var options = {
        cert: cert,
        thumbprint: '5CA6E1202EAFC0A63A5B93A43572EB2376FED309',
        checkExpiration: false,
        realm: 'urn:auth0:safarijv:IBM-Prod'
      };
      var samlp = new Samlp(options, new Saml(options));
      samlp.validateSamlResponse(samlResponse, function (err, profile) {
        if (err) return done(err);
        expect(profile).to.be.ok;
        done();
      });
    });
  });

  describe('getSamlStatus', function(){
    before(function(){
      this.samlp = new Samlp({});
    });

    it('should get result without subcode', function(){
      var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder" /><samlp:StatusMessage>some message</samlp:StatusMessage><samlp:StatusDetail>some details</samlp:StatusDetail></samlp:Status></samlp:Response>';

      var result = this.samlp.getSamlStatus(samlpResponse);

      expect(result.code).to.equal('urn:oasis:names:tc:SAML:2.0:status:Responder');
      expect(result.subCode).to.be.undefined;
      expect(result.message).to.equal('some message');
      expect(result.detail).to.equal('some details');
    });

    it('should get result with sucode', function(){
      var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthNFailed" /></samlp:StatusCode><samlp:StatusMessage>some message</samlp:StatusMessage><samlp:StatusDetail>some details</samlp:StatusDetail></samlp:Status></samlp:Response>';

      var result = this.samlp.getSamlStatus(samlpResponse);
      expect(result.code).to.equal('urn:oasis:names:tc:SAML:2.0:status:Responder');
      expect(result.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:AuthNFailed');
      expect(result.message).to.equal('some message');
      expect(result.detail).to.equal('some details');
    });

    it('should get result without details', function(){
      var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthNFailed" /></samlp:StatusCode><samlp:StatusMessage>some message</samlp:StatusMessage></samlp:Status></samlp:Response>';

      var result = this.samlp.getSamlStatus(samlpResponse);
      expect(result.code).to.equal('urn:oasis:names:tc:SAML:2.0:status:Responder');
      expect(result.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:AuthNFailed');
      expect(result.message).to.equal('some message');
      expect(result.detail).to.be.undefined;
    });

    it('should get result without message', function(){
      var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthNFailed" /></samlp:StatusCode></samlp:Status></samlp:Response>';

      var result = this.samlp.getSamlStatus(samlpResponse);
      expect(result.code).to.equal('urn:oasis:names:tc:SAML:2.0:status:Responder');
      expect(result.subCode).to.equal('urn:oasis:names:tc:SAML:2.0:status:AuthNFailed');
      expect(result.message).be.undefined;
      expect(result.detail).be.undefined;
    });

    it('should get result with status code only', function(){
      var samlpResponse = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" InResponseTo="response" Version="2.0" ><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:fixture-test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/></samlp:Status></samlp:Response>';

      var result = this.samlp.getSamlStatus(samlpResponse);
      expect(result.code).to.equal('urn:oasis:names:tc:SAML:2.0:status:Responder');
      expect(result.subCode).be.undefined;
      expect(result.message).be.undefined;
      expect(result.detail).be.undefined;
    });
  });
});

function doSamlpFlow(samlRequestUrl, callbackEndpoint, callback) {
  request.get({
    jar: request.jar(),
    uri: samlRequestUrl
  }, function (err, response, b){
    if(err) return callback(err);
    expect(response.statusCode)
      .to.equal(200);

    var $ = cheerio.load(b);
    var SAMLResponse = $('input[name="SAMLResponse"]').attr('value');
    var RelayState = $('input[name="RelayState"]').attr('value');

    request.post({
      jar: request.jar(),
      uri: callbackEndpoint,
      form: { SAMLResponse: SAMLResponse, RelayState: RelayState }
    }, function(err, response, body) {
      if(err) return callback(err);
      callback(null, { response: response, body: body });
    });
  });
}