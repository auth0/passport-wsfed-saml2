var expect  = require('chai').expect;
var request = require('request');
var qs      = require('querystring');
var cheerio = require('cheerio');
var xmldom  = require('xmldom');
var fs      = require('fs');
var path    = require('path');
var zlib    = require('zlib');
var crypto  = require('crypto');
var helpers   = require('./helpers');
var server  = require('./fixture/samlp-server');
var Samlp   = require('../lib/passport-wsfed-saml2/samlp');
var Saml    = require('../lib/passport-wsfed-saml2/saml').SAML;

describe('samlp (functional tests)', function () {
  const samlRequest = fs.readFileSync(path.join(__dirname, './samples/encoded/samlrequest_signed_differentcert.txt')).toString()

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
      doSamlpFlow(`http://localhost:5051/samlp?SAMLRequest=${samlRequest}&RelayState=123`,
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
      doSamlpFlow(`http://localhost:5051/samlp?SAMLRequest=${samlRequest}&RelayState=123`,
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
      doSamlpFlow(`http://localhost:5051/samlp?SAMLRequest=${samlRequest}&RelayState=123`,
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
      doSamlpFlow(`http://localhost:5051/samlp?SAMLRequest=${samlRequest}&RelayState=123`,
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

  describe('SAMLResponse with invalid XML', function() {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5051/callback/samlp-with-invalid-xml',
        form: { SAMLResponse: 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIHhtbG5zOnNhbWwycD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9mbWktdGVzdC5hdXRoMC5jb20vbG9naW4vY2FsbGJhY2siIElEPSJfNzY4NjU5OGUzNDk4YjcxOGM3MjcyNmZlMjVhZDU3Y2MiIEluUmVzcG9uc2VUbz0iXzM3ZjAyNjJkYWZlNmJhZWFmYThiIiBJc3N1ZUluc3RhbnQ9IjIwMTQtMDQtMTFUMTE6MzU6MjQuMDYwWiIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSI+aHR0cHM6Ly9hYWktbG9nb24uZXRoei5jaC9pZHAvc2hpYmJvbGV0aDwvc2FtbDI6SXNzdWVyPjxzYW1sMnA6U3RhdHVzPjxzYW1sMnA6U3RhdHVzQ29kZSBWYWx1ZT0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnN0YXR1czpTdWNjZXNzIi8+PHNhbWwycDpTdGF0dXM+PHNhbWwyOkVuY3J5cHRlZEFzc2VydGlvbiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgLz48eGVuYzpFbmNyeXB0ZWREYXRhIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyIgSWQ9Il9jOGY1Y2QyZTAwY2UyMzkwYTJkMjdlMzRjZjQwZWI2YSIgVHlwZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjRWxlbWVudCI+PHhlbmM6RW5jcnlwdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI2FlczEyOC1jYmMiIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyIvPjxkczpLZXlJbmZvIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48eGVuYzpFbmNyeXB0ZWRLZXkgSWQ9Il8wZjczNDk4NTFkMjY0NDk2NWE0N2M2ZjU2OTc1MDk1MSIgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIj48eGVuYzpFbmNyeXB0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjcnNhLW9hZXAtbWdmMXAiIHhtbG5zOnhlbmM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jIyI+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIiB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyIvPjwveGVuYzpFbmNyeXB0aW9uTWV0aG9kPjxkczpLZXlJbmZvPjxkczpLZXlJbmZvIC8+PGRzOktleUluZm8gLz48ZHM6S2V5SW5mbyAvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSURPekNDQWlPZ0F3SUJBZ0lKQVBQb0hyRXBiN291TUEwR0NTcUdTSWIzRFFFQkJRVUFNQjB4R3pBWkJnTlZCQU1URW1adGFTMTANClpYTjBMbUYxZEdnd0xtTnZiVEFlRncweE16QTFNRFl5TXpBek1UZGFGdzB5TnpBeE1UTXlNekF6TVRkYU1CMHhHekFaQmdOVkJBTVQNCkVtWnRhUzEwWlhOMExtRjFkR2d3TG1OdmJUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQUtiOUdpZmYNCitLdlFQd285ZW9PYlNXN05OWVpGclVveFJuNzRxTWNkZlp3a3V3RzNPOEVHaThYK1VzTnROZ3dRbE1WZll0OWxLQjcxaUpTbEtPQmkNCkJQU0ZQN3pQOWpGdFRuZkpjYVJ2ZHZZUG9JQzRZODF0dTZMa05OM2UxLzMxTnArUjZwZDdGNkxmSFdxdWYrQitoeUhKQ1hhc2RkNkoNCmxHb2ViOTQrZW1wajlsbTh3SE5iM3NyLzg4Mzk0S0ozRlVCZXhQelE1cnBLTGU3ZDVmbTRFS08vaXlFcFdIVWxmN2RmOXlHRDZtNzENClB4bys4cjhEcXE3QTVFaEdYL3prNlN1d1o0ai9zeml6eW4vY1h1bGxHZzNQQXNjOVhYTFQ0NTVBMUtFQng1ZVRHck1jN0pRM3VEVXENCnFmRGY0dmp3bE5CY0lqeGcyWDNkTTBzSlZrLzVyMDBDQXdFQUFhTitNSHd3SFFZRFZSME9CQllFRkJzNWxwZnZleU9Tb3BtTlZlZWgNClhQK1BHdGszTUUwR0ExVWRJd1JHTUVTQUZCczVscGZ2ZXlPU29wbU5WZWVoWFArUEd0azNvU0drSHpBZE1Sc3dHUVlEVlFRREV4Sm0NCmJXa3RkR1Z6ZEM1aGRYUm9NQzVqYjIyQ0NRRHo2QjZ4S1crNkxqQU1CZ05WSFJNRUJUQURBUUgvTUEwR0NTcUdTSWIzRFFFQkJRVUENCkE0SUJBUUEyWmszU21TR1RPaC82cmF6ZW0vRmk4R3pFb3BjS2RJRTF1ZUNoVHNBemg2L21pbTVxNWxIMFBXMWI4NXNRMy9jMzFTWVUNClN4VlpCODRLMk1QNitod0MwV1p4a3E4eTBpTUVFQXhXeUMzWjNpOXBTbEdkdzdzdi9OV0p2NFlQam8yc1NOSHVaODBPMTFhM2NYb3UNCll4TE84REJSTXE5VlRzN1JiN3FLRkJXbDVJeCtjWnhWZ2xyeEl2NlcwOE9ycm1xUGVvRGp1aUppQmoyOGNzamhlaFlFbEtZY25VNEwNClJkSWpCbFpGbjFBb1RKUkJGQXlqTDhCdlNNSU1Sa3pFcm8vR3AzSXpqNjAzUkJUR09rdm5pYWxLSGN3TG5WRkZFMHhlWlpVcTdLdzANCkx2TzBYOHVTM0RYN2RUYzJvcXpYT1R4NDIvT2o1cTl4VXVhaXVYME1SWlQwPC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PHhlbmM6Q2lwaGVyRGF0YSB4bWxuczp4ZW5jPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyMiPjx4ZW5jOkNpcGhlclZhbHVlPlBtN2dVRDI5d1AwMTdLUnZKTmdmVzUxRkQ0eHlUTGJ5RDdXbElNRVZUR2xzWnc5K3ZNbUdzL2VkdXJoT2ZVZEV2SGZBV04vdUYzYkxCOTl1Q1pFN0dHLzJ0aDVBS2pLejFaN1NvZWZuUU54dnFvbXUyNUNmWTEwUzFpbitNMU13N3ZrcTZlS0c4bndEQjBDc3JsOXJ6ZUMyekNQRFc1TG81N0x2NDNNbUVpM1dYZkVhbkQwZDJZT2NRVFppaHIzUlpnajl0SDJUQmVKZjhNN28yY1BrOXFBWk40aU56dk1oWE5OV0RDR256SGxIdXNxVk9RNWM4d2l5MmwzdWlUZlk3aEIvTVhpUDVmemRPYitEbWw4NlJrT2MyUVd3RHUwQ0t1ZHBveVRxQW90OUhFZ1JoL25tVXVSQkVKQ3NtWEdyN3FOM3ZSWW5HTXRmdEswZG9VYzN6QT09PC94ZW5jOkNpcGhlclZhbHVlPjwveGVuYzpDaXBoZXJEYXRhPjwveGVuYzpFbmNyeXB0ZWRLZXk+PC9kczpLZXlJbmZvPjx4ZW5jOkNpcGhlckRhdGEgeG1sbnM6eGVuYz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjIj48eGVuYzpDaXBoZXJWYWx1ZT4xY1JHdFhpWFZMYXRhSHFTMWVLM3JtTjlQcnJyZ0laR25XM0xPT25aektuU2w2dWFKWnRENXFyQkRURE5zaXg2ek15cHJPOU5KQVlQYlJEQ21CbWNaVStMSm5aSVdtT3IrQ29SdWJBUGdIT2Q3Q0VoQVB6RGVJZFh0S0V3R29hNHNKbXJRMjlCR3VSejBYS3ljTlJhU2lJa0toRm40dTZCRzV0a2dzS0RRT3Q3dmd0RzhuV21pczZqM0lYSVdrWGpXT2tKWjBHbktXajJqd3EwL3ArdEo1OXM1R3lTQi9uVy9nQW1PcjlLelhJMllQWm5CTk1xSUl6ZTZPNDBaaDRtaXpmUmdTSzM4dE5XQ3NCRlB6Q1krZjJWZVlsMzVORythdUhEZU9BRGtkQkR4d2xqRTJCV0Q2MXBKaFhuRzBTRVBIcnV1b1k3YldjWGpoNDVYLzhiM1hNcHF4ZDFjRFJPZkZMdFRMb0syVjVqcnhiRGRvcVh2TFR2NnZ5NDZGVkZYRVNEV0xmSGFxTjBOTlNsY2hORXJmcFV3SDRNUXNVOGU1UW1yeEw1QUVDVldmQytEYnNOZTVjZFhZcS8wVTBkcWJPV1ZlQkdVL3h0KzJEWmVhSFBTZVpweGhCb3diZ0FKejRlTlpQdnhIWVRGZHducXZhemRneWo4VUdHbEQvZjFoSXFHWHFja3BNbTJ2OEplZUd1akV6SDNnMXNOcEluWG40eVBaTUFLSEtOaVhIZTF3aWk1V2V5Ty9tMHlCUGZreGRrMll1S3NPMy9KWDlOcXltNXV6WUIzbmZZN1JkR21pdXBDV2tpb05aL1hidG5Bb1dDSENyc210am1kdm5rM2NBTVAvdmNSWmluQm9pSjgxdnBLdTNtSm5FdGV6cEVqaUMxY1dnTUxoLzZRK29MbXZOL1dyNVZWZmxjSFJYMWNhTEQrWURncnkybTVCbHBTRjhVKy9KYXR6NjR3Y0V2aXlqVFgwelN6VlRtakptZG44a3FvSEN0V3RvVCtWQUt0MG9CcGRMdHg5eDUzUTVTVG1rUG5xOXdnc3FWRXBGZGFHK25qM1RiZkY5K1FBMHFCVk1BVmxpZmNyb01YTzZRZlpFZUwwNWpFZWFSUGZpK0t5K2tVNUUvMFduTWFVUU1ZZE1kUFh5NW1XenZuZHMzVE5DczRjMWhYc1c2SXFoeTRnQjFPdEFVdjhIeEtPWVhrT0ZMMVN4TEs4Ty80UUUwVEFGd0hvZ0hEY3NVTEIvNDJHZ3IxZjZJVWcyTGNjOTMvN3JOUkhOV21OK21ienBJdUUvT0lRTEM5RW5yM1ErSkdURFJKajJsR0Fidzk4MnlsUzYyS2ZETDlKMWEzdzdtb0ZKM3ZubTdTUmZ4K25CREw2YzFBSDJTS0s1SmsrT3VDOWVSWllwMDdXMy9TQnJOWFVUUzhpbnpRaERLSWwvOVJ0b1Bzbyt3K3RnaCtIY2svNERaQnV0cmtpY3BGejBWZm5pK0VGZXBEZVJLT1ZwY1JNclVFeHdvWFZ3SitBUldMRnBIdDFJQjh4TmJTeFU4WUpzeDlMdWxGeXhUQzVOYWFqU0N4WFhkRENFajE5U2o2MFRYZGcwOHNRY0NYdGxUS1dLVDdQQXl1cGo5dFZtdVg2NkEweGQwdWt3MmhjbSs1bnB4REtEbUhKdWFMSUlzSDB4WDFyQVE0a3VqVHg1aGNGZnEyMDZIK2JBUE1xTEYyTjFDSnlkYUJMd2xoejRwa0tPczhMRXVzTGtySGVUK3hFeHBETnk4MzBZQ3M1SUpnTkY2R3dFcFdiaklGbVNIMlpzSnBycnB4b3h6eGtuZ29DSzYvSlRkYUVoM0diWkVmaFNlSW5kTGFnUktFcjZ5azNFMS9sNzlxTmxCbzlpUndTRE5UVXdkMmVHOENhZVpyYjJQZEIweDk2L3Z4L2lkUXNwQjNCQjkrbzBRaFhndVp5c0pDMmtIdmZUSndZZjRWVDBoL01TQnk1dGVWYU1kUWZxUmpCVm9pbGZncnFaVjlPTHZOOUw3TzUxVGFqVE1EcmdleGxIV3VNNVhMczZUK3pNdXM3WisrNys2aGNEUGg4UXpxY2ljVyt6TGpOTHN3OXhZS09CNlJ4T1NHTy9CekkxcExhbmRHSnJ5bXVsWlBicUJyZEQ1MXFWNUxwWjVBcUU2MHg5RGc0NDNJRkpPeWIxUzN3VCsyb3BBVEFDVDZQV3o0blJsNHZJc2J1M1RlVGdGTXZiUHdKdmV0U1d2ZjNwckdRNDlqVHpMaXhlSUlRTmUyOXdYamZROE1TKzJSUGppMnlpQVFCcllITWo2UzBiWFloYUVCRmFGN1kxNTRxMVJORk5rTmpmN2tVQjBTbVlnaVU4em83QjdLNzRwTm1SbWxIcitMcGtFcHVyVEU5Lzgvd1hhRWFzSitIb0UyNVlTYnFZRitxKzQ1L1NFcEJQdWpCa2ZQdkQwR0pqVCtnbGxiNzFWQU9nMTk2dGN2RFU4TUduSUN6SGM0ajJRaWVhZkF2YzZMNElvMEJRQXhnNDZXTTlIWVJyOGhZeURQNzFCMC95Sm5CV1R5QzUvWFNsRmsrQWFQeXpxdFZpMk5GeFh3bnRldzA1R1NjU2F2NDdKSEFRVFZaRlJsd2k4RkNtaUpKZWVQVWRrb2FlZExOT21oUXFMN0hmZ000RDRmOE9MaHhxdng3Ym5QQkRPMmlBcndYbHFrdy9Lc3l4dlQvZVd3NUZMOW41KzVDTWxiYnJCTEpNM2o2WkVxM3RJOWZuYk1vNmFHUERRb2RURUMwaEY2ZHdJYm02VG5tdFlLcDFZSTR5UWlzMUFURmIxbTY4R0htS0tidXNiMGE4N3BKbzRYbDlQdVdLSFRhMXBWdDBVTWw0RWJjNm14aXdyRytIZzNFdDRXUk5qaTJHQXhWMmYyekFaN1ZsNXpGRk02dmdxbFlqQ3NWZWNLekM1emp6T2Y4aDd0UThKdTUxMWJpRjlhN090cFhCWHZqVWdvcVRFV25SM1pyRjI4MkNNV3VvUXJHbjlwNFR2eldORU1iWjd2cGJiQ2tYS0t3cFhhWXNzL3pwcHg2d3JXWTRNOUdoVE45RVhXTTRXUGVpbmZ1MStUQUdDK3dISFVTd2h2TE9Ob0RsaHhqcU94MVVweVZubmxTeTV2QlBIbWRrYXgzT3o4MWhIY3hHVEtvb3N1U0hRYU9hL2xRelY4Sm9sM2RyZURobjlBWkM1bjRsa3hYV0tUOEhuQUNMS3VUTE4rMXpQUVY0UWorSDcxNUloNkZzNkE3bGY0dVloY2pWcWNVdWZrTHFvcjd0NjdOck5FekIyNSs2UVNRSlhMbTNUU2M2UTlCUDNjNUhWOGZzVHJEL043RUdJUkJGL3BTNldSMzY2UjV6WkJiWjZXbFNOek1TcnlwZnlQVDk5ODhJeGtLRFZqYjE1MkZ3Njg4OTZvUS8rckdxY3BxYlB5bmsvYkpVbThWWU1vbzA3U0J4Y2hURncybmtRc1VLT0J2MkdJT01WQ0d0YUVmWDh5YVBlcGZ4UGFxSm5tVjJTQ2U3Q09vVWQ1b3g2SzgrL21uWUZaTXJ6N3RYQ1VIU1MybDdyU3BYTStXZ013VnIwalh5OXdYSkxKK3NLM0dXSDZYVDAzNHZrMk1KZHdmcU9zQnBwTkFjeStNekd5NDlFVlFULytQb2FlT245MzM3aHBibjFnVmNMd2ovWGMzRll4REtkakY1OGNUL2d0dG52aWRhaktUcGNnQ1l4R1F2KzNRUkhidWFEWnRyRXY0L3phNnpiRGZHcEtzbklqeVVhc21HeHpiQ1Q3ZjFMQU1aYlJwaklnYi9ScVRnVnhEQXRhUGNSVU9YTEE3N29ZZm83Y2h2STd5RlJGbk9lMDNURDhHRFFLaGI5VUlzN1JmRXNYS0xVOVZwZVp3NnZ4Q1lNZDhScTlDbG5kOG1jR0FsNDgrOTRVeUFWZUdUelYzMWVCam44QjQ1R0wzWDkxL2JULzExaHZNS05YMjFQbUZ5eVR5YzZNMXhVY3IzN282YWY0SEFzVW5YZ1o4U1VLUXdKUE1WQzkrRW52RHByUjYvWS81S1l5MFVnb1IrR01IRTNaMXl0UUdZWEZZRlVaVW1NVjJVZ3oySW5pVTRhWExYNFlxQjhMRVgvRjVENnUzcVFCekhkSXhPelNTdlRiRXN6dVhuOFd4NStMNW1MVGM1U1JuNmxQZTRIUVZ1U0lLYzg3Ym5UTDFzNHFadjF0KzlaTUxLSVRHc1J4bjM1YXFZdVBMdDVOM053MlBZUkg4ZHFyZkwvWlA5WW5CWXo2aEFlWXZQVG5pYWF2ZVYzU0dNeW1VRVM5YlVtbHRjOUo0NnR3MkNwYkkxT0NDRDJ3dW1ucTlvbkZEam1oQUticENkaVNlSXFyNll4Y09QbzFXTnNVMmR1Z1Z3L1dYbTl5RUJ4S0o1UHJjNHJhdjhPT2Ezc0g0Z0cyYm9KeEMrMTluenZDbnVmTTRiRVQ3WVY5SVdmaDJLOGJacytRYTZPYjBTOXZnUWw1YWhGekpCUGhNUW91NjhKLzNkQm5ScUlPUENUMUhxcDN2aktlR3B4bGQxRDl3azZNYUREakl4aTJvWDQ3azZYREt6UkprUENabnJFTDZSblRodFJ0dzhiRUJCblZvdTdHWlZMZWtmRmw1MGlHTldBTmJpYTFGaDhad0c3SmxGbnhQZkhOdHYwM1QrT0dmOGhnMDV4YVlWQjRtZURKeC8rWmJBQzBKYUpYeUpNMnJmeTVuY3UxTk9BNWdEV1E3Vkp0MlFyQXh2cmQ5TVV4eHRnbHRtek1Nc1FZbDd3QVByMk5QRW1Nck1EeXJCcVRNY0JWbVg2N05sNGhBck44WUQySE9WZW5pZkkzcGFZSXMySTg3eWJ4SVNsMlEvbDFySXdScHFZSFVzRGNqVjBmUzd5c2VVZUdnK2hEMDdZR1RWaVkvT0JHeEswMzJneUtUcFdVMHFibW8rWTYvWkdVdnBqbldCRWJ5QkhkZ0xia0JUL29CNVE0azdLMi9TQXd6N29DZStJWG9OYkxYYkFNSGZIS296WFNxUysxQkN1TUUxSnNsWGpSWFk1WWJnRms2MU8zUndLRFVMaExUNUdmSlVFUVNoU2h2S05naHYzOUlBY1o2YWlFWlp3WVBUK1BudnNpc1hKanFiM2lhaU1yMCs5aEIvR3hrOHN5amRuVU1mL3FJOEpRU0k5UVhIZ0t6UU5pY0dSZFdjNUpXUkZreUIxMzh5dUF6NHQ4eHI1SzFhNStBUHJ6M1JJem1KWExpSlBySkhhcnlTL1ZNclBKaHR4WFpoYVlsYlJPRFptaUJjci9LVGlaVk02OWNlK3ZTa2FtZHFCakxFTThNWHZXQzRUY1poSDUzZXlmblJNUjIyb3hKVEVlQjZDYWJFZ3diNjNtQXlVb2JUSkdabFlvZ2NpbTZXZ3MwWnFDNllhaVR2dzNuLzEwWnhHWE5XRnNMRGhDa08vTGxqQWh2SXo0VElnN2F1UCsybXRNc2pram9IVDRDMG5QcXhGREZHanVRRHJpblRDZU1ZRGtnVTBhRTZtMzNnRGp2UEZDbGNqTEc4bTd4REtKbmwzTDNsVCs1eUNJSTNvY2NqaGxpTGVlN3JzSklkeFFaeEd3aDB0RUtmSThtdGYxbzlOSnllMEc1UnpXOTdiOXk5T0hEaVloTWNtalFHVHA5ZE54a0h2cU9qak9QbkdBL1FYZDcwYWVHVy9PT25MUjdBdkRzS1owbENrZDN6dFh6eVVLZ0VwQWRHK2FSbkNsT1JodG9xZXJwN1VxUHJvTmRGdHVNWStnOTlyWU9XS0RxSEo0ZFBBK3lRTkFRTHVBNTBLMU5RMHgzbEdlSlpaaTQraCthN1RRdDF4UVNqODBWVk4zR0VJc1I3WE02RXRNa0JLa2h0NjZoS1pQejJpT29mSVl1YUl0QkJiUWRZN3RXTW9LMElUL2ttbVMrK25MSmJiOUh2WDdqMGxvVWhqVFdocHF1MDQzcHRVeVBvWlVEaEVicmVsVzJldW9kc2ZuNHhoN1A1VUlaR2FNVU5HZ2k1bnF6a2p6MXVzaDEzU3huN0g1NTdZeGlZV2p2TmVJWmd6ZGJWK0dKdERDczBoVm0xZzhpbDh2MnEyazViLzlRZWh1NVVpTFNVZ3AvYVp6d1hOL0xkajQyVWxpWHM4TWRPOHVRVFRnZzZDb0dEbVcvaGJZZU1BV3NFelBlUGliRENmU0t0c0gzTlNGWWRUU0hFdjJYUU0zOEkvL2JpTlR1VWhSNzYxT0U5Qy9ndVFmd1lnbkRJZ05uV0NPUTdYRXRqSHZ2SDM2OUZiSEtnNlpwVmlzRWlEMk1qYnpCbEJsTm5FTFFBU3dQOVVBME1iWVQ2L0xuS3hYTnJXTDRwYWs5WjA0R3FBTm0ydTVxcFp5WGZFZzVGWXdUODVHbUpmSW9JQ2lCSk1JeHE0bXlwdTZ4dWRPdnhPeVVCZFE2enQ0dDR4MHp0TWQ3KzlNN3YzdjNjTVZOVFh0WG9NUEZLL1NKQWRaSGVxb2ZIS0FtcEJiaWV2ODhWL05XaVR5SVVUT1c3bkxGdWpSYUtPODZmWnB5c01kKyt5Q0crcEJDZyswZFY5d3RuYjhkdnl5d2hENkoxTExoelQydGZhUU5mWHZ3VUw1d255M3R3Zkd6M3NhV1A2YkYrSmpZd000SlltYjdEbUNySTZML3M5WlJ1TWlGclRFa3JqNUJ0T2oyckpObFlwZ1NWZ2Z2WWtLWDhmZFVhdWczRWRzVktheThkNzRwUE11S3gza0g3N0ZWbktUdWNiTEdSS1AyU1FuT1RvbE1ZTHNlQUhOK2phUkNpODJldTRFVzBxbWNmYjJNM2JjNVBzd0s3UUVQSWVnYW02Sm5jMFhOeUVPU2NWU1hmUUZEU3FGME1jSkVjeVUyQmIwaFgvTStNazd3SEFRUjBxa2tOQU5KYXkrbFAvQVliWVJ1dUtPWTdXRUxheHUzM0dhZ3pZeU5scWJFR1BQQnBTU2tTbCtiMXEyZHRXWGhmd3JXV052Z3lnMUQ4eVN5U2pJUXNaTEUyS1pab2RuZ2labUtqUERjd3pDMFBvcENSVXQ2ZFBZM3ExWTJjMk9Bd1BpY2NkN0YrYWlSSjdzNWpPei9BOHp5NlpLdll1ZW8xSDdoaVd2dFlJZ2YrQy9MaFFuQ0UxR21rODNzdURPQ3JQSUxPMDduOEcrMjZoenEvQ3lGKytGdHNyb29XUTErb29TanNmQWpXaDZ1QUR2N29DbmN3OFdmdjJXVk5pcGVHZU13UlJpcTFuVWFGN3BwK3dONGdsU3NVZzZ2V21GdHQ0QURFeXp3ODBMRExPNGszeXpsQURmc3pJeFc0KzNsT3FKN2loaklvSkMzRlB6djRWNXE5VWFlWjB2NWt2bk5YTmZUb3k0eG95dFROcUVTODFZYjZiK3R5R0pqZFRyai9WZ3l1dEU1b2oyN3R4YU9ObGloYzhObDlQbzZZb3ZrK3BFUU1vMEQ4SlVXNi9qL0FKUnVTT0I1MllMN1BJK3FFQXpIY0tYTXg4d3l3bEVHWEdrako5QXBoWTA4MUFyazJWclA3UEJEd2xwcENlQUtjZ1R3dTNtN0lRL1FibzFQMVhwMlB6U1hVbnI2N0xiRmFTT3ZjalNtNGlBQ3FjeXVPaDFVb0pIRGRRZWJ6UTdrWEdiQ1R6bEVPZ1NRazl5RzJMY25mOGVaVHBvRXZTbUpRNGcyTEovRkpjelBheGI5cUZXaTF0cGt2OVFrd04vTTVSVWd6QmNjNjV2ZUZQZE1ES09VRmU0UnNtV3htbFo2ZXBwQmJxVk5CbFhoQVBIWSs1aXRjWVR3eHVLUGJNRUNjcDYwc01xUEEyMDdoOWl1WVdvclRMMmNyMjQxSlBDQ3lvZVR5TDZ6MjhmbisyQXR5akxCVC8ydXpaUm9iejY4dzNDRUpLU1paQVlURG16ZWpaWXdVbmkxQ3BhM2JEcDNZcHd6ZkFIeEtSbmtwblJUS2gvUmFYVy95RElZb0U5eHQrcFBjb0kycXRLWGZpMjcxRXQ5eUMwTElvRllFQ2dQRE1GRGp2dGZlQTlnS2lpbWNiUThSSGdld3c2c1VLRS81L0VJcGlRS2t0UC9oSUtna2VHbmkxSXJHbnJYNU5aRmVlN1R0V3BlK3ozZUhCRFdJNlh4TGx6a3Y4ZzdQS1ltSkpxZzY2Unl5K1UzSlBkbk9pSkxoTWRzSmd2NDRlNm55am5VK1V5RWRpN3VGTUdoaFdOUlFSNWg0Y1JRMTB4MXMyNUdyUzhZWDlOdWVZNk5nMlAzYUJ4R2E0enZMa3YrSzA2czN3dUl2d2piSWxkdmpqdTM5di80eTlWMlo3VGdRWlFVUVMzQUd5NmFmQ296VXNnN3pFQitOZmx5U0ZwUDQ4eGY2U0NHWFcrbXZ6NVVabWlEMUErNkFlRlBmTktFd1lWZFB2OXN2aElaWlJ6cVQ4RTRNNCtaVUlxS202ZGplRHp1QmdGaEV4djNZNzZlNDd6OFhCa1p0SFV6aHptNlZPTW1rT2JualFlekdWTTBVdnlGbzVYWVZQbzhTQlo5TVBqd1NVbm9CUzB2T01Zb3BSdTBDM1BQR2NVSVFuZ1BncGF2WVRlTHpTWXZzU055WEwySnEvRUd4eWJUekYwN01Kek44VDN6SURUcE9FUjRUOGVGMEl6czVLcERSdFV6c1JLQjFwNm5RcnFmRFdTcE9VRDB1cXU1U3pPTE8vZkJrb1V5QWlWaldtMUFiNWxtSjZWMW4zRHJLazQzVVBMeTJ2MmFMWWZsMWR0QXFkSHBqY2dwaVdLQVptVCtBMU8zMFRLQlVQR3lnTlN5bW45ZGI2ZkJFQWphTG9USG9DS0QrR1RzNTgvTThpb3htM1NUd0F3K1FJUjAyV3RYTjJGM0JpQWV2Z1pGR0xRNEk3eVVvZ1RXdzh2VnFiY0pZWEZOclF2NDl0eVRBcjhRWnhpamIyM1p2Y01EM2ptcDBNbURoTGZza212T0d4WkdLeW9ERzk3b0k4cW1mbzFjQjVxMVUzSk1NSDFudEFiZTl6MWZFTVNOeVpCenVMV3QyQk9MTWU3akNQR0pYSThmKzUrcllmVGJEVlRxeldQK3lrN1pFSVF5TW9kcitoSlE2eEQ4Tm83Q255KzFpMlR0cU1wTGF5YlowUDVDRzlNQ0h6eHMwbHp6bjJiRVFyUmUxVlg5TUJ3NHVmNFFCeUZZZ1phUmN2NzdNdis1alV5QnQ0amhVd3dxdWp3eTRjL3VYdytQQU9iMHBsZ2s0SG8yUDcvUm10bmE0bnZBQWo2Rzl2cVBVS3pqTnh3RmRkRWxFb1ZERDUrK3Q3TnhhYVVXZzljRjhLRFJZU0M0enUxbXNXQXVYZFQ4aEd2Q1lmNjd4bTc1SVB1SnRtZ3FCWmpYUjg3b0NKb3h3aXZ5bzh0dHRxbUFaOFp4K0VCY1hqV2pLMzVKMzZvVFZ3U2JOcnFJYjZLbmpHbEZYSVN3clBORWkrUmtMb3RhU3lPU3ZuS251bERjM0doaEVYYXNCY3dEMElPNzNpZEk0YmlnR2F1bW9sSFF4QWVMRytVOUZycUY4dGdRT1dMenY0aHd3SlFHL2NpNE5GYmZISWpEVnM0bXM5WTdzQldUNkI1T1pNTzZyRE1wOUlsZG1Fcm1VUGE4ejU1ZVdqMDQ1YUxEQkt0Q1k5UHpXaHZXWHhqeTQ3SmxCU2ZETVBNVFhReHJ0T1B1SjRLSmo1V05xTlg3WXoxaTJMTm5weG5KbnltOWNsVTdGV1MrT2dUeTNBOWpYaTFCVXg0QjBHZzhXWUl4LzVBd0pzU0RPVC8yV0NpM09jRXhtUVRveVZrQ2p5UE55ZWNOck9GQmRQenowa1NaQjNJaFU4dW5OT1N0YytaNjdOZnF5K0kvRTlaVDczcUNCYVRJN1UxSFZxQzlsSnluUk1zbUZmMUdvbGNROG5DbXZvK0tPVTVtVkVzL2xvQThIZ3pWZWVNR043SkxaOFhJcUVkbnp5NHQyNlNRbTlobVY2ZDRiS2ZjQmk0MG9XNGZRUFdZRG1pWlorR1MrTDhuSnlYdzNBWkRIWkdKWEhFci85S096RFF0OVU0WVdpYS9NMTIrbFNyWmd5QmlrdWxnbnBBYmU0ZERpMUZMQTZMMUQzQjBIUlozRUdHamRRbng1R1hFZXhnNG9CVlQzS2dRbmpweXJrN0YzR0tQOUhGdnFLTUZ6VWJoL2RCV3k5bjRWc2JXUFlkSDdsSDFyVUg0YzdwN0lrWGc0VlREOE11MzV3b3ZORkErWkVBYmR3Z3o2dTR6NXZpZzhIcHNiUVpNVXZFVy91VE83cVU4UW56Z1o1NHRHcGl2YyszbnBhYnhSUTZSMDNpMHZYdDZCb0JJckFBMndxMmxzMTVSTXhleFZWczdYT25ORDRlcHFoMUJzR2pROC91ejZya1dRNVJFenNCeERxbXpZSTA1UXhYZlducUM2WVloWXpON1FQUzh0SGpYbGxsN0VzKzhVYzhzTytjRkE3REM3Y0hRbVZGaVpXN1NZYmFtTmFHc2FpY2VYTHE4Q3YveDJIZ21oUzYveU1qUFVFVkhoOTVZdHdhc25kT0p5NGdBbUlEWkh0d2RsOWxXY1ZDMDl4MUlBakt5UWlpQjRPLy9DcG9qZjFOUmNiUWF3VVBKMGI5ZXJyWDNFVWM3cU5Vc2NGMlpubXZVVThxM1g2UFVpb2p5TDVGMUFNdWJzcThuOTFmaG5FUmwrY2syQUJWYm9yeEhORlpSVXgvVlNYNHRMZzROUG1VcmhlalNoNXJZUkl6S3Q5OG9PNTBsTlEraS9RVkZUbmt6Ym9SUkkrS0NTM1o1bzJZZ0hlOGx2ZGhDeHYxZ3hjVGhRM21pd2dIeDdmR09LV1Myc2psSkxYanMxbm9raVowTEZ0NTIxaWYzKzFSYVZlRHpCU1hYRFFZVCtwbEI1S0M2L0ZOZEpDWW9mZGVTY0gwK0lHN2FyeWRyOUhUOU5SMXNHczZnc2JYQnNnWnViNXFKVmYzSisvQ3kra2FCYzByTEtyZ3UzZmlGUG1uMDdhWGdtK2xRVjBPVlVkaWVoNm5vQ0oxcHczT2VNdWJ0TU9rcmQyUWRFNEQ3T1ZoVithdUM5b1pIc09uQXhDYnZoYXovTTZYOEFaNXducHUvZVdwdDZ2WHBhWHpXVklJcVBET0NFMnRCSTcrNlNmTHdjVXFlYU5ZSVhtUlRwNnRUOGhhcDduZXpDZldqUGZxU2ZMVGljaFpEU1dlR2hYTXZWNTRCODJ2eWJoM1NBNXZCZDdwRnkzWTlxYnNCaHZDbHRKWmwzK044OXNnbTNJWElyeU5MT3JmL3VUMVJ0NDRrVDNleFM5N3FCWVpteGZXZW5PeUxqOHAxZGJlSjd6MlFxeE1xZXRia3FOUHBucnduMUFMV3VkSU5ZOGhLYnJYS0RDQmhWMmNQTkg3VWdTcnZYVFV2T1UxRnVyQ0FGRThSa09vcWxobUZ4SXRRUHUzNWd4MWFqaVFBTkMxQllTdlkvZzZyL2lLMHRlekFoRGNtaW4xVWF3Qk1qMkZHK2M4ZXdCYzVVbzN6ZUNIdERYVnlsSlY3UUdGVGZZR0JOWmlKUXJkYnFXRmEra01tdjRJUWYzSjY5bjBEeVNwRTJVY0h5dlFKQ3d0czlUN3NMU2h6WWFNVFVKUUFmOHhwcjBXKzVac3NHMjhJcXFsSTNkbUFpM0dQa2REblE3c0ZiNXBWSVVFVHRUQm9kMEp3K0U1UGgvY0Evbk9FbHpRYXRXUmUxWCs3NFl0bzdZSWJBRW56NW1YSGlva1hnTkVzbEdUWXhzWUo5QVBWOSt4WjVKTk1VWFl0OGhrVHBwaFBzN0FlazFpOXhsMW5sbm5FYnY0M3hnM2VMYTRySDBBcy8wTE9GK01yV2Z0aDBoWnQxanJCb05ycmNHOG1WWVJyd29YaXFIS3NSZTRVYTQ4a0YvRXVRWFZKeUZPV05KNUJjYW9xOSswa3lJdnVoeVhxNS9UL0tJTG12cFpTMzZINHJ1bFJhRm1Hb29sejBtaUl4V2FrdHFpUjF1VjhYaWtiekZFUzR2cGV5NHVKMWVBZjUyRCszL2NLY0V6V2E2KzU2VGRFQ0VKQWExWDl2Ni83UzFDZlBxaVkwN1lNMXZXdXNHcEhPQ0FSTFBDWGZ5V2ZXQytVSThPM1FkSEhRaC9XNXpzZ3RFWnVhYWhkWk9lY2VsQmtnS0NIZ1o4NTFpN2IvY25EN2VsRHlCVGJuNHFKRWhSWVRLWUNRZW82SEpFd1N5b3NhOVJrU0lpQklBaGVHaTlSRWJYY2xMY1JnR3FoMXp5Qi9JUHFmMUtXOXFMbzhzaU9wRUlUU3BOeks3NSttMlc0L2c4TjJLTGgvb1MyeGEyTXZGU0pTemdZZmpwYjlOK3pVeE5XR0xjZDVQR2J6STdkYW4yY2tKSmE2UkhLRG1WTWtqYW1ZTHh6M0ZKK29SdUFhTzFpcjMzWGViSGV6ZHErQjRKT2FweVhleGs4M1hIbG1kS211UTg1aWdqRmZPVElHMmFJc2FXcTdDL0ppZmdyK0pqdVRoSm55TVdyYkNSRTV2VkZ0MEdJYWlvR1NsYktIM1RYUnhaK0tXdXozZ3ErWXIzSWNrT1RIRUgwR0FERy9pc2lQSWV4bHJHNmRZaW43V20vUGVkRGVzd0t5TFlwVFMxejNzVGVTSXRFbXpZSERNRURzS0FsNVh5anZOalJvNzg5OHVhRW5pMWIraWpCc2p5b01EY0RFaHcxZzhseWpIZldrSjRwRitIWGpuMzJBak9qb0ZuNVIrcWM1ZWpsTVVxV0N1OUU0UWJTZWtWbmcwSW02OG9naWF5WVVDQTlZQklSd0Y5b3l2REZ5WGRJblhFOFFsZDRkYks2dUpwM2xzbERkclNWczBZQTdxRnBQY0MrWWdFZnBEa2NraXVjR2RINTFWaHYrMmJNWEpabmdNMTU0Sm0rcUJ4MGhOd1R0K1AyMGZ6ZlpueDh2TEM5c3RxZUxPVm9lNFhlZzhQS01TdFQ1ei9yRGQrZk1nTVB2MHd5bWVybEM5ajJ4L0tMYnRTQmtNa0hkTXZjWVY0cjhJNkFCV0tvNE50QmhTYk8wdUcreDUwbjdkOTFhb1R1ZmhrM3plajV1dEM0ZElGRmdFMkZXMmdvcldzSTBBT0huVXJadlgrYmJxYmFZUFMyT05XSW9wcW1hVVUrVXZPUzcwM2Q4WWtjSGFyaTdFREE1dVFKVG5xT1I1YkpieFk3U0hjWEVmMFZFeldpcGgrL0FKMmYvSzJUVUhoNjZZMnpqdnM4cHdKZURKRUQ0U080OEZHMEtOTjk3UzN5NEJMdz09PC94ZW5jOkNpcGhlclZhbHVlPjwveGVuYzpDaXBoZXJEYXRhPjwveGVuYzpFbmNyeXB0ZWREYXRhPjwvc2FtbDI6RW5jcnlwdGVkQXNzZXJ0aW9uPjwvc2FtbDJwOlJlc3BvbnNlPg==' }
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

    it('should be recognized as an invalid xml', function(){
      var err = JSON.parse(bod);
      expect(err.message)
          .to.equal('SAMLResponse should be a valid xml');
    });
  });

  describe('SAMLResponse with utf8 chars (default encoding not configured)', function () {
    var user, r, bod, $;

    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5051/callback/samlp-with-utf8',
        form: { SAMLResponse: fs.readFileSync(path.join(__dirname, './samples/encoded/samlresponse_utf8.txt')).toString() }
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
          .to.equal('_98f3625b1c12bdbda1842b868eee10cdb61385b270');
      expect(user['urn:oid:2.5.4.4'])
          .to.equal('Doë');
    });
  });

  describe('SAMLResponse with ISO-8859-1 chars (default encoding not configured)', function() {
    var user, r, bod, $;

    before(function (done) {
      const samlxml = fs.readFileSync(path.join(__dirname, './samples/plain/samlresponse_explicit_iso.txt')).toString();
      const samlEncoded =  new Buffer(samlxml, 'binary').toString('base64');

      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5051/callback/samlp-with-ISO',
        form: { SAMLResponse: samlEncoded }
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
          .to.equal('nameid');
      expect(user['Email'].trim())
          .to.equal('test@exåmple.com');
    });
  });

  describe('SAMLResponse with ISO-8859-1 chars (default encoding configured)', function() {
    var user, r, bod, $;

    before(function (done) {
      const samlxml = fs.readFileSync(path.join(__dirname, './samples/plain/samlresponse_iso.txt')).toString();
      const samlEncoded =  new Buffer(samlxml, 'binary').toString('base64');

      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5051/callback/samlp-with-ISO-explicit',
        form: { SAMLResponse: samlEncoded }
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
          .to.equal('nameid');
      expect(user['Email'].trim())
          .to.equal('test@exåmple.com');
    });
  });

  describe.skip('SAMLResponse with signed assertion and "ds" prefix defined only at the root of the SAMLResponse', function () {
    var r, bod;

    // samlResponse was not properly generated
    before(function (done) {
      request.post({
        jar: request.jar(),
        uri: 'http://localhost:5051/callback/samlp-with-dsig-at-root',
        form: { SAMLResponse: fs.readFileSync(path.join(__dirname, './samples/encoded/samlresponse_signedassertion_dsprefix.txt')).toString() }
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

        expect(helpers.isValidSignature(signedRequest, signingCert))
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

        expect(helpers.isValidSignature(signedRequest, signingCert))
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
