var xmldom      = require('xmldom');
var xpath       = require('xpath');
var qs          = require('querystring');
var zlib        = require('zlib');
var xtend       = require('xtend');
var url         = require('url');
var xmlenc      = require('xml-encryption');
var crypto      = require('crypto');
var querystring = require('querystring');
var SignedXml   = require('xml-crypto').SignedXml;
var templates   = require('./templates');
var EventEmitter = require('events');

var AuthenticationFailedError = require('./errors/AuthenticationFailedError');

var BINDINGS = {
  HTTP_POST:      'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  HTTP_REDIRECT:  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
};

var ErrorMessages = {
  'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch': 'The SAML responder could not process the request because the version of the request message was incorrect.',
  'urn:oasis:names:tc:SAML:2.0:status:Requester' : 'The request could not be performed due to an error on the part of the requester',
  'urn:oasis:names:tc:SAML:2.0:status:Responder' : 'The request could not be performed due to an error on the part of the SAML responder or SAML authority',
  'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed' : 'The responding provider was unable to successfully authenticate the principal'
};

function ignoreValidationFunction(samlResponseID, done){
  return done();
}

var Samlp = module.exports = function Samlp (options, saml) {
  this.options = options || {};

  if (this.options.thumbprint) {
    this.options.thumbprints = (this.options.thumbprints || []).concat([this.options.thumbprint]);
  }

  if (typeof options.deflate === 'undefined') {
    this.options.deflate = true;
  }

  this.options.checkDestination = (typeof this.options.checkDestination !== 'undefined') ? this.options.checkDestination : true;
  this.options.checkResponseID = (typeof this.options.checkResponseID !== 'undefined') ? this.options.checkResponseID : true;
  this.options.checkInResponseTo = (typeof this.options.checkInResponseTo !== 'undefined') ? this.options.checkInResponseTo : true;

  this.eventEmitter = this.options.eventEmitter || new EventEmitter();
  this._saml = saml;

  this.isValidResponseID = (this.options.checkResponseID && this.options.isValidResponseID) || ignoreValidationFunction;
  this.isValidInResponseTo = (this.options.checkInResponseTo && this.options.isValidInResponseTo) || ignoreValidationFunction;
};

function getProp(obj, path) {
  return path.split('.').reduce(function (prev, curr) {
    return prev[curr];
  }, obj);
}

var supplant = function (tmpl, o) {
  return tmpl.replace(/\@\@([^\@]*)\@\@/g,
    function (a, b) {
      var r = getProp(o, b);
      return typeof r === 'string' || typeof r === 'number' ? r : a;
    }
  );
};

var trimXml = function (xml) {
  return xml.replace(/\r\n/g, '')
      .replace(/\n/g,'')
      .replace(/>(\s*)</g, '><') //unindent
      .trim();
};

var removeHeaders = function  (cert) {
  var pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
  if (pem && pem.length > 0) {
    return pem[2].replace(/[\n|\r\n]/g, '');
  }
  return null;
};

var sign = function (content, key, algorithm) {
  var signer = crypto.createSign(algorithm.toUpperCase());
  signer.update(content);
  return signer.sign(key, 'base64');
};

var algorithms = {
  signature: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1':  'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  digest: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
};

Samlp.prototype = {
  getSamlRequestParams: function (opts, callback) {
    var options = xtend(opts || {}, this.options);

    var signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
    var digestAlgorithm = options.digestAlgorithm || 'sha256';

    var assert_and_destination = templates.assert_and_destination({
      Destination: options.identityProviderUrl,
      AssertionConsumerServiceURL: options.callback
    });

    var model = {
      ID:               options.request_id,
      IssueInstant:     generateInstant(),
      Issuer:           options.realm,
      ProtocolBinding:  options.protocolBinding || BINDINGS.HTTP_POST,
      ForceAuthn:       options.forceAuthn,
      AssertServiceURLAndDestination: assert_and_destination,
      AuthnContext:     options.authnContext || ''
    };

    if (options.requestContext) {
      model = xtend(model, options.requestContext);
    }

    var SAMLRequest = trimXml(!options.requestTemplate ? templates.samlrequest(model) : supplant(options.requestTemplate, model));
    var parsedUrl = url.parse(options.identityProviderUrl, true);
    var params = {
      SAMLRequest: null,
      RelayState: options.RelayState || (parsedUrl.query && parsedUrl.query.RelayState) || ''
    };

    if (options.protocolBinding === BINDINGS.HTTP_POST || !options.deflate) {
      // HTTP-POST or HTTP-Redirect without deflate encoding
      if (options.signingKey) {
        // xml with embedded Signature
        var sig = new SignedXml(null, { signatureAlgorithm: algorithms.signature[signatureAlgorithm] });
        sig.addReference(
          "//*[local-name(.)='AuthnRequest' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
          ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
          algorithms.digest[digestAlgorithm]);

        sig.keyInfoProvider = {
          getKeyInfo: function () {
            return '<X509Data><X509Certificate>' + removeHeaders(options.signingKey.cert) + '</X509Certificate></X509Data>';
          }
        };

        sig.signingKey = options.signingKey.key;
        sig.computeSignature(SAMLRequest, "//*[local-name(.)='Issuer']"); // Signature element must be located after Issuer

        SAMLRequest = trimXml(sig.getSignedXml());
      }

      params.SAMLRequest = new Buffer(SAMLRequest).toString('base64');
      return callback(null, params);
    }

    // HTTP-Redirect with deflate encoding (http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf - section 3.4.4.1)
    zlib.deflateRaw(new Buffer(SAMLRequest), function (err, buffer) {
      if (err) return callback(err);

      params.SAMLRequest = buffer.toString('base64');

      if (options.signingKey) {
        // construct the Signature: a string consisting of the concatenation of the SAMLRequest,
        // RelayState (if present) and SigAlg query string parameters (each one URLencoded)
        if (params.RelayState === '') {
          // if there is no RelayState value, the parameter should be omitted from the signature computation
          delete params.RelayState;
        }

        params.SigAlg = algorithms.signature[signatureAlgorithm];

        try {
          params.Signature = sign(querystring.stringify(params), options.signingKey.key, signatureAlgorithm);
        }
        catch(e) {
          return callback(e);
        }
      }

      callback(null, params);
    });
  },

  getSamlRequestUrl: function (opts, callback) {
    var options = xtend(opts || {}, this.options);
    var parsedUrl = url.parse(options.identityProviderUrl, true);

    this.getSamlRequestParams(options, function (err, params) {
      if (err) return callback(err);

      var samlRequestUrl = options.identityProviderUrl.split('?')[0] + '?' + qs.encode(xtend(parsedUrl.query, params));
      return callback(null, samlRequestUrl);
    });
  },

  getSamlRequestForm: function (opts, callback) {
    var options = xtend(opts || {}, this.options);

    this.getSamlRequestParams(options, function (err, params) {
      if (err) return callback(err);

      return callback(null, templates.form({
        postUrl:      options.identityProviderUrl,
        RelayState:   params.RelayState,
        SAMLRequest:  params.SAMLRequest
      }));
    });
  },

  decodeResponse: function(req) {
    var decoded = new Buffer(req.body['SAMLResponse'], 'base64').toString();
    return decoded;
  },

  extractAssertion: function(samlpResponse, callback) {
    if (typeof samlpResponse === 'string') {
      samlpResponse = new xmldom.DOMParser().parseFromString(samlpResponse);
    }

    var saml2Namespace = 'urn:oasis:names:tc:SAML:2.0:assertion';
    var done = function (err, assertion) {
      if (err) { return callback(err); }

      if (typeof assertion === 'string') {
        assertion = new xmldom.DOMParser().parseFromString(assertion);
      }

      // if saml assertion has a prefix but namespace is defined on parent, copy it to assertion
      if (assertion && assertion.prefix && !assertion.getAttributeNS(saml2Namespace, assertion.prefix)) {
        assertion.setAttribute('xmlns:' + assertion.prefix, assertion.lookupNamespaceURI(assertion.prefix));
      }

      callback(null, assertion);
    };

    var assertions = samlpResponse.getElementsByTagNameNS(saml2Namespace, 'Assertion');
    if (assertions.length > 1) {
      return done(new Error('A SAMLResponse can contains only one Assertion element.'));
    }

    var token = assertions[0];
    if (!token) {
      // check for encrypted assertion
      var encryptedAssertion = samlpResponse.getElementsByTagNameNS(saml2Namespace, 'EncryptedAssertion');
      if (encryptedAssertion.length > 1) {
        return done(new Error('A SAMLResponse can contains only one EncryptedAssertion element.'));
      }

      var encryptedToken = encryptedAssertion[0];
      if (encryptedToken) {
        var encryptedData = encryptedToken.getElementsByTagNameNS('http://www.w3.org/2001/04/xmlenc#', 'EncryptedData')[0];
        if (!encryptedData) {
          return done(new Error('EncryptedData not found.'));
        }

        if (!this.options.decryptionKey) {
          return done(new Error('Assertion is encrypted. Please set options.decryptionKey with your decryption private key.'));
        }

        return xmlenc.decrypt(encryptedData, { key: this.options.decryptionKey, autopadding: this.options.autopadding }, done);
      }
    }

    done(null, token);
  },

  getSamlStatus: function (samlResponse) {
    var status = {};

    if (typeof samlResponse === 'string') {
      samlResponse = new xmldom.DOMParser().parseFromString(samlResponse);
    }

    // status code
    var statusCodeXml = xpath.select("//*[local-name(.)='Status']/*[local-name(.)='StatusCode']", samlResponse)[0];
    if (statusCodeXml) {
      status.code = statusCodeXml.getAttribute('Value');
      // status sub code
      var statusSubCodeXml = xpath.select("//*[local-name(.)='Status']/*[local-name(.)='StatusCode']/*[local-name(.)='StatusCode']", samlResponse)[0];
      if (statusSubCodeXml) {
        status.subCode = statusSubCodeXml.getAttribute('Value');
      }
    }

    // status message
    var samlStatusMsgXml = xpath.select("//*[local-name(.)='Status']/*[local-name(.)='StatusMessage']", samlResponse)[0];
    if (samlStatusMsgXml) {
      status.message = samlStatusMsgXml.textContent;
    }

    // status detail
    var samlStatusDetailXml = xpath.select("//*[local-name(.)='Status']/*[local-name(.)='StatusDetail']", samlResponse)[0];
    if (samlStatusDetailXml) {
      status.detail = samlStatusDetailXml.textContent;
    }

    return status;
  },

  validateSamlResponse: function (samlResponse, callback) {
    var self = this;

    if (typeof samlResponse === 'string') {
      samlResponse = new xmldom.DOMParser().parseFromString(samlResponse);
    }

    // Check that the saml Resopnse actually has a Response object
    var responseXML = xpath.select("//*[local-name(.)='Response']", samlResponse)[0];
    if (!responseXML){ 
      return callback(new Error('XML is not a valid saml response'));
    }

    self.isValidResponseID(responseXML.getAttribute('ID'), function(err){
      if (err) return callback(err);

      var inResponseTo = responseXML.getAttribute('InResponseTo');

      self.isValidInResponseTo(inResponseTo, function(err){
        if (err) return callback(err);

        var destination = responseXML.getAttribute('Destination');

        // https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
        // Page 36 of 91
        // Destination [Optional]
        // A URI reference indicating the address to which this request has been sent. This is useful to prevent
        // malicious forwarding of requests to unintended recipients, a protection that is required by some
        // protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the
        // location at which the message was received. If it does not, the request MUST be discarded. Some
        // protocol bindings may require the use of this attribute (see [SAMLBind]).
        if (self.options && self.options.checkDestination && destination && destination !== self.options.destinationUrl){
          self.eventEmitter.emit('destintationValidationFailed', {
            configuredDestination: self.options.destinationUrl,
            assertionDestination: destination
          });
          // return callback(new Error('Destination endpoint ' + destination + ' did not match ' + self.options.destinationUrl));    
        }

        // check status
        var samlStatus = self.getSamlStatus(samlResponse);

        // Check if this is a known error
        var errorMessage = ErrorMessages[samlStatus.subCode] ||
                          ErrorMessages[samlStatus.code];

        if (errorMessage) {
          // Return auth failed with the actual message or a friendly message
          return callback (new AuthenticationFailedError(samlStatus.message || errorMessage, samlStatus.detail));
        }

        // extract assertion
        self.extractAssertion(samlResponse, function (err, assertion) {
          if (err) { return callback(err); }
          if (!assertion) {
            return callback(new Error('saml response does not contain an Assertion element (Status: ' + samlStatus.code + ')'));
          }

          var samlResponseSignaturePath = "//*[local-name(.)='Response']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
          var isResponseSigned = xpath.select(samlResponseSignaturePath, samlResponse).length > 0;
          var samlAssertionSignaturePath = "//*[local-name(.)='Assertion']/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
          var isAssertionSigned =  xpath.select(samlAssertionSignaturePath, assertion).length > 0;

          if (!isResponseSigned && !isAssertionSigned) {
            return callback(new Error('neither the response nor the assertion are signed'));
          }

         if (isAssertionSigned) {
            var assertionSignature = xpath.select(samlAssertionSignaturePath, assertion)[0];
            if (assertionSignature.prefix) {
              try {
                var dsigNamespace = assertionSignature.lookupNamespaceURI(assertionSignature.prefix);
                if (dsigNamespace && !assertionSignature.getAttribute('xmlns:' + assertionSignature.prefix)) {
                  // saml assertion signature has a prefix but namespace is defined on parent, copy it to assertion
                  assertionSignature.setAttribute('xmlns:' + assertionSignature.prefix, dsigNamespace);
                }
              } catch(e) {}
            }

            // If we find that a namespace was defined in resopnse and is used in assertion, we copy it to the assertion element 
            if (responseXML.attributes) {
              var length = responseXML.attributes.length;
              for (var i = 0; i < length; ++i) {
                var attr = responseXML.attributes[i];
                // If attribute is a namespace, and is the signature prefix and is used in Assertion, cpy it to assertion
                if (attr.name.indexOf("xmlns") === 0 && 
                  attr.name.indexOf('xmlns:' + assertionSignature.prefix) === -1 &&
                  xpath.select("//*[local-name(.)='Assertion']//*[namespace-uri(.)='" + attr.value + "'] or //*[local-name(.)='Assertion']//@*[namespace-uri(.)='" + attr.value + "']", samlResponse)) {
                  assertion.setAttribute(attr.name, attr.value);
                }
              }
            }
          }

          if (isResponseSigned) {
            self._saml.validateSignature(samlResponse, {
              cert: self.options.cert,
              thumbprints: self.options.thumbprints,
              signaturePath: samlResponseSignaturePath
            },
            function (err) {
              if (err) { return callback(err); }

              if (!isAssertionSigned) {
                return self._saml.parseAssertion(assertion, callback);
              }

              return self._saml.validateSamlAssertion(assertion, callback);
            });
          }
          else if (isAssertionSigned) {
            return self._saml.validateSamlAssertion(assertion, callback);
          }
        });
      });
    });
  }
};

function generateInstant() {
  var date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ":" + ('0' + date.getUTCMinutes()).slice(-2) + ":" + ('0' + date.getUTCSeconds()).slice(-2) + "Z";
}