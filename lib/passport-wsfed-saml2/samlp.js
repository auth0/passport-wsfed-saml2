const xpath       = require('xpath');
const qs          = require('querystring');
const zlib        = require('zlib');
const xtend       = require('xtend');
const url         = require('url');
const xmlenc      = require('xml-encryption');
const crypto      = require('crypto');
const querystring = require('querystring');
const xmlCrypto   = require('xml-crypto');
const templates   = require('./templates');
const EventEmitter = require('events');
const validUrl     = require('valid-url');
const xmldom = require('@xmldom/xmldom');

const domParser = new xmldom.DOMParser();
const utils                     = require('./utils');
const AuthenticationFailedError = require('./errors/AuthenticationFailedError');

const saml2Namespace = 'urn:oasis:names:tc:SAML:2.0:assertion';

const BINDINGS = {
  HTTP_POST:      'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  HTTP_REDIRECT:  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
};

const ErrorMessages = {
  'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch': 'The SAML responder could not process the request because the version of the request message was incorrect.',
  'urn:oasis:names:tc:SAML:2.0:status:Requester' : 'The request could not be performed due to an error on the part of the requester',
  'urn:oasis:names:tc:SAML:2.0:status:Responder' : 'The request could not be performed due to an error on the part of the SAML responder or SAML authority',
  'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed' : 'The responding provider was unable to successfully authenticate the principal'
};

const encodingMappings = {
  'ISO-8859-1': 'binary',
  'UTF-8': 'utf8'
};

function ignoreValidationFunction(samlResponseID, done){
  return done();
}

function getProp(obj, path) {
  return path.split('.').reduce(function (prev, curr) {
    return prev[curr];
  }, obj);
}

const supplant = function (tmpl, o) {
  return tmpl.replace(/\@\@([^\@]*)\@\@/g,
      function (a, b) {
        const r = getProp(o, b);
        return typeof r === 'string' || typeof r === 'number' ? r : a;
      }
  );
};

const trimXml = function (xml) {
  return xml.replace(/\r\n/g, '')
      .replace(/\n/g,'')
      .replace(/>(\s*)</g, '><') //unindent
      .trim();
};

const removeHeaders = function (cert) {
  const pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
  if (pem && pem.length > 0) {
    return pem[2].replace(/[\n|\r\n]/g, '');
  }
  return null;
};

const sign = function (content, key, algorithm) {
  const signer = crypto.createSign(algorithm.toUpperCase());
  signer.update(content, 'latin1');
  return signer.sign(key, 'base64');
};

const algorithms = {
  signature: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1':  'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  digest: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
};

function collectAncestorNamespaces(node, nameSpaces = [], maxDeep = 5){
  if (!(node && node.parentNode) || maxDeep <= 0) {
    return nameSpaces;
  }

  const parent = node.parentNode;

  if (parent.attributes && parent.attributes.length > 0){
    for(let i=0;i<parent.attributes.length;i++){
      const attr = parent.attributes[i];
      if (attr && attr.nodeName && attr.nodeName.search(/^xmlns:/) !== -1){
        nameSpaces.push({key: attr.nodeName, value: attr.nodeValue});
      }
    }
  }

  return collectAncestorNamespaces(parent, nameSpaces, maxDeep - 1);
}

function generateInstant() {
  const date = new Date();
  return date.getUTCFullYear() + '-' + ('0' + (date.getUTCMonth()+1)).slice(-2) + '-' + ('0' + date.getUTCDate()).slice(-2) + 'T' + ('0' + date.getUTCHours()).slice(-2) + ':' + ('0' + date.getUTCMinutes()).slice(-2) + ':' + ('0' + date.getUTCSeconds()).slice(-2) + 'Z';
}

function stripQueryAndFragmentFromURL(url) {
  return url.split('#')[0].split('?')[0];
}

class Samlp {
  constructor(options, saml) {
    this.options = options || {};

    if (typeof options.deflate === 'undefined') {
      this.options.deflate = true;
    }

    this.options.checkDestination = (typeof this.options.checkDestination !== 'undefined') ? this.options.checkDestination : true;
    this.options.checkResponseID = (typeof this.options.checkResponseID !== 'undefined') ? this.options.checkResponseID : true;
    this.options.checkInResponseTo = (typeof this.options.checkInResponseTo !== 'undefined') ? this.options.checkInResponseTo : true;

    this.eventEmitter = this.options.eventEmitter || new EventEmitter();
    this._saml = saml;

    this.isValidResponseID = this.options.isValidResponseID || ignoreValidationFunction;
    this.isValidInResponseTo = this.options.isValidInResponseTo || ignoreValidationFunction;

    this.defaultEncoding = encodingMappings[this.options.default_encoding] || 'utf8';

    this.parser = domParser;
  }

  getSamlRequestParams (opts, callback) {
    const options = xtend(opts || {}, this.options);

    const idpUrl = options.identityProviderUrl;
    if (typeof idpUrl !== 'string' || !validUrl.isWebUri(idpUrl)) {
      return callback(new Error(`Invalid identity provider URL: ${JSON.stringify(idpUrl)}`));
    }

    const signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
    const digestAlgorithm = options.digestAlgorithm || 'sha256';

    const assert_and_destination = templates.assert_and_destination({
      Destination: idpUrl,
      AssertionConsumerServiceURL: options.callback
    });

    let model = {
      ID:               options.request_id,
      IssueInstant:     generateInstant(),
      Issuer:           options.realm,
      ProtocolBinding:  options.protocolBinding || BINDINGS.HTTP_POST,
      ForceAuthn:       options.forceAuthn,
      Destination:      idpUrl,
      AssertionConsumerServiceURL: options.assertionConsumerServiceURL || options.callback,
      AssertServiceURLAndDestination: assert_and_destination,
      AuthnContext:     options.authnContext || '',
      ProviderName:     options.providerName || ''
    };

    if (options.requestContext) {
      model = xtend(model, options.requestContext);
    }

    let SAMLRequest;
    let rawRequest;

    if (options.requestTemplate) {
      try {
        rawRequest = supplant(options.requestTemplate, model);
      } catch (e) {
        return callback(new Error('Malformed template passed. Could not parse.'));
      }
    } else {
      rawRequest = templates.samlrequest(model);
    }

    SAMLRequest = trimXml(rawRequest);

    const parsedUrl = url.parse(idpUrl, true);
    const params = {
      SAMLRequest: null,
      RelayState: options.RelayState || (parsedUrl.query && parsedUrl.query.RelayState) || ''
    };

    if (options.protocolBinding === BINDINGS.HTTP_POST || !options.deflate) {
      // HTTP-POST or HTTP-Redirect without deflate encoding
      if (options.signingKey) {
        // xml with embedded Signature

        const sig = new xmlCrypto.SignedXml({
          privateKey: options.signingKey.key,
          signatureAlgorithm: algorithms.signature[signatureAlgorithm],
          canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
          getKeyInfoContent: () => {
            return `<X509Data><X509Certificate>${removeHeaders(options.signingKey.cert)}</X509Certificate></X509Data>`;
          },
        });
        sig.addReference({
          xpath: "//*[local-name(.)='AuthnRequest' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:protocol']",
          transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
          digestAlgorithm: algorithms.digest[digestAlgorithm]
        });
        try {
          // we are not converting SAMLRequest into a DOM before sending to xml-crypto because at the current time we allow the following test:
          // invalid CDATA xml that does not cause an error. This probably *should* cause an error, but it doesn't.
          sig.computeSignature(SAMLRequest, { location: { reference: "//*[local-name(.)='Issuer']", action: 'after' } }); // Signature element must be located after Issuer
        } catch (e) {
          return callback(new Error('fail to compute signature'));
        }

        SAMLRequest = trimXml(sig.getSignedXml());
      }

      params.SAMLRequest = new Buffer(SAMLRequest).toString('base64');
      return callback(null, params);
    }

    // HTTP-Redirect with deflate encoding (http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf - section 3.4.4.1)
    zlib.deflateRaw(new Buffer(SAMLRequest), function (err, buffer) {
      if (err) {return callback(err);}

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
  }

  getSamlRequestUrl (opts, callback) {
    const options = xtend(opts || {}, this.options);

    this.getSamlRequestParams(options, function (err, params) {
      if (err) {return callback(err);}

      let parsedUrl = url.parse(options.identityProviderUrl, true);
      let samlRequestUrl = stripQueryAndFragmentFromURL(options.identityProviderUrl) + '?' + qs.encode(xtend(parsedUrl.query, params));
      if (parsedUrl.hash !== null) {
        samlRequestUrl += parsedUrl.hash;
      }
      return callback(null, samlRequestUrl);
    });
  }

  getSamlRequestForm (opts, callback) {
    const options = xtend(opts || {}, this.options);

    this.getSamlRequestParams(options, function (err, params) {
      if (err) {return callback(err);}

      return callback(null, templates.form({
        postUrl:      options.identityProviderUrl,
        RelayState:   params.RelayState,
        SAMLRequest:  params.SAMLRequest
      }));
    });
  }

  decodeResponse (req) {
    let decoded = new Buffer(req.body['SAMLResponse'], 'base64').toString(this.defaultEncoding);

    const encoding = utils.getEncoding(decoded);
    if (encoding && encodingMappings[encoding] && encodingMappings[encoding] !== this.defaultEncoding){
      // Encoding defers from the one configured, decode again with the correct value
      decoded = new Buffer(req.body['SAMLResponse'], 'base64').toString(encodingMappings[encoding]);
    }

    return decoded;
  }

  // samlpResponse may be both a string or a DOM depending on the caller.
  // if the assertion is encrypted returns:
  //    Document|DOM of the embedded encrypted assertion,
  //    boolean saying there was decryption
  //    str of the original XML of the encrypted assertion
  // else:
  //    Node|DOM of the assertion included in the original XML
  //    boolean saying there was no decryption
  extractAssertion (samlpResponse, callback) {
    samlpResponse = utils.parseSamlResponse(samlpResponse, this.parser);

    const foundAssertions = xpath.select("//*[local-name(.)='Assertion']", samlpResponse);
    if (foundAssertions.length > 1) {
      return callback(new Error('A SAMLResponse can contain only one Assertion element.'));
    }

    // After being sure no more "Assertion" elements are found, we extract it from the expected place
    const assertions = xpath.select("/*[local-name(.)='Response'][1]/*[local-name(.)='Assertion' and namespace-uri(.)='" + saml2Namespace + "']", samlpResponse);
    const token = assertions[0];

    if (!token) {
      // check for encrypted assertion
      const encryptedAssertionPath = "/*[local-name(.)='Response'][1]/*[local-name(.)='EncryptedAssertion' and namespace-uri(.)='" + saml2Namespace + "']";
      const encryptedAssertion = xpath.select(encryptedAssertionPath, samlpResponse);
      if (encryptedAssertion.length > 1) {
        return callback(new Error('A SAMLResponse can contain only one EncryptedAssertion element.'));
      }

      const encryptedToken = encryptedAssertion[0];
      if (encryptedToken) {
        const encryptedData = encryptedToken.getElementsByTagNameNS('http://www.w3.org/2001/04/xmlenc#', 'EncryptedData')[0];
        if (!encryptedData) {
          return callback(new Error('EncryptedData not found.'));
        }

        if (!this.options.decryptionKey) {
          return callback(new Error('Assertion is encrypted. Please set options.decryptionKey with your decryption private key.'));
        }

        return xmlenc.decrypt(encryptedData, {
          key: this.options.decryptionKey,
          autopadding: this.options.autopadding,
          disallowDecryptionWithInsecureAlgorithm: false,
          warnInsecureAlgorithm: false
        }, (err, decryptedAssertion) => {
          if (err) {
            return callback(err)
          }
          const assertion = utils.parseSamlAssertion(decryptedAssertion, this.parser);
          const foundAssertions = xpath.select("//*[local-name(.)='Assertion']", assertion);
          if (foundAssertions.length > 1) {
            return callback(new Error('A EncryptedAssertion can contain only one Assertion element.'));
          }
          // After being sure no more "Assertion" elements are found, we extract it from the expected place
          const assertions = xpath.select("/*[local-name(.)='Assertion' and namespace-uri(.)='" + saml2Namespace + "']", assertion);
          // if there are 0 matches, let the caller handle it
          return callback(null, assertions[0], true, decryptedAssertion);
        });
      }
    }

    callback(null, token, false);
  }

  getSamlStatus (samlResponse) {
    let status = {};

    samlResponse = utils.parseSamlResponse(samlResponse, this.parser);

    // status code
    const statusCodeXml = xpath.select("/*[local-name(.)='Response'][1]/*[local-name(.)='Status']/*[local-name(.)='StatusCode']", samlResponse)[0];
    if (statusCodeXml) {
      status.code = statusCodeXml.getAttribute('Value');
      // status sub code
      const statusSubCodeXml = xpath.select("/*[local-name(.)='Response'][1]/*[local-name(.)='Status']/*[local-name(.)='StatusCode']/*[local-name(.)='StatusCode']", samlResponse)[0];
      if (statusSubCodeXml) {
        status.subCode = statusSubCodeXml.getAttribute('Value');
      }
    }

    // status message
    const samlStatusMsgXml = xpath.select("/*[local-name(.)='Response'][1]/*[local-name(.)='Status']/*[local-name(.)='StatusMessage']", samlResponse)[0];
    if (samlStatusMsgXml) {
      status.message = samlStatusMsgXml.textContent;
    }

    // status detail
    const samlStatusDetailXml = xpath.select("/*[local-name(.)='Response'][1]/*[local-name(.)='Status']/*[local-name(.)='StatusDetail']", samlResponse)[0];
    if (samlStatusDetailXml) {
      status.detail = samlStatusDetailXml.textContent;
    }

    return status;
  }

  validateSamlResponse (samlResponseStr, meta, callback) {
    if (typeof samlResponseStr !== 'string') {
      throw new Error('samlResponse must be a string');
    }
    const samlResponse = utils.parseSamlResponse(samlResponseStr, this.parser);

    // Check that the saml Response actually has a Response object
    const responseXMLs = xpath.select("//*[local-name(.)='Response']", samlResponse);
    if (responseXMLs.length === 0) {
      return callback(new Error('XML is not a valid saml response'));
    }
    if (responseXMLs.length > 1) {
      return callback(new Error('SAMLResponse should be unique'));
    }
    const responseXML = responseXMLs[0];

    this.isValidResponseID(responseXML.getAttribute('ID'), (err) => {
      if (err && this.options.checkResponseID) {
        return callback(err);
      }

      const inResponseTo = responseXML.getAttribute('InResponseTo');

      this.isValidInResponseTo(inResponseTo, (err) => {
        if (err && this.options.checkInResponseTo) {
          return callback(err);
        }

        const destination = responseXML.getAttribute('Destination');

        // https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
        // Page 36 of 91
        // Destination [Optional]
        // A URI reference indicating the address to which this request has been sent. This is useful to prevent
        // malicious forwarding of requests to unintended recipients, a protection that is required by some
        // protocol bindings. If it is present, the actual recipient MUST check that the URI reference identifies the
        // location at which the message was received. If it does not, the request MUST be discarded. Some
        // protocol bindings may require the use of this attribute (see [SAMLBind]).
        if (destination && destination !== this.options.destinationUrl) {
          this.eventEmitter.emit('destinationValidationFailed', {
            configuredDestination: this.options.destinationUrl,
            assertionDestination: destination
          });

          if (this.options.checkDestination) {
            return callback(new Error('Destination endpoint ' + destination + ' did not match ' + this.options.destinationUrl));
          }
        }

        // check status
        const samlStatus = this.getSamlStatus(responseXML);

        // Check if this is a known error
        const errorMessage = ErrorMessages[samlStatus.subCode] ||
            ErrorMessages[samlStatus.code];

        if (errorMessage) {
          // Return auth failed with the actual message or a friendly message
          return callback (new AuthenticationFailedError(samlStatus.message || errorMessage, samlStatus.detail));
        }

        // extract assertion
        this.extractAssertion(responseXML, (err, assertionDom, encrypted, assertionStr) => {
          if (err) { return callback(err); }
          if (!assertionDom) {
            return callback(new Error('saml response does not contain an Assertion element (Status: ' + samlStatus.code + ')'));
          }

          const samlResponseSignaturePath = "/*[local-name(.)='Response'][1]/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";
          const isResponseSigned = xpath.select(samlResponseSignaturePath, responseXML).length > 0;

          const samlAssertionSignaturePath = encrypted ?
              "/*[local-name(.)='Assertion'][1]/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']" :
              "/*[local-name(.)='Response'][1]/*[local-name(.)='Assertion'][1]/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']";

          const isAssertionSigned =  xpath.select(samlAssertionSignaturePath, assertionDom).length > 0;

          this.eventEmitter.emit('SAMLResponse:signatures', {
            isResponseSigned: isResponseSigned,
            isAssertionSigned: isAssertionSigned
          });

          if (!isResponseSigned && !isAssertionSigned) {
            return callback(new Error('neither the response nor the assertion are signed'));
          }

          if (isAssertionSigned) {
            const assertionSignature = xpath.select(samlAssertionSignaturePath, assertionDom)[0];

            // If we find that a namespace was defined in response and is used in assertion, we copy it to the assertion element
            if (responseXML.attributes) {
              const length = responseXML.attributes.length;
              for (let i = 0; i < length; ++i) {
                const attr = responseXML.attributes[i];
                // If attribute is a namespace, and is the signature prefix and is used in Assertion, copy it to assertion
                // Don't set attributes that already exist (xmldom may copy them depending on the version)
                if (!assertionDom.getAttribute(attr.name)) {
                  continue
                }
                const select = encrypted ?
                    "/*[local-name(.)='Assertion'][1]//*[namespace-uri(.)='" + attr.value + "'] or /*[local-name(.)='Assertion'][1]//@*[namespace-uri(.)='" + attr.value + "']" :
                    "/*[local-name(.)='Response'][1]/*[local-name(.)='Assertion'][1]//*[namespace-uri(.)='" + attr.value + "'] or /*[local-name(.)='Response'][1]/*[local-name(.)='Assertion'][1]//@*[namespace-uri(.)='" + attr.value + "']";
                if (attr.name.indexOf('xmlns') === 0 &&
                    attr.name.indexOf('xmlns:' + assertionSignature.prefix) === -1 &&
                    xpath.select(select, responseXML)) {
                  assertionDom.setAttribute(attr.name, attr.value);
                }
              }
            }
          }

          if (isResponseSigned) {
            this._saml.validateSignature(samlResponseStr, {
              meta: meta,
              signaturePath: samlResponseSignaturePath
            }, (err, signed) => {
              if (err) { return callback(err); }

              this.extractAssertion(signed,  (err, assertion) => {
                if (err) {
                  // shouldn't happen
                  return callback(err);
                }
                if (!assertion) {
                  return callback(new Error('saml response does not contain an Assertion element (Status: ' + samlStatus.code + ')'));
                }
                // no need to validate the assertion once again due:
                // In parseAssertion, it decrypts the EncryptedAssertion from solely the signed string. Since the encrypted cipher text is signed via the response element, i.e. a subset, it's integrity is also protected.
                //Even if the underlying Encrypted Assertion post-decryption has a Signature, we don't need to verify it, because the cipher text was already protected
                return this._saml.parseAssertion(assertion, callback);
              });
            });
          }
          else if (isAssertionSigned) {
            return this._saml.validateSamlAssertion(assertionStr || samlResponseStr, { meta }, callback);
          }
        });
      });
    });
  }
}

module.exports = Samlp;