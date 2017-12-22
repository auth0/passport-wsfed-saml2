exports.Strategy = require('./strategy');
exports.SAML = require('./saml');
exports.samlp = require('./samlp');

exports.AuthenticationFailedError = require('./errors/AuthenticationFailedError');
exports.SamlAssertionParserError = require('./errors/SamlAssertionParserError');
exports.SamlResponseParserError = require('./errors/SamlResponseParserError');
exports.WSFederationResultParserError = require('./errors/WSFederationResultParserError');
