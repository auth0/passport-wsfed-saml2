function SamlRequestParserError (message, detail, status) {
    var err = Error.call(this, message);
    err.name = 'SamlRequestParserError';
    err.message = message || 'Error parsing SAMLRequest';
    err.detail = detail;
    err.status = status || 400;
    return err;
}

SamlRequestParserError.prototype = Object.create(Error.prototype);
SamlRequestParserError.prototype.constructor = SamlRequestParserError;

module.exports = SamlRequestParserError;