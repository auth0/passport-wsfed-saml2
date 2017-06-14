function AuthenticationFailedError (message, detail, status) {
  var err = Error.call(this, message);
  err.name = 'AuthenticationFailedError';
  err.message = message || 'Authentication Failed';
  err.detail = detail;
  err.status = status || 401;
  return err;
}

AuthenticationFailedError.prototype = Object.create(Error.prototype);
AuthenticationFailedError.prototype.constructor = AuthenticationFailedError;

module.exports = AuthenticationFailedError;
