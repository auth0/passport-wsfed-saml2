Passport-wsfed-saml2
=============

[![Build Status](https://travis-ci.org/auth0/passport-wsfed-saml2.png)](https://travis-ci.org/auth0/passport-wsfed-saml2)

This is a ws-federation protocol + SAML2 tokens authentication provider for [Passport](http://passportjs.org/).

The code was originally based on Henri Bergius's [passport-saml](https://github.com/bergie/passport-saml) library.

Passport-wsfed-saml2 has been tested to work with both [Windows Azure Active Directory / Access Control Service](https://www.windowsazure.com/en-us/home/features/identity/) and with [Microsoft Active Directory Federation Services](http://en.wikipedia.org/wiki/Active_Directory_Federation_Services).

## Installation

    $ npm install passport-wsfed-saml2

## Usage

### Configure strategy

This example utilizes a development namespace (auth10-dev) on [Windows Azure Access Control Service](https://www.windowsazure.com/en-us/home/features/identity/) and is using Google as the only identity provider configured for the sample application.


```javascript
passport.use(new wsfedsaml2(
  {
    path: '/login/callback',
    realm: 'urn:node:app',
    homeRealm: '', // optionally specify an identity provider to avoid showing the idp selector
    identityProviderUrl: 'https://auth10-dev.accesscontrol.windows.net/v2/wsfederation',
    cert: 'MIIDFjCCAf6gAwIBAgIQDRRprj9lv5RBvaQdlFltDzANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDEyRhdXRoMTAtZGV2LmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTEwOTIxMDMzMjMyWhcNMTIwOTIwMDkzMjMyWjAvMS0wKwYDVQQDEyRhdXRoMTAtZGV2LmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCEIAEB/KKT3ehNMy2MQEyJIQ14CnZ8DC2FZgL5Gw3UBSdRb9JinK/gw7yOQtwKfJUqeoZaUSAAdcdbgqwVxOnMBfWiYX7DGlEznSfqYVnjOWjqqjpoe0h6RaOkdWovDtoidmqVV1tWRJFjkj895clPxkLpnqqcycfXtSdZen0SroGyirD2mhMc9ccLbJ3zRnBNjlvpo5zow1zYows09tNC2EhGROL/OS4JNRQnJRICZC+WkA7Igf3xb4btJOzIPYhFiqCGrd/81CHmAyEuNzyc60I5yomDQfZ91Eb5Uk3F7mlfAlYB2aZwDwldLSOlVE8G1E5xFexF/5KyPC4ShNodAgMBAAGjLjAsMAsGA1UdDwQEAwIE8DAdBgNVHQ4EFgQUyYfx/r0czsPgTzitqey+fGMQpkcwDQYJKoZIhvcNAQEFBQADggEBAB5dgQlM3tKS+/cjlvMCPjZH0Iqo/Wxecri3YWi2iVziZ/TQ3dSV+J/iTyduN7rJmFQzTsNERcsgyAwblwnEKXXvlWo8G/+VDIMh3zVPNQFKns5WPkfkhoSVlnZPTQ8zdXAcWgDXbCgvdqIPozdgL+4l0W0XVL1ugA4/hmMXh4TyNd9Qj7MWvlmwVjevpSqN4wG735jAZFHb/L/vvc91uKqP+JvLNj8tPFVxatzi56X1V8jBM61Hx1Z9D0RCDjtmcQVysVEylW9O6mNy6ZrhLm0q5yecWudfBbTKDqRoCHQRjrMU2c5q/ZFDtgjLim7FaNxFbgTyjeRCPclEhfemYVg='
  },
  function(profile, done) {
    findByEmail(profile.email, function(err, user) {
      if (err) {
        return done(err);
      }
      return done(null, user);
    });
  })
));
```

### Provide the authentication callback

You need to provide a route corresponding to the `path` configuration parameter given to the strategy:

```javascript
app.post('/login/callback',
  passport.authenticate('wsfed-saml2', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);
```

### Jwt

Although this started as wsfed&saml we added support for wsfed&jwt. Usage is

~~~javascript
passport.use(new wsfedsaml2(
  {
    jwt: {
      //same options than node-jsonwebtoken
      algorithm: 'RS256'
    },
    cert: 'MIIDFjCCAf6gAwIBAgIQDRRprj9lv5RBvaQdlFltDzANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDEyRhdXRoMTAtZGV2LmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTEwOTIxMDMzMjMyWhcNMTIwOTIwMDkzMjMyWjAvMS0wKwYDVQQDEyRhdXRoMTAtZGV2LmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCEIAEB/KKT3ehNMy2MQEyJIQ14CnZ8DC2FZgL5Gw3UBSdRb9JinK/gw7yOQtwKfJUqeoZaUSAAdcdbgqwVxOnMBfWiYX7DGlEznSfqYVnjOWjqqjpoe0h6RaOkdWovDtoidmqVV1tWRJFjkj895clPxkLpnqqcycfXtSdZen0SroGyirD2mhMc9ccLbJ3zRnBNjlvpo5zow1zYows09tNC2EhGROL/OS4JNRQnJRICZC+WkA7Igf3xb4btJOzIPYhFiqCGrd/81CHmAyEuNzyc60I5yomDQfZ91Eb5Uk3F7mlfAlYB2aZwDwldLSOlVE8G1E5xFexF/5KyPC4ShNodAgMBAAGjLjAsMAsGA1UdDwQEAwIE8DAdBgNVHQ4EFgQUyYfx/r0czsPgTzitqey+fGMQpkcwDQYJKoZIhvcNAQEFBQADggEBAB5dgQlM3tKS+/cjlvMCPjZH0Iqo/Wxecri3YWi2iVziZ/TQ3dSV+J/iTyduN7rJmFQzTsNERcsgyAwblwnEKXXvlWo8G/+VDIMh3zVPNQFKns5WPkfkhoSVlnZPTQ8zdXAcWgDXbCgvdqIPozdgL+4l0W0XVL1ugA4/hmMXh4TyNd9Qj7MWvlmwVjevpSqN4wG735jAZFHb/L/vvc91uKqP+JvLNj8tPFVxatzi56X1V8jBM61Hx1Z9D0RCDjtmcQVysVEylW9O6mNy6ZrhLm0q5yecWudfBbTKDqRoCHQRjrMU2c5q/ZFDtgjLim7FaNxFbgTyjeRCPclEhfemYVg='
  },
  function(profile, done) {
    findByEmail(profile.email, function(err, user) {
      if (err) {
        return done(err);
      }
      return done(null, user);
    });
  })
));
~~~

### Configure strategy for ADFS (WS-Fed)

This example utilizes a strategy with ADFS using WS-Fed.

```javascript
passport.use('wsfed-saml2', new wsfedsaml2({
	// ADFS RP identifier
	realm: 'urn:node:wsfedapp',
	identityProviderUrl: 'https://my-adfs/adfs/ls',
	// ADFS token signing certificate
	thumbprint: '5D27....D27E'
	// or options.cert: fs.readFileSync("adfs_signing_key.cer")
}, function (profile, done) {
 // ...
}));

```

### Configure strategy for ADFS (SAMLp)

This example utilizes a strategy using SAMLp and RP token encryption.

```javascript
passport.use('wsfed-saml2', new wsfedsaml2({
	// ADFS RP identifier
	realm: 'urn:node:samlapp',
	identityProviderUrl: 'https://my-adfs/adfs/ls',
    // ADFS token signing certificate
    thumbprint: '5D27...D27E',
	// or options.cert: fs.readFileSync("adfs_signing_key.cer")
    protocol: "samlp",
	// This is the private key (use case where ADFS
	// is configured for RP token encryption)
    decryptionKey: fs.readFileSync("server.key")
}, function (profile, done) {
 // ...
}));
```

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Security Notice

The [Security Notice](SECURITY-NOTICE.md) lists the version that is vulnerable and the actions that are required to upgrade to the lastest version.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
