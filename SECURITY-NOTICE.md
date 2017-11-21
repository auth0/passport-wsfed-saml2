Security vulnerability details for passport-wsfed-saml2 < 3.0.5
===============================================================

A vulnerability has been discovered in the passport-wsfed-saml2 library affecting versions < 3.0.5. This vulnerability allows an attacker to impersonate another user and potentially elevate their privileges if the SAML identity provider:

* signs SAML response and signs assertion
* does not sign SAML response and signs assertion

Developers using the passport-wsfed-saml2 Passport Strategy need to upgrade to the latest version: 3.0.5.

Updated packages are available on npm. To ensure delivery of additional bug fixes moving forward, please make sure your `package.json` file is updated to take patch and minor level updates of our libraries. See below:

```
{
  "dependencies": {
    "passport-wsfed-saml2": "^3.0.5"
  }
}
```

## Upgrade Notes

This fix patches the library that your application runs, but will not impact your users, their current state, or any existing sessions.
