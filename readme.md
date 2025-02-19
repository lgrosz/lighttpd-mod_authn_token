# Notice
Use [mod_authn_jwt](https://github.com/lgrosz/mod_authn_jwt) instead.

# General

A Lighty authorization module for general token authentication.

This module can be used as a means of authenticating several applications by
serving tokens from an external authentication server.

# Configuration

```lighttpd.conf
# Token module configuration
auth.backend.token.validator = "validator-program"

# Auth module configuration
auth.require = ( "" =>
    (
        "method"  => "token",
        "realm"   => "",
        "require" => "valid-user",
    )
)
```

`validator-program` can be any program that takes `<token>` (from
`Authorization: Bearer <token>`) and exits 0 if the token is valid.
