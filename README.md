# ngx_http_proxy_auth_akamai_netstorage_module

# Name
`ngx_http_proxy_auth_akamai_netstorage_module` is an Nginx module that automatically generates [Akamai NetStorage](https://www.akamai.com/resources/product-brief/netstorage) authentication headers for proxy requests to Akamai NetStorage. It implements the [Akamai NetStorage Usage Api](https://techdocs.akamai.com/netstorage-usage/reference/format-an-api-call) for secure proxy access.

# Table of Content

- [ngx\_http\_proxy\_auth\_akamai\_netstorage\_module](#ngx_http_proxy_auth_akamai_netstorage_module)
- [Name](#name)
- [Table of Content](#table-of-content)
- [Status](#status)
- [Synopsis](#synopsis)
- [Installation](#installation)
- [Directives](#directives)
    - [`proxy_auth_akamai_netstorage`](#proxy_auth_akamai_netstorage)
    - [`proxy_auth_akamai_netstorage_account`](#proxy_auth_akamai_netstorage_account)
    - [`proxy_auth_akamai_netstorage_key`](#proxy_auth_akamai_netstorage_key)
    - [`proxy_auth_akamai_netstorage_uri`](#proxy_auth_akamai_netstorage_uri)
    - [`proxy_auth_akamai_netstorage_bypass`](#proxy_auth_akamai_netstorage_bypass)
- [Variables](#variables)
    - [`$proxy_auth_akamai_netstorage_action`](#proxy_auth_akamai_netstorage_action)
    - [`$proxy_auth_akamai_netstorage_data`](#proxy_auth_akamai_netstorage_data)
    - [`$proxy_auth_akamai_netstorage_sign`](#proxy_auth_akamai_netstorage_sign)
- [Known Limitations](#known-limitations)
- [Author](#author)
- [License](#license)

# Status
This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

# Synopsis
```nginx
http {
    # Main configuration example
    upstream akamai_netstorage {
        server baseball-nsu.akamaihd.net;
    }

    server {
        listen 80;

        # Enable module and configure Akamai credentials
        proxy_auth_akamai_netstorage on;
        # Optional: Bypass authentication via condition
        proxy_auth_akamai_netstorage_bypass $http_x_akamai_acs_action $arg_nosign $http_nosign;

        proxy_auth_akamai_netstorage_account "UploadAccountMedia";
        proxy_auth_akamai_netstorage_key "AbCd3fgoURanooXsbZ6deuZwIBRui4HvO57gf6Hr1CZGu";

        set $upstream_uri /123456$request_uri;
        proxy_auth_akamai_netstorage_uri $upstream_uri;  # Signature URI

        location / {
            # Optional: Bypass authentication via condition
            proxy_auth_akamai_netstorage_bypass $arg_nosign;

            # Add proxy authentication
            proxy_set_header X-Akamai-ACS-Action $proxy_auth_akamai_netstorage_action;
            proxy_set_header X-Akamai-ACS-Auth-Data $proxy_auth_akamai_netstorage_data;
            proxy_set_header X-Akamai-ACS-Auth-Sign $proxy_auth_akamai_netstorage_sign;

            proxy_set_header Host baseball-nsu.akamaihd.net;
            proxy_pass https://akamai_netstorage$upstream_uri;
        }
    }
}
```

# Installation
To use this module, configure your Nginx branch with `--add-module=/path/to/ngx_http_proxy_auth_akamai_netstorage_module`.

# Directives

### `proxy_auth_akamai_netstorage`

**Syntax:** `proxy_auth_akamai_netstorage on|off;`

**Default:** `off`

**Context:** `http`, `server`, `location`

Enables or disables Akamai NetStorage authentication. When enabled, generates these request headers value to variables:

- `X-Akamai-ACS-Action: version=1&action=download` -> $proxy_auth_akamai_netstorage_action
- `X-Akamai-ACS-Auth-Data: <generated_auth_data>` -> $proxy_auth_akamai_netstorage_data
- `X-Akamai-ACS-Auth-Sign: <generated_signature>` -> $proxy_auth_akamai_netstorage_sign

Note that it will not overwrite existing request headers. You can use `proxy_set_header` to overwrite them.



### `proxy_auth_akamai_netstorage_account`

**Syntax:** `proxy_auth_akamai_netstorage_account <upload_account_id>;`

**Default:** `-`

**Context:** `http`, `server`, `location`

Sets the Akamai NetStorage upload account ID used in authentication data.

### `proxy_auth_akamai_netstorage_key`

**Syntax:** `proxy_auth_akamai_netstorage_key <secret_key>;`

**Default:** `-`

**Context:** `http`, `server`, `location`

Sets the HTTP API key from Akamai NetStorage.

### `proxy_auth_akamai_netstorage_uri`

**Syntax:** `proxy_auth_akamai_netstorage_uri <uri>;`

**Default:** `-`

**Context:** `http`, `server`, `location`

Specifies the uri for signing. It must be explicitly specified and must be exactly the same as the actual upstream request uri. The value can contain variables.

### `proxy_auth_akamai_netstorage_bypass`

**Syntax:** `proxy_auth_akamai_netstorage_bypass string ...;`

**Default:** `-`

**Context:** `http`, `server`, `location`

Defines conditions under which the requests will skip authentication generation. If at least one value of the string parameters is not empty and is not equal to “0” then authentication request headers generation will be skipped.
Example:
```nginx
proxy_auth_akamai_netstorage_bypass $arg_noauth $http_noauth;  # Skip when $arg_noauth or $http_noauth not empty
```

# Variables

### `$proxy_auth_akamai_netstorage_action`

Returns the generated action value (`version=1&action=download`) when the proxy authentication handler has executed successfully, otherwise returns the original `X-Akamai-ACS-Action` request header value if present.

Use with: `proxy_set_header X-Akamai-ACS-Action $proxy_auth_akamai_netstorage_action;`

### `$proxy_auth_akamai_netstorage_data`

Returns the generated authentication data when the proxy authentication handler has executed successfully, otherwise returns the original `X-Akamai-ACS-Auth-Data` request header value if present.

Use with: `proxy_set_header X-Akamai-ACS-Auth-Data $proxy_auth_akamai_netstorage_data;`

### `$proxy_auth_akamai_netstorage_sign`

Returns the generated signature when the proxy authentication handler has executed successfully, otherwise returns the original `X-Akamai-ACS-Auth-Sign` request header value if present.

Use with: `proxy_set_header X-Akamai-ACS-Auth-Sign $proxy_auth_akamai_netstorage_sign;`

# Known Limitations
1. Requires OpenSSL 1.1.1+ (for HMAC-SHA256)
2. Only supports file downloads, and does not support other apis yet.

# Author
Hanada <im@hanada.info>

# License
This module is licensed under the BSD 2-Clause License.