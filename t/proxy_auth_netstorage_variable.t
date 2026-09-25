#!/usr/bin/perl

# Tests for the NetStorage variable fallback build.

###############################################################################

use warnings;
use strict;

use Digest::SHA qw/ hmac_sha256 /;
use MIME::Base64 qw/ encode_base64 /;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite ngx_expr_module
	ngx_http_proxy_auth_netstorage_module/);

plan(skip_all => 'variable fallback build required')
	if $t->has_module('ngx_http_proxy_filter_module');

$t->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8081;
        server_name  backend;

        location / {
            return 200 "$http_x_akamai_acs_action|$http_x_akamai_acs_auth_data|$http_x_akamai_acs_auth_sign";
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        expr special str_eq $arg_mode special;

        proxy_auth_netstorage on;
        proxy_auth_netstorage_account account;
        proxy_auth_netstorage_key base-key;
        proxy_auth_netstorage_uri /signed$request_uri;

        proxy_set_header X-Akamai-ACS-Action $proxy_auth_netstorage_action;
        proxy_set_header X-Akamai-ACS-Auth-Data $proxy_auth_netstorage_data;
        proxy_set_header X-Akamai-ACS-Auth-Sign $proxy_auth_netstorage_sign;

        location = /basic {
            proxy_pass http://127.0.0.1:8081;
        }

        location = /off {
            proxy_auth_netstorage off;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /bypass {
            proxy_auth_netstorage_bypass $arg_skip;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /conditional {
            when special {
                proxy_auth_netstorage_account selected;
                proxy_auth_netstorage_key selected-key;
                proxy_auth_netstorage_uri /selected$request_uri;
            }

            proxy_auth_netstorage_account fallback;
            proxy_auth_netstorage_key fallback-key;
            proxy_auth_netstorage_uri /fallback$request_uri;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /order {
            proxy_auth_netstorage_account first;
            proxy_auth_netstorage_key first-key;
            proxy_auth_netstorage_uri /first$request_uri;

            when special {
                proxy_auth_netstorage_account second;
                proxy_auth_netstorage_key second-key;
                proxy_auth_netstorage_uri /second$request_uri;
            }

            proxy_pass http://127.0.0.1:8081;
        }

        location /inherit/ {
            proxy_auth_netstorage_account inherited;
            proxy_auth_netstorage_key inherited-key;
            proxy_auth_netstorage_uri /inherited$request_uri;

            location = /inherit/child {
                proxy_pass http://127.0.0.1:8081;
            }
        }

        location = /invalid-uri {
            proxy_auth_netstorage_uri invalid;
            proxy_pass http://127.0.0.1:8081;
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  incomplete;

        proxy_auth_netstorage on;
        proxy_auth_netstorage_account account;

        proxy_set_header X-Akamai-ACS-Action $proxy_auth_netstorage_action;
        proxy_set_header X-Akamai-ACS-Auth-Data $proxy_auth_netstorage_data;
        proxy_set_header X-Akamai-ACS-Auth-Sign $proxy_auth_netstorage_sign;

        location / {
            proxy_pass http://127.0.0.1:8081;
        }
    }
}

EOF

$t->run();

###############################################################################

signature_ok(auth_body('/basic?x=1'), '/signed/basic?x=1',
	'account', 'base-key', 'variables contain a valid NetStorage signature');

is(auth_body('/off', 8080, 'GET', original_headers()),
	'old-action|old-data|old-sign',
	'disabled variables fall back to incoming headers');
is(auth_body('/bypass?skip=1', 8080, 'GET', original_headers()),
	'old-action|old-data|old-sign',
	'bypassed variables fall back to incoming headers');

signature_ok(auth_body('/conditional?mode=special'),
	'/selected/conditional?mode=special', 'selected', 'selected-key',
	'matching condition selects account, key, and URI');
signature_ok(auth_body('/conditional?mode=other'),
	'/fallback/conditional?mode=other', 'fallback', 'fallback-key',
	'condition miss selects unconditional signing values');
signature_ok(auth_body('/order?mode=special'), '/first/order?mode=special',
	'first', 'first-key', 'first unconditional signing values win');
signature_ok(auth_body('/inherit/child'), '/inherited/inherit/child',
	'inherited', 'inherited-key', 'signing values inherit into a nested location');

is(auth_body('/', 8082, 'GET', original_headers()),
	'old-action|old-data|old-sign',
	'incomplete credentials fall back to incoming headers');
is(auth_body('/basic', 8080, 'POST', original_headers()),
	'old-action|old-data|old-sign',
	'unsupported method falls back to incoming headers');
like(auth_response('/invalid-uri'), qr/^HTTP\/1\.1 500 /,
	'invalid signing URI fails the request');

signature_ok(auth_body('/basic', 8080, 'OPTIONS'), '/signed/basic',
	'account', 'base-key', 'OPTIONS requests generate variable signatures');

###############################################################################

sub signature_ok {
	my ($body, $uri, $account, $key, $name) = @_;
	my ($action, $data, $sign) = split /\|/, $body, 3;
	my $payload = $data . $uri
		. "\nx-akamai-acs-action:version=1&action=download\n";
	my $expected = encode_base64(hmac_sha256($payload, $key), '');

	my $valid = $action eq 'version=1&action=download'
		&& $data =~ /^5, 0\.0\.0\.0, 0\.0\.0\.0, \d+, [0-9a-f]{32}, \Q$account\E$/
		&& $sign eq $expected;

	ok($valid, $name);
}


sub original_headers {
	return "X-Akamai-ACS-Action: old-action\n"
		. "X-Akamai-ACS-Auth-Data: old-data\n"
		. "X-Akamai-ACS-Auth-Sign: old-sign\n";
}


sub auth_body {
	return http_content(auth_response(@_));
}


sub auth_response {
	my ($uri, $listen, $method, $headers) = @_;
	$listen ||= 8080;
	$method ||= 'GET';
	$headers ||= '';

	return http(<<EOF,
$method $uri HTTP/1.1
Host: localhost
${headers}Connection: close

EOF
		PeerAddr => '127.0.0.1:' . port($listen));
}

###############################################################################
