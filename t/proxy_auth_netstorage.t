#!/usr/bin/perl

# Tests for ngx_http_proxy_auth_netstorage_module with proxy filter support.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite ngx_condition_module
	ngx_http_proxy_auth_netstorage_module/);

plan(skip_all => 'proxy filter build required')
	unless $t->has_module('ngx_http_proxy_filter_module');

$t->plan(10);

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
            return 200 "$request_uri|$http_x_akamai_acs_action|$http_x_akamai_acs_auth_data|$http_x_akamai_acs_auth_sign";
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        condition special str_eq $arg_mode special;

        proxy_auth_netstorage on;
        proxy_auth_netstorage_account account;
        proxy_auth_netstorage_key base-key;
        proxy_auth_netstorage_prefix cp;

        proxy_set_header X-Akamai-ACS-Action stale-action;
        proxy_set_header X-Akamai-ACS-Auth-Data stale-data;
        proxy_set_header X-Akamai-ACS-Auth-Sign stale-sign;

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
                proxy_auth_netstorage_prefix selected-cp;
            }

            proxy_auth_netstorage_account fallback;
            proxy_auth_netstorage_key fallback-key;
            proxy_auth_netstorage_prefix fallback-cp;
            proxy_pass http://127.0.0.1:8081;
        }

        location = /order {
            proxy_auth_netstorage_account first;
            proxy_auth_netstorage_key first-key;
            proxy_auth_netstorage_prefix first-cp;

            when special {
                proxy_auth_netstorage_account second;
                proxy_auth_netstorage_key second-key;
                proxy_auth_netstorage_prefix second-cp;
            }

            proxy_pass http://127.0.0.1:8081;
        }

        location /inherit/ {
            proxy_auth_netstorage_account inherited;
            proxy_auth_netstorage_key inherited-key;
            proxy_auth_netstorage_prefix inherited-cp;

            location = /inherit/child {
                proxy_pass http://127.0.0.1:8081;
            }
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  incomplete;

        proxy_auth_netstorage on;
        proxy_auth_netstorage_account account;

        location / {
            proxy_set_header X-Akamai-ACS-Action stale-action;
            proxy_set_header X-Akamai-ACS-Auth-Data stale-data;
            proxy_set_header X-Akamai-ACS-Auth-Sign stale-sign;
            proxy_pass http://127.0.0.1:8081;
        }
    }
}

EOF

$t->run();

###############################################################################

signature_ok(auth_body('/basic?x=1'), '/cp/basic?x=1', 'account', 'base-key',
	'direct filter rewrites the URI and signs all authentication headers');

is(auth_body('/off'), '/off|stale-action|stale-data|stale-sign',
	'disabled authentication preserves URI and existing headers');
is(auth_body('/bypass?skip=1'),
	'/bypass?skip=1|stale-action|stale-data|stale-sign',
	'bypass preserves URI and existing headers');

signature_ok(auth_body('/conditional?mode=special'),
	'/selected-cp/conditional?mode=special', 'selected', 'selected-key',
	'matching condition selects account, key, and prefix');
signature_ok(auth_body('/conditional?mode=other'),
	'/fallback-cp/conditional?mode=other', 'fallback', 'fallback-key',
	'condition miss selects unconditional credentials');
signature_ok(auth_body('/order?mode=special'),
	'/first-cp/order?mode=special', 'first', 'first-key',
	'first unconditional credentials win over a later condition');
signature_ok(auth_body('/inherit/child'), '/inherited-cp/inherit/child',
	'inherited', 'inherited-key', 'credentials inherit into a nested location');

is(auth_body('/', 8082), '/|stale-action|stale-data|stale-sign',
	'incomplete credentials leave the request unchanged');
is(auth_body('/basic', 8080, 'POST'),
	'/basic|stale-action|stale-data|stale-sign',
	'unsupported method leaves the request unchanged');
signature_ok(auth_body('/basic', 8080, 'OPTIONS'), '/cp/basic',
	'account', 'base-key', 'OPTIONS requests are signed');

###############################################################################

sub signature_ok {
	my ($body, $uri, $account, $key, $name) = @_;
	my ($actual_uri, $action, $data, $sign) = split /\|/, $body, 4;
	my $payload = $data . $uri
		. "\nx-akamai-acs-action:version=1&action=download\n";
	my $expected = encode_base64(hmac_sha256($payload, $key), '');

	my $valid = $actual_uri eq $uri
		&& $action eq 'version=1&action=download'
		&& $data =~ /^5, 0\.0\.0\.0, 0\.0\.0\.0, \d+, [0-9a-f]{32}, \Q$account\E$/
		&& $sign eq $expected;

	ok($valid, $name);
}


sub auth_body {
	my ($uri, $listen, $method) = @_;
	$listen ||= 8080;
	$method ||= 'GET';

	return http_content(http(<<EOF,
$method $uri HTTP/1.1
Host: localhost
Connection: close

EOF
		PeerAddr => '127.0.0.1:' . port($listen)));
}

###############################################################################
