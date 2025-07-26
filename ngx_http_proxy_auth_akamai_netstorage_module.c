
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>


typedef struct {
    ngx_flag_t                 enabled;

    ngx_array_t               *bypass;

    ngx_str_t                  account;
    ngx_str_t                  key;

    ngx_http_complex_value_t  *uri;
} ngx_http_proxy_auth_akamai_netstorage_loc_conf_t;


static ngx_int_t ngx_http_proxy_auth_akamai_netstorage_init(ngx_conf_t *cf);
static void *ngx_http_proxy_auth_akamai_netstorage_create_loc_conf(
    ngx_conf_t *cf);
static char *ngx_http_proxy_auth_akamai_netstorage_merge_loc_conf(
    ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_proxy_auth_akamai_netstorage_handler(
    ngx_http_request_t *r);


/* paan = proxy_auth_akamai_netstorage */
static ngx_str_t  ngx_http_paan_action_name =
    ngx_string("x-akamai-acs-action");
static ngx_str_t  ngx_http_paan_action_value =
    ngx_string("version=1&action=download");
static ngx_str_t  ngx_http_paan_auth_data_name =
    ngx_string("x-akamai-acs-auth-data");
static ngx_str_t  ngx_http_paan_auth_data_prefix =
    ngx_string("5, 0.0.0.0, 0.0.0.0, ");
static ngx_str_t  ngx_http_paan_auth_data_comma =
    ngx_string(", ");
static ngx_str_t  ngx_http_paan_auth_sign_name =
    ngx_string("x-akamai-acs—auth-sign");


static ngx_command_t  ngx_http_proxy_auth_akamai_netstorage_commands[] = {
    { ngx_string("proxy_auth_akamai_netstorage"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_akamai_netstorage_loc_conf_t, enabled),
      NULL },

    { ngx_string("proxy_auth_akamai_netstorage_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_akamai_netstorage_loc_conf_t, bypass),
      NULL },

    { ngx_string("proxy_auth_akamai_netstorage_account"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_akamai_netstorage_loc_conf_t, account),
      NULL },

    { ngx_string("proxy_auth_akamai_netstorage_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_akamai_netstorage_loc_conf_t, key),
      NULL },

    { ngx_string("proxy_auth_akamai_netstorage_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_akamai_netstorage_loc_conf_t, uri),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_proxy_auth_akamai_netstorage_module_ctx = {
    NULL,                                                  /* preconfiguration */
    ngx_http_proxy_auth_akamai_netstorage_init,            /* postconfiguration */

    NULL,                                                  /* create main configuration */
    NULL,                                                  /* init main configuration */

    NULL,                                                  /* create server configuration */
    NULL,                                                  /* merge server configuration */

    ngx_http_proxy_auth_akamai_netstorage_create_loc_conf, /* create location configuration */
    ngx_http_proxy_auth_akamai_netstorage_merge_loc_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_proxy_auth_akamai_netstorage_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_auth_akamai_netstorage_module_ctx,      /* module context */
    ngx_http_proxy_auth_akamai_netstorage_commands,         /* module directives */
    NGX_HTTP_MODULE,                                        /* module type */
    NULL,                                                   /* init master */
    NULL,                                                   /* init module */
    NULL,                                                   /* init process */
    NULL,                                                   /* init thread */
    NULL,                                                   /* exit thread */
    NULL,                                                   /* exit process */
    NULL,                                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_proxy_auth_akamai_netstorage_handler(ngx_http_request_t *r)
{
    ngx_http_proxy_auth_akamai_netstorage_loc_conf_t *conf;

    ngx_list_part_t      *part;
    ngx_table_elt_t      *header;
    ngx_uint_t            i;
    ngx_table_elt_t      *h;
    ngx_time_t           *tp;
    u_char               *p, *buf;
    u_char                random_bytes[16];
    unsigned int          md_len;
    unsigned char         md[EVP_MAX_MD_SIZE];
    ngx_str_t             auth_data, uri, sign_hmac_bin, sign_value;

    conf = ngx_http_get_module_loc_conf(r,
        ngx_http_proxy_auth_akamai_netstorage_module);

    if (!conf->enabled) {
        return NGX_DECLINED;
    }

    switch (ngx_http_test_predicates(r, conf->bypass)) {

    case NGX_ERROR:
        return NGX_ERROR;

    case NGX_DECLINED:
        return NGX_DECLINED;

    default: /* NGX_OK */
        break;
    }
    
    if (conf->account.len == 0 || conf->key.len == 0 || conf->uri == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "proxy_auth_akamai_netstorage: account or key or uri "
                      "not configured");
        return NGX_DECLINED;
    }

    part = &r->headers_in.headers.part;
    header = part->elts;
    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {

            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        } 

        if (header[i].key.len == ngx_http_paan_action_name.len
            && ngx_strncasecmp(header[i].key.data,
                               ngx_http_paan_action_name.data,
                               ngx_http_paan_action_name.len) == 0)
        {
            return NGX_DECLINED;
        }

        if (header[i].key.len == ngx_http_paan_auth_data_name.len
            && ngx_strncasecmp(header[i].key.data,
                               ngx_http_paan_auth_data_name.data,
                               ngx_http_paan_auth_data_name.len) == 0)
        {
            return NGX_DECLINED;
        }

        if (header[i].key.len == ngx_http_paan_auth_sign_name.len
            && ngx_strncasecmp(header[i].key.data,
                               ngx_http_paan_auth_sign_name.data,
                               ngx_http_paan_auth_sign_name.len) == 0)
        {
            return NGX_DECLINED;
        }
    }

    /* X-Akamai-Acs-Auth-Data */
    buf = ngx_pcalloc(r->pool, ngx_http_paan_auth_data_prefix.len
                               + NGX_TIME_T_LEN
                               + ngx_http_paan_auth_data_comma.len * 2
                               + 32 + conf->account.len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    tp = ngx_timeofday();
    p = buf;

    p = ngx_cpymem(p, ngx_http_paan_auth_data_prefix.data, 
                   ngx_http_paan_auth_data_prefix.len);
    p = ngx_sprintf(p, "%T", tp->sec);
    p = ngx_copy(p, ngx_http_paan_auth_data_comma.data,
                   ngx_http_paan_auth_data_comma.len);

    if (RAND_bytes(random_bytes, 16) != 1) {
        ngx_ssl_error(NGX_LOG_ERR, r->connection->log, 0,
                                   "RAND_bytes() failed");
        return NGX_ERROR;
    }

    p = ngx_hex_dump(p, random_bytes, 16);
    p = ngx_copy(p, ngx_http_paan_auth_data_comma.data,
                   ngx_http_paan_auth_data_comma.len);
    p = ngx_copy(p, conf->account.data, conf->account.len);

    auth_data.data = buf;
    auth_data.len = p - buf;

    /* sign payload for X-Akamai-Acs-Auth-Sign */
    if (ngx_http_complex_value(r, conf->uri, &uri) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "proxy_auth_akamai_netstorage: failed to get uri");
        return NGX_ERROR;
    }

    buf = ngx_pnalloc(r->pool, auth_data.len + uri.len
                               + sizeof("\nx-akamai-acs-action:") - 1
                               + ngx_http_paan_action_value.len
                               + sizeof("\n") - 1);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = buf;
    p = ngx_cpymem(p, auth_data.data, auth_data.len);
    p = ngx_cpymem(p, uri.data, uri.len);
    p = ngx_sprintf(p, "\nx-akamai-acs-action:%V\n", &ngx_http_paan_action_value);

    /* HMAC */
    HMAC(EVP_sha256(), alcf->key.data, alcf->key.len, buf, p - buf, md, &md_len);

    sign_hmac_bin.len = md_len;
    sign_hmac_bin.data = ngx_palloc(r->pool, sign_hmac_bin.len);
    if (sign_hmac_bin.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(sign_hmac_bin.data, &md, md_len);

    /* X-Akamai-Acs-Auth-Sign */
    sign_value.len = ngx_base64_encoded_length(sign_hmac_bin.len);
    sign_value.data = ngx_palloc(r->pool, sizeof(sign_value.len));
    if (sign_value.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(&sign_value, &sign_hmac_bin);

    /* add headers */
    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key = ngx_http_paan_action_name;
    h->value = ngx_http_paan_action_value;
    h->lowcase_key = h->key.data;
    h->hash = 1;
    h->next = NULL;

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key = ngx_http_paan_auth_data_name;
    h->value = auth_data;
    h->lowcase_key = h->key.data;
    h->hash = 1;
    h->next = NULL;

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key = ngx_http_paan_auth_sign_name;
    h->value = sign_value;
    h->lowcase_key = h->key.data;
    h->hash = 1;
    h->next = NULL;

    return NGX_DECLINED;
}


static void *
ngx_http_proxy_auth_akamai_netstorage_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_auth_akamai_netstorage_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(
        ngx_http_proxy_auth_akamai_netstorage_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->bypass = NGX_CONF_UNSET_PTR;
    conf->uri = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_proxy_auth_akamai_netstorage_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_proxy_auth_akamai_netstorage_loc_conf_t *prev = parent;
    ngx_http_proxy_auth_akamai_netstorage_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
    ngx_conf_merge_str_value(conf->account, prev->account, "");
    ngx_conf_merge_str_value(conf->key, prev->key, "");
    ngx_conf_merge_ptr_value(conf->uri, prev->uri, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_proxy_auth_akamai_netstorage_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_proxy_auth_akamai_netstorage_handler;

    return NGX_OK;
}