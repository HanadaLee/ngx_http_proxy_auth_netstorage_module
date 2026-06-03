
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#if (NGX_HTTP_PROXY_FILTER)
#include <ngx_http_proxy_filter_module.h>
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>


#define NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_ACTION       0
#define NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_DATA         1
#define NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_SIGN         2


#if !(NGX_HTTP_PROXY_FILTER)
typedef struct {
    ngx_str_t                  data;
    ngx_str_t                  sign;
} ngx_http_proxy_auth_netstorage_ctx_t;
#endif


typedef struct {
    ngx_flag_t                 enabled;

    ngx_array_t               *bypass;

    ngx_str_t                  account;
    ngx_str_t                  key;

#if (NGX_HTTP_PROXY_FILTER)
    ngx_str_t                  prefix;
#else
    ngx_http_complex_value_t  *uri;
#endif
} ngx_http_proxy_auth_netstorage_loc_conf_t;


#if (NGX_HTTP_PROXY_FILTER)
static ngx_int_t ngx_http_proxy_auth_netstorage_request_filter(
    ngx_http_request_t *r, ngx_http_proxy_filter_ctx_t *ctx);
static ngx_int_t ngx_http_proxy_auth_netstorage_set_header(
    ngx_http_request_t *r, ngx_list_t *headers, ngx_str_t *key,
    ngx_uint_t hash, ngx_str_t *value);
#else
static ngx_int_t ngx_http_proxy_auth_netstorage_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_proxy_auth_netstorage_variables(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_proxy_auth_netstorage_handler(ngx_http_request_t *r);
#endif

static ngx_int_t ngx_http_proxy_auth_netstorage_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_proxy_auth_netstorage_sign(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *account, ngx_str_t *key, ngx_str_t *auth_data,
    ngx_str_t *sign_value);

static void *ngx_http_proxy_auth_netstorage_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxy_auth_netstorage_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_str_t  ngx_http_proxy_auth_netstorage_action_name =
    ngx_string("x-akamai-acs-action");
static ngx_str_t  ngx_http_proxy_auth_netstorage_action_value =
    ngx_string("version=1&action=download");
static ngx_str_t  ngx_http_proxy_auth_netstorage_data_name =
    ngx_string("x-akamai-acs-auth-data");
static ngx_str_t  ngx_http_proxy_auth_netstorage_data_prefix =
    ngx_string("5, 0.0.0.0, 0.0.0.0, ");
static ngx_str_t  ngx_http_proxy_auth_netstorage_data_comma =
    ngx_string(", ");
static ngx_str_t  ngx_http_proxy_auth_netstorage_sign_name =
    ngx_string("x-akamai-acs-auth-sign");


static ngx_uint_t  ngx_http_proxy_auth_netstorage_action_name_hash;
static ngx_uint_t  ngx_http_proxy_auth_netstorage_data_name_hash;
static ngx_uint_t  ngx_http_proxy_auth_netstorage_sign_name_hash;


static ngx_command_t  ngx_http_proxy_auth_netstorage_commands[] = {
    { ngx_string("proxy_auth_netstorage"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_netstorage_loc_conf_t, enabled),
      NULL },

    { ngx_string("proxy_auth_netstorage_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_netstorage_loc_conf_t, bypass),
      NULL },

    { ngx_string("proxy_auth_netstorage_account"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_netstorage_loc_conf_t, account),
      NULL },

    { ngx_string("proxy_auth_netstorage_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_netstorage_loc_conf_t, key),
      NULL },

#if (NGX_HTTP_PROXY_FILTER)
    { ngx_string("proxy_auth_netstorage_prefix"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_netstorage_loc_conf_t, prefix),
      NULL },
#else
    { ngx_string("proxy_auth_netstorage_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_auth_netstorage_loc_conf_t, uri),
      NULL },
#endif

      ngx_null_command
};


static ngx_http_module_t  ngx_http_proxy_auth_netstorage_module_ctx = {
#if (NGX_HTTP_PROXY_FILTER)
    NULL,                                           /* preconfiguration */
#else
    ngx_http_proxy_auth_netstorage_add_variables,   /* preconfiguration */
#endif
    ngx_http_proxy_auth_netstorage_init,            /* postconfiguration */

    NULL,                                           /* create main configuration */
    NULL,                                           /* init main configuration */

    NULL,                                           /* create server configuration */
    NULL,                                           /* merge server configuration */

    ngx_http_proxy_auth_netstorage_create_loc_conf, /* create location configuration */
    ngx_http_proxy_auth_netstorage_merge_loc_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_proxy_auth_netstorage_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_auth_netstorage_module_ctx,      /* module context */
    ngx_http_proxy_auth_netstorage_commands,         /* module directives */
    NGX_HTTP_MODULE,                                 /* module type */
    NULL,                                            /* init master */
    NULL,                                            /* init module */
    NULL,                                            /* init process */
    NULL,                                            /* init thread */
    NULL,                                            /* exit thread */
    NULL,                                            /* exit process */
    NULL,                                            /* exit master */
    NGX_MODULE_V1_PADDING
};


#if !(NGX_HTTP_PROXY_FILTER)

static ngx_http_variable_t  ngx_http_proxy_auth_netstorage_vars[] = {

    { ngx_string("proxy_auth_netstorage_action"), NULL,
      ngx_http_proxy_auth_netstorage_variables,
      NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_ACTION,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("proxy_auth_netstorage_data"), NULL,
      ngx_http_proxy_auth_netstorage_variables,
      NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_DATA,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("proxy_auth_netstorage_sign"), NULL,
      ngx_http_proxy_auth_netstorage_variables,
      NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_SIGN,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_proxy_auth_netstorage_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_proxy_auth_netstorage_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_auth_netstorage_variables(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_proxy_auth_netstorage_ctx_t  *ctx;
    ngx_list_part_t                              *part;
    ngx_table_elt_t                              *header;
    ngx_uint_t                                    i;
    ngx_str_t                                    *name;
    ngx_uint_t                                    hash;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_auth_netstorage_module);

    if (ctx && ctx->data.len && ctx->sign.len) {
        switch (data) {
        case NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_ACTION:
            v->len = ngx_http_proxy_auth_netstorage_action_value.len;
            v->data = ngx_http_proxy_auth_netstorage_action_value.data;
            break;

        case NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_DATA:
            v->len = ctx->data.len;
            v->data = ctx->data.data;
            break;

        case NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_SIGN:
            v->len = ctx->sign.len;
            v->data = ctx->sign.data;
            break;

        default:
            v->not_found = 1;
            return NGX_OK;
        }

        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        return NGX_OK;
    }

    switch (data) {
    case NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_ACTION:
        name = &ngx_http_proxy_auth_netstorage_action_name;
        hash = ngx_http_proxy_auth_netstorage_action_name_hash;
        break;

    case NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_DATA:
        name = &ngx_http_proxy_auth_netstorage_data_name;
        hash = ngx_http_proxy_auth_netstorage_data_name_hash;
        break;

    case NGX_HTTP_PROXY_AUTH_NETSTORAGE_VAR_SIGN:
        name = &ngx_http_proxy_auth_netstorage_sign_name;
        hash = ngx_http_proxy_auth_netstorage_sign_name_hash;
        break;

    default:
        v->not_found = 1;
        return NGX_OK;
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

        if (hash == header[i].hash
            && name->len == header[i].key.len
            && ngx_strncmp(name->data, header[i].lowcase_key, name->len) == 0)
        {
            v->len = header[i].value.len;
            v->data = header[i].value.data;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            return NGX_OK;
        }
    }

    v->not_found = 1;
    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_proxy_auth_netstorage_sign(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *account, ngx_str_t *key, ngx_str_t *auth_data,
    ngx_str_t *sign_value)
{
    ngx_time_t           *tp;
    u_char               *p, *buf;
    u_char                random_bytes[16];
    unsigned int          md_len;
    unsigned char         md[EVP_MAX_MD_SIZE];
    ngx_str_t             sign_hmac_bin;

    /* X-Akamai-Acs-Auth-Data */
    buf = ngx_pcalloc(r->pool,
                      ngx_http_proxy_auth_netstorage_data_prefix.len
                      + NGX_TIME_T_LEN
                      + ngx_http_proxy_auth_netstorage_data_comma.len * 2
                      + 32 + account->len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    tp = ngx_timeofday();
    p = buf;

    p = ngx_cpymem(p, ngx_http_proxy_auth_netstorage_data_prefix.data,
                   ngx_http_proxy_auth_netstorage_data_prefix.len);
    p = ngx_sprintf(p, "%T", tp->sec);
    p = ngx_copy(p, ngx_http_proxy_auth_netstorage_data_comma.data,
                 ngx_http_proxy_auth_netstorage_data_comma.len);

    if (RAND_bytes(random_bytes, 16) != 1) {
        ngx_ssl_error(NGX_LOG_ERR, r->connection->log, 0,
                      "RAND_bytes() failed");
        return NGX_ERROR;
    }

    p = ngx_hex_dump(p, random_bytes, 16);
    p = ngx_copy(p, ngx_http_proxy_auth_netstorage_data_comma.data,
                 ngx_http_proxy_auth_netstorage_data_comma.len);
    p = ngx_copy(p, account->data, account->len);

    auth_data->data = buf;
    auth_data->len = p - buf;

    /* sign payload for X-Akamai-Acs-Auth-Sign */
    buf = ngx_pnalloc(r->pool, auth_data->len + uri->len
                               + sizeof("\nx-akamai-acs-action:") - 1
                               + ngx_http_proxy_auth_netstorage_action_value.len
                               + sizeof("\n") - 1);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = buf;
    p = ngx_cpymem(p, auth_data->data, auth_data->len);
    p = ngx_cpymem(p, uri->data, uri->len);
    p = ngx_sprintf(p, "\nx-akamai-acs-action:%V\n",
                    &ngx_http_proxy_auth_netstorage_action_value);

    /* HMAC */
    HMAC(EVP_sha256(), key->data, key->len, buf, p - buf, md, &md_len);

    sign_hmac_bin.len = md_len;
    sign_hmac_bin.data = ngx_palloc(r->pool, sign_hmac_bin.len);
    if (sign_hmac_bin.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(sign_hmac_bin.data, &md, md_len);

    /* X-Akamai-Acs-Auth-Sign */
    sign_value->len = ngx_base64_encoded_length(sign_hmac_bin.len);
    sign_value->data = ngx_palloc(r->pool, sign_value->len);
    if (sign_value->data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(sign_value, &sign_hmac_bin);

    return NGX_OK;
}


#if (NGX_HTTP_PROXY_FILTER)

static ngx_int_t
ngx_http_proxy_auth_netstorage_request_filter(ngx_http_request_t *r,
    ngx_http_proxy_filter_ctx_t *ctx)
{
    ngx_http_proxy_auth_netstorage_loc_conf_t  *plcf;

    ngx_str_t   auth_data, sign_value, *uri, *method, new_uri;
    u_char     *p;

    if (ctx->headers == NULL) {
        return NGX_DECLINED;
    }

    plcf = ngx_http_get_module_loc_conf(r,
                                        ngx_http_proxy_auth_netstorage_module);

    if (!plcf->enabled) {
        return NGX_DECLINED;
    }

    switch (ngx_http_test_predicates(r, plcf->bypass)) {

    case NGX_ERROR:
        return NGX_ERROR;

    case NGX_DECLINED:
        return NGX_DECLINED;

    default: /* NGX_OK */
        break;
    }

    if (ngx_http_proxy_filter_get_method(r, ctx, &method) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "proxy_auth_netstorage: failed to get method");
        return NGX_ERROR;
    }

    if ((method->len != 3 || ngx_strncmp(method->data, "GET", 3) != 0)
        && (method->len != 4 || ngx_strncmp(method->data, "HEAD", 4) != 0)
        && (method->len != 7 || ngx_strncmp(method->data, "OPTIONS", 7) != 0))
    {
        return NGX_DECLINED;
    }

    if (plcf->account.len == 0 || plcf->key.len == 0 || plcf->prefix.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "proxy_auth_netstorage: account, key or prefix "
                      "not configured");
        return NGX_DECLINED;
    }

    if (ngx_http_proxy_filter_get_uri(r, ctx, &uri) != NGX_OK) {
        return NGX_ERROR;
    }

    new_uri.len = 1 + plcf->prefix.len + uri->len;
    new_uri.data = ngx_pnalloc(r->pool, new_uri.len);
    if (new_uri.data == NULL) {
        return NGX_ERROR;
    }

    p = new_uri.data;
    *p++ = '/';
    p = ngx_cpymem(p, plcf->prefix.data, plcf->prefix.len);
    p = ngx_cpymem(p, uri->data, uri->len);

    if (ngx_http_proxy_filter_set_uri(r, ctx, &new_uri) != NGX_OK) {
        return NGX_ERROR;
    }

    uri = &new_uri;

    if (ngx_http_proxy_auth_netstorage_sign(r, uri, &plcf->account,
                                            &plcf->key, &auth_data,
                                            &sign_value)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_proxy_auth_netstorage_set_header(r, ctx->headers,
            &ngx_http_proxy_auth_netstorage_action_name,
            ngx_http_proxy_auth_netstorage_action_name_hash,
            &ngx_http_proxy_auth_netstorage_action_value)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_proxy_auth_netstorage_set_header(r, ctx->headers,
            &ngx_http_proxy_auth_netstorage_data_name,
            ngx_http_proxy_auth_netstorage_data_name_hash, &auth_data)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_proxy_auth_netstorage_set_header(r, ctx->headers,
            &ngx_http_proxy_auth_netstorage_sign_name,
            ngx_http_proxy_auth_netstorage_sign_name_hash, &sign_value)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_proxy_auth_netstorage_set_header(ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *key, ngx_uint_t hash, ngx_str_t *value)
{
    ngx_uint_t        i;
    ngx_uint_t        matched;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    matched = 0;
    part = &headers->part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0) {
            continue;
        }

        if (h[i].key.len != key->len) {
            continue;
        }

        if (ngx_strncasecmp(h[i].key.data, key->data, key->len) != 0) {
            continue;
        }

        if (matched) {
            h[i].hash = 0;
            h[i].value.len = 0;
            h[i].next = NULL;
            continue;
        }

        h[i].hash = hash;
        h[i].key = *key;
        h[i].value = *value;
        matched = 1;
    }

    if (matched) {
        return NGX_OK;
    }

    h = ngx_list_push(headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(h, sizeof(ngx_table_elt_t));

    h->hash = hash;
    h->key = *key;
    h->value = *value;

    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        h->hash = 0;
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    h->next = NULL;

    return NGX_OK;
}

#else

static ngx_int_t
ngx_http_proxy_auth_netstorage_handler(ngx_http_request_t *r)
{
    ngx_str_t                                   auth_data, sign_value, uri;
    ngx_http_proxy_auth_netstorage_ctx_t       *ctx;
    ngx_http_proxy_auth_netstorage_loc_conf_t  *plcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_auth_netstorage_module);
    if (ctx) {
        return NGX_DECLINED;
    }

    plcf = ngx_http_get_module_loc_conf(r,
                                        ngx_http_proxy_auth_netstorage_module);

    if (!plcf->enabled) {
        return NGX_DECLINED;
    }

    switch (ngx_http_test_predicates(r, plcf->bypass)) {

    case NGX_ERROR:
        return NGX_ERROR;

    case NGX_DECLINED:
        return NGX_DECLINED;

    default: /* NGX_OK */
        break;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_OPTIONS))) {
        return NGX_DECLINED;
    }

    if (plcf->account.len == 0 || plcf->key.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "proxy_auth_netstorage: account or key not configured");
        return NGX_DECLINED;
    }

    if (plcf->uri == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "proxy_auth_netstorage: uri not configured");
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, plcf->uri, &uri) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "proxy_auth_netstorage: failed to get uri");
        return NGX_ERROR;
    }

    if (uri.len == 0 || uri.data[0] != '/') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "proxy_auth_netstorage: invalid uri");
        return NGX_ERROR;
    }

    if (ngx_http_proxy_auth_netstorage_sign(r, &uri,
                                            &plcf->account, &plcf->key,
                                            &auth_data, &sign_value)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(r->pool,
        sizeof(ngx_http_proxy_auth_netstorage_ctx_t));

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->data = auth_data;
    ctx->sign = sign_value;

    ngx_http_set_ctx(r, ctx, ngx_http_proxy_auth_netstorage_module);

    return NGX_DECLINED;
}

#endif


static void *
ngx_http_proxy_auth_netstorage_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_auth_netstorage_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_proxy_auth_netstorage_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->bypass = NGX_CONF_UNSET_PTR;
#if !(NGX_HTTP_PROXY_FILTER)
    conf->uri = NGX_CONF_UNSET_PTR;
#endif

    return conf;
}


static char *
ngx_http_proxy_auth_netstorage_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_proxy_auth_netstorage_loc_conf_t *prev = parent;
    ngx_http_proxy_auth_netstorage_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
    ngx_conf_merge_str_value(conf->account, prev->account, "");
    ngx_conf_merge_str_value(conf->key, prev->key, "");
#if (NGX_HTTP_PROXY_FILTER)
    ngx_conf_merge_str_value(conf->prefix, prev->prefix, "");
#else
    ngx_conf_merge_ptr_value(conf->uri, prev->uri, NULL);
#endif

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_proxy_auth_netstorage_init(ngx_conf_t *cf)
{
#if (NGX_HTTP_PROXY_FILTER)
    ngx_http_proxy_filter_pt           *h;
    ngx_http_proxy_filter_main_conf_t  *pmcf;
#else
    ngx_http_handler_pt                *h;
    ngx_http_core_main_conf_t          *cmcf;
#endif

    ngx_http_proxy_auth_netstorage_action_name_hash =
        ngx_hash_key(ngx_http_proxy_auth_netstorage_action_name.data,
                     ngx_http_proxy_auth_netstorage_action_name.len);

    ngx_http_proxy_auth_netstorage_data_name_hash =
        ngx_hash_key(ngx_http_proxy_auth_netstorage_data_name.data,
                     ngx_http_proxy_auth_netstorage_data_name.len);

    ngx_http_proxy_auth_netstorage_sign_name_hash =
        ngx_hash_key(ngx_http_proxy_auth_netstorage_sign_name.data,
                     ngx_http_proxy_auth_netstorage_sign_name.len);

#if (NGX_HTTP_PROXY_FILTER)
    pmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_proxy_filter_module);
    if (pmcf == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(&pmcf->phases[NGX_HTTP_PROXY_REQUEST_FILTER]);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_proxy_auth_netstorage_request_filter;
#else
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_proxy_auth_netstorage_handler;
#endif

    return NGX_OK;
}
