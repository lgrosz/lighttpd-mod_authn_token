/*
 * mod_authn_token - a token-based authentication for Lighttpd
 *
 * lighttpd module
 */

#include "first.h"

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"
#include "http_auth.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

/* plugin config for all request/connections */

typedef struct {
	buffer *validator;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	plugin_config **config_storage;
	plugin_config conf;
} plugin_data;

static handler_t mod_authn_token_check(server *, connection *, void *, const struct http_auth_require_t *, const struct http_auth_backend_t *);

/* init the plugin data */
INIT_FUNC(mod_authn_token_init) {
	static http_auth_scheme_t http_auth_scheme_token =
		{ "token", mod_authn_token_check, NULL };

	plugin_data *p;

	p = calloc(1, sizeof(*p));
	force_assert(p);

	http_auth_scheme_token.p_d = p;
	http_auth_scheme_set(&http_auth_scheme_token);

	return p;
}

/* destroy the plugin data */
FREE_FUNC(mod_authn_token_free) {
	plugin_data *p = p_d;

	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;

	if (p->config_storage) {
		size_t i;

		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];

			if (NULL == s) continue;

			buffer_free(s->validator);

			free(s);
		}
		free(p->config_storage);
	}

	free(p);

	return HANDLER_GO_ON;
}

static handler_t mod_authn_token_send_400_bad_request (server *srv, connection *con)
{
    con->http_status = 400;
    con->mode = DIRECT;
    return HANDLER_FINISHED;
}

static handler_t mod_authn_token_send_401_unauthorized (server *srv, connection *con)
{
    con->http_status = 401;
    con->mode = DIRECT;
    return HANDLER_FINISHED;
}

static handler_t mod_authn_token_send_403_forbidden (server *srv, connection *con)
{
    con->http_status = 403;
    con->mode = DIRECT;
    return HANDLER_FINISHED;
}

static handler_t mod_authn_token_send_500_internal_server_error (server *srv, connection *con)
{
    con->http_status = 500;
    con->mode = DIRECT;
    return HANDLER_FINISHED;
}

#define PATCH(x) \
    p->conf.x = s->x;
static int mod_authn_token_patch_connection(server *srv, connection *con, plugin_data *p)
{
    size_t i, j;
    plugin_config *s = p->config_storage[0];

    PATCH(validator);

    /* skip the first, the global context */
    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("auth.backend.token.validator"))) {
                PATCH(validator);
            }
        }
    }

    return 0;
}
#undef PATCH

handler_t mod_authn_token_check_tkn(server *srv, connection *con, plugin_data *p_d, const struct http_auth_require_t *require, char *token)
{
	mod_authn_token_patch_connection(srv, con, p_d);

	if (buffer_string_is_empty(p_d->conf.validator)) {
		log_error_write(srv, __FILE__, __LINE__, "s", "No validator configured");
		return mod_authn_token_send_500_internal_server_error(srv, con);
	}

	pid_t pid = fork();
	int status;

	if (pid < 0) {
		log_error_write(srv, __FILE__, __LINE__, "s", "Failed to fork");
		return mod_authn_token_send_500_internal_server_error(srv, con);
	} else if (pid == 0) {
		char *prog = p_d->conf.validator->ptr;
		execlp(prog, prog, token, NULL);

		// If execvp returns, it failed
		log_error_write(srv, __FILE__, __LINE__, "s", "Fork returned unexpectedly");
		return mod_authn_token_send_500_internal_server_error(srv, con);
	} else {
		if (waitpid(pid, &status, 0x0) == -1) {
			log_error_write(srv, __FILE__, __LINE__, "s", "Failed to wait for fork");
			return mod_authn_token_send_500_internal_server_error(srv, con);
		}

		if (WIFEXITED(status)) {
			int code = WEXITSTATUS(status);

			if (code == 0) {
				return HANDLER_GO_ON;
			} else {
				return mod_authn_token_send_403_forbidden(srv, con);
			}
		} else if (WIFSIGNALED(status)) {
			log_error_write(srv, __FILE__, __LINE__, "s", "Validator quit");
			return mod_authn_token_send_500_internal_server_error(srv, con);
		} else {
			log_error_write(srv, __FILE__, __LINE__, "s", "Unexpected control flow");
			return mod_authn_token_send_500_internal_server_error(srv, con);
		}
	}
}

handler_t mod_authn_token_check(server *srv, connection *con, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend)
{
	UNUSED(backend);

	data_string * const ds = (data_string*)array_get_element(con->request.headers, "Authorization");

	if (NULL == ds || buffer_is_empty(ds->value)) {
		return mod_authn_token_send_401_unauthorized(srv, con);
	}

	if (0 != strncasecmp(ds->value->ptr, "Bearer ", sizeof("Bearer ")-1)) {
		return mod_authn_token_send_400_bad_request(srv, con);
	}

	return mod_authn_token_check_tkn(srv, con, (plugin_data*)p_d, require, ds->value->ptr+sizeof("Bearer ")-1);
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_authn_token_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;

	config_values_t cv[] = {
		{ "auth.backend.token.validator", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
		{ NULL,                           NULL, T_CONFIG_UNSET,  T_CONFIG_SCOPE_UNSET }
	};

	if (!p) return HANDLER_ERROR;

	p->config_storage = calloc(1, srv->config_context->used * sizeof(plugin_config *));
	force_assert(p->config_storage);

	for (i = 0; i < srv->config_context->used; i++) {
		data_config const* config = (data_config const*)srv->config_context->data[i];
		plugin_config *s = calloc(1, sizeof(plugin_config));
		force_assert(s);

		s->validator = buffer_init();

		cv[0].destination = s->validator;

		p->config_storage[i] = s;

		if (0 != config_insert_values_global(srv, config->value, cv, i == 0 ? T_CONFIG_SCOPE_SERVER : T_CONFIG_SCOPE_CONNECTION)) {
			return HANDLER_ERROR;
		}
	}

	return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_authn_token_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("authn_token");

	p->init        = mod_authn_token_init;
	p->set_defaults  = mod_authn_token_set_defaults;
	p->cleanup     = mod_authn_token_free;

	p->data        = NULL;

	return 0;
}
