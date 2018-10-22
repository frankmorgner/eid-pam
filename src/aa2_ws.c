/*
 * Copyright (C) 2018 Frank Morgner <frankmorgner@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "aa2_ws.h"
#include <json.h>
#include <libwebsockets.h>
#include <signal.h>
#include <string.h>

static struct state {
    unsigned char *cmd;
    size_t cmd_len;
    size_t cmd_max;

    char *result;
    size_t result_len;
    size_t result_max;

    aa2_cb_enter_password_t cb_enter_pin;
    aa2_cb_enter_password_t cb_enter_can;
    aa2_cb_feedback_t cb_insert_card;

    int interrupted;
    struct lws *client_wsi;
} g_state;

static void queue_cmd(struct state *state, const char *cmd)
{
    size_t cmdlen = strlen(cmd);

    /* TODO add queuing ;-) */
    if (cmdlen < state->cmd_max) {
        lwsl_info("-> %s\n", cmd);
        memcpy(state->cmd, cmd, cmdlen);
        state->cmd_len = cmdlen;
        lws_callback_on_writable(state->client_wsi);
    } else {
        state->cmd_len = 0;
    }

    /* Add NUL if possible */
    if (cmdlen < state->cmd_max+1) {
        state->cmd[cmdlen] = '\0';
    }
}

static void handle_secret(struct state *state,
        json_object *root, json_object *msg,
        aa2_cb_enter_password_t cb_enter_password,
        const char *cmd)
{
    json_object *reader;
    const char *reader_val = NULL;
    int keypad_val = 0;
    char *secret = NULL;

    if (TRUE == json_object_object_get_ex(root, "reader", &reader)) {
        json_object *keypad, *name;

        if (TRUE == json_object_object_get_ex(reader, "keypad", &keypad)
                && TRUE == json_object_get_boolean(keypad)) {
            keypad_val = 1;
        }
        if (TRUE == json_object_object_get_ex(reader, "name", &name)
                && NULL != json_object_get_string(msg)) {
            reader_val = json_object_get_string(msg);
        }
    }
    if (NULL != cb_enter_password
            && 1 == cb_enter_password(reader_val, keypad_val, &secret)
            && 0 == keypad_val) {
        static char set_cmd[64];
        snprintf(set_cmd, sizeof set_cmd,
                "{\"cmd\":\"%s\",\"value\":\"%s\"}",
                cmd ? cmd : "", secret ? secret : "");
        set_cmd[sizeof set_cmd - 1] = '\0';
        queue_cmd(state, set_cmd);
        memset(set_cmd, 0, sizeof set_cmd);
    }
}

static void handle_msg(struct state *state, void *in, size_t len)
{
    struct json_tokener* tok = json_tokener_new();
    json_object *root = NULL;
    enum json_tokener_error jerr;

    do {
        json_object *error = NULL, *msg = NULL;
        root = json_tokener_parse_ex(tok, in, len);
        if (TRUE == json_object_object_get_ex(root, "error", &error)) {
            lwsl_err("error: %s\n", json_object_get_string(error));
            state->interrupted = 1;
            break;
        } else if (TRUE == json_object_object_get_ex(root, "msg", &msg)) {
            lwsl_info("<- \"msg\":\"%s\"\n", json_object_get_string(msg));
            if (strcmp(json_object_get_string(msg), "AUTH") == 0) {
                json_object *url = NULL;
                if (TRUE == json_object_object_get_ex(root, "url", &url)) {
                    snprintf(state->result, state->result_max,
                            "%s", json_object_get_string(url));
                    state->result[state->result_max - 1] = '\0';
                    state->result_len = strlen(state->result);
                    state->interrupted = 1;
                }
            } else if (strcmp(json_object_get_string(msg), "ACCESS_RIGHTS") == 0) {
                queue_cmd(state, "{\"cmd\":\"ACCEPT\"}");
            } else if (strcmp(json_object_get_string(msg), "INSERT_CARD") == 0) {
                if (state->cb_insert_card) {
                    state->cb_insert_card();
                }
            } else if (strcmp(json_object_get_string(msg), "ENTER_PIN") == 0) {
                handle_secret(state, root, msg, state->cb_enter_pin, "SET_PIN");
            } else if (strcmp(json_object_get_string(msg), "ENTER_CAN") == 0) {
                handle_secret(state, root, msg, state->cb_enter_can, "SET_CAN");
            } else {
                lwsl_hexdump_level(LLL_ERR, in, len);
                state->interrupted = 1;
            }
        } else {
            lwsl_hexdump_level(LLL_ERR, in, len);
            state->interrupted = 1;
        }
    } while ((jerr = json_tokener_get_error(tok)) == json_tokener_continue);

    if (jerr != json_tokener_success) {
        state->interrupted = 1;
    }
    json_tokener_free(tok);
}

static int callback_aa2_ws(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
    switch (reason) {

        /* because we are protocols[0] ... */
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
                    in ? (char *)in : "(null)");
            g_state.interrupted = 1;
            break;

        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            lwsl_notice("%s: CLIENT_ESTABLISHED\n", __func__);
            queue_cmd(&g_state, "{\"cmd\":\"RUN_AUTH\",\"tcTokenURL\":\"https://www.autentapp.de/AusweisAuskunft/WebServiceRequesterServlet?mode=xml\"}");
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE:
            lwsl_notice("%s: CLIENT_RECEIVE (received %zu bytes)\n", __func__, len);
            lwsl_hexdump_level(LLL_DEBUG, in, len);
            handle_msg(&g_state, in, len);
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE:
            if (g_state.cmd_len) {
                lwsl_notice("%s: CLIENT_WRITEABLE (writing %zu bytes)\n", __func__, g_state.cmd_len);
                lws_write(wsi, g_state.cmd, g_state.cmd_len, LWS_WRITE_TEXT);
            }
            break;

#if 0
        case LWS_CALLBACK_CLIENT_CLOSED:
            g_client_wsi = NULL;
            break;
#endif

        default:
            break;
    }

    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"eid",
		callback_aa2_ws,
		0,
		0,
	},
	{ NULL, NULL, 0, 0 }
};

#define MAX_CMD 256
static void reset_state(struct state *state,
        aa2_cb_enter_password_t cb_enter_pin,
        aa2_cb_enter_password_t cb_enter_can,
        aa2_cb_feedback_t cb_insert_card)
{
    static unsigned char buf[LWS_PRE + MAX_CMD];
    static char res[MAX_CMD];

    memset(buf, 0, sizeof buf);
    memset(res, 0, sizeof res);

    memset(state, 0, sizeof *state);

    state->cmd = buf + LWS_PRE;
    state->cmd_max = sizeof buf - LWS_PRE;

    state->result = res;
    state->result_max = sizeof res;

    state->cb_enter_pin = cb_enter_pin;
    state->cb_enter_can = cb_enter_can;
    state->cb_insert_card = cb_insert_card;
}

const char *aa2_run_auth(const char *tcTokenURL,
        aa2_cb_enter_password_t cb_enter_pin,
        aa2_cb_enter_password_t cb_enter_can,
        aa2_cb_feedback_t cb_insert_card)
{
	struct lws_context_creation_info creation_info;
	struct lws_client_connect_info connect_info;
	struct lws_context *context;
	const char *p;
	int n = 0;

	memset(&creation_info, 0, sizeof creation_info);
	memset(&connect_info, 0, sizeof connect_info);

	creation_info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
	creation_info.protocols = protocols;

	context = lws_create_context(&creation_info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return NULL;
	}

	connect_info.context = context;
	connect_info.port = 24727;
	connect_info.address = "127.0.0.1";
	connect_info.path = "/eID-Kernel";
	connect_info.host = connect_info.address;
	connect_info.origin = connect_info.address;
	connect_info.protocol = protocols[0].name; /* "eid" */
	connect_info.pwsi = &g_state.client_wsi;

    reset_state(&g_state, cb_enter_pin, cb_enter_can, cb_insert_card);

    lwsl_info("ws://%s:%d%s\n", connect_info.address, connect_info.port, connect_info.path);
	lws_client_connect_via_info(&connect_info);

	while (n >= 0 && g_state.interrupted == 0)
		n = lws_service(context, 1000);

	lws_context_destroy(context);

	return g_state.result_len == 0 ? NULL : g_state.result;
}

void aa2_ws_cancel(void)
{
	g_state.interrupted = 1;
}
