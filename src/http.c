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

#include "http.h"
#include <libwebsockets.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>


static struct state {
	http_cb_receive_t http_cb_receive;

    int interrupted;
    struct lws *client_wsi;
} g_state;

int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO | LLL_DEBUG
		   /*
		    * For LLL_ verbosity above NOTICE to be built into lws,
		    * lws must have been configured and built with
		    * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE
		    *
		    */ ;

static int callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	switch (reason) {

	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		g_state.interrupted = 1;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		lwsl_notice("%s: ESTABLISHED_CLIENT_HTTP (%d)\n", __func__, lws_http_client_http_response(wsi));
		break;

	/* chunks of chunked content, with header removed */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		lwsl_notice("%s: RECEIVE_CLIENT_HTTP_READ (received %zu bytes)\n", __func__, len);
		lwsl_hexdump_level(LLL_DEBUG, in, len);
		if (g_state.http_cb_receive) {
			g_state.http_cb_receive(in, len);
		}
		return 0; /* don't passthru */

	/* uninterpreted http content */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			lwsl_notice("%s: RECEIVE_CLIENT_HTTP\n", __func__);
			char buffer[1024 + LWS_PRE];
			char *px = buffer + LWS_PRE;
			int lenx = sizeof(buffer) - LWS_PRE;

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;

			lwsl_hexdump_level(LLL_DEBUG, px, lenx);
		}
		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_notice("%s: COMPLETED_CLIENT_HTTP\n", __func__);
		g_state.interrupted = 1;
		lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		g_state.interrupted = 1;
		lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"http",
		callback_http,
		0,
		0,
	},
	{ NULL, NULL, 0, 0 }
};

static void reset_state(struct state *state,
	   	http_cb_receive_t http_cb_receive)
{
    memset(state, 0, sizeof *state);

	state->http_cb_receive = http_cb_receive;
}

int http_run(const char *address, int port, const char *path,
	   	http_cb_receive_t http_cb_receive)
{
	struct lws_context_creation_info creation_info;
	struct lws_client_connect_info connect_info;
	struct lws_context *context;
	const char *p;
	int n = 0;

	lws_set_log_level(logs, NULL);

	memset(&creation_info, 0, sizeof creation_info);
	memset(&connect_info, 0, sizeof connect_info);

	creation_info.port = CONTEXT_PORT_NO_LISTEN;
	creation_info.protocols = protocols;

	context = lws_create_context(&creation_info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 0;
	}

	connect_info.context = context;
    connect_info.port = 24727;
    connect_info.address = "127.0.0.1";
	connect_info.path = path;
	connect_info.host = connect_info.address;
	connect_info.origin = connect_info.address;
	connect_info.method = "GET";
	connect_info.protocol = protocols[0].name;
	connect_info.pwsi = &g_state.client_wsi;

	reset_state(&g_state, http_cb_receive);

    lwsl_info("http://%s:%d%s\n", connect_info.address, connect_info.port, connect_info.path);
	lws_client_connect_via_info(&connect_info);

	while (n >= 0 && !g_state.interrupted)
		n = lws_service(context, 1000);

	lws_context_destroy(context);

	return n < 0 || g_state.interrupted ?  0 : 1;
}

void http_cancel(void)
{
	g_state.interrupted = 1;
}
