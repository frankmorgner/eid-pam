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

#ifndef PACKAGE
#define PACKAGE "pam_eid"
#endif

#include "selbstauskunft.h"
#include "drop_privs.h"
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

/* We have to make this definitions before we include the pam header files! */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#else
#define pam_syslog(handle, level, msg...) syslog(level, ## msg)
#endif
#ifndef HAVE_PAM_VPROMPT
static int pam_vprompt(pam_handle_t *pamh, int style, char **response,
		const char *fmt, va_list args)
{
	int r = PAM_CRED_INSUFFICIENT;
	const struct pam_conv *conv;
	struct pam_message msg;
	struct pam_response *resp = NULL;
	struct pam_message *(msgp[1]);

	char text[128];
	vsnprintf(text, sizeof text, fmt, args);

	msgp[0] = &msg;
	msg.msg_style = style;
	msg.msg = text;

	if (PAM_SUCCESS != pam_get_item(pamh, PAM_CONV, (const void **) &conv)
			|| NULL == conv || NULL == conv->conv
			|| conv->conv(1, (const struct pam_message **) msgp, &resp, conv->appdata_ptr)
			|| NULL == resp) {
		goto err;
	}
	if (NULL != response) {
		if (resp[0].resp) {
			*response = strdup(resp[0].resp);
			if (NULL == *response) {
				pam_syslog(pamh, LOG_CRIT, "strdup() failed: %s",
						strerror(errno));
				goto err;
			}
		} else {
			*response = NULL;
		}
	}

	r = PAM_SUCCESS;
err:
	if (resp) {
		memset(&resp[0].resp, 0, sizeof resp[0].resp);
		free(&resp[0]);
	}
	return r;
}
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif

static int prompt(pam_handle_t *pamh, int style, char **response,
		const char *fmt, ...)
{
	int r;
	va_list args;

	va_start (args, fmt);
	if (!response) {
		char *p = NULL;
		r = pam_vprompt(pamh, style, &p, fmt, args);
		free(p);
	} else {
		r = pam_vprompt(pamh, style, response, fmt, args);
	}
	va_end(args);

	return r;
}

static struct {
	int eid_ok;
	unsigned int aa2_major;
	unsigned int aa2_minor;
	unsigned int aa2_fix;
} eid_client;

static void check_eid_client(void *contents, size_t size)
{
	if (strnstr(contents, "Implementation-Title: AusweisApp2", size)) {
		char *version = strnstr(contents, "Implementation-Version: ", size);
		if (version && strnstr(contents, "\n", size - (version - (char *) contents))) {
			sscanf(version, "Implementation-Version: %u.%u.%u\n",
					&eid_client.aa2_major, &eid_client.aa2_minor, &eid_client.aa2_fix);
		}
	}
	eid_client.eid_ok = 1;
}

static void module_data_cleanup(pam_handle_t *pamh, void *data, int error_status)
{
	selbstauskunft_cancel();
	memset(&eid_client, 0, sizeof eid_client);
}

static int module_initialize(pam_handle_t * pamh,
		int flags, int argc, const char **argv)
{
	int r;

	eid_run_status(check_eid_client);
	return eid_client.eid_ok == 1 ? PAM_SUCCESS : PAM_SERVICE_ERR;
}

static int module_refresh(pam_handle_t *pamh,
		int flags, int argc, const char **argv,
		const char **user)
{
	int r = PAM_SERVICE_ERR;
	struct module_data *module_data;

	if (1 != eid_client.eid_ok) {
		r = module_initialize(pamh, flags, argc, argv);
		if (PAM_SUCCESS != r) {
			goto err;
		}
	}

	r = pam_get_user(pamh, user, NULL);
	if (PAM_SUCCESS != r) {
		pam_syslog(pamh, LOG_ERR, "pam_get_user() failed %s",
				pam_strerror(pamh, r));
		r = PAM_USER_UNKNOWN;
		goto err;
	}

	r = PAM_SUCCESS;

err:
	return r;
}

static struct state {
	pam_handle_t *pamh;
	char *secret;
} g_state;

static int enter_secret(int keypad, const char *secret_name, char **secret)
{
	int r = 0;
	if (secret) {
		*secret = g_state.secret;
	}
	if (g_state.pamh) {
		if (keypad) {
			prompt(g_state.pamh,
					PAM_TEXT_INFO, NULL,
					"Enter %s on PIN pad",
					secret_name);
			r = 1;
		} else {
			if (PAM_SUCCESS == prompt(g_state.pamh,
						PAM_PROMPT_ECHO_OFF, &g_state.secret,
						"Enter %s: ",
						secret_name)) {
				if (secret)
					*secret = g_state.secret;
				r = 1;
			} else {
				if (secret)
					*secret = NULL;
			}
		}
	}

	return r;
}

static int enter_pin(const char *reader, int keypad,
     char **pin)
{
	return enter_secret(keypad, "PIN", pin);
}

static int enter_can(const char *reader, int keypad,
     char **can)
{
	return enter_secret(keypad, "CAN", can);
}

static void insert_card(void)
{
	if (g_state.pamh) {
		prompt(g_state.pamh, PAM_TEXT_INFO, NULL, "Insert card");
	}
}

static void reset_state(struct state *state,
	pam_handle_t *pamh)
{
    memset(state, 0, sizeof *state);

	state->pamh = pamh;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc,
		const char **argv)
{
	int r;
	const char *user;
	struct passwd *passwd = NULL;
	PAM_MODUTIL_DEF_PRIVS(privs);

	r = module_refresh(pamh, flags, argc, argv,
			&user);
	if (PAM_SUCCESS != r) {
		goto err;
	}

	passwd = getpwnam(user);
	if (!passwd) {
		pam_syslog(pamh, LOG_CRIT, "getpwnam() failed: %s",
				strerror(errno));
		r = PAM_SERVICE_ERR;
		goto err;
	}

	if (pam_modutil_drop_priv(pamh, &privs, passwd)) {
		r = PAM_SERVICE_ERR;
		goto err;
	}

	if (eid_client.aa2_major <= 1 && eid_client.aa2_minor < 15) {
		r = selbstauskunft_http_auth(user);
	} else {
		reset_state(&g_state, pamh);
		r = selbstauskunft_aa2_ws_auth(user, enter_pin, enter_can, insert_card);
		if (g_state.secret) {
			memset(g_state.secret, 0, strlen(g_state.secret));
			free(g_state.secret);
		}
		reset_state(&g_state, NULL);
	}
	switch (r) {
		case 1:
			r = PAM_SUCCESS;
			break;
		case 0:
			r = PAM_AUTH_ERR;
			break;
		default:
			r = PAM_AUTHINFO_UNAVAIL;
			break;
	}

	if (pam_modutil_regain_priv(pamh, &privs)) {
		r = PAM_SESSION_ERR;
		goto err;
	}

err:
	if (passwd) {
		free(passwd);
	}

	return r;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
		const char **argv)
{
	/* Actually, we should return the same value as pam_sm_authenticate(). */
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags, int argc,
		const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t * pamh, int flags, int argc,
		const char **argv)
{
	pam_syslog(pamh, LOG_DEBUG,
			"Function pam_sm_open_session() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
		const char **argv)
{
	pam_syslog(pamh, LOG_DEBUG,
			"Function pam_sm_close_session() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags, int argc,
		const char **argv)
{
	int r;
	const char *user;
	const char *action;

	r = module_refresh(pamh, flags, argc, argv,
			&user);
	if (PAM_SUCCESS != r) {
		goto err;
	}

	if (flags & PAM_CHANGE_EXPIRED_AUTHTOK) {
		/* Yes, we don't implement expiration. */
		r = PAM_SUCCESS;
		goto err;
	} else if (flags & PAM_UPDATE_AUTHTOK) {
		eid_run_pinmanagement(NULL);
	} else {
		memset(&eid_client, 0, sizeof eid_client);
		eid_run_status(check_eid_client);
		if (1 != eid_client.eid_ok) {
			goto err;
		}
	}

	if (flags & PAM_PRELIM_CHECK) {
		r = PAM_TRY_AGAIN;
		goto err;
	}

	r = PAM_SUCCESS;

err:
	return r;
}

#ifdef PAM_STATIC
/* static module data */
struct pam_module _pam_group_modstruct = {
	PACKAGE,
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};
#endif
