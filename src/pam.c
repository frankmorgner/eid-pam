#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef PACKAGE
#define PACKAGE "pam_eid"
#endif

#include "eid.h"
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
#include <syslog.h>
#define pam_syslog(handle, level, msg...) syslog(level, ## msg)
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif

struct module_data {
	CURL *curl;
};

void module_data_cleanup(pam_handle_t *pamh, void *data, int error_status)
{
	struct module_data *module_data = data;
	if (module_data) {
		if (module_data->curl) {
			curl_easy_cleanup(module_data->curl);
		}
		free(module_data);
	}
}

static int module_initialize(pam_handle_t * pamh,
		int flags, int argc, const char **argv,
		struct module_data **module_data)
{
	int r;
	struct module_data *data = calloc(1, sizeof *data);
	if (NULL == data) {
		pam_syslog(pamh, LOG_CRIT, "calloc() failed: %s",
				strerror(errno));
		r = PAM_BUF_ERR;
		goto err;
	}

	data->curl = curl_easy_init();
	if (NULL == data->curl) {
		goto err;
	}

	r = pam_set_data(pamh, PACKAGE, data, module_data_cleanup);
	if (PAM_SUCCESS != r) {
		goto err;
	}

	*module_data = data;
	data = NULL;

err:
	module_data_cleanup(pamh, data, r);

	return r;
}

static int module_refresh(pam_handle_t *pamh,
		int flags, int argc, const char **argv,
		const char **user, CURL **curl)
{
	int r;
	struct module_data *module_data;

	if (PAM_SUCCESS != pam_get_data(pamh, PACKAGE, (void *)&module_data)
			|| NULL == module_data) {
		r = module_initialize(pamh, flags, argc, argv, &module_data);
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

	*curl = module_data->curl;

err:
	return r;
}

struct file_status {
	FILE *file;
	int ok;
};

static size_t
auth_compare(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t consumed = 0;
	struct file_status *status = (struct file_status *)userp;

	if (status->ok == 0) {
		/* we already know that the received data doesn't match */
		consumed = size*nmemb;
		goto err;
	}

	char *buf = calloc(nmemb, size);
	if (!buf)
		goto err;

	consumed = fread(buf, size, nmemb, status->file);

	if (0 != memcmp(buf, contents, consumed)) {
		/* the received data doesn't match */
		status->ok = 0;
		goto err;
	}

	if (strstr(buf, action_eid_ok)) {
		status->ok = 1;
	}

err:
	free(buf);

	return consumed;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc,
		const char **argv)
{
	int r;
	CURL *curl;
	struct file_status status = {NULL, -1};
	const char *user;
	struct passwd *passwd = NULL;
	PAM_MODUTIL_DEF_PRIVS(privs);
	long disable = 0;

	r = module_refresh(pamh, flags, argc, argv,
			&user, &curl);
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

	status.file = auth_fopen(user, "rb");
	if (!status.file) {
		r = PAM_SERVICE_ERR;
		pam_modutil_regain_priv(pamh, &privs);
		goto err;
	}

	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, &disable);
	if (1 == client_action(curl, action_eid)) {
		char *url = NULL;
		long code;
		while (CURLE_OK == curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code)
				&& 300 <= code && code < 400
				&& CURLE_OK == curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &url)
				&& url) {
			/* follow redirects manually to make sure that we get authenticated
			 * data exclusively from https://www.autentapp.de, which we use as
			 * trusted source for comparison against the reference data */
			if (strstr(url, "https://www.autentapp.de")) {
				curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, auth_compare);
				curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&status);
				client_pubkeypinning(curl, user);
			}
			curl_easy_setopt(curl, CURLOPT_URL, url);
			if (CURLE_OK != curl_easy_perform(curl)) {
				break;
			}
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
		}
	}

	switch(status.ok) {
		case 1:
			if (feof(status.file)) {
				/* we received the correct data *and* all of our reference data
				 * has been consumed */
				r = PAM_SUCCESS;
				break;
			}
			/* fall through */
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
	if (status.file) {
		fclose(status.file);
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
	CURL *curl;

	r = module_refresh(pamh, flags, argc, argv,
			&user, &curl);
	if (PAM_SUCCESS != r) {
		goto err;
	}

	if (flags & PAM_CHANGE_EXPIRED_AUTHTOK) {
		/* Yes, we don't implement expiration. */
		r = PAM_SUCCESS;
		goto err;
	} else if (flags & PAM_UPDATE_AUTHTOK) {
		action = action_pinmanagement;
	} else {
		action = action_status;
	}

	if (1 != client_action(curl, action)) {
		r = PAM_AUTHINFO_UNAVAIL;
		goto err;
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
