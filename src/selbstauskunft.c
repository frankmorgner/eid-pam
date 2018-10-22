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
#include "aa2_ws.h"
#include "selbstauskunft.h"
#include <libwebsockets.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <sys/types.h>
#include <uuid/uuid.h>

#define run_selbstauskunft_ok "<ns3:ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok</ns3:ResultMajor>"

struct {
	FILE *file;
	int ok;
} file_status;

static int auth_dirname(const char *login, char filename[PATH_MAX])
{
    struct passwd *pw = getpwnam(login);
    if (!pw || !pw->pw_dir)
        return 0;

    snprintf(filename, PATH_MAX, "%s/.eid",
            pw->pw_dir);

    return 1;
}

static int auth_filename(const char *login, char filename[PATH_MAX])
{
    if (1 != auth_dirname(login, filename))
        return 0;

    strcat(filename, "/authorized_eid");

    return 1;
}

static int auth_mkdir(const char *login)
{
    char dirname[PATH_MAX];

    if (1 != auth_dirname(login, dirname))
        return -1;

    return mkdir(dirname, 0700);
}

static FILE *auth_fopen(const char *login, const char *mode)
{
    char filename[PATH_MAX];

    if (1 != auth_filename(login, filename))
        return NULL;

    return fopen(filename, mode);
}

static int pubkey_filename(const char *login, char filename[PATH_MAX])
{
    if (1 != auth_dirname(login, filename))
        return 0;

    strcat(filename, "/authorized_pubkey");

    return 1;
}

#define _(a) a

static void eid_print(char *contents, size_t count)
{
    struct {
        const char *title;
        const char *pre;
        const char *post;
    } eid[] = {
        {_("Given Name(s):   "), "<GivenNames>","</GivenNames>"},
        {_("Family Name(s):  "), "<FamilyNames>>", "</FamilyNames>"},
        {_("Date Of Birth:   "), "<DateOfBirth>", "</DateOfBirth>"},
    };
    size_t i;

    for (i = 0; i < sizeof eid/sizeof *eid; i++) {
        char *data = strnstr(contents, eid[i].pre, count);
        if (data) {
            char *end = strnstr(data, eid[i].post,
                    count - (data - contents));
            if (end) {
                data += strlen(eid[i].pre);
                printf("%s%.*s\n", eid[i].title, (int) (end - data), data);
                break;
            }
        }
    }
}


static void auth_write(void *contents, size_t size)
{
    size_t consumed = fwrite(contents, size, 1, file_status.file);

    if (strnstr((char *) contents, run_selbstauskunft_ok, consumed)) {
        eid_print(contents, consumed);
        file_status.ok = 1;
    }
}

int selbstauskunft_http_init(const char *login)
{
    file_status.ok = -1;
    file_status.file = auth_fopen(login, "wb");
    if (!file_status.file) {
        if (0 != auth_mkdir(login))
            goto err;
        file_status.file = auth_fopen(login, "wb");
        if (!file_status.file)
            goto err;
    }

    if (!http_run("127.0.0.1", 24727,
                "/eID-Client?tcTokenURL=https://www.autentapp.de/AusweisAuskunft/WebServiceRequesterServlet?mode=xml",
                auth_write)) {
        puts(_("Failed to connect to eID Client"));
        goto err;
    }

err:
    if (file_status.file)
        fclose(file_status.file);

    if (file_status.ok == 1) {
        return 0;
    } else {
        /* eID Client will print some error */
        return 1;
    }
}

static void auth_compare(void *contents, size_t size)
{
	if (file_status.ok == 0) {
		/* we already know that the received data doesn't match */
		goto err;
	}

	char *buf = malloc(size);
	if (!buf) {
		file_status.ok = 0;
		goto err;
    }

	if (size != fread(buf, size, 1, file_status.file)
            || 0 != memcmp(buf, contents, size)) {
		/* the received data doesn't match */
		file_status.ok = 0;
		goto err;
	}

	if (strnstr(buf, run_selbstauskunft_ok, size)) {
		file_status.ok = 1;
	}

err:
	free(buf);
}

int selbstauskunft_http_auth(const char *login)
{
    file_status.ok = -1;
    file_status.file = auth_fopen(login, "wb");
    if (!file_status.file) {
        goto err;
    }

    if (!http_run("127.0.0.1", 24727,
                "/eID-Client?tcTokenURL=https://www.autentapp.de/AusweisAuskunft/WebServiceRequesterServlet?mode=xml",
                auth_compare)) {
        puts(_("Failed to connect to eID Client"));
        goto err;
    }

err:
    if (file_status.file)
        fclose(file_status.file);

    if (file_status.ok == 1) {
        return 1;
    } else {
        return 0;
    }
}

static int parse_url(const char *url, const char **protocol,
	   	const char **address, int *port, const char **path)
{
	char result[256];
	char *result_protocol = NULL, *result_address = NULL, *result_path = NULL, *str_port = NULL;
	int ok = 0, result_port = 0;

	if (!url)
		goto err;

	/* reserve an extra character for moving the path later */
	strncpy(result, url, sizeof result - 1);
	result[sizeof result - 2] = '\0';

	/* cut protocol at the front */
	result_address = strstr(result, "://");
	if (result_address) {
		result_protocol = result;
		*result_address = '\0';
		result_address += strlen("://");
	} else {
		result_address = result;
	}

	/* cut path at the back */
	result_path = strstr(result_address, "/");
	if (result_path) {
		/* Keep the slash in the path. Note that we kept an extra character to not overrun `result` */
		memmove(result_path+1, result_path, strlen(result_path));
		*result_path = '\0';
		result_path++;
	} else {
		result_path = "/";
	}

	/* cut port from the address */
	str_port = strstr(result_address, ":");
	if (str_port) {
		*str_port = '\0';
		str_port++;
		result_port = atoi(str_port);
	} else {
		if (0 == strcmp(result_protocol, "https")) {
			result_port = 443;
		} else if (0 == strcmp(result_protocol, "http")) {
			result_port = 80;
		} else {
			goto err;
		}
	}

	ok = 1;

err:
	*protocol = result_protocol;
	*address = result_address;
	*port = result_port;
	*path = result_path;

	return ok;
}

int selbstauskunft_aa2_ws_auth(const char *login,
        aa2_cb_enter_password_t enter_pin, aa2_cb_enter_password_t enter_can,
        aa2_cb_feedback_t insert_card)
{
	const char *protocol, *address, *path;
	int port;
    file_status.ok = -1;
    file_status.file = auth_fopen(login, "wb");
    if (!file_status.file) {
        goto err;
    }

    if (!parse_url(aa2_run_auth(
                    "https://www.autentapp.de/AusweisAuskunft/WebServiceRequesterServlet?mode=xml",
                    enter_pin, enter_can, insert_card),
                &protocol, &address, &port, &path)
            || !http_run(address, port, path, auth_compare))
		goto err;

    if (!feof(file_status.file)) {
        /* we received the correct data *but* not all of our reference data has
         * been consumed */
        file_status.ok = 0;
    }

err:
	if (file_status.file) {
		fclose(file_status.file);
	}

    if (file_status.ok == 1) {
        return 1;
    } else {
        return 0;
    }
}
