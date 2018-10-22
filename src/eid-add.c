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

#include "strnstr.h"
#include "selbstauskunft.h"
#include <string.h>
#include <unistd.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#include <locale.h>
#define _(string) gettext(string)
#ifndef LOCALEDIR
#define LOCALEDIR "/usr/share/locale"
#endif
#else
#define _(string) string
#endif

int ok;

static void name_print(void *contents, size_t size)
{
    size_t i;
    struct {
        const char *pre;
        const char *post;
    } client[] = {
        /* Status response of AusweisApp2 */
        {"Name: ", "\n"},
        /* Status response of Open eCard App */
        {"<ns12:Name>", "</ns12:Name>"},
    };
    char *start = contents;

    for (i = 0; i < sizeof client/sizeof *client; i++) {
        char *name = strnstr(start, client[i].pre, size);
        if (name) {
            char *end = strnstr(name, client[i].post,
                    size - (name - start));
            if (end) {
                name += strlen(client[i].pre);
                printf(_("Connected to %.*s\n"), (int) (end - name), name);
                ok = 1;
                break;
            }
        }
    }
}

/*
 * lws-minimal-http-client
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the a minimal http client using lws.
 *
 * It visits https://warmcat.com/ and receives the html page there.  You
 * can dump the page data by changing the #if 0 below.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted, bad = 1, status;
static struct lws *client_wsi;

int main(int argc, char **argv)
{
    char user[32];
    ok = 0;

    if (!eid_run_status(name_print)) {
        puts(_("Failed to connect to eID Client"));
        goto err;
    }
    if (ok != 1) {
        puts(_("Connected to unknown eID Client"));
    }

    if (0 != getlogin_r(user, sizeof user))
        goto err;

    if (!selbstauskunft_http_init(user)) {
        puts(_("Failed to connect to eID Client"));
        goto err;
    }

err:
    if (ok == 1) {
        puts(_("Configured ~/.eid/authorized_eid"));
        puts(_("To enable certificate pinning, run\n"));
        puts(  "  echo \\\n"
                "    | openssl s_client -connect www.autentapp.de:443 2>/dev/null \\\n"
                "    | openssl x509 -noout -pubkey \\\n"
                "    | openssl asn1parse -noout -inform PEM -out ~/.eid/authorized_pubkey");
        return 0;
    } else {
        /* eID Client will print some error */
        return 1;
    }
}
