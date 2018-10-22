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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#ifndef HAVE_OPENPAM_TTYCONV
#include <security/pam_misc.h>
#endif

extern int pam_sm_test(pam_handle_t *pamh, int flags, int argc, const char **argv);

int main(int argc, const char **argv)
{
	char user[32];
	pam_handle_t *pamh = NULL;
	struct pam_conv conv = {
#ifdef HAVE_OPENPAM_TTYCONV
		openpam_ttyconv,
#else
		misc_conv,
#endif
		NULL,
	};
	int r;
	int status = EXIT_FAILURE;

	if (0 != getlogin_r(user, sizeof user))
		goto err;

	r = pam_start("test", user, &conv, &pamh);
	if (PAM_SUCCESS != r)
		goto pam_err;

	r = pam_sm_test(pamh, 0, 0, NULL);
	if (PAM_SUCCESS != r)
		goto pam_err;

	status = EXIT_SUCCESS;

pam_err:
	if (PAM_SUCCESS != r) {
		printf("Error: %s\n", pam_strerror(pamh, r));
	} else {
		printf("OK\n");
	}
	pam_end(pamh, r);

err:
	exit(status);
}
