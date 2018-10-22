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

#pragma once

#include <stdio.h>

extern int logs;

typedef void (*http_cb_receive_t)
    (void *in, size_t len);

int http_run(const char *address, int port, const char *path,
        http_cb_receive_t http_cb_receive);
void http_cancel(void);

#define eid_run_status(eid_cb_receive) \
    http_run("127.0.0.1", 24727, \
            "/eID-Client?Status", \
            eid_cb_receive)
#define eid_run_settings(eid_cb_receive) \
    http_run("127.0.0.1", 24727, \
            "/eID-Client?ShowUI=Settings", \
            eid_cb_receive)
#define eid_run_pinmanagement(eid_cb_receive) \
    http_run("127.0.0.1", 24727, \
            "/eID-Client?ShowUI=PINManagement", \
            eid_cb_receive)
