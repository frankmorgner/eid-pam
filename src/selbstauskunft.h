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

#include "aa2_ws.h"
#include "http.h"

int selbstauskunft_http_init(const char *login);
int selbstauskunft_http_auth(const char *login);
int selbstauskunft_aa2_ws_auth(const char *login,
		aa2_cb_enter_password_t enter_pin,
	   	aa2_cb_enter_password_t enter_can,
        aa2_cb_feedback_t cb_insert_card);

#define selbstauskunft_cancel() \
	do { \
		http_cancel(); \
		aa2_ws_cancel(); \
	} while (0)
