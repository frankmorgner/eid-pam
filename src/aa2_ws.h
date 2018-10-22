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

typedef int (*aa2_cb_enter_password_t)
    (const char *reader, int keypad,
     char **password);

typedef void (*aa2_cb_feedback_t)
    (void);

const char *aa2_run_auth(const char *tcTokenURL,
        aa2_cb_enter_password_t cb_enter_pin,
        aa2_cb_enter_password_t cb_enter_can,
        aa2_cb_feedback_t cb_insert_card);
void aa2_ws_cancel(void);
