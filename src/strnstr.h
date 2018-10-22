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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STRNSTR
#include <string.h>
#else
static char *strnstr(const char *haystack, const char *needle, size_t count)
{
    char *found = strstr(haystack, needle);
    if (found && found - haystack <= count) {
        /* for ease of implementation we accept an out of bounds read while
         * searching, but we do not propagate this problem */
        return found;
    }
    return NULL;
}
#endif
