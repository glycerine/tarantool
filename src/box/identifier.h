#ifndef TARANTOOL_BOX_IDENTIFIER_H_INCLUDED
#define TARANTOOL_BOX_IDENTIFIER_H_INCLUDED
/*
 * Copyright 2010-2018, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "trivia/util.h"
#include <stdbool.h>
#include "error.h"

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

/**
 * Check object identifier for invalid symbols.
 * The function checks the str for being printable.
 */
bool
identifier_is_valid(const char *str, uint32_t len);

/**
 * Init identifier check mechanism.
 * This function allocates necessary for icu structures.
 */
void
identifier_init();

/**
 * Clean icu structures.
 */
void
identifier_destroy();

#if defined(__cplusplus)
} /* extern "C" */

/**
 * Throw an error if identifier is not valid.
 */
static inline void
identifier_check_xc(const char *str, uint32_t len)
{
	if (! identifier_is_valid(str, len))
		tnt_raise(ClientError, ER_IDENTIFIER, tt_cstr(str, len));
}

#endif /* defined(__cplusplus) */

#endif /* TARANTOOL_BOX_IDENTIFIER_H_INCLUDED */
