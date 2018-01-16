#ifndef INCLUDES_TARANTOOL_MOD_BOX_CALL_H
#define INCLUDES_TARANTOOL_MOD_BOX_CALL_H
/*
 * Copyright 2010-2016, Tarantool AUTHORS, please see AUTHORS file.
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

#include <stdbool.h>
#include "port.h"

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

struct obuf;
struct call_request;

struct box_function_ctx {
	struct port *port;
};

/**
 * Result of a C function. See box_c_call().
 */
struct box_c_call_result {
	/** Tuple container. */
	struct port port;
};

/**
 * Result of a Lua function/expression.
 * See box_lua_call(), box_lua_eval().
 */
struct box_lua_call_result {
	/** Lua state that stores the result. */
	struct lua_State *L;
	/** Reference to L in tarantool_L. */
	int ref;
};

enum box_call_type {
	BOX_CALL_C = 1,
	BOX_CALL_LUA = 2,
};

/**
 * Result of a CALL/EVAL request.
 */
struct box_call_result {
	enum box_call_type type;
	union {
		struct box_c_call_result c;
		struct box_lua_call_result lua;
	} value;
};

int
box_func_reload(const char *name);

int
box_process_call(struct call_request *request, struct box_call_result *result);

int
box_process_eval(struct call_request *request, struct box_call_result *result);

/**
 * Dump the result of a CALL/EVAL to an output buffer and
 * return the number of values dumped. On failure return -1.
 * If call_16 flag is set, encode the result in the legacy
 * format used in Tarantool < 1.7.1.
 *
 * Note, this function does not rollback the buffer to the
 * initial position in case of failure.
 */
int
box_call_result_dump(struct box_call_result *result,
		     bool call_16, struct obuf *out);

/**
 * Destroy the result of a CALL/EVAL request.
 */
void
box_call_result_destroy(struct box_call_result *result);

#if defined(__cplusplus)
} /* extern "C" */
#endif /* defined(__cplusplus) */

#endif /* INCLUDES_TARANTOOL_MOD_BOX_CALL_H */
