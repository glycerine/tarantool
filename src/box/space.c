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
#include "space.h"
#include <stdlib.h>
#include <string.h>
#include "index.h"
#include "tuple.h"
#include "tuple_compare.h"
#include "tuple_update.h"
#include "trigger.h"
#include "user.h"
#include "session.h"
#include "xrow.h"
#include "iproto_constants.h"
#include "sequence.h"
#include "txn.h"

int
access_check_space(struct space *space, uint8_t access)
{
	struct credentials *cr = current_user();
	/*
	 * If a user has a global permission, clear the respective
	 * privilege from the list of privileges required
	 * to execute the request.
	 * No special check for ADMIN user is necessary
	 * since ADMIN has universal access.
	 */
	access &= ~cr->universal_access;
	if (access && space->def->uid != cr->uid &&
	    access & ~space->access[cr->auth_token].effective) {
		/*
		 * Report access violation. Throw "no such user"
		 * error if there is  no user with this id.
		 * It is possible that the user was dropped
		 * from a different connection.
		 */
		struct user *user = user_find(cr->uid);
		if (user != NULL)
			diag_set(ClientError, ER_SPACE_ACCESS_DENIED,
				 priv_name(access), user->def->name,
				 space->def->name);
		return -1;
	}
	return 0;
}

void
space_fill_index_map(struct space *space)
{
	uint32_t index_count = 0;
	for (uint32_t j = 0; j <= space->index_id_max; j++) {
		struct index *index = space->index_map[j];
		if (index) {
			assert(index_count < space->index_count);
			space->index[index_count++] = index;
		}
	}
}

int
space_create(struct space *space, struct engine *engine,
	     const struct space_vtab *vtab, struct space_def *def,
	     struct rlist *key_list, struct tuple_format *format)
{
	if (!rlist_empty(key_list)) {
		/* Primary key must go first. */
		struct index_def *pk = rlist_first_entry(key_list,
					struct index_def, link);
		assert(pk->iid == 0);
		(void)pk;
	}

	uint32_t index_id_max = 0;
	uint32_t index_count = 0;
	struct index_def *index_def;
	rlist_foreach_entry(index_def, key_list, link) {
		index_count++;
		index_id_max = MAX(index_id_max, index_def->iid);
	}

	memset(space, 0, sizeof(*space));
	space->vtab = vtab;
	space->engine = engine;
	space->index_count = index_count;
	space->index_id_max = index_id_max;
	rlist_create(&space->before_replace);
	rlist_create(&space->on_replace);
	rlist_create(&space->on_stmt_begin);
	space->run_triggers = true;

	space->format = format;
	if (format != NULL)
		tuple_format_ref(format);

	space->def = space_def_dup(def);
	if (space->def == NULL)
		goto fail;

	/* Create indexes and fill the index map. */
	space->index_map = (struct index **)
		calloc(index_count + index_id_max + 1, sizeof(struct index *));
	if (space->index_map == NULL) {
		diag_set(OutOfMemory, (index_count + index_id_max + 1) *
			 sizeof(struct index *), "malloc", "index_map");
		goto fail;
	}
	space->index = space->index_map + index_id_max + 1;
	rlist_foreach_entry(index_def, key_list, link) {
		struct index *index = space_create_index(space, index_def);
		if (index == NULL)
			goto fail_free_indexes;
		space->index_map[index_def->iid] = index;
	}
	space_fill_index_map(space);
	return 0;

fail_free_indexes:
	for (uint32_t i = 0; i <= index_id_max; i++) {
		struct index *index = space->index_map[i];
		if (index != NULL)
			index_delete(index);
	}
fail:
	free(space->index_map);
	if (space->def != NULL)
		space_def_delete(space->def);
	if (space->format != NULL)
		tuple_format_unref(space->format);
	return -1;
}

struct space *
space_new(struct space_def *def, struct rlist *key_list)
{
	struct engine *engine = engine_find(def->engine_name);
	if (engine == NULL)
		return NULL;
	return engine_create_space(engine, def, key_list);
}

void
space_delete(struct space *space)
{
	for (uint32_t j = 0; j <= space->index_id_max; j++) {
		struct index *index = space->index_map[j];
		if (index != NULL)
			index_delete(index);
	}
	free(space->index_map);
	if (space->format != NULL)
		tuple_format_unref(space->format);
	trigger_destroy(&space->before_replace);
	trigger_destroy(&space->on_replace);
	trigger_destroy(&space->on_stmt_begin);
	space_def_delete(space->def);
	space->vtab->destroy(space);
}

/** Do nothing if the space is already recovered. */
void
space_noop(struct space *space)
{
	(void)space;
}

void
space_dump_def(const struct space *space, struct rlist *key_list)
{
	rlist_create(key_list);

	/** Ensure the primary key is added first. */
	for (unsigned j = 0; j < space->index_count; j++)
		rlist_add_tail_entry(key_list, space->index[j]->def, link);
}

struct key_def *
space_index_key_def(struct space *space, uint32_t id)
{
	if (id <= space->index_id_max && space->index_map[id])
		return space->index_map[id]->def->key_def;
	return NULL;
}

void
space_swap_index(struct space *lhs, struct space *rhs,
		 uint32_t lhs_id, uint32_t rhs_id)
{
	struct index *tmp = lhs->index_map[lhs_id];
	lhs->index_map[lhs_id] = rhs->index_map[rhs_id];
	rhs->index_map[rhs_id] = tmp;
}

void
space_run_triggers(struct space *space, bool yesno)
{
	space->run_triggers = yesno;
}

size_t
space_bsize(struct space *space)
{
	return space->vtab->bsize(space);
}

struct index_def *
space_index_def(struct space *space, int n)
{
	return space->index[n]->def;
}

const char *
index_name_by_id(struct space *space, uint32_t id)
{
	struct index *index = space_index(space, id);
	if (index != NULL)
		return index->def->name;
	return NULL;
}

int
space_def_check_compatibility(const struct space_def *old_def,
			      const struct space_def *new_def,
			      bool is_space_empty)
{
	if (strcmp(new_def->engine_name, old_def->engine_name) != 0) {
		diag_set(ClientError, ER_ALTER_SPACE, old_def->name,
			 "can not change space engine");
		return -1;
	}
	if (new_def->id != old_def->id) {
		diag_set(ClientError, ER_ALTER_SPACE, old_def->name,
			 "space id is immutable");
		return -1;
	}
	if (is_space_empty)
		return 0;

	if (new_def->exact_field_count != 0 &&
	    new_def->exact_field_count != old_def->exact_field_count) {
		diag_set(ClientError, ER_ALTER_SPACE, old_def->name,
			 "can not change field count on a non-empty space");
		return -1;
	}
	if (new_def->opts.temporary != old_def->opts.temporary) {
		diag_set(ClientError, ER_ALTER_SPACE, old_def->name,
			 "can not switch temporary flag on a non-empty space");
		return -1;
	}
	uint32_t field_count = MIN(new_def->field_count, old_def->field_count);
	for (uint32_t i = 0; i < field_count; ++i) {
		enum field_type old_type = old_def->fields[i].type;
		enum field_type new_type = new_def->fields[i].type;
		if (! field_type_is_compatible(old_type, new_type)) {
			const char *msg =
				tt_sprintf("Can not change a field type from "\
					   "%s to %s on a not empty space",
					   field_type_strs[old_type],
					   field_type_strs[new_type]);
			diag_set(ClientError, ER_ALTER_SPACE, old_def->name,
				 msg);
			return -1;
		}
		if (old_def->fields[i].is_nullable &&
		    !new_def->fields[i].is_nullable) {
			const char *msg =
				tt_sprintf("Can not disable is_nullable "\
					   "on a not empty space");
			diag_set(ClientError, ER_ALTER_SPACE, old_def->name,
				 msg);
			return -1;
		}
	}
	return 0;
}

/**
 * Convert a request accessing a secondary key to a primary key undo
 * record, given it found a tuple.
 * Flush iproto header of the request to be reconstructed in txn_add_redo().
 *
 * @param request - request to fix
 * @param space - space corresponding to request
 * @param found_tuple - tuple found by secondary key
 */
static void
request_rebind_to_primary_key(struct request *request, struct space *space,
			      struct tuple *found_tuple)
{
	struct index *pk = space_index(space, 0);
	assert(pk != NULL);
	uint32_t key_len;
	char *key = tuple_extract_key(found_tuple, pk->def->key_def, &key_len);
	assert(key != NULL);
	request->key = key;
	request->key_end = key + key_len;
	request->index_id = 0;
	/* Clear the *body* to ensure it's rebuilt at commit. */
	request->header = NULL;
}

/**
 * Handle INSERT/REPLACE in a space with a sequence attached.
 */
static int
request_handle_sequence(struct request *request, struct space *space)
{
	struct sequence *seq = space->sequence;

	assert(seq != NULL);
	assert(request->type == IPROTO_INSERT ||
	       request->type == IPROTO_REPLACE);

	/*
	 * An automatically generated sequence inherits
	 * privileges of the space it is used with.
	 */
	if (!seq->is_generated &&
	    access_check_sequence(seq) != 0)
		return -1;

	struct index *pk = space_index(space, 0);
	if (unlikely(pk == NULL))
		return 0;

	/*
	 * Look up the first field of the primary key.
	 */
	const char *data = request->tuple;
	const char *data_end = request->tuple_end;
	int len = mp_decode_array(&data);
	int fieldno = pk->def->key_def->parts[0].fieldno;
	if (unlikely(len < fieldno + 1))
		return 0;

	const char *key = data;
	if (unlikely(fieldno > 0)) {
		do {
			mp_next(&key);
		} while (--fieldno > 0);
	}

	int64_t value;
	if (mp_typeof(*key) == MP_NIL) {
		/*
		 * If the first field of the primary key is nil,
		 * this is an auto increment request and we need
		 * to replace the nil with the next value generated
		 * by the space sequence.
		 */
		if (unlikely(sequence_next(seq, &value) != 0))
			return -1;

		const char *key_end = key;
		mp_decode_nil(&key_end);

		size_t buf_size = (request->tuple_end - request->tuple) +
						mp_sizeof_uint(UINT64_MAX);
		char *tuple = region_alloc(&fiber()->gc, buf_size);
		if (tuple == NULL)
			return -1;
		char *tuple_end = mp_encode_array(tuple, len);

		if (unlikely(key != data)) {
			memcpy(tuple_end, data, key - data);
			tuple_end += key - data;
		}

		if (value >= 0)
			tuple_end = mp_encode_uint(tuple_end, value);
		else
			tuple_end = mp_encode_int(tuple_end, value);

		memcpy(tuple_end, key_end, data_end - key_end);
		tuple_end += data_end - key_end;

		assert(tuple_end <= tuple + buf_size);

		request->tuple = tuple;
		request->tuple_end = tuple_end;
	} else {
		/*
		 * If the first field is not nil, update the space
		 * sequence with its value, to make sure that an
		 * auto increment request never tries to insert a
		 * value that is already in the space. Note, this
		 * code is also invoked on final recovery to restore
		 * the sequence value from WAL.
		 */
		if (likely(mp_read_int64(&key, &value) == 0))
			return sequence_update(seq, value);
	}
	return 0;
}

/**
 * Given old and new tuples, initialize the corresponding
 * request to be written to WAL.
 */
static int
request_create_from_tuple(struct request *request, struct space *space,
			  struct tuple *old_tuple, struct tuple *new_tuple)
{
	memset(request, 0, sizeof(*request));
	if (old_tuple == new_tuple) {
		/*
		 * Old and new tuples are the same,
		 * turn this request into no-op.
		 */
		request->type = IPROTO_OK;
		return 0;
	}
	request->space_id = space->def->id;
	if (new_tuple == NULL) {
		uint32_t size, key_size;
		const char *data = tuple_data_range(old_tuple, &size);
		request->key = tuple_extract_key_raw(data, data + size,
				space->index[0]->def->key_def, &key_size);
		if (request->key == NULL)
			return -1;
		request->key_end = request->key + key_size;
		request->type = IPROTO_DELETE;
	} else {
		uint32_t size;
		const char *data = tuple_data_range(new_tuple, &size);
		char *buf = region_alloc(&fiber()->gc, size);
		if (buf == NULL)
			return -1;
		memcpy(buf, data, size);
		request->tuple = buf;
		request->tuple_end = buf + size;
		request->type = IPROTO_REPLACE;
	}
	return 0;
}

/**
 * Run BEFORE triggers registered for a space.
 */
static int
space_run_before_replace(struct space *space, struct txn *txn,
			 struct request *request)
{
	if (space->index_count == 0) {
		/* Empty space, nothing to do. */
		return 0;
	}

	struct region *gc = &fiber()->gc;
	enum iproto_type type = request->type;
	struct index *pk = space->index[0];

	const char *key;
	uint32_t part_count;
	struct index *index;

	/*
	 * Lookup the old tuple.
	 */
	if (type == IPROTO_UPDATE || type == IPROTO_DELETE) {
		index = index_find_unique(space, request->index_id);
		if (index == NULL)
			return -1;
		key = request->key;
		part_count = mp_decode_array(&key);
		if (exact_key_validate(index->def->key_def,
				       key, part_count) != 0)
			return -1;
	} else if (type == IPROTO_INSERT || type == IPROTO_REPLACE ||
		   type == IPROTO_UPSERT) {
		index = pk;
		key = tuple_extract_key_raw(request->tuple, request->tuple_end,
					    index->def->key_def, NULL);
		if (key == NULL)
			return -1;
		part_count = mp_decode_array(&key);
	} else {
		/* Unknown request type, nothing to do. */
		return 0;
	}

	struct tuple *old_tuple;
	if (index_get(index, key, part_count, &old_tuple) != 0)
		return -1;

	/*
	 * Create the new tuple.
	 */
	uint32_t new_size, old_size;
	const char *new_data, *new_data_end;
	const char *old_data, *old_data_end;

	switch (request->type) {
	case IPROTO_INSERT:
	case IPROTO_REPLACE:
		new_data = request->tuple;
		new_data_end = request->tuple_end;
		break;
	case IPROTO_UPDATE:
		if (old_tuple == NULL) {
			/* Nothing to update. */
			return 0;
		}
		old_data = tuple_data_range(old_tuple, &old_size);
		old_data_end = old_data + old_size;
		new_data = tuple_update_execute(region_aligned_alloc_cb, gc,
					request->tuple, request->tuple_end,
					old_data, old_data_end, &new_size,
					request->index_base, NULL);
		if (new_data == NULL)
			return -1;
		new_data_end = new_data + new_size;
		break;
	case IPROTO_DELETE:
		new_data = new_data_end = NULL;
		break;
	case IPROTO_UPSERT:
		if (old_tuple == NULL) {
			/*
			 * Turn UPSERT into INSERT, but still check
			 * provided operations.
			 */
			new_data = request->tuple;
			new_data_end = request->tuple_end;
			if (tuple_update_check_ops(region_aligned_alloc_cb, gc,
					request->ops, request->ops_end,
					request->index_base) != 0)
				return -1;
			break;
		}
		old_data = tuple_data_range(old_tuple, &old_size);
		old_data_end = old_data + old_size;
		new_data = tuple_upsert_execute(region_aligned_alloc_cb, gc,
					request->ops, request->ops_end,
					old_data, old_data_end, &new_size,
					request->index_base, false, NULL);
		new_data_end = new_data + new_size;
		break;
	default:
		unreachable();
	}

	struct tuple *new_tuple = NULL;
	if (new_data != NULL) {
		new_tuple = tuple_new(tuple_format_runtime,
				      new_data, new_data_end);
		if (new_tuple == NULL)
			return -1;
		tuple_ref(new_tuple);
	}

	assert(old_tuple != NULL || new_tuple != NULL);

	/*
	 * Execute all registered BEFORE triggers.
	 */
	struct txn_stmt *stmt = txn_current_stmt(txn);
	assert(stmt->old_tuple == NULL && stmt->new_tuple == NULL);
	stmt->old_tuple = old_tuple;
	stmt->new_tuple = new_tuple;

	int rc = trigger_run(&space->before_replace, txn);

	/*
	 * The trigger can't change the old tuple,
	 * but it may replace the new tuple.
	 */
	bool request_changed = (stmt->new_tuple != new_tuple);
	new_tuple = stmt->new_tuple;
	assert(stmt->old_tuple == old_tuple);
	stmt->old_tuple = NULL;
	stmt->new_tuple = NULL;

	if (rc != 0)
		goto out;

	/*
	 * We don't allow to change the value of the primary key
	 * in the same statement.
	 */
	if (old_tuple != NULL && new_tuple != NULL &&
	    tuple_compare(old_tuple, new_tuple, pk->def->key_def) != 0) {
		diag_set(ClientError, ER_CANT_UPDATE_PRIMARY_KEY,
			 pk->def->name, space->def->name);
		rc = -1;
		goto out;
	}

	/*
	 * The trigger changed the resulting tuple.
	 * Fix the request to conform.
	 */
	if (request_changed) {
		rc = request_create_from_tuple(request, space,
					       old_tuple, new_tuple);
	}
out:
	if (new_tuple != NULL)
		tuple_unref(new_tuple);
	return rc;
}

int
space_execute_dml(struct space *space, struct txn *txn,
		  struct request *request, struct tuple **result)
{
	if (unlikely(space->sequence != NULL) &&
	    (request->type == IPROTO_INSERT ||
	     request->type == IPROTO_REPLACE)) {
		/*
		 * The space has a sequence associated with it.
		 * If the tuple has 'nil' for the primary key,
		 * we should replace it with the next sequence
		 * value.
		 */
		if (request_handle_sequence(request, space) != 0)
			return -1;
	}

	if (unlikely(!rlist_empty(&space->before_replace) &&
		     space->run_triggers)) {
		/*
		 * Call BEFORE triggers if any before dispatching
		 * the request. Note, it may change the request
		 * type and arguments.
		 */
		if (space_run_before_replace(space, txn, request) != 0)
			return -1;
	}

	switch (request->type) {
	case IPROTO_INSERT:
	case IPROTO_REPLACE:
		if (space->vtab->execute_replace(space, txn,
						 request, result) != 0)
			return -1;
		break;
	case IPROTO_UPDATE:
		if (space->vtab->execute_update(space, txn,
						request, result) != 0)
			return -1;
		if (*result != NULL && request->index_id != 0) {
			/*
			 * XXX: this is going to break with sync replication
			 * for cases when tuple is NULL, since the leader
			 * will be unable to certify such updates correctly.
			 */
			request_rebind_to_primary_key(request, space, *result);
		}
		break;
	case IPROTO_DELETE:
		if (space->vtab->execute_delete(space, txn,
						request, result) != 0)
			return -1;
		if (*result != NULL && request->index_id != 0)
			request_rebind_to_primary_key(request, space, *result);
		break;
	case IPROTO_UPSERT:
		*result = NULL;
		if (space->vtab->execute_upsert(space, txn, request) != 0)
			return -1;
		break;
	default:
		*result = NULL;
	}
	return 0;
}
