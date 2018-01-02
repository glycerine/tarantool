/*
 * Copyright 2010-2017, Tarantool AUTHORS, please see AUTHORS file.
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

/*
 * This header file defines the interface that the sqlite B-Tree file
 * subsystem.  See comments in the source code for a detailed description
 * of what each interface routine does.
 */
#ifndef SQLITE_BTREE_H
#define SQLITE_BTREE_H

/*
 * Forward declarations of structure
 */
typedef struct BtCursor BtCursor;
typedef struct BtreePayload BtreePayload;


/* The flags parameter to sqlite3BtreeOpen can be the bitwise or of the
 * following values.
 *
 * NOTE:  These values must match the corresponding PAGER_ values in
 * pager.h.
 */

#define BTREE_UNORDERED     8	/* Use of a hash implementation is OK */

#if SQLITE_MAX_MMAP_SIZE>0
#endif


/*
 * The second parameter to sqlite3BtreeGetMeta or sqlite3BtreeUpdateMeta
 * should be one of the following values. The integer values are assigned
 * to constants so that the offset of the corresponding field in an
 * SQLite database header may be found using the following formula:
 *
 *   offset = 36 + (idx * 4)
 *
 * The BTREE_DATA_VERSION value is not really a value stored in the header.
 * It is a read-only number computed by the pager.  But we merge it with
 * the header value access routines since its access pattern is the same.
 * Call it a "virtual meta value".
 */
#define BTREE_SCHEMA_VERSION      1
#define BTREE_FILE_FORMAT         2
#define BTREE_DEFAULT_CACHE_SIZE  3
#define BTREE_TEXT_ENCODING       5
#define BTREE_APPLICATION_ID      8
#define BTREE_DATA_VERSION        15	/* A virtual meta-value */

/*
 * Values that may be OR'd together to form the argument to the
 * BTREE_HINT_FLAGS hint for sqlite3BtreeCursorHint():
 *
 * The BTREE_BULKLOAD flag is set on index cursors when the index is going
 * to be filled with content that is already in sorted order.
 *
 * The BTREE_SEEK_EQ flag is set on cursors that will get OP_SeekGE or
 * OP_SeekLE opcodes for a range search, but where the range of entries
 * selected will all have the same key.  In other words, the cursor will
 * be used only for equality key searches.
 *
 */
#define BTREE_BULKLOAD 0x00000001	/* Used to full index in sorted order */
#define BTREE_SEEK_EQ  0x00000002	/* EQ seeks only - no range seeks */

/*
 * Flags passed as the third argument to sqlite3BtreeCursor().
 *
 * For read-only cursors the wrFlag argument is always zero. For read-write
 * cursors it may be set to either (BTREE_WRCSR|BTREE_FORDELETE) or just
 * (BTREE_WRCSR). If the BTREE_FORDELETE bit is set, then the cursor will
 * only be used by SQLite for the following:
 *
 *   * to seek to and then delete specific entries, and/or
 *
 *   * to read values that will be used to create keys that other
 *     BTREE_FORDELETE cursors will seek to and delete.
 *
 * The BTREE_FORDELETE flag is an optimization hint.  It is not used by
 * by this, the native b-tree engine of SQLite, but it is available to
 * alternative storage engines that might be substituted in place of this
 * b-tree system.  For alternative storage engines in which a delete of
 * the main table row automatically deletes corresponding index rows,
 * the FORDELETE flag hint allows those alternative storage engines to
 * skip a lot of work.  Namely:  FORDELETE cursors may treat all SEEK
 * and DELETE operations as no-ops, and any READ operation against a
 * FORDELETE cursor may return a null row: 0x01 0x00.
 */
#define BTREE_WRCSR     0x00000004	/* read-write cursor */
#define BTREE_FORDELETE 0x00000008	/* Cursor is for seek/delete only */

void sqlite3CursorZero(BtCursor *);
void sqlite3CursorHintFlags(BtCursor *, unsigned);

int sqlite3CloseCursor(BtCursor *);
int sqlite3CursorMovetoUnpacked(BtCursor *,
			       UnpackedRecord * pUnKey, int *pRes);

/* An instance of the BtreePayload object describes the content of a single
 * entry in either an index or table btree.
 *
 * Index btrees (used for indexes and also WITHOUT ROWID tables) contain
 * an arbitrary key and no data.  These btrees have pKey,nKey set to their
 * key and pData,nData,nZero set to zero.
 *
 * Table btrees (used for rowid tables) contain an integer rowid used as
 * the key and passed in the nKey field.  The pKey field is zero.
 * pData,nData hold the content of the new entry.  nZero extra zero bytes
 * are appended to the end of the content when constructing the entry.
 *
 * This object is used to pass information into sqlite3BtreeInsert().  The
 * same information used to be passed as five separate parameters.  But placing
 * the information into this object helps to keep the interface more
 * organized and understandable, and it also helps the resulting code to
 * run a little faster by using fewer registers for parameter passing.
 */
struct BtreePayload {
	const void *pKey;	/* Key content for indexes.  NULL for tables */
	sqlite3_int64 nKey;	/* Size of pKey for indexes.  PRIMARY KEY for tabs */
	const void *pData;	/* Data for tables.  NULL for indexes */
	struct Mem *aMem;	/* First of nMem value in the unpacked pKey */
	u16 nMem;		/* Number of aMem[] value.  Might be zero */
	int nData;		/* Size of pData.  0 if none. */
};

int sqlite3CursorNext(BtCursor *, int *pRes);
int sqlite3CursorPrevious(BtCursor *, int *pRes);
int sqlite3CursorPayload(BtCursor *, u32 offset, u32 amt, void *);

void sqlite3ClearCursor(BtCursor *);
int sqlite3CursorHasHint(BtCursor *, unsigned int mask);

#ifndef NDEBUG
int sqlite3CursorIsValid(BtCursor *);
#endif
int sqlite3CursorIsValidNN(BtCursor *);


#endif				/* SQLITE_BTREE_H */
