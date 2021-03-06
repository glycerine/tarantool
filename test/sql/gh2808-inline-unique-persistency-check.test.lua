-- Regression test for gh-2483
env = require('test_run')
test_run = env.new()

-- Create a table and insert a datum
box.sql.execute([[CREATE TABLE t1(a PRIMARY KEY, b, UNIQUE(b));]])
box.sql.execute([[INSERT INTO t1 VALUES(1,2);]])

-- Sanity check
box.sql.execute([[SELECT * FROM t1]])

test_run:cmd('restart server default');
-- This cmd should not fail
-- before this fix, unique index was notrecovered
-- correctly after restart (#2808)
box.sql.execute([[INSERT INTO t1 VALUES(2,3);]])

-- Sanity check
box.sql.execute([[SELECT * FROM t1]])

-- Cleanup
box.sql.execute([[drop table t1;]])
