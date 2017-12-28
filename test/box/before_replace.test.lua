s = box.schema.space.create('test')
_ = s:create_index('primary')
_ = s:create_index('secondary', {unique = false, parts = {2, 'unsigned'}})

function fail(old, new) error('fail') end
function save(old, new) old_tuple = old new_tuple = new end
function nop(old, new) return new end
function ignore(old, new) return old end
function delete(old, new) return nil end
function update(old, new) return box.tuple.update(new, {{'+', 3, 1}}) end
function bad_update(old, new) return box.tuple.update(new, {{'+', 1, 1}}) end

-- Exception in trigger.
type(s:before_replace(fail))
s:insert{1, 1}
s:select()
s:before_replace(nil, fail)

-- Check 'old' and 'new' trigger arguments.
old_tuple = nil
new_tuple = nil
type(s:before_replace(save))
s:insert{1, 1}
old_tuple, new_tuple
s:replace{1, 2}
old_tuple, new_tuple
s:update(1, {{'+', 2, 1}})
old_tuple, new_tuple
s:upsert({1, 1}, {{'=', 2, 1}})
old_tuple, new_tuple
s:upsert({2, 2}, {{'=', 2, 2}})
old_tuple, new_tuple
s:select()
s:delete(1)
old_tuple, new_tuple
s:delete(2)
old_tuple, new_tuple
s:select()
s:before_replace(nil, save)

-- Returning 'new' from trigger doesn't affect statement.
type(s:before_replace(nop))
s:insert{1, 1}
s:update(1, {{'+', 2, 1}})
s:select()
s:delete(1)
s:select()
s:before_replace(nil, nop)

-- Returning 'old' from trigger skips statement.
s:insert{1, 1}
type(s:before_replace(ignore))
s:insert{2, 2}
s:update(1, {{'+', 2, 1}})
s:delete(1)
s:select()
s:before_replace(nil, ignore)
s:delete(1)

-- Returning nil from trigger turns statement into DELETE.
s:insert{1, 1}
type(s:before_replace(delete))
s:replace{1, 2}
s:select()
s:before_replace(nil, delete)

-- Update statement from trigger.
type(s:before_replace(update))
s:insert{1, 1, 1}
s:update(1, {{'+', 2, 1}})
s:select()
s:before_replace(nil, update)
s:delete(1)

-- Update of the primary key from trigger is forbidden.
s:insert{1, 1}
type(s:before_replace(bad_update))
s:replace{1, 2}
s:before_replace(nil, bad_update)
s:delete(1)

-- Stacking triggers.
old_tuple = nil
new_tuple = nil
type(s:before_replace(save))
type(s:before_replace(update))
s:insert{1, 1, 1}
old_tuple, new_tuple
s:before_replace(nil, save)
s:before_replace(nil, update)

s:drop()
