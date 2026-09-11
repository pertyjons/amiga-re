# Symbolic memory-backed arguments (semantic schema 16)

Memory reads identify an expression without claiming its runtime bytes. Exact,
symbolic, and refused arguments remain exclusive; symbolic arguments do not
increase the exact-resolution percentage.

- `indexed` retains the base location, index register, index width in bytes,
  scale, signed displacement, and read site. Word indexes sign-extend before
  addition. Registers refer to their values at that instruction, even after a
  destination overwrites an index register. The MC68000 scale is 1; reserved
  scale/full-extension encodings for later processors are refused.
- `movem_slot` describes one ascending memory-to-register transfer by its base,
  byte offset, and read site. Word slots are two bytes apart and sign-extend;
  longword slots are four bytes apart. `(An)+` finishes at its old address plus
  the whole transfer size, including when the load mask contains An itself.
- `sign_extended_word` means `sext16(memory16[location])`, as used by MOVEA.W
  and MOVEM.W. It does not claim a 32-bit memory cell exists there.
- `preserve_high` describes a byte/word MOVE into Dn, retaining that register's
  earlier high bits: `replace_low16(D0@$4,memory16[A0])`, for example. Copies
  retain the original register snapshot. Narrow immediate/register writes
  remain refused where their full value is outside the supported domain.

Source expressions have at most three nodes: a base address, an optional index,
and an optional MOVEM slot. Propagation never grows this tree. Existing evidence
and work budgets apply to copies and arithmetic. Incompatible snapshots refuse a
join; branches copying the same established snapshot can still agree. Calls
clobber tracked values. Additive arithmetic wraps at 32 bits after the sized read.

Synthetic tests exercise address/data and word/long indexes, signed displacements,
MOVEM masks and base aliasing, byte/word replacement, sign extension, copies,
branch joins, call clobbers, evidence limits, malformed extensions, truncated
instructions, JSON serialization, and exclusive statistics. The report test's
six independent call cases each retain one symbolic argument and one exact one.
