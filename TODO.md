# TODO

Actionable improvements and problems discovered while working on `amiga-re`
belong here. Completed work is removed; Git history is the record of what
landed. Larger staged work belongs under `plans/`.

Every entry follows the documentation requirements in `AGENTS.md`: purpose,
reason, location, implementation guidance, and verification.

## Control Flow & Disassembly

### Avoid full-image copies when decoding near the end of an image
- **Purpose:** Keep the cost of decoding one instruction proportional to its encoding size, including near EOF.
- **Why:** `control_flow::decode` clones the entire input into a padded buffer whenever fewer than ten bytes remain. Traversals with shared owners and data-table target validation can repeat this allocation for the same final instructions, making a tiny decoding operation expensive on large images.
- **Where:** `crates/amiga-disasm/src/control_flow.rs` (`decode`) and `crates/amiga-disasm/src/control_flow/jump_tables.rs` (target validation).
- **How:** Supply a bounded padded memory view or a small tail buffer that preserves the original PC used by the decoder. Keep the final encoded-range check so truncated instructions are still refused, retain MOVEC handling, and add synthetic tests for complete and truncated instructions at EOF, PC-relative operands, and repeated tail targets. Verify with an allocation measurement or benchmark that tail decoding no longer allocates in proportion to the whole image size.
