//! Milestone 3's acceptance criterion: function names, globals, register
//! locals, and comments resolve in the *correct* image and address space
//! across two modules with overlapping numeric addresses.
//!
//! The fixture's two images deliberately share hunk 0 offset 4. If resolution
//! were keyed on a number, these tests would pass by accident; they are written
//! to fail if it ever is.

use std::path::{Path, PathBuf};

use amiga_project::load;
use amiga_project::resolve::{Index, LocalStorage};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/contract")
}

#[test]
fn a_function_and_its_entity_comment_resolve_together() {
    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("{error}"));
    let index = Index::build(&loaded.project);

    let resolved = index.at("image:main-executable", 0, 0);
    assert_eq!(resolved.function, Some("init_graphics"));
    // The comment targets the *entity*, not the offset. It still arrives here,
    // which is the point of that indirection: renaming or rebasing the function
    // carries the comment with it.
    assert_eq!(resolved.comments.len(), 1);
    assert_eq!(resolved.comments[0].placement, "before");
    assert!(resolved.comments[0].text.contains("graphics.library"));
}

#[test]
fn the_same_numeric_offset_resolves_differently_per_image() {
    // The acceptance criterion. Hunk 0 offset 0 exists in both images, and each
    // has its own function there.
    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("{error}"));
    let index = Index::build(&loaded.project);

    assert_eq!(
        index.at("image:main-executable", 0, 0).function,
        Some("init_graphics")
    );
    assert_eq!(
        index.at("image:level-loader", 0, 0).function,
        Some("load_level")
    );

    // And hunk 0 offset 4: the loader has a symbol there; the main image's
    // annotation for that offset is the deliberately stale one, which must not
    // resolve at all.
    assert_eq!(
        index.at("image:level-loader", 0, 4).symbols,
        vec!["loader_tail"]
    );
    assert!(
        index.at("image:main-executable", 0, 4).is_empty(),
        "a stale annotation resolved: {:?}",
        index.at("image:main-executable", 0, 4)
    );

    // An image the project does not describe says nothing, rather than falling
    // back to whichever image happened to be indexed first.
    assert!(index.at("image:invented", 0, 0).is_empty());
}

#[test]
fn a_stale_annotation_is_excluded_from_lookups_but_still_listed() {
    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("{error}"));
    let index = Index::build(&loaded.project);

    // Excluded from resolution...
    assert!(index.at("image:main-executable", 0, 4).is_empty());
    // ...and still visible, so a user can find and rebase it.
    let stale: Vec<&str> = index.stale().iter().map(|id| id.as_str()).collect();
    assert_eq!(stale, ["annotation:main/stale-note"]);
}

#[test]
fn a_register_local_is_scoped_to_its_function_with_its_lifetime() {
    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("{error}"));
    let index = Index::build(&loaded.project);

    let locals = index.locals("function:init-graphics");
    assert_eq!(locals.len(), 1);
    assert_eq!(locals[0].name, "library_base");
    assert_eq!(locals[0].storage, LocalStorage::Register("d0"));
    // The lifetime is what keeps the name off the rest of the function, where
    // D0 means something else.
    assert_eq!(locals[0].lifetime, Some((10, 14)));

    // A function with no locals has none, rather than inheriting another's.
    assert!(index.locals("function:load-level").is_empty());
}

#[test]
fn a_global_symbol_resolves_in_the_hunk_it_names() {
    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("{error}"));
    let index = Index::build(&loaded.project);

    let resolved = index.at("image:main-executable", 1, 0);
    assert_eq!(resolved.symbols, vec!["graphics_library_name"]);
    assert_eq!(resolved.regions, vec!["text"]);
    // Hunk 1 of the *other* image has nothing: the hunk index is part of the
    // key, not a hint.
    assert!(index.at("image:level-loader", 1, 0).is_empty());
}

#[test]
fn a_runtime_address_resolves_through_the_named_load_map_it_was_given() {
    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("{error}"));
    let index = Index::build(&loaded.project);

    // The fixture's bookmark targets a runtime address under the default map;
    // it must arrive at the hunk offset that map converts it to.
    let resolved = index.at("image:main-executable", 0, 0);
    assert_eq!(resolved.bookmarks, vec!["Program entry"]);

    // The same numeric address means something different under each map, which
    // is why a load map is named rather than assumed.
    assert_eq!(
        index.to_hunk_offset(
            "image:main-executable",
            "loadmap:main/default",
            "0x0000e640"
        ),
        Some((0, 2))
    );
    assert_eq!(
        index.to_hunk_offset(
            "image:main-executable",
            "loadmap:main/relocated",
            "0x00080010"
        ),
        Some((0, 16))
    );
    // Under the relocated map, the default map's entry address is below every
    // segment base, so it converts to nothing rather than to a plausible offset.
    assert_eq!(
        index.to_hunk_offset(
            "image:main-executable",
            "loadmap:main/relocated",
            "0x0000e63e"
        ),
        None
    );
    // An unknown map resolves nothing, even for an address a known map covers.
    assert_eq!(
        index.to_hunk_offset("image:main-executable", "loadmap:invented", "0x0000e63e"),
        None
    );
}

#[test]
fn the_second_hunk_of_a_load_map_is_chosen_by_its_own_base() {
    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("{error}"));
    let index = Index::build(&loaded.project);
    // Hunk 1 is based at 0x00022000 under the default map.
    assert_eq!(
        index.to_hunk_offset(
            "image:main-executable",
            "loadmap:main/default",
            "0x00022004"
        ),
        Some((1, 4))
    );
}

#[test]
fn a_base_register_global_resolves_by_its_slot_and_belongs_to_no_function() {
    // The shape `disasm globals` reports: a small-data slot every function
    // shares. It has no function scope, so it is found by (image, register,
    // displacement) rather than through a function that owns it.
    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("{error}"));
    let index = Index::build(&loaded.project);

    let global = index
        .global("image:main-executable", "a5", -8)
        .expect("the fixture names A5-8");
    assert_eq!(global.name, "map_seed");
    assert_eq!(global.base, "a5");
    assert_eq!(global.width, 4);

    // The register is part of the key: A4-8 is a different global, and naming
    // it after this one would be a confident wrong answer.
    assert!(index.global("image:main-executable", "a4", -8).is_none());
    // So is the image: the fixture's two modules share numeric offsets on
    // purpose, and a slot is no different.
    assert!(index.global("image:loader", "a5", -8).is_none());

    // It appears in the image's listing, and in no other image's.
    let globals = index.globals("image:main-executable");
    assert_eq!(globals.len(), 1);
    assert_eq!(globals[0], global);
    assert!(index.globals("image:loader").is_empty());

    // And it is not a local of any function, which is the distinction the
    // second variable shape exists to make.
    for function in ["function:init-graphics", "function:load-level"] {
        assert!(
            index
                .locals(function)
                .iter()
                .all(|local| local.name != "map_seed")
        );
    }
}

/// The other global shape: shared state at an address rather than behind a base
/// register, which is what a program keeping its state at absolute addresses
/// has. It resolves where the bytes are, so a listing walking a hunk finds it
/// without having to ask a second question.
#[test]
fn a_global_at_an_address_resolves_where_its_bytes_are() {
    let loaded = load(&fixture()).unwrap_or_else(|error| panic!("{error}"));
    let index = Index::build(&loaded.project);

    // Written as a hunk range, and carrying the type it was reviewed as.
    let resolved = index.at("image:main-executable", 1, 0);
    let table = resolved
        .variables
        .iter()
        .find(|variable| variable.name == "level_table")
        .expect("the fixture names a global at hunk 1 offset 0");
    assert_eq!(table.type_id, Some("type:level-table"));
    assert_eq!(table.width, 32);

    // Written as a runtime address, and found at the hunk offset that address
    // converts to under its named load map — the same rule every other target
    // goes through, so one lookup answers for both spellings.
    let resolved = index.at("image:main-executable", 1, 0x10);
    let lives = resolved
        .variables
        .iter()
        .find(|variable| variable.name == "player_lives")
        .expect("the fixture names a global at 0x00022010");
    assert_eq!(lives.type_id, Some("type:s16"));
    assert_eq!(lives.width, 2);

    // A small-data slot is *not* here. It is asked for by slot, and answering
    // "what is at this offset" with it would be a different global.
    assert!(
        index
            .at("image:main-executable", 1, 0)
            .variables
            .iter()
            .all(|variable| variable.name != "map_seed")
    );
    // Nor does the fixture's other module carry either of them, though its hunk
    // offsets overlap numerically on purpose.
    assert!(index.at("image:level-loader", 1, 0).variables.is_empty());
}
