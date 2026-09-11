//! `graphics.bitmap.decode`: what it decodes, and what it refuses before it
//! reads anything.

use amiga_operations::{
    BitmapDecodeArguments, BitmapShape, BobMask, DiagnosticCode, ExecutionContext,
    InMemorySourceResolver, OperationLimits, OperationRequestDocument, PlaneOrder, RequestEnvelope,
    ResolvedSource, Router, SourceName, Status,
};

fn source(bytes: &[u8]) -> InMemorySourceResolver {
    let name = SourceName::parse("planes.bin").expect("a relative name");
    InMemorySourceResolver::new(ResolvedSource::new(name, std::sync::Arc::from(bytes)))
}

fn run(
    resolver: &InMemorySourceResolver,
    arguments: BitmapDecodeArguments,
) -> amiga_operations::OperationOutcome {
    let context = ExecutionContext::new(resolver);
    Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::GraphicsBitmapDecode(arguments)),
        &context,
    )
}

#[test]
fn one_bitplane_decodes_msb_first_to_one_index_per_pixel() {
    // 8x1, one plane: `1010_0000` is alternating set and clear pixels, most
    // significant bit leftmost — the ordering an Amiga bitplane uses.
    let resolver = source(&[0b1010_0000]);
    let outcome = run(&resolver, BitmapDecodeArguments::new("planes.bin", 8, 1, 1));

    assert_eq!(outcome.status, Status::Success);
    let image = outcome.graphics_bitmap_decode().expect("the decode ran");
    assert_eq!(image.width, 8);
    assert_eq!(image.height, 1);
    assert_eq!(image.planes, 1);
    assert_eq!(image.indices, [1, 0, 1, 0, 0, 0, 0, 0]);
    assert!(image.opaque.is_none(), "only `bob` has transparency");
    // The source is pinned, so a caller can prove which bytes produced this.
    assert_eq!(image.source.size, 1);
}

#[test]
fn a_second_plane_contributes_the_next_index_bit() {
    // Plane 0 all set, plane 1 clear for the first four pixels: indices 1 then 3.
    let resolver = source(&[0xff, 0xf0]);
    let outcome = run(&resolver, BitmapDecodeArguments::new("planes.bin", 8, 1, 2));

    let image = outcome.graphics_bitmap_decode().expect("the decode ran");
    assert_eq!(image.indices, [3, 3, 3, 3, 1, 1, 1, 1]);
}

#[test]
fn interleaved_and_contiguous_orders_read_the_same_bytes_differently() {
    // Two rows, two planes. Contiguous: both rows of plane 0, then of plane 1.
    // Interleaved: both planes of row 0, then of row 1. The same four bytes
    // must therefore decode to different images.
    let bytes = [0xf0, 0x0f, 0xcc, 0x33];
    let resolver = source(&bytes);

    let contiguous = run(
        &resolver,
        BitmapDecodeArguments::new("planes.bin", 8, 2, 2).with_plane_order(PlaneOrder::Contiguous),
    );
    let interleaved = run(
        &resolver,
        BitmapDecodeArguments::new("planes.bin", 8, 2, 2).with_plane_order(PlaneOrder::Interleaved),
    );

    let left = contiguous.graphics_bitmap_decode().expect("contiguous ran");
    let right = interleaved
        .graphics_bitmap_decode()
        .expect("interleaved ran");
    assert_ne!(
        left.indices, right.indices,
        "the two plane orders read the same bytes identically, so one is wrong"
    );
}

#[test]
fn every_chunk_interleaved_order_reads_the_same_row_differently() {
    // One 32-pixel row, two planes, eight bytes. Each chunk width takes a
    // different byte as plane 1's first, so all five orders must disagree —
    // except the longword chunk, which for a 32-pixel row *is* the scanline.
    let bytes = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];
    let resolver = source(&bytes);
    let decode = |order| {
        run(
            &resolver,
            BitmapDecodeArguments::new("planes.bin", 32, 1, 2).with_plane_order(order),
        )
        .graphics_bitmap_decode()
        .expect("the decode ran")
        .indices
        .clone()
    };

    let byte = decode(PlaneOrder::ByteInterleaved);
    let word = decode(PlaneOrder::WordInterleaved);
    let longword = decode(PlaneOrder::LongwordInterleaved);
    assert_ne!(byte, word);
    assert_ne!(word, longword);
    assert_eq!(
        longword,
        decode(PlaneOrder::Interleaved),
        "a chunk as wide as the row is the scanline layout"
    );
    // Where each byte's single set bit lands, spelled out for the word layout:
    // bytes 0-1 are plane 0's first word and 2-3 plane 1's.
    assert_eq!(word[0], 1);
    assert_eq!(word[2], 2);
    assert_eq!(word[9], 1);
    assert_eq!(word[11], 2);
}

#[test]
fn a_chunk_interleaved_row_is_padded_up_to_whole_chunks() {
    // 8 pixels is one byte per plane, and a word chunk spends two — so the
    // four bytes that hold two rows byte-interleaved hold only one word-
    // interleaved, and asking for two is refused rather than read short.
    let resolver = source(&[0xff, 0xff, 0xff, 0xff]);
    let two_rows = |order| {
        run(
            &resolver,
            BitmapDecodeArguments::new("planes.bin", 8, 2, 2).with_plane_order(order),
        )
    };
    assert!(
        two_rows(PlaneOrder::ByteInterleaved)
            .graphics_bitmap_decode()
            .is_some()
    );
    assert!(
        two_rows(PlaneOrder::WordInterleaved)
            .graphics_bitmap_decode()
            .is_none(),
        "a word-interleaved decode read past the bytes it was given"
    );
}

#[test]
fn a_glyph_sheet_tiles_glyphs_with_its_separator() {
    // Four 8x1 glyphs, two per row, one pixel of gap: a 17x3 contact sheet.
    let resolver = source(&[0xff, 0x00, 0xff, 0x00]);
    let outcome = run(
        &resolver,
        BitmapDecodeArguments::new("planes.bin", 8, 1, 1)
            .with_shape(BitmapShape::GlyphSheet)
            .with_glyphs(4, 2, 1),
    );

    let image = outcome
        .graphics_bitmap_decode()
        .expect("the sheet rendered");
    // Two columns of 8 with one gap; two rows of 1 with one gap.
    assert_eq!(image.width, 17);
    assert_eq!(image.height, 3);
    assert_eq!(image.indices.len(), image.width * image.height);
}

#[test]
fn a_color_keyed_bob_reports_which_pixels_are_opaque() {
    let resolver = source(&[0b1010_0000]);
    let outcome = run(
        &resolver,
        BitmapDecodeArguments::new("planes.bin", 8, 1, 1)
            .with_shape(BitmapShape::Bob)
            .with_bob_mask(BobMask::ColorKey { index: 0 }),
    );

    let image = outcome.graphics_bitmap_decode().expect("the bob extracted");
    let opaque = image.opaque.as_ref().expect("a bob carries a mask");
    assert_eq!(opaque.len(), image.indices.len());
    // Index 0 is the key, so exactly the set pixels are opaque.
    for (index, is_opaque) in image.indices.iter().zip(opaque) {
        assert_eq!(*is_opaque, *index != 0);
    }
}

#[test]
fn an_oversized_geometry_is_refused_before_the_source_is_read() {
    // The source is one byte. A decode this large could never come from it,
    // and the refusal must not depend on noticing that: the bound is the
    // declared geometry, checked before anything is opened.
    let resolver = source(&[0x00]);
    let context = ExecutionContext::new(&resolver)
        .with_limits(OperationLimits::default().with_maximum_output_pixels(1024));
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::GraphicsBitmapDecode(
            BitmapDecodeArguments::new("planes.bin", 4096, 4096, 4),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Error);
    assert!(outcome.result.is_none());
    assert_eq!(
        outcome.diagnostics[0].code,
        DiagnosticCode::GraphicsOutputTooLarge
    );
    // The operation ran and failed; it was not a malformed request.
    assert_eq!(outcome.exit_code(), 1);
}

#[test]
fn impossible_geometry_is_a_request_error_not_an_operation_failure() {
    let resolver = source(&[0x00; 64]);
    for arguments in [
        BitmapDecodeArguments::new("planes.bin", 0, 8, 1),
        BitmapDecodeArguments::new("planes.bin", 8, 0, 1),
        BitmapDecodeArguments::new("planes.bin", 8, 8, 0),
        BitmapDecodeArguments::new("planes.bin", 8, 8, 9),
    ] {
        let outcome = run(&resolver, arguments);
        assert_eq!(outcome.status, Status::Error);
        assert_eq!(
            outcome.diagnostics[0].code,
            DiagnosticCode::RequestArgumentOutOfRange
        );
        // Refused before any work ran, which automation distinguishes by code.
        assert_eq!(outcome.exit_code(), 2);
    }
}

#[test]
fn an_offset_past_the_end_and_a_source_too_short_are_told_apart() {
    let resolver = source(&[0x00; 8]);

    let past_end = run(
        &resolver,
        BitmapDecodeArguments::new("planes.bin", 8, 1, 1).at_offset(64),
    );
    assert_eq!(
        past_end.diagnostics[0].code,
        DiagnosticCode::GraphicsOffsetOutsideSource
    );

    // Inside the source, but not enough bytes for the geometry.
    let too_short = run(
        &resolver,
        BitmapDecodeArguments::new("planes.bin", 8, 64, 1),
    );
    assert_eq!(
        too_short.diagnostics[0].code,
        DiagnosticCode::GraphicsPlanarUndecodable
    );
}

#[test]
fn a_cancelled_decode_reports_no_image() {
    let resolver = source(&[0xff; 4096]);
    let cancel = std::sync::atomic::AtomicBool::new(true);
    let context = ExecutionContext::new(&resolver).with_cancel(&cancel);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::GraphicsBitmapDecode(
            BitmapDecodeArguments::new("planes.bin", 512, 64, 1),
        )),
        &context,
    );

    assert_eq!(outcome.status, Status::Cancelled);
    assert!(outcome.result.is_none());
    assert_eq!(outcome.exit_code(), 3);
}

#[test]
fn the_digest_covers_every_argument_that_changes_the_image() {
    let resolver = source(&[0xff; 64]);
    let base = run(&resolver, BitmapDecodeArguments::new("planes.bin", 8, 8, 1));
    let digest = |outcome: &amiga_operations::OperationOutcome| {
        outcome
            .normalized_request_sha256
            .clone()
            .expect("a normalized request has a digest")
    };

    // Anything that changes what is decoded must change the digest, or a
    // reviewed plan could be committed against different pixels than approved.
    for different in [
        BitmapDecodeArguments::new("planes.bin", 8, 8, 1).at_offset(4),
        BitmapDecodeArguments::new("planes.bin", 16, 8, 1),
        BitmapDecodeArguments::new("planes.bin", 8, 8, 2),
        BitmapDecodeArguments::new("planes.bin", 8, 8, 1).with_plane_order(PlaneOrder::Interleaved),
        BitmapDecodeArguments::new("planes.bin", 8, 8, 1).with_shape(BitmapShape::Bob),
    ] {
        assert_ne!(
            digest(&base),
            digest(&run(&resolver, different)),
            "two different decodes share a request digest"
        );
    }

    // Spelling a default out explicitly is the same request.
    assert_eq!(
        digest(&base),
        digest(&run(
            &resolver,
            BitmapDecodeArguments::new("planes.bin", 8, 8, 1)
                .at_offset(0)
                .with_shape(BitmapShape::Bitmap)
                .with_plane_order(PlaneOrder::Contiguous)
        ))
    );
}
