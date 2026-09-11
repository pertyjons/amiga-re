//! `graphics.bitmap.compare`: which pixels two images disagree about, and how.
//!
//! The tests are about the distinctions a digest cannot make. Two images that
//! differ everywhere because a palette was permuted, two that agree pixel for
//! pixel and look different, and two that differ in one corner are three
//! findings, and a comparison that reported "they differ" for all three would be
//! the thing this operation replaces.

use std::sync::Arc;

use amiga_operations::{
    BitmapCompareArguments, BitmapCompareResult, ComparedBitmap, ExecutionContext,
    InMemorySourceResolver, OperationRequestDocument, PixelRect, RequestEnvelope, ResolvedSource,
    Router, SourceName, Status,
};

/// An 8x4 index image, one byte per pixel.
const WIDTH: usize = 8;
const HEIGHT: usize = 4;

fn resolver(images: &[(&str, Vec<u8>)]) -> InMemorySourceResolver {
    InMemorySourceResolver::holding(
        images
            .iter()
            .map(|(name, bytes)| {
                ResolvedSource::new(
                    SourceName::parse(name).expect("a valid name"),
                    Arc::from(bytes.clone()),
                )
            })
            .collect(),
    )
}

fn compare(
    arguments: BitmapCompareArguments,
    context: &ExecutionContext<'_>,
) -> BitmapCompareResult {
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::GraphicsBitmapCompare(arguments)),
        context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    outcome
        .graphics_bitmap_compare()
        .expect("a comparison result")
        .clone()
}

fn refusal(arguments: BitmapCompareArguments, context: &ExecutionContext<'_>) -> String {
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::GraphicsBitmapCompare(arguments)),
        context,
    );
    assert_eq!(outcome.status, Status::Error);
    outcome
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>()
        .join(" | ")
}

fn side(name: &str) -> ComparedBitmap {
    ComparedBitmap::new(name, WIDTH, HEIGHT)
}

/// A permuted palette differs in every pixel and is one substitution.
///
/// This is the finding the operation exists for. A digest says the two images
/// are unrelated; the substitution table says every 1 became a 2 and the picture
/// is otherwise identical, which is a palette permutation and not a redraw.
#[test]
fn a_permuted_palette_is_one_substitution_covering_every_differing_pixel() {
    let ones = vec![1_u8; WIDTH * HEIGHT];
    let twos = vec![2_u8; WIDTH * HEIGHT];
    let resolver = resolver(&[("a.idx", ones), ("b.idx", twos)]);
    let context = ExecutionContext::new(&resolver);
    let result = compare(
        BitmapCompareArguments::new(side("a.idx"), side("b.idx")),
        &context,
    );

    assert!(!result.identical);
    assert_eq!(result.differing_pixels, 32);
    assert_eq!(result.compared_pixels, 32);
    assert_eq!(result.substitutions_total, 1);
    assert_eq!(result.substitutions[0].from, 1);
    assert_eq!(result.substitutions[0].to, 2);
    assert_eq!(result.substitutions[0].pixels, 32);
    // One region, covering the whole image: the difference is not localized,
    // which is itself the shape of a palette fault rather than a geometry one.
    assert_eq!(result.regions_total, 1);
    assert_eq!(result.regions[0].pixels, 32);
}

/// Two images that agree pixel for pixel and look different is a *palette*
/// disagreement, and is reported as one rather than as agreement.
#[test]
fn identical_indices_under_different_palettes_are_a_palette_only_difference() {
    let pixels = vec![1_u8; WIDTH * HEIGHT];
    let resolver = resolver(&[("a.idx", pixels.clone()), ("b.idx", pixels)]);
    let context = ExecutionContext::new(&resolver);
    let result = compare(
        BitmapCompareArguments::new(
            side("a.idx").with_palette(vec![0x0000, 0x0f00]),
            side("b.idx").with_palette(vec![0x0000, 0x000f]),
        ),
        &context,
    );

    assert!(result.identical, "the indices agree everywhere");
    assert!(!result.colours_identical);
    assert!(result.palette_only);
    assert_eq!(result.differing_pixels, 0);
    assert_eq!(result.differing_colour_pixels, 32);
    assert!(result.differing_bounds.is_none());
}

/// A localized difference has a bounding box and a region, and both name where.
#[test]
fn a_differing_corner_is_reported_with_its_bounds_and_its_region() {
    let clean = vec![0_u8; WIDTH * HEIGHT];
    let mut spotted = clean.clone();
    spotted[2 * WIDTH + 5] = 7;
    spotted[2 * WIDTH + 6] = 7;
    let resolver = resolver(&[("a.idx", clean), ("b.idx", spotted)]);
    let context = ExecutionContext::new(&resolver);
    let result = compare(
        BitmapCompareArguments::new(side("a.idx"), side("b.idx")),
        &context,
    );

    assert_eq!(result.differing_pixels, 2);
    let bounds = result.differing_bounds.expect("a bounding box");
    assert_eq!(
        (bounds.x, bounds.y, bounds.width, bounds.height),
        (5, 2, 2, 1)
    );
    // Four-connected and adjacent, so one region rather than two.
    assert_eq!(result.regions_total, 1);
    assert_eq!(result.regions[0].pixels, 2);
}

/// A crop's findings are in the image's coordinates, not the crop's.
///
/// `compared` has always been the crop rectangle in the first image's
/// coordinates; `differing_bounds` and each region's bounds used to be counted
/// from the crop's own corner, so a reader who cropped and then looked the
/// reported rectangle up in the image found it displaced by the crop origin with
/// nothing in the response saying the two were in different frames. The crop
/// here starts at (4, 1) precisely so the two frames do not coincide, which is
/// what the uncropped tests above cannot distinguish.
#[test]
fn a_crop_reports_its_findings_in_the_image_s_coordinates() {
    let clean = vec![0_u8; WIDTH * HEIGHT];
    let mut spotted = clean.clone();
    spotted[2 * WIDTH + 5] = 7;
    spotted[2 * WIDTH + 6] = 7;
    let resolver = resolver(&[("a.idx", clean), ("b.idx", spotted)]);
    let context = ExecutionContext::new(&resolver);
    let mut arguments = BitmapCompareArguments::new(side("a.idx"), side("b.idx"));
    arguments.crop = Some(PixelRect {
        x: 4,
        y: 1,
        width: 4,
        height: 3,
    });
    let result = compare(arguments, &context);

    assert_eq!(result.differing_pixels, 2);
    assert_eq!(
        (
            result.compared.x,
            result.compared.y,
            result.compared.width,
            result.compared.height
        ),
        (4, 1, 4, 3)
    );
    let bounds = result.differing_bounds.expect("a bounding box");
    assert_eq!(
        (bounds.x, bounds.y, bounds.width, bounds.height),
        (5, 2, 2, 1),
        "the same rectangle the uncropped comparison reports, not (1, 1)"
    );
    assert_eq!(result.regions_total, 1);
    let region = result.regions[0].bounds;
    assert_eq!(
        (region.x, region.y, region.width, region.height),
        (5, 2, 2, 1)
    );
}

/// A mask excludes pixels from the comparison, and the totals say how many.
///
/// A comparison that silently ignored a region would report a passing result
/// nobody could audit; the excluded count is what makes it auditable.
#[test]
fn a_pinned_mask_excludes_pixels_and_the_result_counts_them() {
    let clean = vec![0_u8; WIDTH * HEIGHT];
    let mut spotted = clean.clone();
    spotted[0] = 3;
    // Everything except the first pixel is compared.
    let mut mask = vec![1_u8; WIDTH * HEIGHT];
    mask[0] = 0;
    let digest = amiga_core::sha256(&mask);
    let resolver = resolver(&[
        ("a.idx", clean),
        ("b.idx", spotted),
        ("mask.bin", mask.clone()),
    ]);
    let context = ExecutionContext::new(&resolver);
    let mut arguments = BitmapCompareArguments::new(side("a.idx"), side("b.idx"));
    arguments.mask = Some(amiga_operations::ValidityMask {
        source: amiga_operations::SourceLocator::file("mask.bin"),
        sha256: digest.clone(),
        offset: None,
        maximum_input_bytes: None,
    });
    let result = compare(arguments.clone(), &context);

    assert!(result.identical, "the only difference was masked out");
    assert_eq!(result.masked_pixels, 1);
    assert_eq!(result.compared_pixels, 31);

    // And a mask whose digest does not match is refused: an unpinned mask could
    // turn a failing comparison into a passing one with nothing to say it had.
    let mut stale = arguments;
    if let Some(mask) = stale.mask.as_mut() {
        mask.sha256 = "0".repeat(64);
    }
    let message = refusal(stale, &context);
    assert!(message.contains("hashes to"), "{message}");
}

/// Differing dimensions are refused rather than resampled.
#[test]
fn two_images_of_different_sizes_are_refused_rather_than_resampled() {
    let resolver = resolver(&[
        ("a.idx", vec![0_u8; WIDTH * HEIGHT]),
        ("b.idx", vec![0_u8; WIDTH * HEIGHT * 4]),
    ]);
    let context = ExecutionContext::new(&resolver);
    let message = refusal(
        BitmapCompareArguments::new(side("a.idx"), ComparedBitmap::new("b.idx", 16, 8)),
        &context,
    );
    assert!(message.contains("does not resample"), "{message}");
}

/// An explicit alignment shifts one side, and a sample it moves outside the
/// image is a difference rather than a match.
#[test]
fn an_explicit_alignment_shifts_one_side_and_the_edge_it_leaves_differs() {
    // A single set pixel, one column apart in the two images.
    let mut left = vec![0_u8; WIDTH * HEIGHT];
    left[WIDTH + 2] = 5;
    let mut right = vec![0_u8; WIDTH * HEIGHT];
    right[WIDTH + 3] = 5;
    let resolver = resolver(&[("a.idx", left), ("b.idx", right)]);
    let context = ExecutionContext::new(&resolver);

    // Unaligned, the two set pixels are two differences.
    let plain = compare(
        BitmapCompareArguments::new(side("a.idx"), side("b.idx")),
        &context,
    );
    assert_eq!(plain.differing_pixels, 2);

    // Shifting the second side one pixel left lines them up — and costs the
    // rightmost column, whose samples now fall outside the image.
    let mut aligned = side("b.idx");
    aligned.align = Some(amiga_operations::PixelOffset { x: 1, y: 0 });
    let shifted = compare(
        BitmapCompareArguments::new(side("a.idx"), aligned),
        &context,
    );
    assert_eq!(
        shifted.differing_pixels, HEIGHT as u64,
        "the set pixels agree; what differs is the column the shift left empty"
    );
    let bounds = shifted.differing_bounds.expect("a bounding box");
    assert_eq!(bounds.x, (WIDTH - 1) as u64);
    assert_eq!(bounds.width, 1);
}

/// With a palette on one side only, the two are compared in index space alone.
///
/// Resolving one side's indices through a palette and the other's through
/// nothing would report a difference about the *request* rather than about the
/// pictures — every pixel whose index is not its own colour word.
#[test]
fn one_palette_between_two_sides_compares_indices_and_says_so() {
    let pixels = vec![1_u8; WIDTH * HEIGHT];
    let resolver = resolver(&[("a.idx", pixels.clone()), ("b.idx", pixels)]);
    let context = ExecutionContext::new(&resolver);
    let outcome = Router::execute(
        &RequestEnvelope::read(OperationRequestDocument::GraphicsBitmapCompare(
            BitmapCompareArguments::new(
                side("a.idx").with_palette(vec![0x0000, 0x0f00]),
                side("b.idx"),
            ),
        )),
        &context,
    );
    assert_eq!(outcome.status, Status::Success, "{:?}", outcome.diagnostics);
    let result = outcome
        .graphics_bitmap_compare()
        .expect("a comparison result");
    assert!(result.identical);
    assert!(
        result.colours_identical,
        "the colour answer mirrors the index answer when only one side has a palette"
    );
    assert!(!result.palette_only);
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("index space")),
        "{:?}",
        outcome.diagnostics
    );
}

/// A moved sprite is a source-plane difference, not fabricated playfield data.
#[test]
fn a_moved_sprite_keeps_identical_playfield_indices_and_reports_its_origin() {
    let indices = vec![0_u8; WIDTH * HEIGHT];
    let mut left_sources = vec![0_u8; WIDTH * HEIGHT];
    left_sources[1] = 1;
    let mut right_sources = vec![0_u8; WIDTH * HEIGHT];
    right_sources[2] = 1;
    let resolver = resolver(&[
        ("a.idx", indices.clone()),
        ("b.idx", indices),
        ("a.sources", left_sources),
        ("b.sources", right_sources),
    ]);
    let context = ExecutionContext::new(&resolver);
    let result = compare(
        BitmapCompareArguments::new(
            side("a.idx").with_pixel_sources("a.sources"),
            side("b.idx").with_pixel_sources("b.sources"),
        ),
        &context,
    );

    assert!(result.identical);
    assert_eq!(result.differing_pixels, 0);
    let sources = result.pixel_sources.expect("a source-plane comparison");
    assert!(!sources.identical);
    assert_eq!(sources.differing_pixels, 2);
}

/// An absent source plane is unknown, not an all-playfield plane.
#[test]
fn one_pixel_source_plane_is_refused() {
    let indices = vec![0_u8; WIDTH * HEIGHT];
    let resolver = resolver(&[
        ("a.idx", indices.clone()),
        ("b.idx", indices),
        ("a.sources", vec![0_u8; WIDTH * HEIGHT]),
    ]);
    let context = ExecutionContext::new(&resolver);
    let message = refusal(
        BitmapCompareArguments::new(side("a.idx").with_pixel_sources("a.sources"), side("b.idx")),
        &context,
    );
    assert!(message.contains("both sides"), "{message}");
}
