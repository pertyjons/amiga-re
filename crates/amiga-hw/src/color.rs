//! Amiga color conversions.

/// Expand a 12-bit Amiga `$0RGB` color word to 8-bit-per-channel RGB by
/// replicating each 4-bit nibble into the high and low nibble (`n * 17`), which
/// maps `0x0` to `0` and `0xF` to `255`.
#[must_use]
pub fn rgb4_to_rgb8(value: u16) -> [u8; 3] {
    let red = u8::try_from((value >> 8) & 0x0f).unwrap_or_default();
    let green = u8::try_from((value >> 4) & 0x0f).unwrap_or_default();
    let blue = u8::try_from(value & 0x0f).unwrap_or_default();
    [red * 17, green * 17, blue * 17]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_the_extremes_and_a_midpoint() {
        assert_eq!(rgb4_to_rgb8(0x000), [0, 0, 0]);
        assert_eq!(rgb4_to_rgb8(0xfff), [255, 255, 255]);
        assert_eq!(rgb4_to_rgb8(0x08f), [0, 0x88, 0xff]);
    }
}
