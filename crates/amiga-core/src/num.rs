//! Small numeric parsing shared by the CLI's argument handling.

/// Parse a `u32` written in decimal or, with a `0x`/`0X` prefix, hexadecimal.
///
/// Returns a `String` error so it can be used directly as a `clap` value parser.
///
/// # Errors
/// Returns a message if `value` is not a valid decimal or hex integer.
pub fn parse_u32(value: &str) -> Result<u32, String> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    match hex {
        Some(digits) => u32::from_str_radix(digits, 16),
        None => value.parse(),
    }
    .map_err(|error| format!("invalid integer {value:?}: {error}"))
}

/// Parse a `u64` the same way, for the offsets and lengths a project target
/// carries.
///
/// A separate function rather than a widened [`parse_u32`]: a command that
/// accepts a 64-bit offset and one that accepts a 32-bit address are different
/// promises, and silently accepting the wider value in the narrower place is
/// how an out-of-range argument becomes a truncated one.
///
/// # Errors
/// Returns a message if `value` is not a valid decimal or hex integer.
pub fn parse_u64(value: &str) -> Result<u64, String> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    match hex {
        Some(digits) => u64::from_str_radix(digits, 16),
        None => value.parse(),
    }
    .map_err(|error| format!("invalid integer {value:?}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_and_hex() {
        assert_eq!(parse_u32("42"), Ok(42));
        assert_eq!(parse_u32("0x2A"), Ok(0x2a));
        assert_eq!(parse_u32("0X10"), Ok(16));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_u32("nope").is_err());
        assert!(parse_u32("0xzz").is_err());
    }

    #[test]
    fn the_wide_parser_reaches_past_u32() {
        assert_eq!(parse_u64("0x100000000"), Ok(1 << 32));
        assert_eq!(parse_u64("4294967296"), Ok(1 << 32));
        assert!(parse_u64("nope").is_err());
    }
}
