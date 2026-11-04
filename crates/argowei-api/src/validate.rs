//! Checks for text that users type into the API (labels, notes, group names).
//!
//! Every value is trimmed first. Lengths are counted in characters, not bytes,
//! so "Wohnzimmer" and "Büro" are measured the way a person reads them.
//! Messages name the field so the dashboard can show them as they are.

use std::ops::RangeInclusive;

use crate::error::ApiError;

/// A one-line value such as a name or label: no control characters at all.
///
/// `length` is the allowed number of characters after trimming. A range that
/// starts at 0 allows an empty value (the caller decides what empty means).
pub fn single_line(
    raw: &str,
    field: &str,
    length: RangeInclusive<usize>,
) -> Result<String, ApiError> {
    let value = raw.trim();
    check_length(value, field, &length)?;
    if value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field} must be a single line without control characters"
        )));
    }
    Ok(value.to_owned())
}

/// Free text such as notes: line breaks and tabs are fine, other control
/// characters are not (they would corrupt what the dashboard displays).
pub fn multi_line(
    raw: &str,
    field: &str,
    length: RangeInclusive<usize>,
) -> Result<String, ApiError> {
    let value = raw.trim();
    check_length(value, field, &length)?;
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(ApiError::BadRequest(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(value.to_owned())
}

fn check_length(value: &str, field: &str, length: &RangeInclusive<usize>) -> Result<(), ApiError> {
    if length.contains(&value.chars().count()) {
        return Ok(());
    }
    let (min, max) = (length.start(), length.end());
    Err(ApiError::BadRequest(if *min == 0 {
        format!("{field} must be at most {max} characters")
    } else {
        format!("{field} must be {min}-{max} characters")
    }))
}

/// For unit tests: the message of a validation error, or a panic.
#[cfg(test)]
pub(crate) fn bad_request<T: std::fmt::Debug>(result: Result<T, ApiError>) -> String {
    match result {
        Err(ApiError::BadRequest(message)) => message,
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_trimmed() {
        assert_eq!(
            single_line("  Wohnzimmer  ", "name", 1..=64).unwrap(),
            "Wohnzimmer"
        );
        assert_eq!(multi_line("  a\nb \n", "notes", 0..=10).unwrap(), "a\nb");
    }

    #[test]
    fn lengths_count_characters_not_bytes() {
        assert!(single_line(&"ä".repeat(64), "label", 0..=64).is_ok());
        assert_eq!(
            bad_request(single_line(&"ä".repeat(65), "label", 0..=64)),
            "label must be at most 64 characters"
        );
    }

    #[test]
    fn a_required_value_says_so_in_its_range() {
        assert_eq!(
            bad_request(single_line("   ", "name", 1..=64)),
            "name must be 1-64 characters"
        );
        assert_eq!(
            bad_request(single_line(&"x".repeat(65), "name", 1..=64)),
            "name must be 1-64 characters"
        );
        assert_eq!(
            single_line("", "label", 0..=64).unwrap(),
            "",
            "optional values may be empty"
        );
    }

    #[test]
    fn single_line_values_reject_every_control_character() {
        for raw in ["two\nlines", "tab\there", "bell\u{7}", "nul\0byte"] {
            assert_eq!(
                bad_request(single_line(raw, "label", 0..=64)),
                "label must be a single line without control characters",
                "{raw:?}"
            );
        }
    }

    #[test]
    fn multi_line_values_allow_line_breaks_and_tabs_only() {
        assert!(multi_line("a\r\nb\tc", "notes", 0..=100).is_ok());
        assert_eq!(
            bad_request(multi_line("bell\u{7}", "notes", 0..=100)),
            "notes must not contain control characters"
        );
    }

    #[test]
    fn length_is_checked_before_content() {
        // A long value with a control character reports the length first, as
        // the handlers always have.
        let raw = format!("{}\u{7}", "x".repeat(20));
        assert_eq!(
            bad_request(multi_line(&raw, "notes", 0..=10)),
            "notes must be at most 10 characters"
        );
    }
}
