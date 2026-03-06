//! SCIM filter parser (RFC 7644 Section 3.4.2.2).
//!
//! Supports: `eq`, `ne`, `co`, `sw`, `pr`, `and`, `or`, `not`, grouping with parentheses.
//! Attribute paths support optional schema qualifiers (e.g., `userName`, `urn:...:User:userName`).

use nom::IResult;
use nom::Parser;
use nom::branch::alt;
use nom::bytes::complete::{tag_no_case, take_while1};
use nom::character::complete::{char, multispace0, multispace1};
use nom::combinator::{map, opt};
use nom::sequence::{delimited, preceded};

use crate::error::ScimError;

/// Parsed SCIM filter expression.
#[derive(Debug, Clone, PartialEq)]
pub enum ScimFilter {
    /// Attribute comparison: `attr op value`.
    Compare {
        attr: String,
        op: CompareOp,
        value: String,
    },
    /// Attribute presence: `attr pr`.
    Present { attr: String },
    /// Logical AND.
    And(Box<ScimFilter>, Box<ScimFilter>),
    /// Logical OR.
    Or(Box<ScimFilter>, Box<ScimFilter>),
    /// Logical NOT.
    Not(Box<ScimFilter>),
}

/// SCIM comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Contains.
    Co,
    /// Starts with.
    Sw,
}

/// Parse a SCIM filter string into a `ScimFilter` AST.
///
/// Args:
/// * `input`: The raw SCIM filter string.
///
/// Usage:
/// ```ignore
/// let filter = parse_filter("userName eq \"deploy-bot\"")?;
/// ```
pub fn parse_filter(input: &str) -> Result<ScimFilter, ScimError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ScimError::InvalidFilter {
            message: "Filter cannot be empty.".into(),
        });
    }
    match parse_or(trimmed) {
        Ok(("", filter)) => Ok(filter),
        Ok((remaining, _)) => Err(ScimError::InvalidFilter {
            message: format!(
                "Unexpected trailing input: '{}'. Check filter syntax.",
                remaining
            ),
        }),
        Err(_) => Err(ScimError::InvalidFilter {
            message: format!(
                "Failed to parse filter: '{}'. Supported: eq, ne, co, sw, pr, and, or, not.",
                input
            ),
        }),
    }
}

// Precedence: OR < AND < NOT < atom
fn parse_or(input: &str) -> IResult<&str, ScimFilter> {
    let (input, left) = parse_and(input)?;
    let (input, right) = opt(preceded(
        (multispace1, tag_no_case("or"), multispace1),
        parse_or,
    ))
    .parse(input)?;
    match right {
        Some(r) => Ok((input, ScimFilter::Or(Box::new(left), Box::new(r)))),
        None => Ok((input, left)),
    }
}

fn parse_and(input: &str) -> IResult<&str, ScimFilter> {
    let (input, left) = parse_not(input)?;
    let (input, right) = opt(preceded(
        (multispace1, tag_no_case("and"), multispace1),
        parse_and,
    ))
    .parse(input)?;
    match right {
        Some(r) => Ok((input, ScimFilter::And(Box::new(left), Box::new(r)))),
        None => Ok((input, left)),
    }
}

fn parse_not(input: &str) -> IResult<&str, ScimFilter> {
    alt((
        map(
            preceded((tag_no_case("not"), multispace1), parse_atom),
            |f| ScimFilter::Not(Box::new(f)),
        ),
        parse_atom,
    ))
    .parse(input)
}

fn parse_atom(input: &str) -> IResult<&str, ScimFilter> {
    alt((parse_grouped, parse_presence, parse_comparison)).parse(input)
}

fn parse_grouped(input: &str) -> IResult<&str, ScimFilter> {
    delimited((char('('), multispace0), parse_or, (multispace0, char(')'))).parse(input)
}

fn parse_attr_path(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == '.' || c == ':').parse(input)
}

fn parse_presence(input: &str) -> IResult<&str, ScimFilter> {
    let (input, attr) = parse_attr_path(input)?;
    let (input, _) = multispace1.parse(input)?;
    let (input, _) = tag_no_case("pr").parse(input)?;
    Ok((
        input,
        ScimFilter::Present {
            attr: attr.to_string(),
        },
    ))
}

fn parse_comparison(input: &str) -> IResult<&str, ScimFilter> {
    let (input, attr) = parse_attr_path(input)?;
    let (input, _) = multispace1.parse(input)?;
    let (input, op) = parse_compare_op(input)?;
    let (input, _) = multispace1.parse(input)?;
    let (input, value) = parse_value(input)?;
    Ok((
        input,
        ScimFilter::Compare {
            attr: attr.to_string(),
            op,
            value: value.to_string(),
        },
    ))
}

fn parse_compare_op(input: &str) -> IResult<&str, CompareOp> {
    alt((
        map(tag_no_case("eq"), |_| CompareOp::Eq),
        map(tag_no_case("ne"), |_| CompareOp::Ne),
        map(tag_no_case("co"), |_| CompareOp::Co),
        map(tag_no_case("sw"), |_| CompareOp::Sw),
    ))
    .parse(input)
}

fn parse_value(input: &str) -> IResult<&str, &str> {
    delimited(char('"'), take_while1(|c: char| c != '"'), char('"')).parse(input)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_eq() {
        let f = parse_filter(r#"userName eq "deploy-bot""#).unwrap();
        assert_eq!(
            f,
            ScimFilter::Compare {
                attr: "userName".into(),
                op: CompareOp::Eq,
                value: "deploy-bot".into(),
            }
        );
    }

    #[test]
    fn parse_ne() {
        let f = parse_filter(r#"active ne "false""#).unwrap();
        assert!(matches!(
            f,
            ScimFilter::Compare {
                op: CompareOp::Ne,
                ..
            }
        ));
    }

    #[test]
    fn parse_co() {
        let f = parse_filter(r#"displayName co "bot""#).unwrap();
        assert!(matches!(
            f,
            ScimFilter::Compare {
                op: CompareOp::Co,
                ..
            }
        ));
    }

    #[test]
    fn parse_sw() {
        let f = parse_filter(r#"userName sw "deploy""#).unwrap();
        assert!(matches!(
            f,
            ScimFilter::Compare {
                op: CompareOp::Sw,
                ..
            }
        ));
    }

    #[test]
    fn parse_pr() {
        let f = parse_filter("externalId pr").unwrap();
        assert_eq!(
            f,
            ScimFilter::Present {
                attr: "externalId".into()
            }
        );
    }

    #[test]
    fn parse_and_or() {
        let f = parse_filter(r#"userName eq "a" and active eq "true""#).unwrap();
        assert!(matches!(f, ScimFilter::And(_, _)));
    }

    #[test]
    fn parse_or_expr() {
        let f = parse_filter(r#"userName eq "a" or userName eq "b""#).unwrap();
        assert!(matches!(f, ScimFilter::Or(_, _)));
    }

    #[test]
    fn parse_precedence_and_before_or() {
        // a or b and c → a or (b and c)
        let f = parse_filter(r#"userName eq "a" or userName eq "b" and active eq "true""#).unwrap();
        match f {
            ScimFilter::Or(_, right) => assert!(matches!(*right, ScimFilter::And(_, _))),
            _ => panic!("expected Or at top level"),
        }
    }

    #[test]
    fn parse_grouped() {
        let f =
            parse_filter(r#"(userName eq "a" or userName eq "b") and active eq "true""#).unwrap();
        match f {
            ScimFilter::And(left, _) => assert!(matches!(*left, ScimFilter::Or(_, _))),
            _ => panic!("expected And at top level"),
        }
    }

    #[test]
    fn parse_not() {
        let f = parse_filter(r#"not userName eq "test""#).unwrap();
        assert!(matches!(f, ScimFilter::Not(_)));
    }

    #[test]
    fn parse_schema_qualified_attr() {
        let f = parse_filter(r#"urn:ietf:params:scim:schemas:core:2.0:User:userName eq "bot""#)
            .unwrap();
        match f {
            ScimFilter::Compare { attr, .. } => {
                assert!(attr.contains("urn:ietf:params:scim"));
            }
            _ => panic!("expected Compare"),
        }
    }

    #[test]
    fn parse_empty_filter() {
        assert!(parse_filter("").is_err());
        assert!(parse_filter("  ").is_err());
    }

    #[test]
    fn parse_invalid_filter() {
        assert!(parse_filter("not_a_filter").is_err());
    }
}
