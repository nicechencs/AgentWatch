//! Recursive-descent parser for the api-and-cli §4.2 grammar.
//!
//! No parser generator and no database dependency. `~` is always a substring
//! operator; nothing here compiles or executes a regular expression.

use super::ast::{Expr, FieldRef, Op, Term, Value};
use super::error::FilterError;
use super::registry::{self, FieldType};

/// Parse a filter query into an [`Expr`].
///
/// The empty string and a string of only whitespace parse as [`Expr::True`].
/// Failure returns the byte offset where the query stopped matching.
pub fn parse(input: &str) -> Result<Expr, FilterError> {
    let mut parser = Parser { input, pos: 0 };
    parser.skip_ws();
    if parser.eof() {
        return Ok(Expr::True);
    }
    let expr = parser.parse_or()?;
    parser.skip_ws();
    if !parser.eof() {
        return Err(parser.syntax("end of input"));
    }
    Ok(expr)
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn parse_or(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_and()?;
        while self.eat_keyword(&["or", "OR", "||"]) {
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_unary()?;
        loop {
            let saved = self.pos;
            let explicit = self.eat_keyword(&["and", "AND", "&&"]);
            if !explicit {
                // A space between two primaries is `and`, but not before `or`,
                // a closing parenthesis, or the end of the input.
                self.skip_ws();
                if self.pos == saved
                    || self.eof()
                    || self.peek(")")
                    || self.keyword_ahead(&["or", "OR", "||"])
                {
                    self.pos = saved;
                    break;
                }
            }
            let right = self.parse_unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, FilterError> {
        self.skip_ws();
        if self.eat_keyword(&["not", "NOT"]) || self.eat("-") || self.eat("!") {
            let inner = self.parse_unary()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, FilterError> {
        self.skip_ws();
        if self.eat("(") {
            let inner = self.parse_or()?;
            self.skip_ws();
            if !self.eat(")") {
                return Err(self.syntax("`)`"));
            }
            return Ok(inner);
        }
        self.parse_term()
    }

    fn parse_term(&mut self) -> Result<Expr, FilterError> {
        let start = self.pos;
        let word = self.read_value_token()?;
        // No whitespace is allowed between a field and its operator, so `a:b`
        // is a term while `a : b` is two bare words joined by a space-and.
        let Some(op) = self.read_op() else {
            return Ok(Expr::Term(Term {
                field: FieldRef::Bare,
                op: Op::Contains,
                values: vec![Value::Text(word)],
                offset: start,
            }));
        };
        let field = match registry::lookup(&word) {
            Some(info) => FieldRef::Named(info),
            None => {
                let suggestion = registry::suggest(&word)
                    .map(|name| format!(", did you mean `{name}`?"))
                    .unwrap_or_default();
                return Err(FilterError::UnknownField {
                    offset: start,
                    name: word,
                    suggestion,
                });
            }
        };
        self.skip_ws();
        let values = self.parse_value_list(field.name(), self.field_type(&field))?;
        if values.is_empty() {
            return Err(self.syntax("a value"));
        }
        self.check_operator(start, field.name(), self.field_type(&field), op)?;
        Ok(Expr::Term(Term {
            field,
            op,
            values,
            offset: start,
        }))
    }

    fn field_type(&self, field: &FieldRef) -> FieldType {
        match field {
            FieldRef::Named(info) => info.ty,
            FieldRef::Bare => FieldType::String,
        }
    }

    fn parse_value_list(&mut self, field: &str, ty: FieldType) -> Result<Vec<Value>, FilterError> {
        let bracketed = self.eat("[");
        let mut values = Vec::new();
        loop {
            values.push(self.parse_value(field, ty)?);
            // Look ahead for a comma, but put the whitespace back when there
            // is none: that space is the implicit `and` before the next term.
            let after_value = self.pos;
            self.skip_ws();
            if self.eat(",") {
                continue;
            }
            self.pos = after_value;
            break;
        }
        if bracketed && !self.eat("]") {
            return Err(self.syntax("`]`"));
        }
        Ok(values)
    }

    fn parse_value(&mut self, field: &str, ty: FieldType) -> Result<Value, FilterError> {
        let start = self.pos;
        if let Some(sign) = self.reltime_sign() {
            let nanos = self.read_duration().ok_or_else(|| FilterError::BadValue {
                offset: start,
                field: field.to_owned(),
                expected: "relative time",
                value: self.remainder_word().to_owned(),
            })?;
            // `read_duration` rewinds so it can reject a non-duration. The
            // sign check already proved one is here, so consume it for real.
            self.pos = start;
            let _ = self.read_duration();
            return Ok(Value::RelativeTime {
                from_session_start: sign,
                nanos,
            });
        }
        let token = self.read_value_token()?;
        match ty {
            FieldType::Bool => match token.as_str() {
                "true" => Ok(Value::Bool(true)),
                "false" => Ok(Value::Bool(false)),
                _ => Err(self.bad_value(start, field, "bool", &token)),
            },
            FieldType::Number => self.finish_number(start, field, &token).map(Value::Number),
            FieldType::Bytes => Ok(Value::Number(self.finish_bytes(start, field, &token)?)),
            FieldType::Duration => Ok(Value::Number(self.finish_duration(start, field, &token)?)),
            FieldType::Time => self.finish_time(start, field, &token),
            FieldType::String | FieldType::Glob | FieldType::Enum => Ok(Value::Text(token)),
        }
    }

    fn finish_number(&self, start: usize, field: &str, token: &str) -> Result<i64, FilterError> {
        parse_i64(token).ok_or_else(|| self.bad_value(start, field, "number", token))
    }

    fn finish_bytes(&self, start: usize, field: &str, token: &str) -> Result<i64, FilterError> {
        let (number, unit) = split_unit(token);
        let base =
            parse_f64(number).ok_or_else(|| self.bad_value(start, field, "byte count", token))?;
        let factor: i64 = match unit {
            "" | "B" => 1,
            "KB" => 1_000,
            "MB" => 1_000_000,
            "GB" => 1_000_000_000,
            "KiB" => 1024,
            "MiB" => 1024 * 1024,
            "GiB" => 1024 * 1024 * 1024,
            _ => return Err(self.bad_value(start, field, "byte count", token)),
        };
        Ok((base * factor as f64) as i64)
    }

    fn finish_duration(&self, start: usize, field: &str, token: &str) -> Result<i64, FilterError> {
        duration_nanos(token).ok_or_else(|| self.bad_value(start, field, "duration", token))
    }

    fn finish_time(&self, start: usize, field: &str, token: &str) -> Result<Value, FilterError> {
        if let Some(nanos) = duration_nanos(token) {
            return Ok(Value::RelativeTime {
                from_session_start: true,
                nanos,
            });
        }
        parse_i64(token)
            .map(Value::Number)
            .ok_or_else(|| self.bad_value(start, field, "time", token))
    }

    /// `+` counts from the session start, `-` counts back from now.
    fn reltime_sign(&mut self) -> Option<bool> {
        let saved = self.pos;
        let positive = if self.peek("+") {
            self.pos += 1;
            true
        } else if self.peek("-") {
            self.pos += 1;
            false
        } else {
            return None;
        };
        if self.read_duration().is_some() {
            self.pos = saved;
            return Some(positive);
        }
        self.pos = saved;
        None
    }

    fn read_duration(&mut self) -> Option<i64> {
        let saved = self.pos;
        // A leading sign belongs to the relative time, not to the duration.
        if self.peek("+") || self.peek("-") {
            self.pos += 1;
        }
        let token = self.read_value_token().ok()?;
        match duration_nanos(&token) {
            Some(nanos) => Some(nanos),
            None => {
                self.pos = saved;
                None
            }
        }
    }

    fn read_op(&mut self) -> Option<Op> {
        for (text, op) in [
            ("!=", Op::Ne),
            (">=", Op::Ge),
            ("<=", Op::Le),
            (">", Op::Gt),
            ("<", Op::Lt),
            ("=", Op::Eq),
            (":", Op::Match),
            ("~", Op::Contains),
        ] {
            if self.eat(text) {
                return Some(op);
            }
        }
        if self.eat_keyword(&["in"]) {
            return Some(Op::In);
        }
        None
    }

    fn check_operator(
        &self,
        offset: usize,
        field: &str,
        ty: FieldType,
        op: Op,
    ) -> Result<(), FilterError> {
        let numeric = matches!(
            ty,
            FieldType::Number | FieldType::Bytes | FieldType::Duration | FieldType::Time
        );
        let text = matches!(ty, FieldType::String | FieldType::Glob | FieldType::Enum);
        let ok = match op {
            Op::Gt | Op::Ge | Op::Lt | Op::Le => numeric,
            Op::Contains => text,
            Op::Match | Op::Eq | Op::Ne | Op::In => true,
        };
        if ok {
            Ok(())
        } else {
            Err(FilterError::BadOperator {
                offset,
                field: field.to_owned(),
                op: op_name(op).to_owned(),
            })
        }
    }

    fn read_value_token(&mut self) -> Result<String, FilterError> {
        self.skip_ws();
        if self.eof() {
            return Err(self.syntax("a value"));
        }
        if self.peek("\"") {
            return self.read_quoted('"');
        }
        if self.peek("'") {
            return self.read_quoted('\'');
        }
        let start = self.pos;
        while let Some(ch) = self.char_at(self.pos) {
            if ch.is_whitespace() || "()[],!=><&|".contains(ch) {
                break;
            }
            // `:` always ends a token (`kind:file`). `~` ends one only after
            // the first byte, so it is the operator in `argv~"-d"` while a
            // leading `~/.ssh/**` stays a single value.
            if ch == ':' || (ch == '~' && self.pos != start) {
                break;
            }
            self.pos += ch.len_utf8();
        }
        if self.pos == start {
            return Err(self.syntax("a value"));
        }
        Ok(self.input[start..self.pos].to_owned())
    }

    fn read_quoted(&mut self, quote: char) -> Result<String, FilterError> {
        self.pos += quote.len_utf8();
        let mut out = String::new();
        while let Some(ch) = self.char_at(self.pos) {
            self.pos += ch.len_utf8();
            if ch == quote {
                return Ok(out);
            }
            if ch == '\\' && quote == '"' {
                let Some(escaped) = self.char_at(self.pos) else {
                    return Err(self.syntax("an escape"));
                };
                self.pos += escaped.len_utf8();
                out.push(escaped);
                continue;
            }
            out.push(ch);
        }
        Err(self.syntax("a closing quote"))
    }

    fn eat_keyword(&mut self, words: &[&str]) -> bool {
        let saved = self.pos;
        self.skip_ws();
        for word in words {
            if self.boundary_word(word) {
                return true;
            }
        }
        self.pos = saved;
        false
    }

    fn keyword_ahead(&self, words: &[&str]) -> bool {
        let rest = &self.input[self.pos..];
        words.iter().any(|word| {
            let Some(after) = rest.strip_prefix(word) else {
                return false;
            };
            after.chars().next().is_none_or(|ch| !is_word_char(ch))
        })
    }

    fn boundary_word(&mut self, word: &str) -> bool {
        let rest = &self.input[self.pos..];
        let Some(after) = rest.strip_prefix(word) else {
            return false;
        };
        if after.chars().next().is_some_and(is_word_char) {
            return false;
        }
        self.pos += word.len();
        true
    }

    fn eat(&mut self, literal: &str) -> bool {
        if self.peek(literal) {
            self.pos += literal.len();
            true
        } else {
            false
        }
    }

    fn peek(&self, literal: &str) -> bool {
        self.input[self.pos..].starts_with(literal)
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.char_at(self.pos) {
            if !ch.is_whitespace() {
                break;
            }
            self.pos += ch.len_utf8();
        }
    }

    fn eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn char_at(&self, pos: usize) -> Option<char> {
        self.input[pos..].chars().next()
    }

    fn remainder_word(&self) -> &str {
        self.input[self.pos..]
            .split_whitespace()
            .next()
            .unwrap_or("")
    }

    fn syntax(&self, expected: &'static str) -> FilterError {
        let found = self.input[self.pos..].chars().take(16).collect::<String>();
        FilterError::Syntax {
            offset: self.pos,
            expected,
            found: if found.is_empty() {
                "end of input".to_owned()
            } else {
                found
            },
        }
    }

    fn bad_value(
        &self,
        offset: usize,
        field: &str,
        expected: &'static str,
        value: &str,
    ) -> FilterError {
        FilterError::BadValue {
            offset,
            field: field.to_owned(),
            expected,
            value: value.to_owned(),
        }
    }
}

fn is_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn op_name(op: Op) -> &'static str {
    match op {
        Op::Match => ":",
        Op::Eq => "=",
        Op::Ne => "!=",
        Op::Gt => ">",
        Op::Ge => ">=",
        Op::Lt => "<",
        Op::Le => "<=",
        Op::Contains => "~",
        Op::In => "in",
    }
}

fn split_unit(token: &str) -> (&str, &str) {
    for unit in ["KiB", "MiB", "GiB", "KB", "MB", "GB", "B"] {
        if let Some(number) = token.strip_suffix(unit) {
            if !number.is_empty() {
                return (number, unit);
            }
        }
    }
    (token, "")
}

fn duration_nanos(token: &str) -> Option<i64> {
    for (suffix, factor) in [
        ("ms", 1_000_000_i64),
        ("s", 1_000_000_000),
        ("m", 60_000_000_000),
        ("h", 3_600_000_000_000),
        ("d", 86_400_000_000_000),
    ] {
        if let Some(number) = token.strip_suffix(suffix) {
            let value = parse_f64(number)?;
            return Some((value * factor as f64) as i64);
        }
    }
    None
}

fn parse_i64(token: &str) -> Option<i64> {
    token.parse::<i64>().ok()
}

fn parse_f64(token: &str) -> Option<f64> {
    if token.is_empty() || token.chars().any(|ch| !ch.is_ascii_digit() && ch != '.') {
        return None;
    }
    token.parse::<f64>().ok()
}
