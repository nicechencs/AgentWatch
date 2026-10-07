//! Subset of the api-and-cli §4.2 filter BNF.
//!
//! P1 fields: `kind`, `proc`, `pid`, `domain`, `ip`, `port`, `evidence`, `time`.
//! `path` parses and then fails as [`QueryError::UnsupportedField`]. Any other
//! field is [`QueryError::UnknownField`]. User text never becomes SQL text;
//! [`super::sql`] binds every value.

use crate::query::error::QueryError;

/// A parsed filter. An empty string is [`Expr::True`].
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// No constraint.
    True,
    /// One comparison.
    Term(Term),
    /// Both sides.
    And(Box<Expr>, Box<Expr>),
    /// Either side.
    Or(Box<Expr>, Box<Expr>),
    /// Negation.
    Not(Box<Expr>),
}

/// `field op values`.
#[derive(Debug, Clone, PartialEq)]
pub struct Term {
    /// P1 field.
    pub field: Field,
    /// Comparison.
    pub op: Op,
    /// One or more values. `:` with several values means any-of.
    pub values: Vec<Value>,
}

/// Fields this layer knows how to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Timeline category: `proc`, `net`, `dns`, `gap` (and the documented later names).
    Kind,
    /// Process executable basename.
    Proc,
    /// OS pid.
    Pid,
    /// Flow domain or DNS qname.
    Domain,
    /// Remote IP.
    Ip,
    /// Remote port.
    Port,
    /// Evidence label.
    Evidence,
    /// Record time, absolute nanoseconds or a relative duration.
    Time,
}

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Glob for strings, equality for numbers. Multiple values are any-of.
    Match,
    /// Equality.
    Eq,
    /// Inequality.
    Ne,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Case-insensitive substring. Not a regular expression.
    Contains,
}

/// A literal from the filter.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Quoted text, or a glob / ident token.
    Text(String),
    /// Integer, or a decimal that was exact.
    Number(i64),
    /// `+` is relative to the session start; `-` is relative to `now_ns`.
    RelativeTime {
        /// Sign as parsed. `true` means `+`.
        from_session_start: bool,
        /// Duration in nanoseconds.
        nanos: i64,
    },
    /// `true` or `false`.
    Bool(bool),
}

struct Parser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

/// Parse `input`. An empty or all-whitespace string is [`Expr::True`].
///
/// `path` is recognized so it can be rejected as unsupported rather than ignored.
pub fn parse(input: &str) -> Result<Expr, QueryError> {
    let mut p = Parser {
        src: input,
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    if p.eof() {
        return Ok(Expr::True);
    }
    let expr = p.parse_or()?;
    p.skip_ws();
    if !p.eof() {
        return Err(QueryError::Parse {
            offset: p.pos,
            message: "trailing input",
        });
    }
    Ok(expr)
}

impl<'a> Parser<'a> {
    fn eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.bytes.get(self.pos) {
            if b.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_or(&mut self) -> Result<Expr, QueryError> {
        let mut left = self.parse_and()?;
        loop {
            self.skip_ws();
            if self.eat_keyword("or") || self.eat_exact("||") {
                let right = self.parse_and()?;
                left = Expr::Or(Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, QueryError> {
        let mut left = self.parse_unary()?;
        loop {
            let before = self.pos;
            self.skip_ws();
            if self.eat_keyword("and") || self.eat_exact("&&") {
                let right = self.parse_unary()?;
                left = Expr::And(Box::new(left), Box::new(right));
                continue;
            }
            // A space between two primaries is `and` (BNF: `<ws>`).
            // `or` / `||` belong to the outer expression; do not swallow them.
            if self.pos != before && self.starts_primary() && !self.at_or() {
                let right = self.parse_unary()?;
                left = Expr::And(Box::new(left), Box::new(right));
                continue;
            }
            self.pos = before;
            break;
        }
        Ok(left)
    }

    fn starts_primary(&self) -> bool {
        match self.bytes.get(self.pos).copied() {
            Some(b'(') | Some(b'"') | Some(b'\'') => true,
            Some(b) if is_glob_byte(b) => true,
            _ => false,
        }
    }

    fn parse_unary(&mut self) -> Result<Expr, QueryError> {
        self.skip_ws();
        if self.eat_keyword("not") || self.eat_exact("!") || self.eat_exact("-") {
            let inner = self.parse_unary()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, QueryError> {
        self.skip_ws();
        if self.eat_exact("(") {
            let inner = self.parse_or()?;
            self.skip_ws();
            if !self.eat_exact(")") {
                return Err(QueryError::Parse {
                    offset: self.pos,
                    message: "missing closing parenthesis",
                });
            }
            return Ok(inner);
        }
        self.parse_term_or_bare()
    }

    fn parse_term_or_bare(&mut self) -> Result<Expr, QueryError> {
        self.skip_ws();
        let start = self.pos;
        if self.bytes.get(self.pos).copied() == Some(b'"')
            || self.bytes.get(self.pos).copied() == Some(b'\'')
        {
            let text = self.parse_quoted()?;
            return Ok(Expr::Term(Term {
                field: Field::Domain,
                op: Op::Contains,
                values: vec![Value::Text(text)],
            }));
        }
        // Field names stop at an operator. `:` is also a glob byte (Windows
        // paths), so a field cannot be read with the value scanner.
        let token = self.parse_field_token()?;
        self.skip_ws();
        if self.peek_op().is_some() {
            let field = classify_field(&token)?;
            let op = self.parse_op()?;
            let values = self.parse_value_list()?;
            return Ok(Expr::Term(Term { field, op, values }));
        }
        // A bare glob with no operator is a substring probe of domain / qname.
        // `path` without an operator is still unsupported: the token is the field
        // only when an operator follows. A bare word is a value.
        let _ = start;
        Ok(Expr::Term(Term {
            field: Field::Domain,
            op: Op::Contains,
            values: vec![Value::Text(token)],
        }))
    }

    fn peek_op(&self) -> Option<Op> {
        let rest = self.rest();
        if rest.starts_with("!=") {
            Some(Op::Ne)
        } else if rest.starts_with(">=") {
            Some(Op::Ge)
        } else if rest.starts_with("<=") {
            Some(Op::Le)
        } else if rest.starts_with('>') {
            Some(Op::Gt)
        } else if rest.starts_with('<') {
            Some(Op::Lt)
        } else if rest.starts_with('~') {
            Some(Op::Contains)
        } else if rest.starts_with(':') {
            Some(Op::Match)
        } else if rest.starts_with('=') {
            Some(Op::Eq)
        } else if rest.starts_with("in") {
            let after = rest.as_bytes().get(2).copied();
            if after.is_none() || after.is_some_and(|b| b.is_ascii_whitespace() || b == b'[') {
                Some(Op::Match)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn parse_op(&mut self) -> Result<Op, QueryError> {
        self.skip_ws();
        let op = self.peek_op().ok_or(QueryError::Parse {
            offset: self.pos,
            message: "expected an operator",
        })?;
        let rest = self.rest();
        let len = if rest.starts_with("!=")
            || rest.starts_with(">=")
            || rest.starts_with("<=")
            || rest.starts_with("in")
        {
            2
        } else {
            1
        };
        self.pos += len;
        Ok(op)
    }

    fn parse_value_list(&mut self) -> Result<Vec<Value>, QueryError> {
        self.skip_ws();
        if self.eat_exact("[") {
            let mut values = Vec::new();
            loop {
                self.skip_ws();
                if self.eat_exact("]") {
                    break;
                }
                values.push(self.parse_value()?);
                self.skip_ws();
                if self.eat_exact("]") {
                    break;
                }
                if !self.eat_exact(",") {
                    return Err(QueryError::Parse {
                        offset: self.pos,
                        message: "expected comma or closing bracket",
                    });
                }
            }
            if values.is_empty() {
                return Err(QueryError::Parse {
                    offset: self.pos,
                    message: "empty value list",
                });
            }
            return Ok(values);
        }
        let mut values = vec![self.parse_value()?];
        loop {
            let save = self.pos;
            self.skip_ws();
            if self.eat_exact(",") {
                values.push(self.parse_value()?);
            } else {
                self.pos = save;
                break;
            }
        }
        Ok(values)
    }

    fn parse_value(&mut self) -> Result<Value, QueryError> {
        self.skip_ws();
        if self.bytes.get(self.pos).copied() == Some(b'"')
            || self.bytes.get(self.pos).copied() == Some(b'\'')
        {
            return Ok(Value::Text(self.parse_quoted()?));
        }
        if self.rest().starts_with('+') || (self.rest().starts_with('-') && self.looks_like_rel()) {
            return self.parse_reltime();
        }
        if self.rest().starts_with("true") && self.keyword_end("true".len()) {
            self.pos += 4;
            return Ok(Value::Bool(true));
        }
        if self.rest().starts_with("false") && self.keyword_end("false".len()) {
            self.pos += 5;
            return Ok(Value::Bool(false));
        }
        if self
            .bytes
            .get(self.pos)
            .copied()
            .is_some_and(|b| b.is_ascii_digit())
        {
            // `10.0.0.1` is an address, not a fractional number. A number is a
            // digit run, an optional fraction, and then a unit or a boundary.
            if self.looks_like_number() {
                return self.parse_number_or_duration();
            }
        }
        let token = self.parse_glob_token()?;
        Ok(Value::Text(token))
    }

    fn looks_like_number(&self) -> bool {
        let bytes = self.rest().as_bytes();
        let mut i = 0;
        while bytes.get(i).copied().is_some_and(|b| b.is_ascii_digit()) {
            i += 1;
        }
        if bytes.get(i).copied() == Some(b'.') {
            i += 1;
            let frac = i;
            while bytes.get(i).copied().is_some_and(|b| b.is_ascii_digit()) {
                i += 1;
            }
            if i == frac {
                return false;
            }
        }
        match bytes.get(i).copied() {
            None => true,
            Some(b) if b.is_ascii_whitespace() || matches!(b, b',' | b')' | b']') => true,
            Some(b's') | Some(b'm') | Some(b'h') | Some(b'd') => true,
            _ => false,
        }
    }

    fn looks_like_rel(&self) -> bool {
        let bytes = self.rest().as_bytes();
        let mut i = 1;
        if bytes.get(i).copied().is_some_and(|b| b.is_ascii_digit()) {
            while bytes
                .get(i)
                .copied()
                .is_some_and(|b| b.is_ascii_digit() || b == b'.')
            {
                i += 1;
            }
            let unit = &self.rest()[i..];
            return unit.starts_with("ms")
                || unit.starts_with('s')
                || unit.starts_with('m')
                || unit.starts_with('h')
                || unit.starts_with('d');
        }
        false
    }

    fn parse_reltime(&mut self) -> Result<Value, QueryError> {
        let from_session_start = if self.eat_exact("+") {
            true
        } else if self.eat_exact("-") {
            false
        } else {
            return Err(QueryError::Parse {
                offset: self.pos,
                message: "expected a relative time",
            });
        };
        let nanos = self.parse_duration_nanos()?;
        Ok(Value::RelativeTime {
            from_session_start,
            nanos,
        })
    }

    fn parse_number_or_duration(&mut self) -> Result<Value, QueryError> {
        let start = self.pos;
        self.consume_number_spelling()?;
        let spelling = &self.src[start..self.pos];
        if self.starts_duration_unit() {
            let n: f64 = spelling.parse().map_err(|_| QueryError::Parse {
                offset: start,
                message: "not a number",
            })?;
            let unit_nanos = self.consume_duration_unit()?;
            let nanos = duration_to_nanos(n, unit_nanos).ok_or(QueryError::Parse {
                offset: start,
                message: "duration is out of range",
            })?;
            return Ok(Value::Number(nanos));
        }
        if spelling.contains('.') {
            return Err(QueryError::Parse {
                offset: start,
                message: "fractional numbers need a unit",
            });
        }
        let n: i64 = spelling.parse().map_err(|_| QueryError::Parse {
            offset: start,
            message: "integer is out of range",
        })?;
        Ok(Value::Number(n))
    }

    fn parse_duration_nanos(&mut self) -> Result<i64, QueryError> {
        let start = self.pos;
        if !self
            .bytes
            .get(self.pos)
            .copied()
            .is_some_and(|b| b.is_ascii_digit())
        {
            return Err(QueryError::Parse {
                offset: self.pos,
                message: "expected a duration",
            });
        }
        self.consume_number_spelling()?;
        let spelling = &self.src[start..self.pos];
        let n: f64 = spelling.parse().map_err(|_| QueryError::Parse {
            offset: start,
            message: "not a number",
        })?;
        let unit = self.consume_duration_unit()?;
        duration_to_nanos(n, unit).ok_or(QueryError::Parse {
            offset: start,
            message: "duration is out of range",
        })
    }

    fn starts_duration_unit(&self) -> bool {
        let rest = self.rest();
        rest.starts_with("ms")
            || rest.starts_with('s')
            || rest.starts_with('m')
            || rest.starts_with('h')
            || rest.starts_with('d')
    }

    fn consume_duration_unit(&mut self) -> Result<i64, QueryError> {
        let rest = self.rest();
        let (len, scale) = if rest.starts_with("ms") {
            (2, 1_000_000_i64)
        } else if rest.starts_with('s') {
            (1, 1_000_000_000)
        } else if rest.starts_with('m') {
            (1, 60 * 1_000_000_000)
        } else if rest.starts_with('h') {
            (1, 3_600 * 1_000_000_000)
        } else if rest.starts_with('d') {
            (1, 86_400 * 1_000_000_000)
        } else {
            return Err(QueryError::Parse {
                offset: self.pos,
                message: "expected a duration unit",
            });
        };
        self.pos += len;
        Ok(scale)
    }

    fn consume_number_spelling(&mut self) -> Result<(), QueryError> {
        let start = self.pos;
        while self
            .bytes
            .get(self.pos)
            .copied()
            .is_some_and(|b| b.is_ascii_digit())
        {
            self.pos += 1;
        }
        if self.bytes.get(self.pos).copied() == Some(b'.') {
            self.pos += 1;
            let frac = self.pos;
            while self
                .bytes
                .get(self.pos)
                .copied()
                .is_some_and(|b| b.is_ascii_digit())
            {
                self.pos += 1;
            }
            if self.pos == frac {
                return Err(QueryError::Parse {
                    offset: start,
                    message: "not a number",
                });
            }
        }
        if self.pos == start {
            return Err(QueryError::Parse {
                offset: start,
                message: "not a number",
            });
        }
        Ok(())
    }

    fn parse_quoted(&mut self) -> Result<String, QueryError> {
        let quote = self.bytes.get(self.pos).copied().ok_or(QueryError::Parse {
            offset: self.pos,
            message: "expected a quoted value",
        })?;
        self.pos += 1;
        let mut out = String::new();
        if quote == b'\'' {
            loop {
                let b = self.bytes.get(self.pos).copied().ok_or(QueryError::Parse {
                    offset: self.pos,
                    message: "unterminated single quote",
                })?;
                self.pos += 1;
                if b == b'\'' {
                    break;
                }
                out.push(char::from(b));
            }
            return Ok(out);
        }
        loop {
            let b = self.bytes.get(self.pos).copied().ok_or(QueryError::Parse {
                offset: self.pos,
                message: "unterminated double quote",
            })?;
            self.pos += 1;
            if b == b'\\' {
                let next = self.bytes.get(self.pos).copied().ok_or(QueryError::Parse {
                    offset: self.pos,
                    message: "unterminated escape",
                })?;
                self.pos += 1;
                out.push(char::from(next));
                continue;
            }
            if b == b'"' {
                break;
            }
            out.push(char::from(b));
        }
        Ok(out)
    }

    fn parse_field_token(&mut self) -> Result<String, QueryError> {
        let start = self.pos;
        while self.bytes.get(self.pos).copied().is_some_and(is_field_byte) {
            self.pos += 1;
        }
        if let Some(cut) = keyword_cut(&self.src[start..self.pos]) {
            self.pos = start + cut;
        }
        if self.pos == start {
            return self.parse_glob_token();
        }
        // `kind:` must not become the bare value `kind` plus trailing `:`.
        let save = self.pos;
        self.skip_ws();
        let op = self.peek_op().is_some();
        self.pos = save;
        if !op && self.bytes.get(self.pos).copied().is_some_and(is_glob_byte) {
            return self.parse_glob_token_from(start);
        }
        Ok(self.src[start..self.pos].to_string())
    }

    fn parse_glob_token_from(&mut self, start: usize) -> Result<String, QueryError> {
        self.pos = start;
        self.parse_glob_token()
    }

    fn parse_glob_token(&mut self) -> Result<String, QueryError> {
        let start = self.pos;
        while self.bytes.get(self.pos).copied().is_some_and(is_glob_byte) {
            self.pos += 1;
        }
        // Whitespace is not a glob byte, so `a OR kind` is one token unless we
        // stop when the next non-space word is a keyword.
        if self.followed_by_keyword() {
            // token already ended at the whitespace; nothing to trim.
        } else if let Some(cut) = keyword_cut(&self.src[start..self.pos]) {
            self.pos = start + cut;
        }
        if self.pos == start {
            return Err(QueryError::Parse {
                offset: self.pos,
                message: "expected a value",
            });
        }
        Ok(self.src[start..self.pos].to_string())
    }

    fn at_or(&self) -> bool {
        let rest = self.rest();
        if rest.starts_with("||") {
            return true;
        }
        rest.len() >= 2
            && rest[..2].eq_ignore_ascii_case("or")
            && rest.as_bytes().get(2).is_none_or(|b| !is_ident_byte(*b))
    }

    fn followed_by_keyword(&self) -> bool {
        let mut i = self.pos;
        while self
            .bytes
            .get(i)
            .copied()
            .is_some_and(|b| b.is_ascii_whitespace())
        {
            i += 1;
        }
        let rest = &self.src[i..];
        for word in ["and", "or", "not"] {
            if rest.len() >= word.len() && rest[..word.len()].eq_ignore_ascii_case(word) {
                let after = rest.as_bytes().get(word.len()).copied();
                if after.is_none() || after.is_some_and(|b| !is_ident_byte(b)) {
                    return true;
                }
            }
        }
        false
    }

    fn eat_exact(&mut self, lit: &str) -> bool {
        if self.rest().starts_with(lit) {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }

    fn eat_keyword(&mut self, word: &str) -> bool {
        let rest = self.rest();
        let len = word.len();
        if rest.len() >= len && rest[..len].eq_ignore_ascii_case(word) && self.keyword_end(len) {
            self.pos += len;
            true
        } else {
            false
        }
    }

    fn keyword_end(&self, len: usize) -> bool {
        match self.bytes.get(self.pos + len).copied() {
            None => true,
            Some(b) => !is_ident_byte(b),
        }
    }
}

/// Index inside `token` where `and` / `or` / `not` begins, if the keyword
/// sits on a boundary and is not the whole token (`orange` stays intact).
fn keyword_cut(token: &str) -> Option<usize> {
    let bytes = token.as_bytes();
    for word in ["and", "or", "not"] {
        let w = word.as_bytes();
        let mut i = 0;
        while i + w.len() <= bytes.len() {
            if bytes[i..i + w.len()].eq_ignore_ascii_case(w) {
                let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
                let after = i + w.len();
                let after_ok = after == bytes.len() || !is_ident_byte(bytes[after]);
                if before_ok && after_ok && i > 0 {
                    return Some(i);
                }
            }
            i += 1;
        }
    }
    None
}

fn is_field_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.')
}

fn is_glob_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'_' | b'.' | b'/' | b'~' | b'*' | b'?' | b'-' | b'@' | b':' | b'\\'
        )
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn classify_field(token: &str) -> Result<Field, QueryError> {
    let lower = token.to_ascii_lowercase();
    match lower.as_str() {
        "kind" => Ok(Field::Kind),
        "proc" => Ok(Field::Proc),
        "pid" => Ok(Field::Pid),
        "domain" | "qname" => Ok(Field::Domain),
        "ip" | "remote.ip" => Ok(Field::Ip),
        "port" | "remote.port" => Ok(Field::Port),
        "evidence" => Ok(Field::Evidence),
        "time" => Ok(Field::Time),
        "path" | "dir" => Err(QueryError::UnsupportedField { field: lower }),
        _ => Err(QueryError::UnknownField { field: lower }),
    }
}

fn duration_to_nanos(n: f64, unit_nanos: i64) -> Option<i64> {
    if !n.is_finite() || n < 0.0 {
        return None;
    }
    let nanos = n * (unit_nanos as f64);
    if nanos > i64::MAX as f64 {
        return None;
    }
    Some(nanos as i64)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn term(field: Field, op: Op, values: Vec<Value>) -> Expr {
        Expr::Term(Term { field, op, values })
    }

    fn text(s: &str) -> Value {
        Value::Text(s.to_string())
    }

    // --- positive (1–20) ---

    #[test]
    fn pos_empty_is_true() {
        assert_eq!(parse("").unwrap(), Expr::True);
        assert_eq!(parse("   ").unwrap(), Expr::True);
    }

    #[test]
    fn pos_kind_exact() {
        assert_eq!(
            parse("kind:net").unwrap(),
            term(Field::Kind, Op::Match, vec![text("net")])
        );
    }

    #[test]
    fn pos_kind_or_list() {
        assert_eq!(
            parse("kind:net,dns").unwrap(),
            term(Field::Kind, Op::Match, vec![text("net"), text("dns")])
        );
    }

    #[test]
    fn pos_kind_bracket_list() {
        assert_eq!(
            parse("kind:[net, dns]").unwrap(),
            term(Field::Kind, Op::Match, vec![text("net"), text("dns")])
        );
    }

    #[test]
    fn pos_proc_glob() {
        assert_eq!(
            parse("proc:node*").unwrap(),
            term(Field::Proc, Op::Match, vec![text("node*")])
        );
    }

    #[test]
    fn pos_pid_eq() {
        assert_eq!(
            parse("pid=42").unwrap(),
            term(Field::Pid, Op::Eq, vec![Value::Number(42)])
        );
    }

    #[test]
    fn pos_pid_match_is_eq() {
        assert_eq!(
            parse("pid:42").unwrap(),
            term(Field::Pid, Op::Match, vec![Value::Number(42)])
        );
    }

    #[test]
    fn pos_domain_quoted_injection() {
        assert_eq!(
            parse(r#"domain:"x' OR 1=1 --""#).unwrap(),
            term(Field::Domain, Op::Match, vec![text("x' OR 1=1 --")])
        );
    }

    #[test]
    fn pos_domain_glob() {
        assert_eq!(
            parse("domain:*.example.com").unwrap(),
            term(Field::Domain, Op::Match, vec![text("*.example.com")])
        );
    }

    #[test]
    fn pos_ip_and_port() {
        let expr = parse("ip:10.0.0.1 port:443").unwrap();
        match expr {
            Expr::And(left, right) => {
                assert_eq!(*left, term(Field::Ip, Op::Match, vec![text("10.0.0.1")]));
                assert_eq!(
                    *right,
                    term(Field::Port, Op::Match, vec![Value::Number(443)])
                );
            }
            other => panic!("expected and, got {other:?}"),
        }
    }

    #[test]
    fn pos_remote_dotted_fields() {
        assert_eq!(
            parse("remote.ip:1.2.3.4").unwrap(),
            term(Field::Ip, Op::Match, vec![text("1.2.3.4")])
        );
        assert_eq!(
            parse("remote.port>=1024").unwrap(),
            term(Field::Port, Op::Ge, vec![Value::Number(1024)])
        );
    }

    #[test]
    fn pos_evidence_list() {
        assert_eq!(
            parse("evidence:I,S").unwrap(),
            term(Field::Evidence, Op::Match, vec![text("I"), text("S")])
        );
    }

    #[test]
    fn pos_explicit_and_or() {
        let expr = parse("kind:net AND domain:a OR kind:dns").unwrap();
        match expr {
            Expr::Or(left, right) => {
                assert!(matches!(*left, Expr::And(_, _)));
                assert_eq!(*right, term(Field::Kind, Op::Match, vec![text("dns")]));
            }
            other => panic!("expected or, got {other:?}"),
        }
    }

    #[test]
    fn pos_not_and_bang() {
        assert_eq!(
            parse("not kind:gap").unwrap(),
            Expr::Not(Box::new(term(Field::Kind, Op::Match, vec![text("gap")])))
        );
        assert_eq!(
            parse("!pid=1").unwrap(),
            Expr::Not(Box::new(term(Field::Pid, Op::Eq, vec![Value::Number(1)])))
        );
    }

    #[test]
    fn pos_parens_change_binding() {
        let expr = parse("(kind:net or kind:dns) and port:443").unwrap();
        assert!(matches!(expr, Expr::And(ref l, _) if matches!(**l, Expr::Or(_, _))));
    }

    #[test]
    fn pos_time_relative_and_compare() {
        assert_eq!(
            parse("time>+5m").unwrap(),
            term(
                Field::Time,
                Op::Gt,
                vec![Value::RelativeTime {
                    from_session_start: true,
                    nanos: 5 * 60 * 1_000_000_000,
                }]
            )
        );
        assert_eq!(
            parse("time>=1000").unwrap(),
            term(Field::Time, Op::Ge, vec![Value::Number(1000)])
        );
    }

    #[test]
    fn pos_contains_and_ne() {
        assert_eq!(
            parse("domain~example").unwrap(),
            term(Field::Domain, Op::Contains, vec![text("example")])
        );
        assert_eq!(
            parse("pid!=7").unwrap(),
            term(Field::Pid, Op::Ne, vec![Value::Number(7)])
        );
    }

    #[test]
    fn pos_qname_alias_and_in_list() {
        assert_eq!(
            parse("qname:*.example.com").unwrap(),
            term(Field::Domain, Op::Match, vec![text("*.example.com")])
        );
        assert_eq!(
            parse("evidence in [E1, E2]").unwrap(),
            term(Field::Evidence, Op::Match, vec![text("E1"), text("E2")])
        );
    }

    #[test]
    fn pos_bool_duration_and_double_or() {
        assert_eq!(
            parse("kind:net || kind:dns").unwrap(),
            Expr::Or(
                Box::new(term(Field::Kind, Op::Match, vec![text("net")])),
                Box::new(term(Field::Kind, Op::Match, vec![text("dns")])),
            )
        );
        assert_eq!(
            parse("time:-10s").unwrap(),
            term(
                Field::Time,
                Op::Match,
                vec![Value::RelativeTime {
                    from_session_start: false,
                    nanos: 10 * 1_000_000_000,
                }]
            )
        );
    }

    #[test]
    fn pos_quoted_escape_and_case() {
        assert_eq!(
            parse(r#"proc:"a\"b""#).unwrap(),
            term(Field::Proc, Op::Match, vec![text("a\"b")])
        );
        assert_eq!(
            parse("KIND:Net").unwrap(),
            term(Field::Kind, Op::Match, vec![text("Net")])
        );
    }

    #[test]
    fn pos_bare_word_is_domain_substring() {
        assert_eq!(
            parse("example.com").unwrap(),
            term(Field::Domain, Op::Contains, vec![text("example.com")])
        );
    }

    // --- negative (21–36) ---

    #[test]
    fn neg_path_unsupported() {
        let err = parse("path:~/.ssh/**").unwrap_err();
        assert!(matches!(err, QueryError::UnsupportedField { field } if field == "path"));
    }

    #[test]
    fn neg_dir_unsupported() {
        let err = parse("dir:/tmp").unwrap_err();
        assert!(matches!(err, QueryError::UnsupportedField { field } if field == "dir"));
    }

    #[test]
    fn neg_unknown_field() {
        let err = parse("exe:curl").unwrap_err();
        assert!(matches!(err, QueryError::UnknownField { field } if field == "exe"));
    }

    #[test]
    fn neg_bytes_up_unknown() {
        let err = parse("bytes_up>1MB").unwrap_err();
        assert!(matches!(err, QueryError::UnknownField { .. }));
    }

    #[test]
    fn neg_unterminated_quote() {
        let err = parse(r#"domain:"oops"#).unwrap_err();
        assert!(
            matches!(err, QueryError::Parse { message, .. } if message.contains("unterminated"))
        );
    }

    #[test]
    fn neg_missing_paren() {
        let err = parse("(kind:net").unwrap_err();
        assert!(
            matches!(err, QueryError::Parse { message, .. } if message.contains("parenthesis"))
        );
    }

    #[test]
    fn neg_trailing() {
        let err = parse("kind:net )").unwrap_err();
        assert!(matches!(err, QueryError::Parse { message, .. } if message == "trailing input"));
    }

    #[test]
    fn neg_empty_list() {
        let err = parse("kind:[]").unwrap_err();
        assert!(matches!(err, QueryError::Parse { message, .. } if message.contains("empty")));
    }

    #[test]
    fn neg_operator_without_value() {
        let err = parse("kind:").unwrap_err();
        assert!(matches!(err, QueryError::Parse { .. }));
    }

    #[test]
    fn neg_dangling_and() {
        let err = parse("kind:net and").unwrap_err();
        assert!(matches!(err, QueryError::Parse { .. }));
    }

    #[test]
    fn neg_double_operator() {
        let err = parse("pid=>1").unwrap_err();
        assert!(matches!(err, QueryError::Parse { .. }));
    }

    #[test]
    fn neg_fraction_without_unit() {
        let err = parse("pid=1.5").unwrap_err();
        assert!(matches!(err, QueryError::Parse { message, .. } if message.contains("fractional")));
    }

    #[test]
    fn neg_not_without_operand() {
        let err = parse("not").unwrap_err();
        assert!(matches!(err, QueryError::Parse { .. }));
    }

    #[test]
    fn neg_comma_inside_field_space() {
        let err = parse("kind:net,").unwrap_err();
        assert!(matches!(err, QueryError::Parse { .. }));
    }

    #[test]
    fn neg_unknown_dotted() {
        let err = parse("local.port:1").unwrap_err();
        assert!(matches!(err, QueryError::UnknownField { field } if field == "local.port"));
    }

    #[test]
    fn neg_path_is_not_silently_dropped_beside_kind() {
        let err = parse("kind:file path:/tmp").unwrap_err();
        assert!(matches!(err, QueryError::UnsupportedField { .. }));
    }
}
