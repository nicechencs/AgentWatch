//! Path globs, the subset api-and-cli §4.3 names.
//!
//! `*` matches inside one path segment. `**` matches across separators, including
//! zero segments. `?` matches one character that is not a separator. Everything
//! else is literal. There is no character class and no brace expansion: those
//! are not in the filter grammar, and a backtracking implementation would be
//! the ReDoS the docs forbid.
//!
//! Matching walks the path once per glob. The globs are compiled to segments up
//! front, so a batch of rules still costs a linear scan of the path rather than
//! a scan of the pattern source on every call.

/// One compiled glob.
#[derive(Debug, Clone)]
pub struct PathGlob {
    /// Original pattern, after `~` expansion. Kept for diagnostics only.
    pub source: String,
    parts: Vec<Part>,
    /// `true` when ASCII case is ignored. Set for Windows rules.
    case_insensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    /// Exact segment text.
    Literal(String),
    /// `*`: one segment, any contents (including empty).
    Star,
    /// `**`: zero or more segments.
    Globstar,
    /// A segment that mixes literals, `*`, and `?`.
    Mixed(Vec<Atom>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Atom {
    Lit(String),
    Star,
    /// `?`.
    One,
}

impl PathGlob {
    /// Compile `pattern`. An empty pattern matches nothing.
    pub fn compile(pattern: &str, case_insensitive: bool) -> Self {
        let source = pattern.to_owned();
        let parts = split_pattern(pattern)
            .into_iter()
            .map(|segment| compile_segment(&segment, case_insensitive))
            .collect();
        Self {
            source,
            parts,
            case_insensitive,
        }
    }

    /// `true` when `path` matches. Separators in `path` may be `/` or `\`.
    pub fn is_match(&self, path: &str) -> bool {
        if self.parts.is_empty() {
            return false;
        }
        let segments = split_path(path, self.case_insensitive);
        match_from(&self.parts, &segments)
    }
}

fn compile_segment(segment: &str, case_insensitive: bool) -> Part {
    if segment == "**" {
        return Part::Globstar;
    }
    if segment == "*" {
        return Part::Star;
    }
    let has_meta = segment.chars().any(|ch| ch == '*' || ch == '?');
    if !has_meta {
        return Part::Literal(fold(segment, case_insensitive));
    }
    Part::Mixed(atoms(segment, case_insensitive))
}

fn atoms(segment: &str, case_insensitive: bool) -> Vec<Atom> {
    let mut out = Vec::new();
    let mut lit = String::new();
    for ch in segment.chars() {
        match ch {
            '*' => {
                push_lit(&mut out, &mut lit);
                if !matches!(out.last(), Some(Atom::Star)) {
                    out.push(Atom::Star);
                }
            }
            '?' => {
                push_lit(&mut out, &mut lit);
                out.push(Atom::One);
            }
            other => lit.push(fold_char(other, case_insensitive)),
        }
    }
    push_lit(&mut out, &mut lit);
    out
}

fn push_lit(out: &mut Vec<Atom>, lit: &mut String) {
    if !lit.is_empty() {
        out.push(Atom::Lit(std::mem::take(lit)));
    }
}

fn split_pattern(pattern: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in pattern.chars() {
        if ch == '/' || ch == '\\' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn split_path(path: &str, case_insensitive: bool) -> Vec<String> {
    split_pattern(path)
        .into_iter()
        .map(|seg| fold(&seg, case_insensitive))
        .collect()
}

fn fold(text: &str, case_insensitive: bool) -> String {
    if case_insensitive {
        text.chars().map(|ch| fold_char(ch, true)).collect()
    } else {
        text.to_owned()
    }
}

fn fold_char(ch: char, case_insensitive: bool) -> char {
    if case_insensitive {
        ch.to_ascii_lowercase()
    } else {
        ch
    }
}

fn match_from(parts: &[Part], segments: &[String]) -> bool {
    let mut p = 0;
    let mut s = 0;
    while p < parts.len() {
        match &parts[p] {
            Part::Globstar => {
                // `**` at the end matches the rest, including nothing.
                if p + 1 == parts.len() {
                    return true;
                }
                // Try the remainder at every segment boundary, including here.
                while s <= segments.len() {
                    if match_from(&parts[p + 1..], &segments[s..]) {
                        return true;
                    }
                    if s == segments.len() {
                        break;
                    }
                    s += 1;
                }
                return false;
            }
            Part::Star => {
                if s >= segments.len() {
                    return false;
                }
                s += 1;
                p += 1;
            }
            Part::Literal(want) => {
                if s >= segments.len() || segments[s] != *want {
                    return false;
                }
                s += 1;
                p += 1;
            }
            Part::Mixed(atoms) => {
                if s >= segments.len() || !segment_match(atoms, &segments[s]) {
                    return false;
                }
                s += 1;
                p += 1;
            }
        }
    }
    s == segments.len()
}

fn segment_match(atoms: &[Atom], segment: &str) -> bool {
    // Atoms are a sequence of literals, `*`, and `?` inside one segment.
    // `*` is the only thing that branches, and it only moves forward.
    match_atoms(atoms, segment)
}

fn match_atoms(atoms: &[Atom], text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    fn rec(atoms: &[Atom], chars: &[char]) -> bool {
        let mut a = 0;
        let mut c = 0;
        while a < atoms.len() {
            match &atoms[a] {
                Atom::Star => {
                    if a + 1 == atoms.len() {
                        return true;
                    }
                    while c <= chars.len() {
                        if rec(&atoms[a + 1..], &chars[c..]) {
                            return true;
                        }
                        if c == chars.len() {
                            break;
                        }
                        c += 1;
                    }
                    return false;
                }
                Atom::One => {
                    if c >= chars.len() {
                        return false;
                    }
                    c += 1;
                    a += 1;
                }
                Atom::Lit(lit) => {
                    let lit_chars: Vec<char> = lit.chars().collect();
                    if chars[c..].len() < lit_chars.len() {
                        return false;
                    }
                    if chars[c..c + lit_chars.len()] != lit_chars[..] {
                        return false;
                    }
                    c += lit_chars.len();
                    a += 1;
                }
            }
        }
        c == chars.len()
    }
    rec(atoms, &chars)
}
