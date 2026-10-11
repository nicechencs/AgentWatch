//! `cmd.exe` command-line construction for batch files.
//!
//! Windows normally passes argv as one command-line string. `cmd.exe` has
//! different parsing rules from the C runtime, so the normal Windows quoting
//! routine is not safe for `.cmd` / `.bat` targets. This is the conservative
//! algorithm used by Rust's standard library after CVE-2024-24576: it quotes
//! command metacharacters, disables delayed expansion, neutralises `%` variable
//! expansion, and rejects line separators which `cmd.exe` can truncate.
//!
//! The guarantee is limited to building this `cmd.exe /c` invocation: a `%NAME%`
//! argument is passed literally rather than expanded from the launch environment.
//! `cmd.exe` has no mode that turns off percent expansion altogether, and this
//! cannot make a batch script safe if that script feeds an argument into a new
//! command line of its own.

/// An argument which cannot safely travel through `cmd.exe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UnsafeBatchArgument {
    /// The original argument, retained only so the CLI can explain its refusal.
    pub(super) argument: String,
}

/// Whether `name` names a batch file according to Windows path parsing.
///
/// Windows strips ASCII spaces and periods from the final path component before
/// choosing a file. Trim them here too, otherwise `script.cmd. ` would bypass
/// the batch-file branch.
pub(super) fn is_batch_file_name(name: &str) -> bool {
    let final_name = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .trim_end_matches([' ', '.']);
    final_name.rsplit_once('.').is_some_and(|(_, extension)| {
        extension.eq_ignore_ascii_case("cmd") || extension.eq_ignore_ascii_case("bat")
    })
}

/// Build the complete `cmd.exe /c` command line for an already-resolved batch
/// script and its argv. The returned buffer is NUL terminated for
/// `CreateProcessW`.
pub(super) fn batch_command_line(
    script: &str,
    args: &[String],
) -> Result<Vec<u16>, UnsafeBatchArgument> {
    // `/e:ON` is required for the no-op `%` expansion below; `/v:OFF` prevents
    // a literal `!` from becoming delayed variable expansion; `/d` skips
    // AutoRun commands. The outer quotes delimit the `/c` command as one unit.
    let mut command: Vec<u16> = "cmd.exe /e:ON /v:OFF /d /c \"".encode_utf16().collect();
    command.push(u16::from(b'\"'));
    command.extend(script.encode_utf16());
    command.push(u16::from(b'\"'));

    for argument in args {
        if argument.contains(['\r', '\n']) {
            return Err(UnsafeBatchArgument {
                argument: argument.clone(),
            });
        }
        command.push(u16::from(b' '));
        append_batch_argument(&mut command, argument);
    }
    command.push(u16::from(b'\"'));
    command.push(0);
    Ok(command)
}

fn append_batch_argument(command: &mut Vec<u16>, argument: &str) {
    // Quote anything except the deliberately small safe ASCII set. `\\` is
    // included: it needs no escaping unless this argument is quoted.
    const UNQUOTED: &str = r#"#$*+-./:?@\_"#;
    let quote = argument.is_empty()
        || argument.ends_with('\\')
        || argument.chars().any(|character| {
            (character.is_ascii()
                && !(character.is_ascii_alphanumeric() || UNQUOTED.contains(character)))
                || character.is_control()
        });
    if quote {
        command.push(u16::from(b'\"'));
    }

    let mut backslashes = 0_usize;
    for unit in argument.encode_utf16() {
        if unit == u16::from(b'\\') {
            backslashes += 1;
        } else {
            if unit == u16::from(b'\"') {
                // The earlier copies (written when the backslashes were read)
                // plus these make 2n before the doubled quote.
                command.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
                command.push(u16::from(b'\"'));
            } else if unit == u16::from(b'%') || unit == u16::from(b'\r') {
                // `%cd:~,%` is always an empty substring of cmd's built-in
                // current-directory variable. Prefixing each `%` with it
                // preserves the literal percent while preventing `%NAME%`
                // expansion during this command's construction.
                command.extend("%%cd:~,".encode_utf16());
            }
            backslashes = 0;
        }
        command.push(unit);
    }
    if quote {
        command.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
        command.push(u16::from(b'\"'));
    } else {
        command.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
    }
}

#[cfg(test)]
mod tests {
    use super::{batch_command_line, is_batch_file_name};

    fn line(script: &str, args: &[&str]) -> String {
        let args: Vec<String> = args.iter().map(|argument| (*argument).to_owned()).collect();
        let units = match batch_command_line(script, &args) {
            Ok(units) => units,
            Err(error) => panic!("safe batch argv rejected: {error:?}"),
        };
        match String::from_utf16(&units[..units.len() - 1]) {
            Ok(command) => command,
            Err(error) => panic!("batch command was not UTF-16: {error}"),
        }
    }

    #[test]
    fn recognises_batch_names_after_windows_path_normalisation() {
        assert!(is_batch_file_name("tool.cmd"));
        assert!(is_batch_file_name(r"C:\\tools\\TOOL.BAT. "));
        assert!(!is_batch_file_name("tool.exe"));
        assert!(!is_batch_file_name("tool.cmd\\other.exe"));
    }

    #[test]
    fn command_metacharacters_and_edge_arguments_stay_quoted() {
        let command = line(
            r"C:\\safe\\echoargs.cmd",
            &[
                "a&calc",
                "a|whoami",
                "%PATH%",
                "^",
                "say \"hi\"",
                "<input",
                ">output",
                "!bang!",
                "(group)",
                "trailing\\",
                "",
            ],
        );
        assert!(command.starts_with("cmd.exe /e:ON /v:OFF /d /c \""));
        for fragment in [
            "\"a&calc\"",
            "\"a|whoami\"",
            "\"%%cd:~,%PATH%%cd:~,%\"",
            "\"^\"",
            "\"say \"\"hi\"\"\"",
            "\"<input\"",
            "\">output\"",
            "\"!bang!\"",
            "\"(group)\"",
            r#""trailing\\""#,
        ] {
            assert!(
                command.contains(fragment),
                "missing {fragment:?} from {command}"
            );
        }
        // Two quotes represent the empty argument; the last quote closes `/c`.
        assert!(command.ends_with(" \"\"\""), "{command}");
    }

    #[test]
    fn line_breaks_are_refused() {
        for argument in ["one\ntwo", "one\rtwo"] {
            let error = match batch_command_line("script.cmd", &[argument.to_owned()]) {
                Err(error) => error,
                Ok(_) => panic!("line separators must not be safe for cmd.exe"),
            };
            assert_eq!(error.argument, argument);
        }
    }
}
