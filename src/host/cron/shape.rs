//! The exact shapes of owned crontab lines, so a journal can only reinstall
//! a line some Onebox version writes — never an arbitrary job that merely
//! ends with a marker (E-8.1#17).
//!
//! A line is parsed into its parts (schedule, `env` assignments of
//! allowlisted variables, the managed executable, the job's arguments, the
//! redirection), the parts are checked (known subcommand for the tag,
//! absolute log), and the line is accepted only when rendering those parts
//! the way that version did gives back exactly the same text.
//!
//! | form | shape |
//! |---|---|
//! | v3 | `{s} PATH={SAFE_PATH} env {K='v'…} '{exe}' {job} >>'{log}' 2>&1 # onebox:{tag}` (`%` escaped) |
//! | v2 autostart | `{s} env {K='v'…} '{exe}' service {name} start >/dev/null 2>&1 # onebox-rust:{name}` |
//! | v2 certificates | `{s} {exe} cert renew proxy\|site --cron >/dev/null 2>&1 # onebox-native-cert-{t}` (`subscription renew --cron` for `subscription`) |
//! | v2 FRP | `{s} env {K='v'…} '{exe}' frps renew --cron\|frps start >>'{log}' 2>&1 # onebox-frps-renew\|boot` (`%` escaped) |
//! | v1 boot | matched exactly by the classification |
//!
//! Retired renewal jobs (acme.sh's own cron line, v1 `cert-renew`) have no
//! exact shape: they are removed but never reinstalled.

use super::line::{assemble, command, env_words, split_schedule};
use super::{Form, Ownership, Tag, MARKER};
use crate::host::service::{env_key_allowed, validate_env, validate_name};
use crate::sys::exec::SAFE_PATH;
use crate::sys::text::quote_shell;
use std::path::Path;

/// The parts of a job command.
struct Job {
    env: Vec<(String, String)>,
    exe: String,
    args: Vec<String>,
    /// `>/dev/null` or `>>{path}` (decoded).
    redirect: String,
}

impl Ownership {
    /// Whether `line`, classified as `tag` in `form`, has a shape Onebox
    /// writes (trailing blanks and CR, which classification ignores too,
    /// are ignored).
    pub(super) fn restorable(&self, line: &str, tag: &Tag, form: Form) -> bool {
        let line = line.trim_end_matches([' ', '\t', '\r']);
        match form {
            Form::V3 => self.v3_shape(line, tag),
            Form::V2Boot => self.v2_boot_shape(line, tag),
            Form::V2Cert(target) => self.v2_cert_shape(line, target),
            Form::V2Frp => self.v2_frp_shape(line, tag),
            Form::V1Boot => true,
            Form::Retired => false,
        }
    }

    fn v3_shape(&self, line: &str, tag: &Tag) -> bool {
        let Some(body) = line.strip_suffix(&format!("{MARKER}{tag}")) else {
            return false;
        };
        let Some((schedule, text)) = split_schedule(body) else {
            return false;
        };
        let Some(job) = parse_job(&unescape(text), true) else {
            return false;
        };
        let Some(log) = job.redirect.strip_prefix(">>") else {
            return false;
        };
        job.exe == self.exe
            && job_args(tag).is_some_and(|args| job.args == args)
            && Path::new(log).is_absolute()
            && assemble(schedule, &command(&job.env, &job.exe, &job.args, log), tag) == line
    }

    fn v2_boot_shape(&self, line: &str, tag: &Tag) -> bool {
        let Some(service) = tag.as_str().strip_prefix("boot:") else {
            return false;
        };
        let marker = format!(" # onebox-rust:{service}");
        let Some((schedule, text)) = line.strip_suffix(&marker).and_then(split_schedule) else {
            return false;
        };
        let Some(job) = parse_job(text, false) else {
            return false;
        };
        let rendered = format!(
            "{schedule} env {} {} service {service} start >/dev/null 2>&1{marker}",
            env_words(&job.env),
            quote_shell(&self.exe)
        );
        job.exe == self.exe && !job.env.is_empty() && rendered == line
    }

    fn v2_cert_shape(&self, line: &str, target: &str) -> bool {
        let marker = format!(" # onebox-native-cert-{target}");
        let Some((schedule, _)) = line.strip_suffix(&marker).and_then(split_schedule) else {
            return false;
        };
        // v2 refused to write a line for any other executable path.
        let bare = self
            .exe
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b));
        let job = match target {
            "subscription" => "subscription renew --cron".to_owned(),
            other => format!("cert renew {other} --cron"),
        };
        let rendered = format!("{schedule} {} {job} >/dev/null 2>&1{marker}", self.exe);
        bare && rendered == line
    }

    fn v2_frp_shape(&self, line: &str, tag: &Tag) -> bool {
        let (marker, job_words) = match tag.as_str() {
            "frp-renew" => (" # onebox-frps-renew", "frps renew --cron"),
            "frp-boot" => (" # onebox-frps-boot", "frps start"),
            _ => return false,
        };
        let Some((schedule, text)) = line.strip_suffix(marker).and_then(split_schedule) else {
            return false;
        };
        let Some(job) = parse_job(&unescape(text), false) else {
            return false;
        };
        let Some(log) = job.redirect.strip_prefix(">>") else {
            return false;
        };
        let rendered = format!(
            "{schedule} env {} {} {job_words} >>{} 2>&1{marker}",
            env_words(&job.env),
            quote_shell(&self.exe),
            quote_shell(log)
        )
        .replace('%', "\\%");
        job.exe == self.exe
            && !job.env.is_empty()
            && job.args.join(" ") == job_words
            && Path::new(log).is_absolute()
            && rendered == line
    }
}

/// The job arguments of a v3 tag; tags without a v3 job have none.
fn job_args(tag: &Tag) -> Option<Vec<String>> {
    let words: Vec<&str> = match tag.as_str() {
        "renew" => vec!["renew", "--cron"],
        "frp-renew" => vec!["frps", "renew", "--cron"],
        "frp-boot" => vec!["frps", "start"],
        other => {
            let service = other.strip_prefix("boot:")?;
            validate_name(service).ok()?;
            vec!["service", service, "start"]
        }
    };
    Some(words.into_iter().map(str::to_owned).collect())
}

/// `[PATH=SAFE_PATH] env {K=v…} {exe} {args…} {redirect} 2>&1` from decoded
/// words; the assignments must be allowlisted and unique.
fn parse_job(text: &str, path_prefix: bool) -> Option<Job> {
    let words = shell_words(text)?;
    let mut rest = words.as_slice();
    if path_prefix {
        let (first, tail) = rest.split_first()?;
        if *first != format!("PATH={SAFE_PATH}") {
            return None;
        }
        rest = tail;
    }
    let (first, tail) = rest.split_first()?;
    if first != "env" {
        return None;
    }
    rest = tail;
    let mut env = Vec::new();
    while let Some((key, value)) = rest.first().and_then(|w| w.split_once('=')) {
        if !env_key_allowed(key) {
            break;
        }
        env.push((key.to_owned(), value.to_owned()));
        rest = &rest[1..];
    }
    validate_env(&env).ok()?;
    let (exe, rest) = rest.split_first()?;
    let (last, rest) = rest.split_last()?;
    let (redirect, args) = rest.split_last()?;
    (last == "2>&1").then(|| Job {
        env,
        exe: exe.clone(),
        args: args.to_vec(),
        redirect: redirect.clone(),
    })
}

/// Undo cron's `\%` escaping. A bare `%` (cron would end the command
/// there) makes the line unparsable.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'%') => {
                out.push('%');
                chars.next();
            }
            // Not producible by the renderers: forces a mismatch.
            '%' => out.push('\0'),
            c => out.push(c),
        }
    }
    out
}

/// Split shell words separated by single spaces, decoding single quotes
/// and backslash escapes. Lenient on purpose: the caller compares the
/// re-rendered line with the original, which rejects anything a renderer
/// would not produce.
fn shell_words(text: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' if !started => return None,
            ' ' => {
                words.push(std::mem::take(&mut word));
                started = false;
            }
            '\'' => {
                started = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        quoted => word.push(quoted),
                    }
                }
            }
            '\\' => {
                started = true;
                word.push(chars.next()?);
            }
            c if c.is_control() => return None,
            c => {
                started = true;
                word.push(c);
            }
        }
    }
    if !started {
        return None;
    }
    words.push(word);
    Some(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_words_decode_the_renderers_quoting() {
        let words = shell_words(r"env A='x y' 'it'\''s' plain >>'/l' 2>&1").unwrap();
        assert_eq!(words, ["env", "A=x y", "it's", "plain", ">>/l", "2>&1"]);
        for bad in ["", " a", "a  b", "a ", "'open", "a\\", "a\tb"] {
            assert!(shell_words(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn unescape_rejects_bare_percent() {
        assert_eq!(unescape(r"a\%b"), "a%b");
        assert!(unescape("a%b").contains('\0'));
    }
}
