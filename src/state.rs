use crate::{
    context::Context,
    model::{Protocol, State},
    util, Result,
};
use std::{collections::BTreeMap, fs, path::Path};

const KEYS:&str="PROTOCOLS SERVER_ADDR SERVER_IPV4 SERVER_IPV6 SERVER_IPV4_WARP SERVER_IPV6_WARP NODE_NAME LISTEN_ADDR UUID PASSWORD SS_METHOD SS_PASSWORD REALITY_PRIVATE_KEY REALITY_PUBLIC_KEY REALITY_SHORT_ID REALITY_SNI REALITY_DEST REALITY_SITE_ENABLED REALITY_SITE_DOMAIN REALITY_SITE_PORT REALITY_SITE_TITLE REALITY_SITE_HTTPS WS_PATH VMESS_PATH XHTTP_PATH GRPC_SERVICE HY2_OBFS HY2_OBFS_PASSWORD HY2_HOP HY2_PROFILE HY2_UP_MBPS HY2_DOWN_MBPS RESOURCE_PROFILE SHADOWTLS_SNI SHADOWTLS_DEST SHADOWTLS_PASSWORD SHADOWTLS_SS_PASSWORD TLS_MODE DOMAIN TLS_SNI CERT_FILE KEY_FILE ACME_METHOD SB_VERSION XR_VERSION BLOCK_PRIVATE BLOCK_BT REALITY_GUARD_PORT VMESS_TLS CLASH_SECRET CERT_PINNED OWN_IP_CIDRS INSTALLED_AT";
fn allowed_key(key: &str) -> bool {
    KEYS.split_whitespace().any(|k| k == key)
        || ["PORT_", "CORE_"].iter().any(|prefix| {
            key.strip_prefix(prefix)
                .and_then(|p| p.replace('_', "-").parse::<Protocol>().ok())
                .is_some()
        })
}

/// Decode only shell literals produced by printf %q. Never invoke a shell.
pub fn shell_literal(input: &str) -> Result<String> {
    fn push(out: &mut Vec<u8>, c: char) {
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                i += 1;
                push(&mut out, *chars.get(i).ok_or("悬空转义")?);
                i += 1;
            }
            '\'' => {
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    push(&mut out, chars[i]);
                    i += 1;
                }
                if i == chars.len() {
                    return Err("单引号未关闭".into());
                }
                i += 1;
            }
            '"' => {
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    match chars[i] {
                        '$' | '`' => return Err("状态不能包含展开或命令替换".into()),
                        '\\' => {
                            i += 1;
                            let c = *chars.get(i).ok_or("悬空转义")?;
                            if !['$', '`', '"', '\\'].contains(&c) {
                                out.push(b'\\')
                            }
                            push(&mut out, c);
                            i += 1;
                        }
                        c => {
                            push(&mut out, c);
                            i += 1;
                        }
                    }
                }
                if i == chars.len() {
                    return Err("双引号未关闭".into());
                }
                i += 1;
            }
            '$' if chars.get(i + 1) == Some(&'\'') => {
                i += 2;
                while i < chars.len() && chars[i] != '\'' {
                    if chars[i] != '\\' {
                        push(&mut out, chars[i]);
                        i += 1;
                        continue;
                    }
                    i += 1;
                    let c = *chars.get(i).ok_or("悬空ANSI转义")?;
                    i += 1;
                    match c {
                        'n' => out.push(b'\n'),
                        'r' => out.push(b'\r'),
                        't' => out.push(b'\t'),
                        'a' => out.push(7),
                        'b' => out.push(8),
                        'e' | 'E' => out.push(27),
                        'f' => out.push(12),
                        'v' => out.push(11),
                        '\\' | '\'' | '"' => push(&mut out, c),
                        'x' | 'u' | 'U' => {
                            let max = match c {
                                'x' => 2,
                                'u' => 4,
                                _ => 8,
                            };
                            let start = i;
                            while i < chars.len() && i - start < max && chars[i].is_ascii_hexdigit()
                            {
                                i += 1
                            }
                            if start == i {
                                return Err("ANSI数值转义无效".into());
                            }
                            let n = u32::from_str_radix(
                                &chars[start..i].iter().collect::<String>(),
                                16,
                            )?;
                            if c == 'x' {
                                out.push(n as u8)
                            } else {
                                push(&mut out, char::from_u32(n).ok_or("Unicode转义无效")?);
                            }
                        }
                        '0'..='7' => {
                            let start = i - 1;
                            while i < chars.len() && i - start < 3 && matches!(chars[i], '0'..='7')
                            {
                                i += 1
                            }
                            let n = u32::from_str_radix(
                                &chars[start..i].iter().collect::<String>(),
                                8,
                            )?;
                            out.push((n & 255) as u8);
                        }
                        _ => return Err("不支持的ANSI转义".into()),
                    }
                }
                if i == chars.len() {
                    return Err("ANSI单引号未关闭".into());
                }
                i += 1;
            }
            c if c.is_whitespace() || "$`;|&<>(){}".contains(c) => {
                return Err("状态只能包含字面量赋值，不能包含命令".into())
            }
            c => {
                push(&mut out, c);
                i += 1;
            }
        }
    }
    if out.contains(&0) {
        return Err("状态不能包含NUL".into());
    }
    Ok(String::from_utf8(out)?)
}
pub fn parse_legacy(text: &str) -> Result<State> {
    let mut state = State::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or("旧状态不是赋值语句")?;
        if !allowed_key(key) || state.values.contains_key(key) {
            return Err(format!("未知或重复状态字段: {key}").into());
        }
        state.set(key, shell_literal(value)?);
    }
    upgrade(&mut state);
    state.validate()?;
    Ok(state)
}
pub fn parse_nul(bytes: &[u8]) -> Result<State> {
    let mut chunks = bytes.split(|v| *v == 0).collect::<Vec<_>>();
    if chunks.last() == Some(&&b""[..]) {
        chunks.pop();
    }
    if chunks.len() % 2 != 0 {
        return Err("快照键值不完整".into());
    }
    let mut state = State::default();
    for pair in chunks.chunks(2) {
        let key = std::str::from_utf8(pair[0])?;
        if !allowed_key(key) || state.values.contains_key(key) {
            return Err("快照字段未知或重复".into());
        }
        state.set(key, std::str::from_utf8(pair[1])?);
    }
    upgrade(&mut state);
    state.validate()?;
    Ok(state)
}
fn upgrade(state: &mut State) {
    if state.enabled(Protocol::VmessWs) && state.get("VMESS_TLS").is_empty() {
        state.set("VMESS_TLS", if state.vmess_tls() { "1" } else { "0" });
    }
}
fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    util::safe_path(path)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err("状态文件类型或大小无效".into());
    }
    Ok(fs::read(path)?)
}
pub fn expected_hash(ctx: &Context) -> Result<String> {
    let path = if ctx.paths.state().is_file() {
        ctx.paths.state()
    } else if ctx.paths.legacy_state().is_file() {
        ctx.paths.legacy_state()
    } else {
        return Ok("absent".into());
    };
    Ok(util::sha256(&read_bounded(&path)?))
}
pub fn attach_expected(ctx: &Context, state: &mut State) -> Result<()> {
    state.set("__EXPECTED_STATE_HASH", expected_hash(ctx)?);
    Ok(())
}
pub fn load(ctx: &Context) -> Result<State> {
    let path = if ctx.paths.state().is_file() {
        ctx.paths.state()
    } else {
        ctx.paths.legacy_state()
    };
    let bytes = read_bounded(&path)?;
    let mut state = if path == ctx.paths.state() {
        let mut s: State = serde_json::from_slice(&bytes)?;
        upgrade(&mut s);
        s.validate()?;
        s
    } else {
        parse_legacy(std::str::from_utf8(&bytes)?)?
    };
    state.set("__EXPECTED_STATE_HASH", util::sha256(&bytes));
    Ok(state)
}
pub fn installed(ctx: &Context) -> bool {
    ctx.paths.state().is_file() || ctx.paths.legacy_state().is_file()
}
pub fn save(ctx: &Context, state: &State) -> Result<()> {
    state.validate()?;
    util::safe_path(&ctx.paths.root)?;
    fs::create_dir_all(&ctx.paths.root)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&ctx.paths.root, fs::Permissions::from_mode(0o700))?;
    let old = ctx.paths.legacy_state();
    let backup = ctx.paths.root.join("onebox.conf.pre-rust");
    if old.exists() && !backup.exists() {
        util::atomic_write(&backup, &read_bounded(&old)?, 0o600)?;
    }
    let mut clean = state.clone();
    clean.values.retain(|key, _| !key.starts_with("__"));
    util::atomic_write(
        &ctx.paths.state(),
        &serde_json::to_vec_pretty(&clean)?,
        0o600,
    )
}
pub fn read_string_map(path: &Path) -> Result<BTreeMap<String, String>> {
    Ok(serde_json::from_slice(&read_bounded(path)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decodes_printf_literals() {
        for (input, expected) in [
            (r"a\ b", "a b"),
            (r"a\$\(b\)", "a$(b)"),
            ("''", ""),
            ("$'line\\n中文\\t'", "line\n中文\t"),
            ("\"hello\"", "hello"),
        ] {
            assert_eq!(shell_literal(input).unwrap(), expected)
        }
    }
    #[test]
    fn decodes_byte_escaped_utf8() {
        assert_eq!(
            shell_literal(r"$'\344\270\255\346\226\207'").unwrap(),
            "中文"
        );
        assert_eq!(shell_literal(r"$'\xe4\xb8\xad'").unwrap(), "中");
    }
    #[test]
    fn rejects_execution() {
        for bad in [
            "$(touch /tmp/pwn)",
            "`id`",
            "ok;true",
            "hello world",
            "\"$HOME\"",
            "a|b",
            "$'unterminated",
        ] {
            assert!(shell_literal(bad).is_err(), "{bad}")
        }
    }
    #[test]
    fn legacy_preserves_reality() {
        let text="PROTOCOLS=anytls-reality\nPORT_anytls_reality=443\nCORE_anytls_reality=singbox\nPASSWORD=hello\\ world\nREALITY_PRIVATE_KEY=keep\n";
        let s = parse_legacy(text).unwrap();
        assert_eq!(s.get("PASSWORD"), "hello world");
        assert_eq!(s.get("REALITY_PRIVATE_KEY"), "keep");
        assert!(parse_legacy(&(text.to_owned() + "PASSWORD=duplicate")).is_err());
    }
}
