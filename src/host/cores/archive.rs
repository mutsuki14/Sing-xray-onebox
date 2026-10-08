//! Extract one named executable from a release package (`.tar.gz` for
//! sing-box, `.zip` for Xray) without unpacking anything else.
//!
//! Both readers stream the member into `out` with a byte cap and refuse
//! packages containing absolute or `..` paths or links (v2 rejected those
//! for tar; the same rule now covers zip). The zip reader is a minimal
//! central-directory reader for stored and deflated members (flate2), with
//! CRC-32 verification; it replaces v2's dependency on the `unzip` package.

use crate::error::{Error, Result};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path};

const UNSAFE: &str = "内核压缩包含不安全路径";
const MISSING: &str = "压缩包未包含内核";
const DUPLICATE: &str = "压缩包含多个内核文件";
const CORRUPT: &str = "内核压缩包已损坏";

fn corrupt(detail: &str) -> Error {
    Error::msg(format!("{CORRUPT}（{detail}）"))
}

/// Only plain relative paths are acceptable inside a package.
fn safe_member(path: &Path) -> bool {
    path.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

fn is_named(path: &Path, binary: &str) -> bool {
    path.file_name().is_some_and(|n| n == binary)
}

/// A new private output file (refuses an existing path or symlink).
fn create_output(out: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(out)
        .map_err(|e| Error::io(out, e))
}

/// Copy at most `max` bytes from `reader` into `out`; more is an error.
fn copy_capped(reader: impl Read, out: &Path, max: u64) -> Result<u64> {
    let mut file = create_output(out)?;
    let copied = io::copy(&mut reader.take(max + 1), &mut file).map_err(|e| Error::io(out, e))?;
    if copied > max {
        return Err(Error::msg(format!("内核文件超过 {} MiB", max >> 20)));
    }
    file.sync_all().map_err(|e| Error::io(out, e))?;
    Ok(copied)
}

/// Extract the regular file named `binary` (at any depth) from a gzip tar.
pub fn extract_tar_gz(package: &Path, binary: &str, out: &Path, max: u64) -> Result<u64> {
    let file = File::open(package).map_err(|e| Error::io(package, e))?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(BufReader::new(file)));
    let entries = archive.entries().map_err(|e| tar_error(&e))?;
    let mut written = None;
    for entry in entries {
        let entry = entry.map_err(|e| tar_error(&e))?;
        let path = entry.path().map_err(|e| tar_error(&e))?.into_owned();
        let kind = entry.header().entry_type();
        if !safe_member(&path) || kind.is_symlink() || kind.is_hard_link() {
            return Err(Error::msg(UNSAFE));
        }
        if !(kind.is_file() && is_named(&path, binary)) {
            continue;
        }
        if written.is_some() {
            return Err(Error::msg(DUPLICATE));
        }
        written = Some(copy_capped(entry, out, max)?);
    }
    written.ok_or_else(|| Error::msg(MISSING))
}

fn tar_error(e: &io::Error) -> Error {
    corrupt(&e.to_string())
}

// ---- zip ------------------------------------------------------------------

const EOCD_SIG: u32 = 0x0605_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;
const EOCD_LEN: usize = 22;
/// The EOCD record may be followed by a comment of up to 65535 bytes.
const EOCD_SEARCH: u64 = EOCD_LEN as u64 + 0xffff;
const CENTRAL_MAX: u64 = 16 * 1024 * 1024;
const UNIX_HOST: u16 = 3;
const S_IFMT: u32 = 0o170_000;
const S_IFLNK: u32 = 0o120_000;

fn le16(b: &[u8], at: usize) -> Result<u16> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| corrupt("记录截断"))
}

fn le32(b: &[u8], at: usize) -> Result<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| corrupt("记录截断"))
}

/// The parts of a central-directory entry we need.
#[derive(Debug)]
struct ZipMember {
    name: String,
    flags: u16,
    method: u16,
    crc: u32,
    compressed: u64,
    size: u64,
    local_offset: u64,
    symlink: bool,
}

fn read_at(file: &mut File, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut buf))
        .map_err(|_| corrupt("读取越界"))?;
    Ok(buf)
}

/// `(central directory offset, size, entry count)` from the EOCD record.
fn find_central(file: &mut File, len: u64) -> Result<(u64, u64, u16)> {
    let tail_len = len.min(EOCD_SEARCH);
    let tail = read_at(file, len - tail_len, tail_len as usize)?;
    let at = (0..=tail.len().saturating_sub(EOCD_LEN))
        .rev()
        .find(|&i| le32(&tail, i).is_ok_and(|sig| sig == EOCD_SIG))
        .ok_or_else(|| corrupt("缺少目录记录"))?;
    let (disk, cd_disk) = (le16(&tail, at + 4)?, le16(&tail, at + 6)?);
    let count = le16(&tail, at + 10)?;
    let size = le32(&tail, at + 12)?;
    let offset = le32(&tail, at + 16)?;
    if count == 0xffff || size == u32::MAX || offset == u32::MAX {
        return Err(Error::msg("不支持 ZIP64 压缩包"));
    }
    if disk != 0 || cd_disk != 0 {
        return Err(Error::msg("不支持分卷压缩包"));
    }
    let (offset, size) = (u64::from(offset), u64::from(size));
    if size > CENTRAL_MAX || offset + size > len {
        return Err(corrupt("目录记录越界"));
    }
    Ok((offset, size, count))
}

fn parse_central(cd: &[u8], count: u16) -> Result<Vec<ZipMember>> {
    let mut members = Vec::with_capacity(usize::from(count));
    let mut at = 0;
    for _ in 0..count {
        if le32(cd, at)? != CENTRAL_SIG {
            return Err(corrupt("目录项签名无效"));
        }
        let name_len = usize::from(le16(cd, at + 28)?);
        let extra_len = usize::from(le16(cd, at + 30)?);
        let comment_len = usize::from(le16(cd, at + 32)?);
        let name = cd
            .get(at + 46..at + 46 + name_len)
            .ok_or_else(|| corrupt("文件名截断"))?;
        let host = le16(cd, at + 4)? >> 8;
        let mode = le32(cd, at + 38)? >> 16;
        members.push(ZipMember {
            name: String::from_utf8_lossy(name).into_owned(),
            flags: le16(cd, at + 8)?,
            method: le16(cd, at + 10)?,
            crc: le32(cd, at + 16)?,
            compressed: u64::from(le32(cd, at + 20)?),
            size: u64::from(le32(cd, at + 24)?),
            local_offset: u64::from(le32(cd, at + 42)?),
            symlink: host == UNIX_HOST && mode & S_IFMT == S_IFLNK,
        });
        at += 46 + name_len + extra_len + comment_len;
    }
    Ok(members)
}

/// Pick the single regular member named `binary`, refusing unsafe entries.
fn select_member(members: Vec<ZipMember>, binary: &str) -> Result<ZipMember> {
    let mut found = None;
    for member in members {
        let path = Path::new(&member.name);
        let unsafe_name = member.name.contains('\\') || !safe_member(path);
        if unsafe_name || member.symlink {
            return Err(Error::msg(UNSAFE));
        }
        if member.name.ends_with('/') || !is_named(path, binary) {
            continue;
        }
        if found.is_some() {
            return Err(Error::msg(DUPLICATE));
        }
        found = Some(member);
    }
    found.ok_or_else(|| Error::msg(MISSING))
}

/// Offset of the member's data (after its local header).
fn data_offset(file: &mut File, member: &ZipMember) -> Result<u64> {
    let header = read_at(file, member.local_offset, 30)?;
    if le32(&header, 0)? != LOCAL_SIG {
        return Err(corrupt("文件头签名无效"));
    }
    let name_len = u64::from(le16(&header, 26)?);
    let extra_len = u64::from(le16(&header, 28)?);
    Ok(member.local_offset + 30 + name_len + extra_len)
}

/// A reader that computes the CRC-32 of what passes through.
struct CrcReader<R> {
    inner: R,
    crc: flate2::Crc,
}

impl<R: Read> Read for CrcReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.crc.update(&buf[..n]);
        Ok(n)
    }
}

/// Extract the member named `binary` (at any depth) from a zip archive.
pub fn extract_zip(package: &Path, binary: &str, out: &Path, max: u64) -> Result<u64> {
    let mut file = File::open(package).map_err(|e| Error::io(package, e))?;
    let len = file.metadata().map_err(|e| Error::io(package, e))?.len();
    let (offset, size, count) = find_central(&mut file, len)?;
    let central = read_at(&mut file, offset, size as usize)?;
    let member = select_member(parse_central(&central, count)?, binary)?;
    if member.flags & 1 != 0 {
        return Err(Error::msg("不支持加密压缩包"));
    }
    if member.size > max {
        return Err(Error::msg(format!("内核文件超过 {} MiB", max >> 20)));
    }
    let start = data_offset(&mut file, &member)?;
    if start + member.compressed > len {
        return Err(corrupt("数据越界"));
    }
    file.seek(SeekFrom::Start(start))
        .map_err(|e| Error::io(package, e))?;
    let raw = BufReader::new(file).take(member.compressed);
    let written = match member.method {
        0 => write_checked(raw, out, &member, max)?,
        8 => write_checked(flate2::read::DeflateDecoder::new(raw), out, &member, max)?,
        m => return Err(Error::msg(format!("不支持的压缩方式 {m}"))),
    };
    Ok(written)
}

fn write_checked(reader: impl Read, out: &Path, member: &ZipMember, max: u64) -> Result<u64> {
    let mut crc_reader = CrcReader {
        inner: reader,
        crc: flate2::Crc::new(),
    };
    let written = copy_capped(&mut crc_reader, out, max)?;
    if written != member.size || crc_reader.crc.sum() != member.crc {
        let _ = std::fs::remove_file(out);
        return Err(corrupt("CRC 校验失败"));
    }
    Ok(written)
}

/// Test helper: write a zip archive with the given members
/// (`(name, bytes, deflate, unix_mode)`). Kept here so the format logic
/// and its test writer live side by side.
#[cfg(test)]
pub(crate) fn write_zip(path: &Path, members: &[(&str, &[u8], bool, u32)]) {
    use std::io::Write;
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data, deflate, mode) in members {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let body = if *deflate {
            let mut enc =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(data).unwrap();
            enc.finish().unwrap()
        } else {
            data.to_vec()
        };
        let method: u16 = if *deflate { 8 } else { 0 };
        let offset = out.len() as u32;
        let common = |v: &mut Vec<u8>| {
            v.extend_from_slice(&20u16.to_le_bytes()); // version needed
            v.extend_from_slice(&0u16.to_le_bytes()); // flags
            v.extend_from_slice(&method.to_le_bytes());
            v.extend_from_slice(&[0, 0, 0x21, 0]); // time, date
            v.extend_from_slice(&crc.sum().to_le_bytes());
            v.extend_from_slice(&(body.len() as u32).to_le_bytes());
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(&(name.len() as u16).to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes()); // extra
        };
        out.extend_from_slice(&LOCAL_SIG.to_le_bytes());
        common(&mut out);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&body);
        central.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
        central.extend_from_slice(&((UNIX_HOST << 8) | 20).to_le_bytes());
        common(&mut central);
        central.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // comment, disk, internal
        central.extend_from_slice(&(mode << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    let count = members.len() as u16;
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    std::fs::write(path, out).unwrap();
}

/// Test helper: write a gzip tar with `(raw name, bytes, entry type)`
/// members. Names are copied verbatim into the header (no validation), so
/// tests can build hostile archives; links point at `target`.
#[cfg(test)]
pub(crate) fn write_tar_gz(path: &Path, members: &[(&str, &[u8], tar::EntryType)]) {
    let gz =
        flate2::write::GzEncoder::new(File::create(path).unwrap(), flate2::Compression::fast());
    let mut builder = tar::Builder::new(gz);
    for (name, data, kind) in members {
        let mut header = tar::Header::new_old();
        let raw = &mut header.as_old_mut().name;
        raw[..name.len()].copy_from_slice(name.as_bytes());
        header.set_entry_type(*kind);
        header.set_size(data.len() as u64);
        header.set_mode(0o755);
        if kind.is_symlink() || kind.is_hard_link() {
            header.set_link_name("target").unwrap();
        }
        header.set_cksum();
        builder.append(&header, *data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap();
}

#[cfg(test)]
mod tests;
