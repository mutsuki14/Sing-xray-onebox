use crate::Result;
use sha2::{Digest,Sha256};
use std::{fs::{self,File,OpenOptions},io::{Read,Write},os::unix::fs::{OpenOptionsExt,PermissionsExt},path::{Path,PathBuf}};

pub fn random_hex(bytes:usize)->Result<String>{let mut data=vec![0;bytes];File::open("/dev/urandom")?.read_exact(&mut data)?;Ok(data.iter().map(|b|format!("{b:02x}")).collect())}
pub fn sha256(data:&[u8])->String{format!("{:x}",Sha256::digest(data))}
pub fn atomic_write(path:&Path,data:&[u8],mode:u32)->Result<()> {
    let parent=path.parent().ok_or("路径没有父目录")?;fs::create_dir_all(parent)?;
    let tmp=parent.join(format!(".onebox-{}",random_hex(12)?));
    let result=(||->Result<()>{let mut f=OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;f.write_all(data)?;f.sync_all()?;fs::set_permissions(&tmp,fs::Permissions::from_mode(mode))?;fs::rename(&tmp,path)?;File::open(parent)?.sync_all()?;Ok(())})();
    if result.is_err(){let _=fs::remove_file(tmp);}result
}
pub fn safe_path(path:&Path)->Result<()> {
    if !path.is_absolute(){return Err("路径必须为绝对路径".into())}
    let mut current=PathBuf::new();
    for c in path.components(){if matches!(c,std::path::Component::ParentDir){return Err("路径不能包含 ..".into())}current.push(c);if let Ok(m)=fs::symlink_metadata(&current){if m.file_type().is_symlink(){return Err(format!("不允许符号链接: {}",current.display()).into())}}}
    Ok(())
}
pub fn valid_domain(s:&str)->bool{s.len()<=253&&s.contains('.')&&!s.ends_with('.')&&s.split('.').all(|l|!l.is_empty()&&l.len()<=63&&!l.starts_with('-')&&!l.ends_with('-')&&l.bytes().all(|c|c.is_ascii_alphanumeric()||c==b'-'))}
pub fn url_encode(s:&str)->String{s.bytes().map(|b|if b.is_ascii_alphanumeric()||b"-_.~".contains(&b){(b as char).to_string()}else{format!("%{b:02X}")}).collect()}
pub fn path_str(p:&Path)->Result<&str>{p.to_str().ok_or_else(||"路径不是 UTF-8".into())}
pub fn now()->u64{std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()}

