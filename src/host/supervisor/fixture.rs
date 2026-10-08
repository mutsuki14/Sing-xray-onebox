//! Test support: fake `/proc` entries below `Paths::system_root`.

use std::fs;
use std::path::{Path, PathBuf};

/// Writes `/proc/{pid}/{stat,exe,cmdline}` under a system root.
pub struct FakeProc {
    root: PathBuf,
}

impl FakeProc {
    pub fn new(system_root: &Path) -> FakeProc {
        FakeProc {
            root: system_root.join("proc"),
        }
    }

    pub fn dir(&self, pid: u32) -> PathBuf {
        self.root.join(pid.to_string())
    }

    /// A live process started at `start` running `exe` with `argv`.
    pub fn add(&self, pid: u32, start: u64, exe: &Path, argv: &[&str]) {
        self.add_raw(pid, start, "S", exe, &cmdline(argv));
    }

    /// A process whose argv is one title string (nginx), NUL padded.
    pub fn add_title(&self, pid: u32, start: u64, exe: &Path, title: &str) {
        let mut raw = title.as_bytes().to_vec();
        raw.extend_from_slice(&[0; 8]);
        self.add_raw(pid, start, "S", exe, &raw);
    }

    pub fn add_raw(&self, pid: u32, start: u64, state: &str, exe: &Path, cmdline: &[u8]) {
        let dir = self.dir(pid);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("stat"), stat_line(pid, "a (b) c", state, start)).unwrap();
        fs::write(dir.join("cmdline"), cmdline).unwrap();
        std::os::unix::fs::symlink(exe, dir.join("exe")).unwrap();
        fs::write(dir.join("comm"), "fake\n").unwrap();
    }

    /// Turn `pid` into a zombie (state Z).
    pub fn zombie(&self, pid: u32) {
        let stat = self.dir(pid).join("stat");
        let text = fs::read_to_string(&stat).unwrap();
        let (head, tail) = text.rsplit_once(") S ").unwrap();
        fs::write(stat, format!("{head}) Z {tail}")).unwrap();
    }

    pub fn remove(&self, pid: u32) {
        let _ = fs::remove_dir_all(self.dir(pid));
    }

    pub fn exists(&self, pid: u32) -> bool {
        self.dir(pid).exists()
    }
}

/// A `/proc/PID/stat` line whose field 22 is `start`.
pub fn stat_line(pid: u32, comm: &str, state: &str, start: u64) -> String {
    format!("{pid} ({comm}) {state} 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {start} 1024 9 18446744073709551615\n")
}

pub fn cmdline(argv: &[&str]) -> Vec<u8> {
    argv.iter().flat_map(|a| a.bytes().chain([0])).collect()
}
