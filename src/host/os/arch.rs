//! CPU architecture from `uname -m` and the per-artifact naming tables.
//!
//! The tables were checked against the published assets of sing-box 1.14.2,
//! Xray 26.3.27, frp 0.71.0 and Onebox 2.0.1 (an asset missing upstream maps
//! to `None`, so callers can say so before downloading anything).

use crate::ctx::Ctx;
use crate::error::{Error, Result};

/// CPU features that make a 32-bit ARM CPU an ARMv7 with hardware float
/// (v2 rule; `armv8l` is a 64-bit CPU running a 32-bit userland).
const ARMV7_FEATURES: [&str; 4] = ["vfpv3", "vfpv4", "neon", "asimd"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Arch {
    Amd64,
    I386,
    Arm64,
    Armv7,
    Armv6,
    Armv5,
    S390x,
    Riscv64,
    Loong64,
    Ppc64le,
    Ppc64,
    Mips64le,
    Mips64,
    Mipsle,
    Mips,
}

/// Naming used by the Actions-bbr-v3 kernel releases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BbrArch {
    /// Release tag prefix (`x86_64-7.2.8`, `arm64-7.2.8-max`).
    pub tag: &'static str,
    /// Debian architecture of the `.deb` packages.
    pub deb: &'static str,
}

impl Arch {
    /// Detect from `uname -m`, `{system_root}/proc/cpuinfo` (32-bit ARM
    /// float support) and this binary's endianness (MIPS).
    pub fn detect(ctx: &Ctx) -> Result<Arch> {
        let machine = super::machine(ctx)?;
        let cpuinfo = super::read_system_file(ctx, "/proc/cpuinfo").unwrap_or_default();
        Arch::from_uname(&machine, &cpuinfo, cfg!(target_endian = "little"))
    }

    /// Map a `uname -m` value (v2 table). `cpuinfo` decides ARMv7 vs ARMv6
    /// for `armv7*`/`armv8l`; `little_endian` picks the MIPS variant because
    /// `uname -m` reports `mips`/`mips64` for both byte orders.
    pub fn from_uname(machine: &str, cpuinfo: &str, little_endian: bool) -> Result<Arch> {
        let arch = match machine {
            "x86_64" | "amd64" => Arch::Amd64,
            "i386" | "i486" | "i586" | "i686" | "x86" => Arch::I386,
            "aarch64" | "arm64" => Arch::Arm64,
            "s390x" => Arch::S390x,
            "riscv64" => Arch::Riscv64,
            "loongarch64" | "loong64" => Arch::Loong64,
            "ppc64le" => Arch::Ppc64le,
            "ppc64" => Arch::Ppc64,
            m if m.starts_with("armv7") || m == "armv8l" => {
                if ARMV7_FEATURES.iter().any(|f| cpuinfo.contains(f)) {
                    Arch::Armv7
                } else {
                    Arch::Armv6
                }
            }
            m if m.starts_with("armv6") => Arch::Armv6,
            m if m.starts_with("arm") => Arch::Armv5,
            m if m.starts_with("mips64") => {
                if little_endian {
                    Arch::Mips64le
                } else {
                    Arch::Mips64
                }
            }
            m if m.starts_with("mips") => {
                if little_endian {
                    Arch::Mipsle
                } else {
                    Arch::Mips
                }
            }
            _ => return Err(Error::msg(format!("不支持的架构: {machine}"))),
        };
        Ok(arch)
    }

    /// Display name (the sing-box spelling, also used in messages).
    pub fn id(self) -> &'static str {
        match self {
            Arch::Amd64 => "amd64",
            Arch::I386 => "386",
            Arch::Arm64 => "arm64",
            Arch::Armv7 => "armv7",
            Arch::Armv6 => "armv6",
            Arch::Armv5 => "armv5",
            Arch::S390x => "s390x",
            Arch::Riscv64 => "riscv64",
            Arch::Loong64 => "loong64",
            Arch::Ppc64le => "ppc64le",
            Arch::Ppc64 => "ppc64",
            Arch::Mips64le => "mips64le",
            Arch::Mips64 => "mips64",
            Arch::Mipsle => "mipsle",
            Arch::Mips => "mips",
        }
    }

    /// sing-box asset architecture; sing-box publishes nothing for ppc64.
    pub fn singbox(self) -> Option<&'static str> {
        (self != Arch::Ppc64).then(|| self.id())
    }

    /// sing-box package names in preference order (v2 suffix table: musl
    /// first where it exists, softfloat for MIPS).
    pub fn singbox_assets(self, version: &str) -> Vec<String> {
        let Some(arch) = self.singbox() else {
            return Vec::new();
        };
        let suffixes: &[&str] = match self {
            Arch::Mips | Arch::Mips64 => &["-softfloat"],
            Arch::Mipsle => &["-softfloat-musl", "-softfloat", ""],
            Arch::Mips64le => &["", "-softfloat"],
            Arch::Amd64 | Arch::Arm64 => &["-musl", "", "-glibc"],
            _ => &["-musl", ""],
        };
        suffixes
            .iter()
            .map(|suffix| format!("sing-box-{version}-linux-{arch}{suffix}.tar.gz"))
            .collect()
    }

    /// Xray asset architecture (`Xray-linux-{arch}.zip`).
    pub fn xray(self) -> &'static str {
        match self {
            Arch::Amd64 => "64",
            Arch::I386 => "32",
            Arch::Arm64 => "arm64-v8a",
            Arch::Armv7 => "arm32-v7a",
            Arch::Armv6 => "arm32-v6",
            Arch::Armv5 => "arm32-v5",
            Arch::S390x => "s390x",
            Arch::Riscv64 => "riscv64",
            Arch::Loong64 => "loong64",
            Arch::Ppc64le => "ppc64le",
            Arch::Ppc64 => "ppc64",
            Arch::Mips64le => "mips64le",
            Arch::Mips64 => "mips64",
            Arch::Mipsle => "mips32le",
            Arch::Mips => "mips32",
        }
    }

    /// The Xray release package for this architecture.
    pub fn xray_asset(self) -> String {
        format!("Xray-linux-{}.zip", self.xray())
    }

    /// frp asset architecture (`frp_{version}_linux_{arch}.tar.gz`). frp
    /// builds `arm_hf` for ARMv7 and soft-float `arm` for older ARM, and
    /// publishes no Linux package for x86, s390x or ppc64*.
    pub fn frp(self) -> Option<&'static str> {
        match self {
            Arch::Amd64 => Some("amd64"),
            Arch::Arm64 => Some("arm64"),
            Arch::Armv7 => Some("arm_hf"),
            Arch::Armv6 | Arch::Armv5 => Some("arm"),
            Arch::Riscv64 => Some("riscv64"),
            Arch::Loong64 => Some("loong64"),
            Arch::Mips64le => Some("mips64le"),
            Arch::Mips64 => Some("mips64"),
            Arch::Mipsle => Some("mipsle"),
            Arch::Mips => Some("mips"),
            Arch::I386 | Arch::S390x | Arch::Ppc64le | Arch::Ppc64 => None,
        }
    }

    /// `frp_{version}_linux_{arch}.tar.gz` (version without a leading `v`).
    pub fn frp_asset(self, version: &str) -> Option<String> {
        self.frp()
            .map(|arch| format!("frp_{version}_linux_{arch}.tar.gz"))
    }

    /// Onebox release architecture: the four static musl builds.
    pub fn onebox(self) -> Option<&'static str> {
        match self {
            Arch::Amd64 => Some("amd64"),
            Arch::Arm64 => Some("arm64"),
            Arch::I386 => Some("386"),
            Arch::Armv7 => Some("armv7"),
            _ => None,
        }
    }

    /// `onebox-linux-{amd64|arm64|386|armv7}-musl`.
    pub fn onebox_asset(self) -> Option<String> {
        self.onebox()
            .map(|arch| format!("onebox-linux-{arch}-musl"))
    }

    /// Actions-bbr-v3 kernels exist for x86_64 and arm64 only.
    pub fn bbr(self) -> Option<BbrArch> {
        match self {
            Arch::Amd64 => Some(BbrArch {
                tag: "x86_64",
                deb: "amd64",
            }),
            Arch::Arm64 => Some(BbrArch {
                tag: "arm64",
                deb: "arm64",
            }),
            _ => None,
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}
