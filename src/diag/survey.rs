//! What is installed and loadable: the node state and FRP. Gathered once
//! per diagnosis; every check that needs the configuration reads it here.

use crate::ctx::Ctx;
use crate::domain::NodeConfig;
use crate::frp::model::{self as frp, FrpState};
use crate::state::{Loaded, Origin, StateStore};

/// The node's `state.json` as found.
#[derive(Debug)]
pub enum NodeState {
    /// Not installed (no `state.json`, no v1 `onebox.conf`).
    Absent,
    /// Present but unusable (invalid JSON or values, a v1-only install, a
    /// newer schema); the message says why.
    Invalid(String),
    Loaded(Box<Loaded>),
}

impl NodeState {
    /// Load the state; never fails (failures are [`NodeState::Invalid`]).
    pub fn load(ctx: &Ctx) -> NodeState {
        match StateStore::load(ctx) {
            Ok(None) => NodeState::Absent,
            Ok(Some(loaded)) => NodeState::Loaded(Box::new(loaded)),
            Err(e) => NodeState::Invalid(e.to_string()),
        }
    }

    pub fn config(&self) -> Option<&NodeConfig> {
        match self {
            NodeState::Loaded(loaded) => Some(&loaded.config),
            _ => None,
        }
    }

    /// Whether a node exists at all (even an unreadable one).
    pub fn present(&self) -> bool {
        !matches!(self, NodeState::Absent)
    }

    /// `v3` / `v2` / `absent` / `invalid` (support report).
    pub fn id(&self) -> &'static str {
        match self {
            NodeState::Absent => "absent",
            NodeState::Invalid(_) => "invalid",
            NodeState::Loaded(loaded) => match loaded.origin {
                Origin::V3 => "v3",
                Origin::V2 { .. } => "v2",
            },
        }
    }
}

/// The FRP server state as found.
#[derive(Debug)]
pub enum FrpFound {
    /// FRP is not installed (no `.managed` plus state file).
    Absent,
    /// Installed, but the state file cannot be used; the message says why.
    Invalid(String),
    Loaded(Box<FrpState>),
}

impl FrpFound {
    /// Load the FRP state; never fails.
    pub fn load(ctx: &Ctx) -> FrpFound {
        match frp::load(&ctx.paths) {
            Ok(None) => FrpFound::Absent,
            Ok(Some(state)) => FrpFound::Loaded(Box::new(state)),
            Err(e) => FrpFound::Invalid(e.to_string()),
        }
    }

    pub fn installed(&self) -> bool {
        !matches!(self, FrpFound::Absent)
    }

    pub fn state(&self) -> Option<&FrpState> {
        match self {
            FrpFound::Loaded(state) => Some(state),
            _ => None,
        }
    }
}

/// The installed components a diagnosis looks at.
#[derive(Debug)]
pub struct Survey {
    pub node: NodeState,
    pub frp: FrpFound,
}

impl Survey {
    pub fn gather(ctx: &Ctx) -> Survey {
        Survey {
            node: NodeState::load(ctx),
            frp: FrpFound::load(ctx),
        }
    }

    /// The node configuration when it could be loaded.
    pub fn config(&self) -> Option<&NodeConfig> {
        self.node.config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::fixtures;
    use crate::domain::{Core, Protocol};
    use crate::sys::fs::TempDir;
    use std::fs;

    #[test]
    fn node_states() {
        let dir = TempDir::new("diag-survey").unwrap();
        let (ctx, _, _) = Ctx::test(dir.path());
        let absent = Survey::gather(&ctx);
        assert!(!absent.node.present() && !absent.frp.installed());
        assert!(absent.frp.state().is_none());
        assert_eq!(absent.node.id(), "absent");
        assert!(absent.config().is_none());

        fs::create_dir_all(&ctx.paths.root).unwrap();
        fs::write(ctx.paths.state(), "{not json").unwrap();
        let invalid = NodeState::load(&ctx);
        assert_eq!(invalid.id(), "invalid");
        assert!(invalid.present() && invalid.config().is_none());
        match invalid {
            NodeState::Invalid(message) => assert!(message.contains("state.json"), "{message}"),
            other => panic!("{other:?}"),
        }

        let cfg = fixtures::config(&[(Protocol::VlessReality, 443, Core::Singbox)]);
        StateStore::save(&ctx, &cfg).unwrap();
        let loaded = NodeState::load(&ctx);
        assert_eq!(loaded.id(), "v3");
        assert_eq!(loaded.config(), Some(&cfg));
    }

    #[test]
    fn v1_only_installs_are_invalid_with_the_upgrade_message() {
        let dir = TempDir::new("diag-survey-v1").unwrap();
        let (ctx, _, _) = Ctx::test(dir.path());
        fs::create_dir_all(&ctx.paths.root).unwrap();
        fs::write(ctx.paths.legacy_v1_state(), "X=1\n").unwrap();
        match NodeState::load(&ctx) {
            NodeState::Invalid(message) => assert_eq!(message, crate::state::V1_MESSAGE),
            other => panic!("{other:?}"),
        }
    }
}
