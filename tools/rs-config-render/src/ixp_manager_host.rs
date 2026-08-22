use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub(crate) router_handle: String,
    pub(crate) runtime_state_dir: PathBuf,
    pub(crate) activation_state_dir: PathBuf,
    pub(crate) host_state_dir: PathBuf,
    pub(crate) rbgp_addr: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenderBinding {
    pub(crate) router_handle: String,
    pub(crate) runtime_state_dir: PathBuf,
}
fn valid_handle(handle: &str) -> bool {
    (1..=128).contains(&handle.len())
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
fn valid_path(path: &Path) -> bool {
    path.is_absolute()
        && path.to_str().is_some()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}
fn valid_render(handle: &str, runtime: &Path) -> bool {
    valid_handle(handle) && valid_path(runtime) && runtime.file_name() == Some(handle.as_ref())
}
impl RenderBinding {
    pub fn new(router_handle: &str, runtime_state_dir: &Path) -> Result<Self, &'static str> {
        let binding = Self {
            router_handle: router_handle.to_owned(),
            runtime_state_dir: runtime_state_dir.to_owned(),
        };
        binding
            .valid()
            .then_some(binding)
            .ok_or("runtime state directory basename must equal valid router handle")
    }
    pub(crate) fn valid(&self) -> bool {
        valid_render(&self.router_handle, &self.runtime_state_dir)
    }
}
impl Binding {
    pub fn new(
        router_handle: &str,
        runtime: &Path,
        activation: &Path,
        host: &Path,
        rbgp_addr: &str,
    ) -> Result<Self, &'static str> {
        let binding = Self {
            router_handle: router_handle.to_owned(),
            runtime_state_dir: runtime.to_owned(),
            activation_state_dir: activation.to_owned(),
            host_state_dir: host.to_owned(),
            rbgp_addr: rbgp_addr.to_owned(),
        };
        binding
            .valid()
            .then_some(binding)
            .ok_or("invalid router host binding")
    }
    pub(crate) fn valid(&self) -> bool {
        valid_render(&self.router_handle, &self.runtime_state_dir)
            && valid_path(&self.activation_state_dir)
            && valid_path(&self.host_state_dir)
            && self.activation_state_dir == self.runtime_state_dir.join("activation")
            && self.rbgp_addr == format!("unix://{}/grpc.sock", self.runtime_state_dir.display())
    }
    pub fn render_binding(&self) -> RenderBinding {
        RenderBinding {
            router_handle: self.router_handle.clone(),
            runtime_state_dir: self.runtime_state_dir.clone(),
        }
    }
    pub fn rbgp_addr(&self) -> &str {
        &self.rbgp_addr
    }
}
#[cfg(unix)]
fn private_dir(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_dir() && metadata.permissions().mode() & 0o777 == 0o700
    })
}
#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Refused(&'static str),
    RecoveryRequired,
}
#[cfg(unix)]
mod unix {
    use super::{Binding, Error};
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::Path;
    const FENCE: &str = "ixp-manager-host-fence.json";
    pub struct Guard(#[allow(dead_code)] File, Binding);
    fn sync_dir(path: &Path) -> Result<(), Error> {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Error::RecoveryRequired)
    }
    fn host_lock(state: &Path) -> Result<File, Error> {
        let path = state.join("ixp-manager-host.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|_| Error::Refused("host lock is unavailable"))?;
        let opened = file
            .metadata()
            .map_err(|_| Error::Refused("unsafe host lock"))?;
        let named = fs::symlink_metadata(path).map_err(|_| Error::Refused("unsafe host lock"))?;
        if !named.file_type().is_file()
            || named.nlink() != 1
            || named.permissions().mode() & 0o777 != 0o600
            || (named.dev(), named.ino()) != (opened.dev(), opened.ino())
        {
            return Err(Error::Refused("host lock is not private"));
        }
        file.try_lock()
            .map_err(|_| Error::Refused("another host command is active"))?;
        Ok(file)
    }
    /// True unless the fence file is proven absent; an unreadable fence counts
    /// as present so callers fail closed.
    pub(crate) fn fence_present(state: &Path) -> bool {
        !matches!(
            fs::symlink_metadata(state.join(FENCE)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    }
    fn read_fence(state: &Path) -> Result<Option<Binding>, Error> {
        let path = state.join(FENCE);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::RecoveryRequired),
        };
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o600
            || !(1..=64 * 1024).contains(&metadata.len())
        {
            return Err(Error::RecoveryRequired);
        }
        let bytes = fs::read(path).map_err(|_| Error::RecoveryRequired)?;
        let binding: Binding =
            serde_json::from_slice(&bytes).map_err(|_| Error::RecoveryRequired)?;
        binding
            .valid()
            .then_some(Some(binding))
            .ok_or(Error::RecoveryRequired)
    }
    fn write_fence(state: &Path, binding: &Binding) -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(state.join(FENCE))
            .map_err(|_| Error::RecoveryRequired)?;
        serde_json::to_writer_pretty(&mut file, binding).map_err(|_| Error::RecoveryRequired)?;
        file.write_all(b"\n")
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::RecoveryRequired)?;
        sync_dir(state)
    }
    impl Guard {
        pub fn claim_new(binding: &Binding) -> Result<Self, Error> {
            Self::claim(binding, false)
        }
        pub fn claim_existing(binding: &Binding) -> Result<Self, Error> {
            Self::claim(binding, true)
        }
        fn claim(binding: &Binding, existing: bool) -> Result<Self, Error> {
            if !binding.valid()
                || ![
                    &binding.runtime_state_dir,
                    &binding.activation_state_dir,
                    &binding.host_state_dir,
                ]
                .into_iter()
                .all(|path| {
                    super::private_dir(path) && fs::canonicalize(path).ok().as_deref() == Some(path)
                })
            {
                return Err(Error::Refused("host binding directories are not private"));
            }
            let lock = host_lock(&binding.host_state_dir)?;
            match (existing, read_fence(&binding.host_state_dir)?) {
                (false, None) => write_fence(&binding.host_state_dir, binding)?,
                (false, Some(_)) => return Err(Error::RecoveryRequired),
                (true, Some(owner)) if owner == *binding => {}
                (true, Some(_)) => return Err(Error::Refused("foreign host fence")),
                (true, None) => return Err(Error::Refused("no pending host fence exists")),
            }
            Ok(Self(lock, binding.clone()))
        }
        pub fn clear(&self) -> Result<(), Error> {
            let binding = &self.1;
            match read_fence(&binding.host_state_dir)? {
                Some(owner) if owner == *binding => {}
                Some(_) => return Err(Error::Refused("foreign host fence cannot be cleared")),
                None => return Err(Error::RecoveryRequired),
            }
            fs::remove_file(binding.host_state_dir.join(FENCE))
                .map_err(|_| Error::RecoveryRequired)?;
            sync_dir(&binding.host_state_dir)
        }
        pub(crate) fn owns(&self, binding: &Binding) -> bool {
            self.1 == *binding
        }
    }
}
#[cfg(unix)]
pub use unix::Guard;
#[cfg(unix)]
pub(crate) use unix::fence_present;
