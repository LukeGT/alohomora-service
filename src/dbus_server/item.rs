use jiff::Timestamp;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ffi::CStr, mem::MaybeUninit, ptr, sync::Arc};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tokio::{sync::RwLock, task::spawn_blocking};

use zbus::{
    fdo::{self, DBusProxy},
    interface,
    message::Header,
    names::{BusName, UniqueName},
    object_server::InterfaceDeref,
    zvariant::{ObjectPath, Optional, Type, Value},
    Connection, ObjectServer,
};

use crate::{
    auth_gate::AuthGate,
    caller_command,
    dbus_server::collection::Collection,
    error::{Error, Result},
    key_store::SecureKey,
    process_cmdline,
    process_tree::ProcTree,
    secret_store::SecretStore,
};

use super::{
    secret_transfer::Secret,
    session::Session,
    unlock_grants::{Target, UnlockGrants},
    utils::{secret_alias_path, secret_path, time_to_int, try_interface, EMPTY_PATH},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
/// Holds information about the last process to access (decrypt) an item
pub struct SecretAccessor<'a> {
    #[serde(borrow)]
    pub dbus_name: Optional<UniqueName<'a>>,
    pub uid: u32,
    pub username: Optional<String>,
    pub pid: u32,
    pub process_name: Optional<String>,
    // ms since epoch
    pub timestamp: i64,
    /// Sanitised command line of the caller (see `caller_command`). Kept off
    /// the D-Bus wire so the `LastAccess` signature stays unchanged.
    #[serde(skip)]
    pub cmdline: Optional<String>,
}

impl<'a> Default for SecretAccessor<'a> {
    fn default() -> Self {
        Self {
            dbus_name: Optional::from(None),
            uid: 0,
            username: Optional::from(None),
            pid: 0,
            timestamp: 0,
            process_name: Optional::from(None),
            cmdline: Optional::from(None),
        }
    }
}

// Hand-written because the derive ignores `#[serde(skip)]` and would put
// `cmdline` into the signature while serialisation omits it.
impl Type for SecretAccessor<'_> {
    fn signature() -> zbus::zvariant::Signature<'static> {
        zbus::zvariant::Signature::from_static_str_unchecked("(sususx)")
    }
}

fn username_from_uid(uid: u32) -> Option<String> {
    let buffer_len = unsafe {
        match libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) {
            n if n > 0 => n as usize,
            _ => 16_384,
        }
    };
    let mut passwd = MaybeUninit::<libc::passwd>::uninit();
    let mut result = ptr::null_mut();
    let mut buffer = vec![0 as libc::c_char; buffer_len];

    let status = unsafe {
        libc::getpwuid_r(
            uid as libc::uid_t,
            passwd.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };

    if status != 0 || result.is_null() {
        return None;
    }

    let passwd = unsafe { passwd.assume_init() };
    if passwd.pw_name.is_null() {
        return None;
    }

    unsafe { CStr::from_ptr(passwd.pw_name) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

impl SecretAccessor<'static> {
    /// Create a SecretAccessor when caller details are unknown or missing (e.g. missing D-Bus sender header).
    /// Timestamp is set to current time, but user and process information remain empty.
    pub fn for_unknown_caller() -> Self {
        Self {
            dbus_name: Optional::from(None),
            uid: 0,
            username: Optional::from(None),
            pid: 0,
            process_name: Optional::from(None),
            timestamp: Timestamp::now().as_millisecond(),
            cmdline: Optional::from(None),
        }
    }

    /// Create a SecretAccessor populated with the current process's identity and timestamp.
    /// Used when the authentication request originates internally from Alohomora itself.
    pub fn for_current_process() -> Self {
        let pid = std::process::id();
        let uid = unsafe { libc::getuid() };
        let username = username_from_uid(uid);
        let process_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .or_else(|| {
                std::env::args().next().and_then(|a| {
                    std::path::Path::new(&a)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                })
            });

        let cmdline = Some(process_cmdline::read_command_line(
            ProcTree::system().root(),
            pid,
        ));

        Self {
            dbus_name: Optional::from(None),
            uid,
            username: username.into(),
            pid,
            process_name: process_name.into(),
            timestamp: Timestamp::now().as_millisecond(),
            cmdline: cmdline.into(),
        }
    }

    /// Fetch data about a SecretAccessor given a unique name
    pub async fn from_dbus_name<'a>(
        connection: &Connection,
        name: &UniqueName<'a>,
    ) -> Result<Self> {
        let prox = DBusProxy::new(connection).await?;
        // clone to be owned - we need to store this
        let name: UniqueName<'static> = name.to_owned();
        let bus_name = BusName::Unique(name.as_ref());
        // fetch pid and uid using dbus apis
        let pid = prox
            .get_connection_unix_process_id(bus_name.as_ref())
            .await
            .map_err(zbus::Error::from)?;
        let uid = prox
            .get_connection_unix_user(bus_name)
            .await
            .map_err(zbus::Error::from)?;

        let username = spawn_blocking(move || username_from_uid(uid))
            .await
            .unwrap()
            .into();

        let process_name = spawn_blocking(move || {
            // fetch process info
            let mut system = System::new();
            let pid_struct = Pid::from_u32(pid);
            system.refresh_processes_specifics(
                // only fetch info about this process
                ProcessesToUpdate::Some(&[pid_struct]),
                false,
                // only fetches name/pid
                ProcessRefreshKind::nothing(),
            );
            // get name
            let process = system.process(pid_struct)?;
            Some(process.name().to_string_lossy().into_owned())
        })
        .await
        .unwrap();

        let name_for_cmdline = process_name.clone();
        let cmdline = spawn_blocking(move || {
            caller_command::system_command_line_for_caller(pid, name_for_cmdline.as_deref())
        })
        .await
        .unwrap();

        Ok(Self {
            uid,
            username,
            pid,
            dbus_name: Optional::from(Some(name)),
            timestamp: Timestamp::now().as_millisecond(),
            process_name: process_name.into(),
            cmdline: Some(cmdline).into(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Item<'a> {
    pub collection_id: Arc<String>,
    pub id: Arc<String>,
    pub store: Box<dyn SecretStore<'a> + Send + Sync>,
    pub auth_gate: AuthGate,
    pub last_access: Arc<RwLock<Option<SecretAccessor<'static>>>>,
    pub notify_on_access: bool,
    pub grants: UnlockGrants,
}

impl<'a> Item<'a> {
    fn path(&'_ self) -> ObjectPath<'_> {
        secret_path(&*self.collection_id, &*self.id).unwrap()
    }

    pub fn target(&self) -> Target {
        Target::Item {
            collection: self.collection_id.clone(),
            item: self.id.clone(),
        }
    }

    async fn broadcast_collection_signal(&self, connection: &Connection, name: &str) -> Result {
        Collection::broadcast_collection_signal(
            self.store.as_ref(),
            self.collection_id.clone(),
            connection,
            name,
            self.path(),
        )
        .await
    }

    pub async fn read_with_session(
        &self,
        header: &Header<'_>,
        session: &InterfaceDeref<'_, Session>,
        connection: &Connection,
    ) -> Result<Secret> {
        // fail before consuming a grant or asking for approval
        session.check_owner(header)?;
        let access_info = access_info_from_header(header, connection).await?;
        let secret_key = secret_key_for(
            &self.auth_gate,
            &self.grants,
            header,
            &[self.target()],
            access_info.as_ref(),
        )
        .await?;

        self.read_with_session_and_key(header, session, connection, &secret_key, access_info)
            .await
    }

    pub async fn read_with_session_and_key(
        &self,
        header: &Header<'_>,
        session: &InterfaceDeref<'_, Session>,
        connection: &Connection,
        secret_key: &SecureKey,
        access_info: Option<SecretAccessor<'static>>,
    ) -> Result<Secret> {
        debug!(
            "Fetching secret {}/{} for {}",
            self.collection_id,
            self.id,
            header
                .sender()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "[unknown ID]".into())
        );

        let secret_value = self
            .store
            .read_secret_with_key(&*self.collection_id, &*self.id, secret_key)
            .await?;

        // send desktop notification if enabled
        if self.notify_on_access {
            let label = self
                .store
                .get_secret_label(self.collection_id.clone(), self.id.clone())
                .await
                .unwrap_or_else(|_| self.id.to_string());
            send_access_notification(connection, &label, access_info.as_ref()).await;
        }

        *self.last_access.write().await = access_info;

        session.encrypt(secret_value, header)
    }
}

pub(crate) async fn access_info_from_header(
    header: &Header<'_>,
    connection: &Connection,
) -> Result<Option<SecretAccessor<'static>>> {
    if let Some(id) = header.sender() {
        Ok(Some(SecretAccessor::from_dbus_name(connection, id).await?))
    } else {
        Ok(Some(SecretAccessor::for_unknown_caller()))
    }
}

/// The secret key from the caller's unlock grant, or else a blocking phone
/// approval (bounded by the client's D-Bus timeout, typically 25s), which is
/// cancelled if the caller leaves the bus.
pub(crate) async fn secret_key_for(
    auth_gate: &AuthGate,
    grants: &UnlockGrants,
    header: &Header<'_>,
    targets: &[Target],
    access_info: Option<&SecretAccessor<'_>>,
) -> Result<SecureKey> {
    let Some(sender) = header.sender() else {
        return auth_gate.request_secret_key(access_info).await;
    };
    if let Some(key) = grants.take(sender, targets) {
        debug!("Using unlock grant for {sender}");
        return Ok(key);
    }
    let gone = grants.disconnected(sender.as_str());
    tokio::select! {
        result = auth_gate.request_secret_key(access_info) => result,
        () = gone => {
            info!("{sender} left the bus; cancelled its approval request");
            Err(Error::PermissionDenied)
        }
    }
}

async fn send_access_notification(
    connection: &Connection,
    label: &str,
    accessor: Option<&SecretAccessor<'_>>,
) {
    let summary = format!("Secret '{}' accessed", label);
    let body = if let Some(accessor) = accessor {
        let process = accessor
            .process_name
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("<unknown>");
        let user = accessor
            .username
            .as_ref()
            .map(|s| format!("{} (UID {})", s, accessor.uid))
            .unwrap_or_else(|| format!("UID {}", accessor.uid));
        format!(
            "Application <b>{}</b> (PID {}, {}) accessed this secret.",
            process, accessor.pid, user
        )
    } else {
        // We don't know anything about the accessor
        "An unknown application accessed this secret".into()
    };
    let actions: Vec<&str> = vec![];
    let hints: HashMap<&str, Value<'_>> = HashMap::new();

    if let Err(e) = connection
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "pass-secret-service",
                0u32,
                "dialog-password",
                summary.as_str(),
                body.as_str(),
                actions,
                hints,
                -1i32,
            ),
        )
        .await
    {
        warn!("Failed to send access notification: {}", e);
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item<'static> {
    /// Custom method for accessor info.
    /// It would probably be more spec-compliant to define a custom interface
    /// for this method but that would require a new struct with zbus.
    async fn last_access(&'_ self) -> Optional<SecretAccessor<'_>> {
        Optional::from(self.last_access.read().await.clone())
    }

    async fn delete(
        &'_ self,
        #[zbus(connection)] connection: &Connection,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<ObjectPath<'_>> {
        // delete from the stoer
        self.store
            .delete_secret(self.collection_id.clone(), self.id.clone())
            .await?;

        self.broadcast_collection_signal(connection, "ItemDeleted")
            .await?;

        // delete the objects off of dbus
        try_interface(object_server.remove::<Self, _>(self.path()).await)?;

        for alias in self
            .store
            .list_aliases_for_collection(self.collection_id.clone())
            .await?
        {
            // delete from each alias
            if let Some(path) = secret_alias_path(&*alias, &*self.id) {
                try_interface(object_server.remove::<Self, _>(path).await)?;
            }
        }

        // no prompts required to delete
        Ok(EMPTY_PATH)
    }

    async fn get_secret(
        &self,
        session: ObjectPath<'_>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(Secret,)> {
        Ok((self
            .read_with_session(
                &header,
                &try_interface(object_server.interface::<_, Session>(&session).await)?
                    .ok_or(Error::InvalidSession)?
                    .get()
                    .await,
                connection,
            )
            .await?,))
    }

    async fn set_secret(
        &self,
        secret: Secret,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<()> {
        debug!(
            "Setting secret {}/{} from {}",
            self.collection_id,
            self.id,
            header
                .sender()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "[unknown ID]".into())
        );

        // decrypt first so an invalid secret never consumes a grant
        let secret_value =
            try_interface(object_server.interface::<_, Session>(&secret.session).await)?
                .ok_or(Error::InvalidSession)?
                .get()
                .await
                .decrypt(secret, &header)?;

        let access_info = access_info_from_header(&header, connection).await?;
        let secret_key = secret_key_for(
            &self.auth_gate,
            &self.grants,
            &header,
            &[self.target()],
            access_info.as_ref(),
        )
        .await?;

        self.store
            .set_secret(&*self.collection_id, &*self.id, secret_value, &secret_key)
            .await?;

        self.broadcast_collection_signal(connection, "ItemChanged")
            .await?;

        Ok(())
    }

    /// Unlocked while any client holds a grant for this item: property getters
    /// cannot see the caller, so this is global rather than per-client.
    #[zbus(property)]
    async fn locked(&self) -> bool {
        !self.grants.covered_by_anyone(&self.target())
    }

    #[zbus(property)]
    async fn attributes(&self) -> fdo::Result<HashMap<String, String>> {
        let attributes = self
            .store
            .read_secret_attrs(self.collection_id.clone(), self.id.clone())
            .await?;
        Ok(attributes)
    }

    #[zbus(property)]
    async fn set_attributes(
        &mut self,
        attributes: HashMap<String, String>,
        //#[zbus(connection)] connection: &Connection
    ) -> fdo::Result<()> {
        self.store
            .set_secret_attrs(self.collection_id.clone(), self.id.clone(), attributes)
            .await?;

        //self.broadcast_collection_signal(connection, "ItemChanged");

        Ok(())
    }

    #[zbus(property)]
    async fn label(&self) -> fdo::Result<String> {
        Ok(self
            .store
            .get_secret_label(self.collection_id.clone(), self.id.clone())
            .await?)
    }

    #[zbus(property)]
    async fn set_label(
        &mut self,
        label: String,
        //#[zbus(connection)] connection: &Connection
    ) -> fdo::Result<()> {
        self.store
            .set_secret_label(self.collection_id.clone(), self.id.clone(), label)
            .await?;

        //self.broadcast_collection_signal(connection, "ItemChanged");

        Ok(())
    }

    #[zbus(property)]
    async fn created(&self) -> fdo::Result<u64> {
        let metadata = self
            .store
            .stat_secret(&*self.collection_id, &*self.id)
            .await?;
        Ok(time_to_int(metadata.created()))
    }

    #[zbus(property)]
    async fn modified(&self) -> fdo::Result<u64> {
        let metadata = self
            .store
            .stat_secret(&*self.collection_id, &*self.id)
            .await?;
        Ok(time_to_int(metadata.modified()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_accessor_for_current_process() {
        let accessor = SecretAccessor::for_current_process();
        assert_eq!(accessor.pid, std::process::id());
        assert_eq!(accessor.uid, unsafe { libc::getuid() });
        assert!(accessor.timestamp > 0);
        assert!(accessor.username.is_some());
        assert!(accessor.process_name.is_some());
        assert!(accessor.dbus_name.is_none());
        assert!(!accessor.cmdline.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_secret_accessor_for_unknown_caller() {
        let accessor = SecretAccessor::for_unknown_caller();
        assert_eq!(accessor.pid, 0);
        assert_eq!(accessor.uid, 0);
        assert!(accessor.timestamp > 0);
        assert!(accessor.username.is_none());
        assert!(accessor.process_name.is_none());
        assert!(accessor.dbus_name.is_none());
        assert!(accessor.cmdline.is_none());
    }

    #[test]
    fn test_secret_accessor_dbus_signature_excludes_cmdline() {
        // LastAccess is consumed over D-Bus by the CLI; adding the display-only
        // cmdline must not change the wire format.
        assert_eq!(
            <SecretAccessor as Type>::signature().to_string(),
            "(sususx)"
        );
        let mut accessor = SecretAccessor::default();
        accessor.cmdline = Some("ignored on the wire".to_string()).into();
        let ctx = zbus::zvariant::serialized::Context::new_dbus(zbus::zvariant::LE, 0);
        let bytes = zbus::zvariant::to_bytes(ctx, &accessor).unwrap();
        let (decoded, _): (SecretAccessor, _) = bytes.deserialize().unwrap();
        assert!(decoded.cmdline.is_none());
    }
}
