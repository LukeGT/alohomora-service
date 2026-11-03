//! `org.freedesktop.Secret.Prompt` objects returned by `Service.Unlock`.
//!
//! libsecret calls `Unlock`, then `Prompt` and waits for `Completed` without a
//! method-call timeout, so the phone approval can take up to the
//! authorization timeout instead of D-Bus' 25s reply limit.

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::Duration,
};

use futures_util::StreamExt;
use log::{debug, info, warn};
use tokio::{task::AbortHandle, time::sleep};
use zbus::{
    fdo::{self, DBusProxy},
    interface,
    message::Header,
    names::{BusName, OwnedUniqueName},
    object_server::{ResponseDispatchNotifier, SignalContext},
    zvariant::{OwnedObjectPath, Value},
    Connection, ObjectServer,
};

use crate::auth_gate::AuthGate;

use super::{
    item::SecretAccessor,
    unlock_grants::{Target, UnlockGrants},
};

/// Prompts that are never started are removed after this long.
const PROMPT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Most prompts a single client may have outstanding at once.
pub const MAX_PROMPTS_PER_CALLER: usize = 8;

enum State {
    Idle,
    Running(AbortHandle),
    Done,
}

pub struct PromptInner {
    path: OwnedObjectPath,
    caller: OwnedUniqueName,
    targets: Vec<Target>,
    /// Paths reported as unlocked in `Completed`.
    result: Vec<OwnedObjectPath>,
    accessor: Option<SecretAccessor<'static>>,
    auth_gate: AuthGate,
    grants: UnlockGrants,
    registry: PromptRegistry,
    connection: Connection,
    state: Mutex<State>,
}

pub struct PromptRequest {
    pub path: OwnedObjectPath,
    pub caller: OwnedUniqueName,
    pub targets: Vec<Target>,
    pub result: Vec<OwnedObjectPath>,
    pub accessor: Option<SecretAccessor<'static>>,
}

impl PromptInner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Move to `Done`; `None` if another path already finished the prompt.
    fn take_done(&self) -> Option<Option<AbortHandle>> {
        match std::mem::replace(&mut *self.state(), State::Done) {
            State::Done => None,
            State::Idle => Some(None),
            State::Running(task) => Some(Some(task)),
        }
    }

    /// Start the approval once `reply_sent` fires, so `Completed` can never
    /// overtake the reply to the `Prompt` call.
    fn start(
        self: &Arc<Self>,
        reply_sent: impl Future<Output = ()> + Send + 'static,
    ) -> fdo::Result<()> {
        let mut state = self.state();
        if !matches!(*state, State::Idle) {
            return Err(fdo::Error::Failed("prompt was already used".into()));
        }
        let inner = self.clone();
        let task = tokio::spawn(async move {
            reply_sent.await;
            inner.run().await
        });
        *state = State::Running(task.abort_handle());
        Ok(())
    }

    async fn run(&self) {
        let outcome = self
            .auth_gate
            .request_secret_key(self.accessor.as_ref())
            .await;
        if self.take_done().is_none() {
            return;
        }
        match outcome {
            Ok(key) => {
                info!("Prompt {} approved for {}", self.path, self.caller);
                self.grants
                    .insert(self.caller.clone(), self.targets.clone(), key);
                self.complete(false, self.result.clone()).await;
            }
            Err(err) => {
                info!("Prompt {} not approved: {err}", self.path);
                self.complete(true, vec![]).await;
            }
        }
    }

    /// Dismiss the prompt, cancelling a running approval. No-op once done.
    pub async fn dismiss(&self) {
        if let Some(task) = self.take_done() {
            debug!("Dismissing prompt {}", self.path);
            if let Some(task) = task {
                task.abort();
            }
            self.complete(true, vec![]).await;
        }
    }

    async fn dismiss_if_idle(&self) {
        {
            let mut state = self.state();
            if !matches!(*state, State::Idle) {
                return;
            }
            *state = State::Done;
        }
        debug!("Removing unused prompt {}", self.path);
        self.complete(true, vec![]).await;
    }

    async fn complete(&self, dismissed: bool, result: Vec<OwnedObjectPath>) {
        match SignalContext::new(&self.connection, self.path.as_ref()) {
            Ok(ctx) => {
                if let Err(err) = Prompt::completed(&ctx, dismissed, Value::from(result)).await {
                    warn!("Failed to emit Completed for {}: {err}", self.path);
                }
            }
            Err(err) => warn!("Invalid prompt path {}: {err}", self.path),
        }
        self.registry.remove(&self.path);
        let _ = self
            .connection
            .object_server()
            .remove::<Prompt, _>(&self.path)
            .await;
    }

    fn check_caller(&self, header: &Header<'_>) -> fdo::Result<()> {
        if header.sender().is_some_and(|s| *s == self.caller) {
            Ok(())
        } else {
            Err(fdo::Error::AccessDenied(
                "You didn't create that prompt".into(),
            ))
        }
    }
}

pub struct Prompt(Arc<PromptInner>);

impl Prompt {
    /// Export a new prompt and return its path.
    pub async fn register(
        request: PromptRequest,
        auth_gate: AuthGate,
        grants: UnlockGrants,
        registry: PromptRegistry,
        connection: &Connection,
        object_server: &ObjectServer,
    ) -> zbus::Result<OwnedObjectPath> {
        let idle_timeout = PROMPT_IDLE_TIMEOUT.min(auth_gate.authorization_timeout());
        let inner = Arc::new(PromptInner {
            path: request.path,
            caller: request.caller,
            targets: request.targets,
            result: request.result,
            accessor: request.accessor,
            auth_gate,
            grants,
            registry: registry.clone(),
            connection: connection.clone(),
            state: Mutex::new(State::Idle),
        });
        let path = inner.path.clone();
        if !object_server.at(&path, Prompt(inner.clone())).await? {
            return Err(zbus::Error::Failure(format!(
                "prompt path {path} already in use"
            )));
        }
        registry.insert(inner.clone());

        // Clients that never call Prompt must not leave objects behind.
        let weak: Weak<PromptInner> = Arc::downgrade(&inner);
        tokio::spawn(async move {
            sleep(idle_timeout).await;
            if let Some(inner) = weak.upgrade() {
                inner.dismiss_if_idle().await;
            }
        });
        Ok(path)
    }
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(
        &self,
        window_id: String,
        #[zbus(header)] header: Header<'_>,
    ) -> fdo::Result<ResponseDispatchNotifier<()>> {
        self.0.check_caller(&header)?;
        debug!("Starting prompt {} (window id {window_id:?})", self.0.path);
        let (reply, reply_sent) = ResponseDispatchNotifier::new(());
        self.0.start(reply_sent)?;
        Ok(reply)
    }

    async fn dismiss(&self, #[zbus(header)] header: Header<'_>) -> fdo::Result<()> {
        self.0.check_caller(&header)?;
        self.0.dismiss().await;
        Ok(())
    }

    #[zbus(signal)]
    async fn completed(
        ctx: &SignalContext<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

/// Live prompts by path, so a disconnecting client's prompts can be dismissed.
#[derive(Clone, Default)]
pub struct PromptRegistry(Arc<Mutex<HashMap<OwnedObjectPath, Arc<PromptInner>>>>);

impl std::fmt::Debug for PromptRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptRegistry")
            .field("count", &self.lock().len())
            .finish()
    }
}

impl PromptRegistry {
    fn lock(&self) -> MutexGuard<'_, HashMap<OwnedObjectPath, Arc<PromptInner>>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn insert(&self, prompt: Arc<PromptInner>) {
        self.lock().insert(prompt.path.clone(), prompt);
    }

    fn remove(&self, path: &OwnedObjectPath) {
        self.lock().remove(path);
    }

    pub fn count_for(&self, caller: &str) -> usize {
        self.lock()
            .values()
            .filter(|p| p.caller.as_str() == caller)
            .count()
    }

    fn for_caller(&self, caller: &str) -> Vec<Arc<PromptInner>> {
        self.lock()
            .values()
            .filter(|p| p.caller.as_str() == caller)
            .cloned()
            .collect()
    }
}

/// Dismiss prompts and drop grants of clients that leave the bus (e.g. the
/// sudo hook exiting when the user presses Enter to use a password instead).
pub async fn watch_disconnects(
    connection: &Connection,
    registry: PromptRegistry,
    grants: UnlockGrants,
) -> zbus::Result<()> {
    let dbus = DBusProxy::new(connection).await?;
    let mut gone = dbus
        .receive_name_owner_changed_with_args(&[(2, "")])
        .await?;
    tokio::spawn(async move {
        let _dbus = dbus;
        while let Some(signal) = gone.next().await {
            let Ok(args) = signal.args() else { continue };
            let BusName::Unique(name) = args.name() else {
                continue;
            };
            grants.client_gone(name.as_str());
            for prompt in registry.for_caller(name.as_str()) {
                prompt.dismiss().await;
            }
            // a prompt that completed while we were dismissing may have
            // added a grant for the departed client
            grants.remove_caller(name.as_str());
        }
        warn!("Stopped watching for disconnecting D-Bus clients");
    });
    Ok(())
}
