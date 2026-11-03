//! Single-use unlock grants produced by an approved `Prompt`.
//!
//! An approved `Unlock` parks the secret key for the caller's follow-up
//! `GetSecrets` (or `GetSecret`/`CreateItem`/`SetSecret`), which consumes it.
//! A grant is bound to the caller's D-Bus unique name and the approved
//! targets, is never reused, and is dropped if it is not claimed within
//! [`GRANT_CLAIM_TIMEOUT`], on disconnect or on `Lock`.
//!
//! It also broadcasts client disconnects so a blocking approval request can
//! be cancelled when its caller leaves the bus.

use std::{
    fmt,
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Duration,
};

use tokio::{
    sync::broadcast::{self, error::RecvError},
    time::{sleep_until, Instant},
};
use zbus::names::{OwnedUniqueName, UniqueName};

use crate::key_store::SecureKey;

/// How long an unclaimed approval is kept before its key is discarded. Only
/// needs to cover the client's follow-up call after `Prompt.Completed`.
pub const GRANT_CLAIM_TIMEOUT: Duration = Duration::from_secs(10);

/// A lockable object, reduced to ids so `/aliases/default/x` and
/// `/collection/<id>/x` are the same target.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    Collection(Arc<String>),
    Item {
        collection: Arc<String>,
        item: Arc<String>,
    },
}

impl Target {
    /// Whether a grant on `self` gives access to `other`.
    fn covers(&self, other: &Target) -> bool {
        match (self, other) {
            (Target::Collection(c), Target::Item { collection, .. }) => c == collection,
            _ => self == other,
        }
    }

    /// Whether locking `self` must invalidate a grant on `other`.
    fn overlaps(&self, other: &Target) -> bool {
        self.covers(other) || other.covers(self)
    }
}

struct Grant {
    id: u64,
    caller: OwnedUniqueName,
    targets: Vec<Target>,
    key: SecureKey,
    expires: Instant,
}

impl Grant {
    fn covers(&self, target: &Target) -> bool {
        self.targets.iter().any(|t| t.covers(target))
    }
}

struct Inner {
    grants: Mutex<Vec<Grant>>,
    gone: broadcast::Sender<Arc<str>>,
}

#[derive(Clone)]
pub struct UnlockGrants(Arc<Inner>);

impl Default for UnlockGrants {
    fn default() -> Self {
        let (gone, _) = broadcast::channel(64);
        Self(Arc::new(Inner {
            grants: Mutex::new(Vec::new()),
            gone,
        }))
    }
}

impl fmt::Debug for UnlockGrants {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockGrants")
            .field("count", &self.lock().len())
            .finish()
    }
}

static NEXT_GRANT_ID: AtomicU64 = AtomicU64::new(0);

impl UnlockGrants {
    fn lock(&self) -> MutexGuard<'_, Vec<Grant>> {
        // a panic while holding the lock cannot leave the Vec inconsistent
        self.0.grants.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Lock the grant list with expired grants already removed.
    fn live(&self) -> MutexGuard<'_, Vec<Grant>> {
        let mut grants = self.lock();
        let now = Instant::now();
        grants.retain(|g| g.expires > now);
        grants
    }

    /// Indices of `caller`'s grants needed to cover every target.
    fn covering(grants: &[Grant], caller: &str, targets: &[Target]) -> Option<Vec<usize>> {
        if targets.is_empty() {
            return None;
        }
        let mut used = Vec::new();
        for target in targets {
            let index = grants
                .iter()
                .position(|g| g.caller.as_str() == caller && g.covers(target))?;
            if !used.contains(&index) {
                used.push(index);
            }
        }
        Some(used)
    }

    /// Park an approved key; must be called inside a tokio runtime.
    pub fn insert(&self, caller: OwnedUniqueName, targets: Vec<Target>, key: SecureKey) {
        if targets.is_empty() {
            return;
        }
        let id = NEXT_GRANT_ID.fetch_add(1, Ordering::Relaxed);
        let expires = Instant::now() + GRANT_CLAIM_TIMEOUT;
        self.live().push(Grant {
            id,
            caller,
            targets,
            key,
            expires,
        });
        // discard the key promptly if nobody claims it
        let grants = self.clone();
        tokio::spawn(async move {
            sleep_until(expires).await;
            grants.lock().retain(|g| g.id != id);
        });
    }

    /// Whether `caller` holds unclaimed grants covering every target
    /// (without consuming them).
    pub fn covers(&self, caller: &UniqueName<'_>, targets: &[Target]) -> bool {
        Self::covering(&self.live(), caller.as_str(), targets).is_some()
    }

    /// Consume `caller`'s grants covering every target and return the key.
    /// All-or-nothing: nothing is consumed unless every target is covered.
    pub fn take(&self, caller: &UniqueName<'_>, targets: &[Target]) -> Option<SecureKey> {
        let mut grants = self.live();
        let mut used = Self::covering(&grants, caller.as_str(), targets)?;
        used.sort_unstable();
        let mut key = None;
        for index in used.into_iter().rev() {
            key = Some(grants.remove(index).key);
        }
        key
    }

    /// Whether any caller holds an unclaimed grant for `target` (drives the
    /// global `Locked` property, whose getter cannot see the caller).
    pub fn covered_by_anyone(&self, target: &Target) -> bool {
        self.live().iter().any(|g| g.covers(target))
    }

    pub fn remove_caller(&self, caller: &str) {
        self.lock().retain(|g| g.caller.as_str() != caller);
    }

    /// `caller` left the bus: drop its grants and wake [`Self::disconnected`].
    pub fn client_gone(&self, caller: &str) {
        self.remove_caller(caller);
        let _ = self.0.gone.send(caller.into());
    }

    /// Resolves once `caller` leaves the bus (subscribes immediately).
    pub fn disconnected(&self, caller: &str) -> impl Future<Output = ()> + Send + 'static {
        let mut gone = self.0.gone.subscribe();
        let caller: Arc<str> = caller.into();
        async move {
            loop {
                match gone.recv().await {
                    Ok(name) if name == caller => return,
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => std::future::pending::<()>().await,
                }
            }
        }
    }

    /// Drop every grant touching any of `targets`.
    pub fn revoke(&self, targets: &[Target]) {
        self.lock().retain(|g| {
            !g.targets
                .iter()
                .any(|t| targets.iter().any(|r| r.overlaps(t)))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> OwnedUniqueName {
        UniqueName::try_from(s.to_string()).unwrap().into()
    }

    fn key(byte: u8) -> SecureKey {
        let mut raw = [byte; 32];
        SecureKey::from_slice_mut(&mut raw).unwrap()
    }

    fn col(c: &str) -> Target {
        Target::Collection(Arc::new(c.into()))
    }

    fn item(c: &str, i: &str) -> Target {
        Target::Item {
            collection: Arc::new(c.into()),
            item: Arc::new(i.into()),
        }
    }

    fn key_byte(k: SecureKey) -> u8 {
        let mut b = 0;
        k.unlock(|k| b = k[0]);
        b
    }

    #[tokio::test]
    async fn grant_is_consumed_by_first_use() {
        let grants = UnlockGrants::default();
        let a = name(":1.1");
        grants.insert(a.clone(), vec![col("c")], key(7));

        assert!(grants.covers(&a, &[col("c")]));
        assert!(grants.covers(&a, &[col("c")]), "covers() must not consume");
        assert_eq!(key_byte(grants.take(&a, &[col("c")]).unwrap()), 7);
        assert!(grants.take(&a, &[col("c")]).is_none());
        assert!(!grants.covers(&a, &[col("c")]));
        assert!(!grants.covered_by_anyone(&col("c")));
    }

    #[tokio::test]
    async fn collection_grant_covers_its_items_only() {
        let grants = UnlockGrants::default();
        let a = name(":1.1");
        grants.insert(a.clone(), vec![col("c")], key(7));

        assert!(grants.covers(&a, &[item("c", "x"), item("c", "y")]));
        assert!(!grants.covers(&a, &[item("c", "x"), item("d", "y")]));
        assert!(!grants.covers(&a, &[col("d")]));
        assert!(!grants.covers(&a, &[]));
        assert!(grants.covered_by_anyone(&item("c", "x")));
        assert!(!grants.covered_by_anyone(&item("d", "x")));

        // a failed take consumes nothing
        assert!(grants.take(&a, &[item("c", "x"), item("d", "y")]).is_none());
        assert!(grants.take(&a, &[item("c", "x"), item("c", "y")]).is_some());
        assert!(!grants.covers(&a, &[item("c", "x")]));
    }

    #[tokio::test]
    async fn item_grant_does_not_cover_collection() {
        let grants = UnlockGrants::default();
        let a = name(":1.1");
        grants.insert(a.clone(), vec![item("c", "x")], key(1));
        assert!(grants.covers(&a, &[item("c", "x")]));
        assert!(!grants.covers(&a, &[item("c", "y")]));
        assert!(!grants.covers(&a, &[col("c")]));
        assert!(!grants.covered_by_anyone(&col("c")));
    }

    #[tokio::test]
    async fn take_consumes_every_grant_it_used() {
        let grants = UnlockGrants::default();
        let a = name(":1.1");
        grants.insert(a.clone(), vec![item("c", "x")], key(1));
        grants.insert(a.clone(), vec![item("c", "y")], key(1));
        grants.insert(a.clone(), vec![item("c", "z")], key(1));
        assert!(grants.take(&a, &[item("c", "x"), item("c", "y")]).is_some());
        assert!(!grants.covers(&a, &[item("c", "x")]));
        assert!(!grants.covers(&a, &[item("c", "y")]));
        assert!(grants.covers(&a, &[item("c", "z")]));
    }

    #[tokio::test]
    async fn grants_are_bound_to_the_caller() {
        let grants = UnlockGrants::default();
        let (a, b) = (name(":1.1"), name(":1.2"));
        grants.insert(a.clone(), vec![col("c")], key(1));
        assert!(!grants.covers(&b, &[col("c")]));
        assert!(grants.take(&b, &[col("c")]).is_none());
        // the Locked property is global
        assert!(grants.covered_by_anyone(&col("c")));
        assert!(grants.take(&a, &[col("c")]).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn unclaimed_grants_are_discarded() {
        let grants = UnlockGrants::default();
        let a = name(":1.1");
        grants.insert(a.clone(), vec![col("c")], key(1));
        tokio::time::advance(GRANT_CLAIM_TIMEOUT - Duration::from_secs(1)).await;
        assert!(grants.covers(&a, &[col("c")]));
        tokio::time::sleep(Duration::from_secs(2)).await;
        // the cleanup task removed the key without any further access
        assert!(grants.lock().is_empty());
        assert!(grants.take(&a, &[col("c")]).is_none());
        assert!(!grants.covered_by_anyone(&col("c")));
    }

    #[tokio::test]
    async fn remove_caller_drops_only_their_grants() {
        let grants = UnlockGrants::default();
        let (a, b) = (name(":1.1"), name(":1.2"));
        grants.insert(a.clone(), vec![col("c")], key(1));
        grants.insert(b.clone(), vec![col("c")], key(1));
        grants.remove_caller(a.as_str());
        assert!(!grants.covers(&a, &[col("c")]));
        assert!(grants.covers(&b, &[col("c")]));
    }

    #[tokio::test]
    async fn disconnected_resolves_for_that_client_only() {
        let grants = UnlockGrants::default();
        grants.insert(name(":1.1"), vec![col("c")], key(1));
        let mut a = Box::pin(grants.disconnected(":1.1"));
        let mut b = Box::pin(grants.disconnected(":1.2"));
        grants.client_gone(":1.1");
        tokio::time::timeout(Duration::from_secs(1), &mut a)
            .await
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut b)
            .await
            .is_err());
        assert!(!grants.covered_by_anyone(&col("c")));
    }

    #[tokio::test]
    async fn revoke_drops_overlapping_grants() {
        let grants = UnlockGrants::default();
        let a = name(":1.1");
        grants.insert(a.clone(), vec![col("c")], key(1));
        grants.insert(a.clone(), vec![item("d", "x")], key(1));
        grants.insert(a.clone(), vec![item("e", "x")], key(1));

        // locking an item invalidates a grant on its collection
        grants.revoke(&[item("c", "y")]);
        assert!(!grants.covers(&a, &[item("c", "z")]));

        // locking a collection invalidates grants on its items
        grants.revoke(&[col("d")]);
        assert!(!grants.covers(&a, &[item("d", "x")]));

        assert!(grants.covers(&a, &[item("e", "x")]));
    }
}
