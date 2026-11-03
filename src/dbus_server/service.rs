use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use dyn_clone::clone_box;
use log::{debug, info};
use nanoid::nanoid;
use zbus::{
    fdo, interface,
    message::Header,
    object_server::SignalContext,
    zvariant::{Array, ObjectPath, OwnedObjectPath, OwnedValue, Value},
    Connection, ObjectServer,
};

use crate::{
    auth_gate::AuthGate,
    dbus_server::secret_transfer::{DhIetf1024Sha256Aes128CbcPkcs7Transfer, SessionTransfer},
    error::{Error, OptionNoneNotFound, Result},
    pass::PasswordStore,
    secret_store::{
        get_collection_dir, redb::RedbSecretStore, slugify, SecretStore, NANOID_ALPHABET,
    },
};

use super::{
    collection::Collection,
    item::{access_info_from_header, secret_key_for, Item},
    prompt::{watch_disconnects, Prompt, PromptRegistry, PromptRequest, MAX_PROMPTS_PER_CALLER},
    secret_transfer::{PlainTextTransfer, Secret},
    session::Session,
    unlock_grants::{Target, UnlockGrants},
    utils::{
        alias_path, collection_path, prompt_path, secret_alias_path, secret_path, session_path,
        try_interface, EMPTY_PATH,
    },
};

/// Default name of the initially created collection and alias
pub const DEFAULT_COLLECTION_NAME: &'static str = "default";

#[derive(Debug)]
pub struct Service<'a> {
    store: Box<dyn SecretStore<'a> + Send + Sync>,
    auth_gate: AuthGate,
    forget_password_on_lock: bool,
    notify_on_access: bool,
    grants: UnlockGrants,
    prompts: PromptRegistry,
}

impl Service<'static> {
    pub async fn init(
        connection: Connection,
        pass: &'static PasswordStore,
        auth_gate: AuthGate,
        forget_password_on_lock: bool,
        notify_on_access: bool,
    ) -> Result<Self> {
        let store = Box::new(RedbSecretStore::new(pass).await?);
        let grants = UnlockGrants::default();
        let prompts = PromptRegistry::default();
        watch_disconnects(&connection, prompts.clone(), grants.clone()).await?;

        {
            let object_server = connection.object_server();

            let mut aliases = store.list_all_aliases().await?;

            // initialize the default store if necessary
            if !aliases.contains_key(DEFAULT_COLLECTION_NAME) {
                let id = store
                    .create_collection(Some("Default".into()), Some(DEFAULT_COLLECTION_NAME.into()))
                    .await?;
                aliases.insert(id, vec![DEFAULT_COLLECTION_NAME.into()]);
            }

            // add existing collections
            for collection in store.collections().await {
                let collection_aliases = aliases.remove(&collection).into_iter().flatten();
                let path = collection_path(&collection).unwrap();

                let collection_id = Arc::new(collection);

                let secrets: Vec<_> = store
                    .list_secrets(&*collection_id)
                    .await?
                    .into_iter()
                    .map(|id| Item {
                        store: store.clone(),
                        auth_gate: auth_gate.clone(),
                        id: Arc::new(id),
                        collection_id: collection_id.clone(),
                        last_access: Default::default(),
                        notify_on_access,
                        grants: grants.clone(),
                    })
                    .collect();

                // add the collection secrets
                for secret in &secrets {
                    if let Some(path) = secret_path(&*collection_id, &*secret.id) {
                        object_server.at(path, secret.clone()).await?;
                    }
                }

                let c = Collection {
                    store: store.clone(),
                    id: collection_id,
                    auth_gate: auth_gate.clone(),
                    notify_on_access,
                    grants: grants.clone(),
                };

                // add the aliases
                for alias in collection_aliases {
                    if let Some(path) = alias_path(&alias) {
                        object_server.at(path, c.clone()).await?;
                    }
                    // add the secrets under the alias
                    for secret in &secrets {
                        if let Some(path) = secret_alias_path(&alias, &*secret.id) {
                            object_server.at(path, secret.clone()).await?;
                        }
                    }
                }
                // add the collection
                object_server.at(path, c).await?;
            }
        }

        Ok(Service {
            store,
            auth_gate,
            forget_password_on_lock,
            notify_on_access,
            grants,
            prompts,
        })
    }

    fn make_collection(&self, name: String) -> Collection<'static> {
        Collection {
            id: Arc::new(name),
            store: clone_box(self.store.as_ref()),
            auth_gate: self.auth_gate.clone(),
            notify_on_access: self.notify_on_access,
            grants: self.grants.clone(),
        }
    }

    /// Reduce an item or collection path (including alias paths) to a target.
    async fn resolve_target(object_server: &ObjectServer, path: &ObjectPath<'_>) -> Result<Target> {
        if let Some(item) = try_interface(object_server.interface::<_, Item>(path).await)? {
            return Ok(item.get().await.target());
        }
        let collection = try_interface(object_server.interface::<_, Collection>(path).await)?
            .into_not_found()?;
        let id = collection.get().await.id.clone();
        Ok(Target::Collection(id))
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service<'static> {
    async fn open_session(
        &'_ self,
        algorithm: String,
        input: OwnedValue,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        #[zbus(connection)] connection: &Connection,
    ) -> fdo::Result<(Value<'_>, ObjectPath<'_>)> {
        // print sender's unique name
        debug!(
            "Opening session for {} with algorithm {}",
            header
                .sender()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "[unknown ID]".into()),
            algorithm
        );

        let client_name = header.sender().unwrap().to_owned().into();
        let id = nanoid!(8, &NANOID_ALPHABET);
        let path = session_path(id).unwrap();
        let (session_transfer, additional_data): (Box<dyn SessionTransfer + Send + Sync>, Value) =
            match &*algorithm {
                "plain" => (Box::new(PlainTextTransfer), "".into()),
                "dh-ietf1024-sha256-aes128-cbc-pkcs7" => {
                    // input should be a byte array
                    let client_pub_key = input
                        .downcast_ref::<Array>()
                        .ok()
                        .and_then(|v: Array| -> Option<Vec<u8>> { v.try_into().ok() })
                        .ok_or_else(|| {
                            fdo::Error::InvalidArgs(
                                "expected OpenSession input to be of type `ay`".into(),
                            )
                        })?;

                    let transfer =
                        DhIetf1024Sha256Aes128CbcPkcs7Transfer::new(&client_pub_key[..])?;
                    // send the client the pubkey
                    let pub_key = Value::from(transfer.get_pub_key());
                    (Box::new(transfer), pub_key)
                }
                _ => {
                    return Err(fdo::Error::NotSupported(
                        "Algorithm is not supported".into(),
                    ))
                }
            };
        let session = Session::new(
            session_transfer,
            client_name,
            path.clone().into(),
            connection.clone(),
        );
        object_server.at(&path, session).await?;
        Ok((additional_data, path))
    }

    async fn create_collection(
        &'_ self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
        #[zbus(signal_context)] signal: SignalContext<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<(ObjectPath<'_>, ObjectPath<'_>)> {
        // stringify the labelg
        let label: Option<String> = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(|v| v.downcast_ref().ok());

        // slugify the alias and handle the case where it's empty
        let alias = slugify(&alias);

        let alias = if alias == "" { None } else { Some(alias) };

        let id = self.store.create_collection(label, alias.clone()).await?;
        let collection_path = collection_path(&id).unwrap();

        debug!("Creating collection {id}");

        // if the collection here doesn't exist, create it and handle alises
        // the only reason it might exist is if they supplied an existing alias
        if try_interface(
            object_server
                .interface::<_, Collection>(&collection_path)
                .await,
        )?
        .is_none()
        {
            let c = self.make_collection(id);

            object_server.at(&collection_path, c.clone()).await?;

            // if they supplied an alias, handle it
            if let Some(alias) = alias {
                let alias_path = alias_path(&alias).unwrap();
                // remove the alias at this point
                try_interface(object_server.remove::<Collection, _>(&alias_path).await)?;

                object_server.at(&alias_path, c).await?;
            }

            Self::collection_created(&signal, collection_path.clone()).await?;
        }

        Ok((collection_path, EMPTY_PATH))
    }

    async fn search_items(
        &'_ self,
        attributes: HashMap<String, String>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(Vec<ObjectPath<'_>>, Vec<ObjectPath<'_>>)> {
        let items = self.store.search_all_collections(attributes).await?;
        let caller = header.sender();
        let (mut unlocked, mut locked) = (vec![], vec![]);
        for (collection, secrets) in items {
            let collection = Arc::new(collection);
            for secret in secrets {
                let Some(path) = secret_path(&*collection, &secret) else {
                    continue;
                };
                let target = Target::Item {
                    collection: collection.clone(),
                    item: Arc::new(secret),
                };
                // items count as unlocked only for the client holding the grant
                if caller.is_some_and(|c| self.grants.covers(c, &[target])) {
                    unlocked.push(path);
                } else {
                    locked.push(path);
                }
            }
        }
        Ok((unlocked, locked))
    }

    async fn lock(
        &'_ self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<(Vec<OwnedObjectPath>, ObjectPath<'_>)> {
        let mut targets = Vec::with_capacity(objects.len());
        for object_path in &objects {
            targets.push(Self::resolve_target(object_server, object_path).await?);
        }
        self.grants.revoke(&targets);

        if self.forget_password_on_lock {
            // all parent collection directories for the items given
            let collection_dirs: HashSet<PathBuf> = targets
                .iter()
                .map(|target| match target {
                    Target::Collection(id) | Target::Item { collection: id, .. } => {
                        get_collection_dir(id)
                    }
                })
                .collect();
            debug!(
                "Locking collections [{}]",
                collection_dirs
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            self.store
                .get_pass()
                .gpg_forget_cached_password(collection_dirs)
                .await?;
        };

        Ok((objects, EMPTY_PATH))
    }

    /// Unlocking needs a phone approval, which can take far longer than a
    /// D-Bus method call may block, so it goes through a Prompt object whose
    /// approval becomes a single-use grant for this caller.
    async fn unlock(
        &'_ self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(header)] header: Header<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        if objects.is_empty() {
            return Ok((vec![], EMPTY_PATH.into()));
        }
        let caller = header.sender().ok_or(Error::PermissionDenied)?.to_owned();

        let mut targets = Vec::with_capacity(objects.len());
        for object_path in &objects {
            targets.push(Self::resolve_target(object_server, object_path).await?);
        }

        if self.grants.covers(&caller, &targets) {
            debug!("Unlock for {caller}: already covered by a grant");
            return Ok((objects, EMPTY_PATH.into()));
        }

        let (covered, remaining): (Vec<_>, Vec<_>) = objects
            .iter()
            .cloned()
            .zip(&targets)
            .partition(|(_, target)| self.grants.covers(&caller, std::slice::from_ref(*target)));
        let covered = covered.into_iter().map(|(p, _)| p).collect();
        let remaining = remaining.into_iter().map(|(p, _)| p).collect();

        if self.prompts.count_for(caller.as_str()) >= MAX_PROMPTS_PER_CALLER {
            return Err(Error::InvalidRequest(
                "too many outstanding prompts for this client".into(),
            ));
        }
        let accessor = access_info_from_header(&header, connection).await?;
        let path: OwnedObjectPath = prompt_path(nanoid!(8, &NANOID_ALPHABET)).unwrap().into();
        let path = Prompt::register(
            PromptRequest {
                path,
                caller: caller.clone().into(),
                targets,
                result: remaining,
                accessor,
            },
            self.auth_gate.clone(),
            self.grants.clone(),
            self.prompts.clone(),
            connection,
            object_server,
        )
        .await?;
        info!("Unlock for {caller} needs approval via prompt {path}");

        Ok((covered, path))
    }

    async fn get_secrets(
        &self,
        items: Vec<ObjectPath<'_>>,
        session: ObjectPath<'_>,
        #[zbus(object_server)] object_server: &ObjectServer,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<HashMap<OwnedObjectPath, Secret>> {
        let session_ref = try_interface(object_server.interface::<_, Session>(&session).await)?
            .ok_or(Error::InvalidSession)?;
        let session = session_ref.get().await;
        if items.is_empty() {
            return Ok(HashMap::new());
        }
        // fail before consuming a grant or asking for approval
        session.check_owner(&header)?;

        let mut resolved = Vec::with_capacity(items.len());
        let mut targets = Vec::with_capacity(items.len());
        for item_path in items {
            let item_ref = try_interface(object_server.interface::<_, Item>(&item_path).await)?
                .into_not_found()?;
            targets.push(item_ref.get().await.target());
            resolved.push((item_path, item_ref));
        }

        let access_info = access_info_from_header(&header, connection).await?;
        // without a prior Unlock this blocks within the client's D-Bus timeout
        let secret_key = secret_key_for(
            &self.auth_gate,
            &self.grants,
            &header,
            &targets,
            access_info.as_ref(),
        )
        .await?;

        let mut results = HashMap::with_capacity(resolved.len());

        for (item_path, item_ref) in resolved {
            let secret = item_ref
                .get()
                .await
                .read_with_session_and_key(
                    &header,
                    &session,
                    connection,
                    &secret_key,
                    access_info.clone(),
                )
                .await?;
            results.insert(item_path.into(), secret);
        }

        Ok(results)
    }

    async fn read_alias(&'_ self, name: String) -> Result<ObjectPath<'_>> {
        let alias = slugify(&name);

        if let Some(target) = collection_path(self.store.get_alias(Arc::new(alias)).await?) {
            Ok(target)
        } else {
            Ok(EMPTY_PATH)
        }
    }

    async fn set_alias(
        &self,
        name: String,
        collection: OwnedObjectPath,
        #[zbus(object_server)] object_server: &ObjectServer,
    ) -> Result<()> {
        let alias = Arc::new(slugify(&name));

        let alias_path = alias_path(&alias).unwrap();

        let collection = collection.as_ref();

        // remove the alias at this point
        try_interface(object_server.remove::<Collection, _>(&alias_path).await)?;

        // remove all secrets under this alias
        if let Ok(old_target) = self.store.get_alias(alias.clone()).await {
            let secrets = self.store.list_secrets(&old_target).await?;

            for secret in secrets {
                if let Some(path) = secret_alias_path(&*alias, &secret) {
                    try_interface(object_server.remove::<Item, _>(&path).await)?;
                }
            }
        }

        let target_collection_id = if collection == EMPTY_PATH {
            None
        } else {
            let collection_interface = object_server
                .interface::<_, Collection>(&collection)
                .await?
                .get()
                .await
                .to_owned();
            object_server.at(&alias_path, collection_interface).await?;

            // get just the ID
            let collection_id = collection
                .strip_prefix("/org/freedesktop/secrets/collection/")
                .map(|s| s.to_string());

            if let Some(id) = &collection_id {
                // add secrets under this alias
                for secret in self.store.list_secrets(&id).await? {
                    if let Some(path) = secret_alias_path(&*alias, &secret) {
                        if let Some(item) =
                            try_interface(object_server.interface::<_, Item>(&path).await)?
                        {
                            object_server.at(&path, item.get().await.to_owned()).await?;
                        }
                    }
                }
            }

            collection_id
        };
        // save this persistently
        self.store.set_alias(alias, target_collection_id).await?;
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&'_ self) -> Vec<ObjectPath<'_>> {
        self.store
            .collections()
            .await
            .into_iter()
            .filter_map(collection_path)
            .collect()
    }

    // signals

    #[zbus(signal)]
    async fn collection_created(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_deleted(ctx: &SignalContext<'_>, path: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_modified(ctx: &SignalContext<'_>, path: ObjectPath<'_>)
        -> zbus::Result<()>;
}
