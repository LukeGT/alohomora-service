use secure_types::SecureString;
use std::{
    collections::{HashMap, HashSet},
    env, fmt,
    fs::{FileType, Metadata},
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::{
    fs::{
        metadata, read, read_dir, read_to_string, remove_dir_all, remove_file, DirBuilder, File,
        OpenOptions,
    },
    io::AsyncWriteExt,
    process::Command,
};

use crate::{
    error::{Error, Result},
    key_store::{self, SecureKey},
};

pub struct PasswordStore {
    pub directory: PathBuf,
    gpg_opts: Option<String>,
    symmetric_gpg_passphrase: SecureString,
    file_mode: u32,
    dir_mode: u32,
}

impl fmt::Debug for PasswordStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordStore")
            .field("directory", &self.directory)
            .field("gpg_opts", &self.gpg_opts)
            .field("file_mode", &self.file_mode)
            .field("dir_mode", &self.dir_mode)
            .finish_non_exhaustive()
    }
}

impl PasswordStore {
    /// Initialize this PasswordStore instance from env vars
    pub fn from_env(
        password_store_dir: Option<PathBuf>,
        symmetric_gpg_passphrase: SecureString,
    ) -> Result<Self> {
        let mut env: HashMap<String, String> = env::vars().collect();

        // Either ~/.password-store or $PASSWORD_STORE_DIR
        let directory = password_store_dir.unwrap_or_else(|| {
            env.get("PASSWORD_STORE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    let home = Path::new(env.get("HOME").expect("$HOME must be set"));
                    home.join(".password-store")
                })
        });

        let gpg_opts = env.remove("PASSWORD_STORE_GPG_OPTS");

        let umask = env
            .get("PASSWORD_STORE_UMASK")
            .and_then(|s| u32::from_str_radix(s, 8).ok())
            .unwrap_or(0o077);

        // lower 3 octal digits
        let dir_mode = !umask & 0o777;
        // lower 3 digits without execute bit
        let file_mode = !(umask | 0o111) & 0o777;

        Ok(Self {
            directory,
            gpg_opts,
            symmetric_gpg_passphrase,
            dir_mode,
            file_mode,
        })
    }

    fn get_full_secret_path(&self, path: impl AsRef<Path>) -> PathBuf {
        let mut path = self.directory.join(path);

        // add .gpg to the end if necessary
        if !path.ends_with(".gpg") {
            let os_str = path.as_mut_os_string();
            os_str.push(".gpg");
        };

        path
    }

    fn make_gpg_process(&self) -> Command {
        let mut command = Command::new("gpg");

        // apply the gpg opts
        if let Some(opts) = &self.gpg_opts {
            command.args(opts.split_ascii_whitespace());
        }

        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        command
    }

    #[allow(dead_code)]
    fn add_symmetric_passphrase_args<'a>(&self, command: &'a mut Command) -> &'a mut Command {
        Self::add_symmetric_passphrase_args_with(command, &self.symmetric_gpg_passphrase)
    }

    fn add_symmetric_passphrase_args_with<'a>(
        command: &'a mut Command,
        passphrase: &SecureString,
    ) -> &'a mut Command {
        passphrase.unlock_str(|passphrase| {
            command
                .arg("--batch")
                .arg("--yes")
                .arg("--pinentry-mode")
                .arg("loopback")
                .arg("--passphrase")
                .arg(passphrase)
                .arg("--no-symkey-cache")
        })
    }

    /// Read a single password at the given path
    pub async fn read_password(
        &self,
        path: impl AsRef<Path>,
        _can_prompt: bool,
    ) -> Result<Vec<u8>> {
        self.read_password_with_passphrase(path, &self.symmetric_gpg_passphrase)
            .await
    }

    async fn encrypt_with_passphrase(&self, value: &[u8], passphrase: &SecureString) -> Result<Vec<u8>> {
        let mut command = self.make_gpg_process();
        Self::add_symmetric_passphrase_args_with(&mut command, passphrase);

        let mut process = command
            .arg("--symmetric")
            .arg("--cipher-algo")
            .arg("AES256")
            .arg("-")
            .spawn()?;

        let mut stdin = process.stdin.take().expect("child has stdin");
        let value = value.to_vec();
        tokio::task::spawn(async move { stdin.write_all(&value).await });

        let output = process.wait_with_output().await?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(Error::GpgError(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ))
        }
    }

    async fn decrypt_with_passphrase(&self, encrypted_data: &[u8], passphrase: &SecureString) -> Result<Vec<u8>> {
        let mut command = self.make_gpg_process();
        Self::add_symmetric_passphrase_args_with(&mut command, passphrase);

        command.arg("--decrypt").arg("-");

        let mut process = command.spawn()?;
        let mut stdin = process.stdin.take().expect("child has stdin");
        let encrypted_data = encrypted_data.to_vec();
        tokio::task::spawn(async move { stdin.write_all(&encrypted_data).await });

        let output = process.wait_with_output().await?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(Error::GpgError(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ))
        }
    }

    pub async fn read_password_with_key(
        &self,
        path: impl AsRef<Path>,
        key: &SecureKey,
    ) -> Result<Vec<u8>> {
        // 1. Decrypt outer layer using local_key (self.symmetric_gpg_passphrase)
        let outer_decrypted = self.read_password_with_passphrase(path, &self.symmetric_gpg_passphrase).await?;

        // 2. Decrypt inner layer using secret_key
        let secret_passphrase = key_store::key_to_passphrase(key);
        let inner_decrypted = self.decrypt_with_passphrase(&outer_decrypted, &secret_passphrase).await?;

        Ok(inner_decrypted)
    }

    async fn read_password_with_passphrase(
        &self,
        path: impl AsRef<Path>,
        passphrase: &SecureString,
    ) -> Result<Vec<u8>> {
        let contents = read(self.get_full_secret_path(path)).await?;
        self.decrypt_with_passphrase(&contents, passphrase).await
    }

    /// Look for a `.gpg-id` file starting from `dir` up to `self.directory`.
    ///
    /// Some tools, like `gopass` may encrypt a file for multiple recipients and thus contain
    /// multiple IDs in the `.gpg-id` file.
    async fn get_gpg_ids(&self, dir: impl AsRef<Path>) -> Result<Vec<String>> {
        for component in dir.as_ref().ancestors() {
            let gpg_id_path = component.join(".gpg-id");
            match read_to_string(gpg_id_path).await {
                Ok(value) => return Ok(value.trim().lines().map(String::from).collect()),
                // not found, continue
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => Err(e)?,
            }

            // at the root pass dir
            if component == self.directory {
                break;
            }
        }
        // we couldn't find a gpg key
        return Err(Error::NotInitialized);
    }

    async fn ensure_dirs(&self, dir: impl AsRef<Path>) -> Result {
        // create this dir
        Ok(DirBuilder::new()
            .recursive(true)
            .mode(self.dir_mode)
            .create(dir)
            .await?)
    }

    /// write a single password encrypted with both local_key and secret_key
    pub async fn write_password_with_key(
        &self,
        path: impl AsRef<Path>,
        value: Vec<u8>,
        key: &SecureKey,
    ) -> Result {
        let full_path = self.get_full_secret_path(path);
        let dir = full_path.parent().expect("path is a file");
        self.ensure_dirs(dir).await?;

        // 1. Encrypt with secret_key first
        let secret_passphrase = key_store::key_to_passphrase(key);
        let inner_encrypted = self.encrypt_with_passphrase(&value, &secret_passphrase).await?;

        // 2. Encrypt with local_key
        let outer_encrypted = self.encrypt_with_passphrase(&inner_encrypted, &self.symmetric_gpg_passphrase).await?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(self.file_mode)
            .open(full_path)
            .await?;

        file.write_all(&outer_encrypted).await?;
        Ok(())
    }

    pub async fn delete_password(&self, path: impl AsRef<Path>) -> Result {
        let full_path = self.get_full_secret_path(path);
        match remove_file(full_path).await {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /****** Some useful FS utilities ******/

    /// list the file and directories inside a parent directory
    pub async fn list_items(&self, dir: impl AsRef<Path>) -> Result<Vec<(FileType, String)>> {
        let dir = self.directory.join(dir);
        self.ensure_dirs(&dir).await?;

        let mut dir_items = read_dir(dir).await?;

        let mut items = vec![];

        while let Some(item) = dir_items.next_entry().await? {
            let file_type = item.file_type().await?;
            let name = item.file_name().to_string_lossy().into_owned();
            items.push((file_type, name));
        }

        Ok(items)
    }

    /// open a file for writing
    pub async fn open_file(&self, file_path: impl AsRef<Path>) -> Result<File> {
        let path = self.directory.join(file_path);
        self.ensure_dirs(path.parent().expect("path is not a file"))
            .await?;

        Ok(OpenOptions::new()
            .write(true)
            .create(true)
            .read(true)
            .mode(self.file_mode)
            .open(path)
            .await?)
    }

    /// get metadata on a file
    pub async fn stat_file(&self, file_path: impl AsRef<Path>) -> Result<Metadata> {
        let path = self.directory.join(file_path);
        self.ensure_dirs(path.parent().expect("path is not a file"))
            .await?;

        Ok(metadata(path).await?)
    }

    /// make a dir and all its parents
    pub async fn make_dir(&self, dir: impl AsRef<Path>) -> Result {
        self.ensure_dirs(self.directory.join(dir)).await
    }

    /// recursively remove a dir
    pub async fn remove_dir(&self, dir: impl AsRef<Path>) -> Result {
        Ok(remove_dir_all(self.directory.join(dir)).await?)
    }

    /// make gpg-agent forget the cached password for the keys associated with the given collections
    pub async fn gpg_forget_cached_password(
        &self,
        collection_dirs: HashSet<impl AsRef<Path>>,
    ) -> Result {
        // all unique GPG key ids to clear cache for
        let mut gpg_ids = HashSet::new();

        for dir in collection_dirs {
            gpg_ids.extend(self.get_gpg_ids(self.directory.join(dir)).await?);
        }

        // get the keygrip for each key
        let gpg_result = self
            .make_gpg_process()
            .arg("--batch")
            .arg("--with-colons")
            .arg("--with-keygrip")
            .arg("--list-key")
            .args(gpg_ids)
            .output()
            .await?;

        // return any errors that occurred
        if !gpg_result.status.success() {
            return Err(Error::GpgError(
                String::from_utf8_lossy(&gpg_result.stderr).into_owned(),
            ));
        }

        let gpg_out =
            String::from_utf8(gpg_result.stdout).expect("gpg colon output is valid UTF-8");

        let mut gpg_line_iter = gpg_out.trim().lines().map(|line| line.split(':'));

        loop {
            // find the (sub)key for encryption
            if gpg_line_iter
                .position(|mut line| {
                    // Field 1: type (index 0)
                    let Some(key_type) = line.nth(0) else {
                        return false;
                    };

                    // public key or subkey
                    if key_type != "pub" && key_type != "sub" {
                        return false;
                    }

                    // Field 12: capabilities (index 11, 10 after type is consumed)
                    let Some(caps) = line.nth(10) else {
                        return false;
                    };

                    // pubkey or subkey that has the 'e' (encryption) capability
                    caps.contains('e')
                })
                .is_none()
            {
                // no more keys with encryption capability found - break
                break;
            }

            // look for the following keygrip
            let Some(keygrip) = gpg_line_iter.find_map(|mut line| {
                let Some(item_type) = line.nth(0) else {
                    return None;
                };

                // keygrip
                if item_type != "grp" {
                    return None;
                }

                // Field 10: keygrip (user id) (index 9, 8 after type is consumed)
                let Some(keygrip) = line.nth(8) else {
                    return None;
                };

                Some(keygrip)
            }) else {
                return Err(Error::GpgError("no keygrip found".into()));
            };

            // make gpg agent forget the passphrase for this key
            let gpg_agent_command = format!("clear_passphrase --mode=normal {}", keygrip);
            let gpg_agent_result = Command::new("gpg-connect-agent")
                .arg(gpg_agent_command)
                .arg("/bye")
                .output()
                .await?;

            if !gpg_agent_result.status.success() {
                return Err(Error::GpgError(
                    String::from_utf8_lossy(&gpg_agent_result.stderr).into_owned(),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_types::SecureArray;

    #[tokio::test]
    async fn test_write_and_read_password_with_key() {
        let temp_dir = std::env::temp_dir().join(format!("test_pass_{}", nanoid::nanoid!()));
        let local_passphrase = SecureString::from("local-test-passphrase");
        let store = PasswordStore::from_env(Some(temp_dir.clone()), local_passphrase).unwrap();

        let mut key_bytes = [42u8; 32];
        let secret_key = SecureArray::from_slice_mut(&mut key_bytes).unwrap();

        let secret_path = "test/secret";
        let secret_value = b"super-secret-password-123".to_vec();

        store
            .write_password_with_key(secret_path, secret_value.clone(), &secret_key)
            .await
            .unwrap();

        let decrypted = store
            .read_password_with_key(secret_path, &secret_key)
            .await
            .unwrap();

        assert_eq!(decrypted, secret_value);

        // Verify that decrypting with wrong key fails
        let mut wrong_bytes = [99u8; 32];
        let wrong_key = SecureArray::from_slice_mut(&mut wrong_bytes).unwrap();
        let wrong_result = store.read_password_with_key(secret_path, &wrong_key).await;
        assert!(wrong_result.is_err());

        // Cleanup
        let _ = remove_dir_all(&temp_dir).await;
    }
}

