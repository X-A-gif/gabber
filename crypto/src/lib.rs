use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    framing::{MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent},
    group::{GroupId, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedWelcome},
    key_packages::KeyPackageIn,
    prelude::{tls_codec::*, Ciphersuite, MlsMessageOut, OpenMlsProvider, ProtocolVersion},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use std::{collections::HashMap, io::Cursor, sync::RwLock};
use tls_codec::Serialize;
use wasm_bindgen::prelude::*;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
const MAX_PROVIDER_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROVIDER_RECORDS: usize = 100_000;
const MAX_PROVIDER_ENTRY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
struct GabberProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for GabberProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

fn serialize_storage(storage: &MemoryStorage) -> Result<Vec<u8>, JsError> {
    let values = storage
        .values
        .read()
        .map_err(|_| JsError::new("MLS storage lock is poisoned"))?;
    if values.len() > MAX_PROVIDER_RECORDS {
        return Err(JsError::new("MLS storage contains too many records"));
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for (key, value) in values.iter() {
        if key.len() > MAX_PROVIDER_ENTRY_BYTES || value.len() > MAX_PROVIDER_ENTRY_BYTES {
            return Err(JsError::new("MLS storage record exceeds the size limit"));
        }
        bytes.extend_from_slice(&(key.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(value);
        if bytes.len() > MAX_PROVIDER_SNAPSHOT_BYTES {
            return Err(JsError::new("MLS storage snapshot exceeds 32 MiB"));
        }
    }
    Ok(bytes)
}

fn deserialize_storage(bytes: &[u8]) -> Result<MemoryStorage, JsError> {
    if bytes.len() > MAX_PROVIDER_SNAPSHOT_BYTES {
        return Err(JsError::new("MLS storage snapshot exceeds 32 MiB"));
    }
    let mut cursor = Cursor::new(bytes);
    let read_u32 = |cursor: &mut Cursor<&[u8]>| -> Result<u32, JsError> {
        let mut value = [0u8; 4];
        std::io::Read::read_exact(cursor, &mut value)
            .map_err(|_| JsError::new("MLS storage snapshot is truncated"))?;
        Ok(u32::from_be_bytes(value))
    };
    let count = read_u32(&mut cursor)? as usize;
    if count > MAX_PROVIDER_RECORDS {
        return Err(JsError::new(
            "MLS storage snapshot contains too many records",
        ));
    }
    let mut values = HashMap::with_capacity(count);
    for _ in 0..count {
        let key_len = read_u32(&mut cursor)? as usize;
        let value_len = read_u32(&mut cursor)? as usize;
        if key_len > MAX_PROVIDER_ENTRY_BYTES || value_len > MAX_PROVIDER_ENTRY_BYTES {
            return Err(JsError::new("MLS storage record exceeds the size limit"));
        }
        let mut key = vec![0u8; key_len];
        let mut value = vec![0u8; value_len];
        std::io::Read::read_exact(&mut cursor, &mut key)
            .map_err(|_| JsError::new("MLS storage snapshot is truncated"))?;
        std::io::Read::read_exact(&mut cursor, &mut value)
            .map_err(|_| JsError::new("MLS storage snapshot is truncated"))?;
        values.insert(key, value);
    }
    if cursor.position() as usize != bytes.len() {
        return Err(JsError::new("MLS storage snapshot contains trailing bytes"));
    }
    Ok(MemoryStorage {
        values: RwLock::new(values),
    })
}

#[wasm_bindgen]
pub struct MlsClient {
    provider: GabberProvider,
    signature_keys: SignatureKeyPair,
    credential: CredentialWithKey,
}

#[wasm_bindgen]
pub struct MlsGroupSession {
    group: MlsGroup,
}

#[wasm_bindgen]
pub struct Invitation {
    commit: Vec<u8>,
    welcome: Vec<u8>,
}

#[wasm_bindgen]
impl Invitation {
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Vec<u8> {
        self.commit.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Vec<u8> {
        self.welcome.clone()
    }
}

#[wasm_bindgen]
impl MlsClient {
    #[wasm_bindgen(constructor)]
    pub fn new(name: &str) -> Result<MlsClient, JsError> {
        let provider = GabberProvider::default();
        let signature_keys = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|error| JsError::new(&error.to_string()))?;
        signature_keys
            .store(provider.storage())
            .map_err(|error| JsError::new(&error.to_string()))?;

        let credential = BasicCredential::new(name.as_bytes().to_vec());
        let credential = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        };

        Ok(Self {
            provider,
            signature_keys,
            credential,
        })
    }

    pub fn restore(
        name: &str,
        snapshot: &[u8],
        public_signature_key: &[u8],
    ) -> Result<MlsClient, JsError> {
        if public_signature_key.len() != 32 {
            return Err(JsError::new("Invalid MLS signature key in saved session"));
        }
        let provider = GabberProvider {
            crypto: RustCrypto::default(),
            storage: deserialize_storage(snapshot)?,
        };
        let signature_keys = SignatureKeyPair::read(
            provider.storage(),
            public_signature_key,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| JsError::new("Saved MLS signature key is missing from local state"))?;
        let credential = BasicCredential::new(name.as_bytes().to_vec());
        let credential = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        };
        Ok(Self {
            provider,
            signature_keys,
            credential,
        })
    }

    pub fn export_storage(&self) -> Result<Vec<u8>, JsError> {
        serialize_storage(self.provider.storage())
    }

    pub fn create_key_package(&self) -> Result<Vec<u8>, JsError> {
        let key_package = openmls::prelude::KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signature_keys,
                self.credential.clone(),
            )
            .map_err(|error| JsError::new(&error.to_string()))?
            .key_package()
            .tls_serialize_detached()
            .map_err(|error| JsError::new(&error.to_string()))?;

        Ok(key_package)
    }

    pub fn key_package_signature_key(&self, key_package_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
        let key_package = KeyPackageIn::tls_deserialize_exact_bytes(key_package_bytes)
            .map_err(|error| JsError::new(&error.to_string()))?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(key_package.leaf_node().signature_key().as_slice().to_vec())
    }

    pub fn public_signature_key(&self) -> Vec<u8> {
        self.signature_keys.public().to_vec()
    }

    pub fn create_group(&self, group_id: &[u8]) -> Result<MlsGroupSession, JsError> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signature_keys,
            &config,
            GroupId::from_slice(group_id),
            self.credential.clone(),
        )
        .map_err(|error| JsError::new(&error.to_string()))?;

        Ok(MlsGroupSession { group })
    }

    pub fn join_group(&self, welcome_bytes: &[u8]) -> Result<MlsGroupSession, JsError> {
        let welcome_message = MlsMessageIn::tls_deserialize_exact_bytes(welcome_bytes)
            .map_err(|error| JsError::new(&error.to_string()))?
            .extract();
        let MlsMessageBodyIn::Welcome(welcome) = welcome_message else {
            return Err(JsError::new("Expected an MLS Welcome message"));
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(|error| JsError::new(&error.to_string()))?;
        let group = staged
            .into_group(&self.provider)
            .map_err(|error| JsError::new(&error.to_string()))?;

        Ok(MlsGroupSession { group })
    }

    pub fn load_group(&self, group_id: &[u8]) -> Result<MlsGroupSession, JsError> {
        let group_id = GroupId::from_slice(group_id);
        let group = MlsGroup::load(self.provider.storage(), &group_id)
            .map_err(|error| JsError::new(&error.to_string()))?
            .ok_or_else(|| JsError::new("Saved MLS group is missing from local state"))?;
        Ok(MlsGroupSession { group })
    }
}

#[wasm_bindgen]
impl MlsGroupSession {
    pub fn group_id(&self) -> Vec<u8> {
        self.group.group_id().as_slice().to_vec()
    }

    pub fn has_member_signature_key(&self, signature_key: &[u8]) -> bool {
        self.group
            .members()
            .any(|member| member.signature_key.as_slice() == signature_key)
    }

    pub fn add_member(
        &mut self,
        client: &MlsClient,
        key_package_bytes: &[u8],
    ) -> Result<Invitation, JsError> {
        let key_package = KeyPackageIn::tls_deserialize_exact_bytes(key_package_bytes)
            .map_err(|error| JsError::new(&error.to_string()))?
            .validate(client.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|error| JsError::new(&error.to_string()))?;
        let (commit, welcome, _) = self
            .group
            .add_members(
                &client.provider,
                &client.signature_keys,
                std::slice::from_ref(&key_package),
            )
            .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(Invitation {
            commit: serialize_message(&commit)?,
            welcome: serialize_message(&welcome)?,
        })
    }

    pub fn merge_pending_commit(&mut self, client: &MlsClient) -> Result<(), JsError> {
        self.group
            .merge_pending_commit(&client.provider)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    pub fn encrypt(&mut self, client: &MlsClient, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let message = self
            .group
            .create_message(&client.provider, &client.signature_keys, plaintext)
            .map_err(|error| JsError::new(&error.to_string()))?;

        serialize_message(&message)
    }

    pub fn decrypt(&mut self, client: &MlsClient, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        let message = MlsMessageIn::tls_deserialize_exact_bytes(ciphertext)
            .map_err(|error| JsError::new(&error.to_string()))?
            .try_into_protocol_message()
            .map_err(|error| JsError::new(&error.to_string()))?;
        let processed = self
            .group
            .process_message(&client.provider, message)
            .map_err(|error| JsError::new(&error.to_string()))?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
            _ => Err(JsError::new(
                "Received an MLS control message, not chat content",
            )),
        }
    }
}

fn serialize_message(message: &MlsMessageOut) -> Result<Vec<u8>, JsError> {
    message
        .tls_serialize_detached()
        .map_err(|error| JsError::new(&error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{MlsClient, MlsMessageIn};
    use tls_codec::DeserializeBytes;

    #[test]
    fn two_clients_exchange_only_mls_ciphertext() {
        let alice = MlsClient::new("alice").expect("create Alice identity");
        let bob = MlsClient::new("bob").expect("create Bob identity");
        let bob_key_package = bob.create_key_package().expect("create Bob key package");

        let mut alice_group = alice
            .create_group(b"gabber-local-test")
            .expect("create MLS group");
        let invitation = alice_group
            .add_member(&alice, &bob_key_package)
            .expect("add Bob to MLS group");
        alice_group
            .merge_pending_commit(&alice)
            .expect("merge add-member commit");
        let mut bob_group = bob
            .join_group(&invitation.welcome())
            .expect("join MLS group from Welcome");

        let plaintext = b"secret test message";
        let ciphertext = alice_group
            .encrypt(&alice, plaintext)
            .expect("encrypt message");
        assert_ne!(ciphertext, plaintext);
        assert!(!ciphertext
            .windows(plaintext.len())
            .any(|window| window == plaintext));

        assert_eq!(
            bob_group
                .decrypt(&bob, &ciphertext)
                .expect("decrypt message"),
            plaintext
        );
    }

    #[test]
    fn wrong_group_cannot_decrypt_message() {
        let alice = MlsClient::new("alice").expect("create Alice identity");
        let bob = MlsClient::new("bob").expect("create Bob identity");
        let mallory = MlsClient::new("mallory").expect("create Mallory identity");
        let bob_key_package = bob.create_key_package().expect("create Bob key package");
        let mut alice_group = alice
            .create_group(b"gabber-test-group")
            .expect("create MLS group");
        let invitation = alice_group
            .add_member(&alice, &bob_key_package)
            .expect("add Bob to MLS group");
        alice_group
            .merge_pending_commit(&alice)
            .expect("merge add-member commit");
        let mut bob_group = bob
            .join_group(&invitation.welcome())
            .expect("join MLS group from Welcome");
        let ciphertext = alice_group
            .encrypt(&alice, b"not for Mallory")
            .expect("encrypt message");
        let mut unrelated_group = mallory
            .create_group(b"unrelated-group")
            .expect("create unrelated group");

        let unrelated_message = MlsMessageIn::tls_deserialize_exact_bytes(&ciphertext)
            .expect("deserialize MLS ciphertext")
            .try_into_protocol_message()
            .expect("parse MLS protocol message");
        assert!(unrelated_group
            .group
            .process_message(&mallory.provider, unrelated_message)
            .is_err());
        assert_eq!(
            bob_group
                .decrypt(&bob, &ciphertext)
                .expect("decrypt message"),
            b"not for Mallory"
        );
    }

    #[test]
    fn restored_client_resumes_existing_group_ratchets() {
        let alice = MlsClient::new("alice").expect("create Alice identity");
        let bob = MlsClient::new("bob").expect("create Bob identity");
        let bob_key_package = bob.create_key_package().expect("create Bob key package");
        let mut alice_group = alice
            .create_group(b"gabber-persisted-test")
            .expect("create MLS group");
        let invitation = alice_group
            .add_member(&alice, &bob_key_package)
            .expect("add Bob to MLS group");
        alice_group
            .merge_pending_commit(&alice)
            .expect("merge add-member commit");
        let mut bob_group = bob
            .join_group(&invitation.welcome())
            .expect("join MLS group from Welcome");

        let first_message = alice_group
            .encrypt(&alice, b"before restart")
            .expect("encrypt before restart");
        assert_eq!(
            bob_group
                .decrypt(&bob, &first_message)
                .expect("decrypt before restart"),
            b"before restart"
        );

        let group_id = alice_group.group_id();
        let snapshot = alice.export_storage().expect("serialize Alice storage");
        let restored_alice = MlsClient::restore("alice", &snapshot, &alice.public_signature_key())
            .expect("restore Alice client");
        let mut restored_group = restored_alice
            .load_group(&group_id)
            .expect("load saved MLS group");
        let second_message = restored_group
            .encrypt(&restored_alice, b"after restart")
            .expect("encrypt after restart");
        assert_eq!(
            bob_group
                .decrypt(&bob, &second_message)
                .expect("decrypt after restart"),
            b"after restart"
        );
    }
}
