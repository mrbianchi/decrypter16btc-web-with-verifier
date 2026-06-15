mod utils;

use aes::cipher::BlockEncryptMut;
use wasm_bindgen::prelude::*;

use aes::Aes256;
use cbc::cipher::{KeyIvInit, BlockDecryptMut, block_padding::Pkcs7};
use hex;
use sha2::{Digest, Sha256, Sha512};

use cbc::Decryptor;
use cbc::Encryptor;

use k256::{
    ecdsa::SigningKey,
    SecretKey,
};
use serde::{Deserialize, Serialize};

use std::sync::Mutex;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Stato globale per memorizzare la ckey decifrata (32 bytes) dopo una decifratura riuscita.
static DECRYPTED_CKEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

#[derive(Serialize, Deserialize)]
pub struct DecryptResult {
    pub success: bool,
    pub error: Option<String>,
    pub ckey_decrypted: Option<String>,
    pub pubkey: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SignResult {
    pub success: bool,
    pub error: Option<String>,
    pub signature_hex: Option<String>,
    pub message: Option<String>,
}

/// Decifra la mkey con la passphrase, poi decifra la ckey con la mkey.
/// Se tutto va bene, memorizza la ckey decifrata e restituisce JSON con i dati.
#[wasm_bindgen]
pub fn bcore_decrypt_wasm(passphrase: String) -> String {
    match bcore_decrypt(&passphrase, false) {
        Ok(result) => serde_json::to_string(&result).unwrap_or_else(|e| {
            format!(r#"{{"success":false,"error":"{}"}}"#, e)
        }),
        Err(e) => {
            // Se fallisce, resettiamo la ckey memorizzata
            let mut ckey_store = DECRYPTED_CKEY.lock().unwrap();
            *ckey_store = None;
            serde_json::to_string(&DecryptResult {
                success: false,
                error: Some(e),
                ckey_decrypted: None,
                pubkey: None,
            }).unwrap()
        }
    }
}

/// Firma un messaggio usando la ckey precedentemente decifrata.
/// Restituisce la firma in formato hex.
#[wasm_bindgen]
pub fn sign_message_wasm(message: String) -> String {
    let result = sign_message_with_ckey(&message);
    serde_json::to_string(&result).unwrap_or_else(|e| {
        format!(r#"{{"success":false,"error":"{}"}}"#, e)
    })
}

pub fn bcore_decrypt(passphrase: &str, use_test_data: bool) -> Result<DecryptResult, String> {
    let data_16 = vec![
        "$bitcoin$96$1bbd24dc0f23175483d619a24e15f4a06e7e1d3d8b13d9a979b7f4223792836f50520c27c698fa9468ff95f481b888f0$16$65e1017f33467568$63533$2$00$2$00",
        "ed08539535cbec7a75f14820a05c7e52c4e8a30885859e7a43f771f330901f39e74d10e005b4b0aa8240a253885f5b8e",
        "0200fcf1533b1acf64c345f6488e0c465f781fa6194ea5c3d8f8ee4fd61989ab78"
    ];
    let data_test = vec![
        "$bitcoin$96$8aef44ef19c8f18196f20511aa714f8456937c5ae43de42697df870eebd2530bf18d3ff64fdb41f9395f6429bcb29d9f$16$b3b4b4af39406076$483644$2$00$2$00",
        "2d3207d4fe9dcb5f1508ee8e98605dc4b96ba165dcbebae651d0774ec4253e12176e1ab15ccbeade29277a29959143ff",
        "036679023406dc5f5656bf7ff60ce1d3266a929bfe70496b651371518b40bcbf4d"
    ];

    let data = if use_test_data { data_test } else { data_16 };

    let parts: Vec<&str> = data[0].split('$').collect();
    let encrypted_mkey_hex = parts.get(3).ok_or("Falta encrypted_mkey")?;
    let salt_hex = parts.get(5).ok_or("Falta salt")?;
    let iterations: u32 = parts.get(6).ok_or("Falta iterations")?.parse().map_err(|_| "Iteraciones no válidas")?;

    let salt = hex::decode(salt_hex).map_err(|_| "Salt inválido")?;
    let encrypted_mkey = hex::decode(encrypted_mkey_hex).map_err(|_| "mkey inválido")?;

    // Derivación de clave e IV
    let (decryptkey, iv) = evp_bytes_to_key(passphrase.as_bytes(), &salt, iterations);

    // AES-256-CBC con clave derivada e IV
    let decryptor = Decryptor::<Aes256>::new_from_slices(&decryptkey, &iv)
        .map_err(|_| "No se pudo crear el decryptor de mkey")?;

    let decrypted_mkey = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted_mkey)
        .map_err(|_| "Fallo al desencriptar la mkey")?;

    if decrypted_mkey.len() != 32 {
        return Err("La clave AES (mkey) debe tener 32 bytes exactamente".to_string());
    }

    // Verifica re-encriptando
    let encryptor = Encryptor::<Aes256>::new_from_slices(&decryptkey, &iv)
        .map_err(|_| "No se pudo crear el encryptor")?;

    let reencrypted_mkey = encryptor.encrypt_padded_vec_mut::<Pkcs7>(&decrypted_mkey);

    if encrypted_mkey != reencrypted_mkey {
        return Err("La mkey re-encriptada no coincide con la original".to_string());
    }

    // Decifra la ckey
    let encrypted_ckey = hex::decode(&data[1]).map_err(|_| "ckey inválido")?;
    let pubkey_hex = data[2];
    let pubkey = hex::decode(pubkey_hex).map_err(|_| "pubkey inválido")?;

    // IV per ckey = primi 16 byte di sha256(sha256(pubkey))
    let iv_ckey = &sha256(&sha256(&pubkey))[0..16];

    let decryptor = Decryptor::<Aes256>::new_from_slices(&decrypted_mkey[0..32], iv_ckey)
        .map_err(|_| "No se pudo crear el decryptor de ckey")?;

    let decrypted_ckey = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted_ckey)
        .map_err(|_| "Fallo al desencriptar la ckey")?;

    if decrypted_ckey.len() != 32 {
        return Err("La ckey descifrada debe tener 32 bytes exactamente".to_string());
    }

    // Memorizza la ckey decifrata per uso futuro (firma)
    let mut ckey_bytes = [0u8; 32];
    ckey_bytes.copy_from_slice(&decrypted_ckey);
    let mut ckey_store = DECRYPTED_CKEY.lock().unwrap();
    *ckey_store = Some(ckey_bytes);

    // Deriva la pubkey dalla ckey (non usare quella del dataset!)
    let secret_key = SecretKey::from_slice(&ckey_bytes)
        .map_err(|_| "No se pudo crear SecretKey desde la ckey")?;
    let signing_key = SigningKey::from(secret_key);
    let derived_pubkey = signing_key.verifying_key().to_encoded_point(false);
    let derived_pubkey_hex = hex::encode(derived_pubkey.as_bytes());

    Ok(DecryptResult {
        success: true,
        error: None,
        ckey_decrypted: Some(hex::encode(&decrypted_ckey)),
        pubkey: Some(derived_pubkey_hex),
    })
}

fn sign_message_with_ckey(message: &str) -> SignResult {
    let ckey_store = DECRYPTED_CKEY.lock().unwrap();
    let ckey_bytes = match *ckey_store {
        Some(bytes) => bytes,
        None => {
            return SignResult {
                success: false,
                error: Some("No hay ckey descifrada. Primero desencripta exitosamente.".to_string()),
                signature_hex: None,
                message: None,
            };
        }
    };

    // Converti i 32 bytes in una SecretKey k256
    let secret_key = match SecretKey::from_slice(&ckey_bytes) {
        Ok(sk) => sk,
        Err(e) => {
            return SignResult {
                success: false,
                error: Some(format!("Error al crear SecretKey: {}", e)),
                signature_hex: None,
                message: None,
            };
        }
    };

    let signing_key = SigningKey::from(secret_key);

    // Hash del messaggio con SHA-256 e firma
    let digest = Sha256::digest(message.as_bytes());
    let (signature, _recovery_id) = signing_key.sign_prehash_recoverable(&digest)
        .map_or_else(
            |e| {
                return (None, format!("Error al firmar: {}", e));
            },
            |(sig, recid)| (Some((sig, recid)), String::new()),
        );

    let (signature, _recovery_id) = match signature {
        Some(sig) => sig,
        None => {
            return SignResult {
                success: false,
                error: Some("Error al firmar: no se pudo crear la firma".to_string()),
                signature_hex: None,
                message: None,
            };
        }
    };

    let sig_hex = hex::encode(signature.to_der().as_bytes());

    SignResult {
        success: true,
        error: None,
        signature_hex: Some(sig_hex),
        message: Some(message.to_string()),
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(data);
    digest.finalize().to_vec()
}

fn evp_bytes_to_key(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
) -> ([u8; 32], [u8; 16]) {
    let mut digest = Sha512::new();
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    let mut temp = vec![];

    // Generate the initial digest
    digest.update(passphrase);
    digest.update(salt);
    temp.extend_from_slice(&digest.finalize_reset());

    // Perform additional iterations
    for _ in 1..iterations {
        digest.update(&temp);
        temp = digest.finalize_reset().to_vec();
    }

    // Extract key and IV
    key.copy_from_slice(&temp[..32]);
    iv.copy_from_slice(&temp[32..48]);

    (key, iv)
}