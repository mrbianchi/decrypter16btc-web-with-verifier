mod utils;

use aes::cipher::BlockEncryptMut;
use wasm_bindgen::prelude::*;

use aes::Aes256;
use cbc::cipher::{KeyIvInit, block_padding::Pkcs7, BlockDecryptMut};
use hex;
use sha2::{Digest, Sha256, Sha512};

use cbc::Decryptor;
use cbc::Encryptor;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn bcore_decrypt_wasm(passphrase: String) -> bool {
    match bcore_decrypt(passphrase) {
        Ok(_) => true,
        Err(_) => false
    }
}

pub fn bcore_decrypt(passphrase: String) -> Result<(), String> {

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

    let data = data_16;

    let parts: Vec<&str> = data[0].split('$').collect();
    let encrypted_mkey_hex = parts.get(3).ok_or("Falta encrypted_mkey")?;
    let salt_hex = parts.get(5).ok_or("Falta salt")?;
    let iterations: u32 = parts.get(6).ok_or("Falta iterations")?.parse().map_err(|_| "Iteraciones no válidas")?;

    let salt = hex::decode(salt_hex).map_err(|_| "Salt inválido")?;
    let encrypted_mkey = hex::decode(encrypted_mkey_hex).map_err(|_| "mkey inválido")?;

    println!("encrypted original {:?}", hex::encode(&encrypted_mkey));

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

    let encryptor = Encryptor::<Aes256>::new_from_slices(&decryptkey, &iv)
        .map_err(|_| "No se pudo crear el encryptor")?;

    let reencrypted_mkey = encryptor.encrypt_padded_vec_mut::<Pkcs7>(&decrypted_mkey);

    println!(
        "encrypted original {:?}-re encrypted{:?}",
        hex::encode(&encrypted_mkey),
        hex::encode(&reencrypted_mkey)
    );

    println!("decrypted mkey-{:?}", hex::encode(&decrypted_mkey));

    if encrypted_mkey != reencrypted_mkey {
        return Err("La mkey re-encriptada no coincide con la original".to_string());
    }

    // 16
    //let hex_encrypted_ckey = "";
    //test 
    let hex_encrypted_ckey = "";
    let encrypted_ckey = hex::decode(&data[1]).map_err(|_| "ckey inválido")?;

    // 16
    let pubkey = hex::decode("0200fcf1533b1acf64c345f6488e0c465f781fa6194ea5c3d8f8ee4fd61989ab78").expect("pubkey inválido");
    // test
    let pubkey = hex::decode("").map_err(|_| "pubkey inválido")?;

    let iv_ckey = &sha256(sha256(pubkey))[0..16];

    // AES-256-CBC con clave derivada e IV
    let decryptor = Decryptor::<Aes256>::new_from_slices(&decrypted_mkey[0..32], iv_ckey)
        .map_err(|_| "No se pudo crear el decryptor de ckey")?;

    let decrypted_ckey = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted_ckey)
        .map_err(|_| "Fallo al desencriptar la ckey")?;

    println!("decrypted ckey-{:?}", hex::encode(&decrypted_ckey));

    Ok(())
}

fn sha256(hex: Vec<u8>) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(hex);
    let result = digest.finalize().to_vec();
    println!("hashed vec {:?}", &result);
    println!("hashed {:?}", hex::encode(&result));
    result
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
