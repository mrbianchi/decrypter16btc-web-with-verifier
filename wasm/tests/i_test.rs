// Importa la librería que contiene la función `bcore_decrypt`
use decrypter16btc::bcore_decrypt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcore_decrypt_test_data() {
        // Prueba con el dataset data_test y la contraseña "test"
        let result = bcore_decrypt("test", true);
        assert!(result.is_ok(), "Error al testear con data_test: {:?}", result.err());
        let decrypt_result = result.unwrap();
        assert!(decrypt_result.success);
        assert!(decrypt_result.ckey_decrypted.is_some());
    }

    #[test]
    fn test_bcore_decrypt_wrong_password() {
        // Contraseña incorrecta debe fallar
        let result = bcore_decrypt("wrongpassword", true);
        assert!(result.is_err(), "Debería haber fallado con contraseña incorrecta");
    }
}
