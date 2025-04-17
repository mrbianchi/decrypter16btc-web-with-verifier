// Importa la librería que contiene la función `bcore_decrypt`
use decrypter16btc::bcore_decrypt;

#[cfg(test)] // Este atributo indica que solo se compilará cuando se realicen pruebas
mod tests {
    // Traemos la función `bcore_decrypt` desde el módulo principal
    use super::*;

    #[test] // Marca la función como una prueba
    fn test_bcore_decrypt() {
        let result = bcore_decrypt(String::from("test"));
        assert_eq!(result.clone(), Ok(()), "Error al testear: {:?}", result.err());
    }
}
