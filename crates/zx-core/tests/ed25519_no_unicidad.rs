//! Regresión de la inferencia «firmador determinista => firma válida única».
//!
//! Estos vectores pertenecen a una clave de prueba pública (semilla `[0x42; 32]`).
//! El propietario eligió dos nonces distintos para el mismo mensaje de 32 bytes.
//! Se comprueba el verificador real, no un sustituto de Ed25519 ni bloques DAG completos.
//! Véase `veritas/consenso/identidad-copias/INFORME.md` para construcción y alcance.

use ed25519_zebra::{SigningKey, VerificationKey};
use zx_core::firma::{ClavePublica, Firma, verificar};

fn vector<const N: usize>(texto: &str) -> Result<[u8; N], hex::FromHexError> {
    let mut bytes = [0u8; N];
    hex::decode_to_slice(texto, &mut bytes)?;
    Ok(bytes)
}

#[test]
fn dos_firmas_distintas_del_propietario_verifican_el_mismo_mensaje() -> Result<(), hex::FromHexError>
{
    let mensaje = [0x5au8; 32];
    let publica = vector::<32>("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")?;
    let firma_1 = vector::<64>(concat!(
        "24ef009e018cee33fac042bd1f4cfbeeed1c579a7f653ab032a8f2783285ae6fcc81",
        "0fbd4fbe13196e333e5232caa3b3f0e3d86ef2c1b7c87bfaf669c25ee805"
    ))?;
    let firma_2 = vector::<64>(concat!(
        "2efd2c9cbbf50d0088858d79f49923fde9556cf7c3dd3466411be33b8e53cd08e",
        "68394026b9f4881d6ea66adbe82f9604a3a80da36711c891c259239d61b200e"
    ))?;

    // No se usa una clave de orden pequeño ni otra clave excepcional.
    let privada = SigningKey::from([0x42u8; 32]);
    let publica_normal: [u8; 32] = VerificationKey::from(&privada).into();
    assert_eq!(publica, publica_normal);

    // El firmador estándar sigue siendo determinista. Es una propiedad diferente.
    let estandar_1: [u8; 64] = privada.sign(&mensaje).into();
    let estandar_2: [u8; 64] = privada.sign(&mensaje).into();
    assert_eq!(estandar_1, estandar_2);
    assert_ne!(firma_1, firma_2);
    assert_ne!(firma_1, estandar_1);
    assert_ne!(firma_2, estandar_1);

    let clave = ClavePublica::desde_bytes(publica);
    let mut otro_mensaje = mensaje;
    otro_mensaje[0] ^= 1;
    let otra_privada = SigningKey::from([0x43u8; 32]);
    let otra_publica: [u8; 32] = VerificationKey::from(&otra_privada).into();
    let otra_clave = ClavePublica::desde_bytes(otra_publica);

    for bytes in [firma_1, firma_2] {
        let firma = Firma::desde_bytes(bytes);
        assert!(verificar(&clave, &firma, &mensaje).is_ok());
        assert!(verificar(&clave, &firma, &otro_mensaje).is_err());
        assert!(verificar(&otra_clave, &firma, &mensaje).is_err());
    }
    Ok(())
}
