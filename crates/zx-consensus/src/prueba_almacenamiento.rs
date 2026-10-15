//! PT-3bc · verificador de pruebas de almacenamiento como `trait` (`REVISION-PT3a` decisión 7).
//!
//! Mientras el circuito real no existe (PT-3f), el **único** verificador es inerte y marcado, y
//! solo se admite en `Red::Dev`. Fuera de dev [`verificador_para`] devuelve `None`: un nodo de otra
//! red **no arranca** con el verificador inerte.

use zx_core::{OperacionAlmacenamiento, Red};

/// Verificador de pruebas de almacenamiento.
pub trait VerificadorAlmacenamiento: Send + Sync + core::fmt::Debug {
    /// Verifica una operación de prueba de almacenamiento (`0x01`/`0x02`).
    ///
    /// Devuelve `false` si la prueba no verifica. El verificador inerte acepta toda operación bien
    /// formada.
    fn verificar_prueba(&self, op: &OperacionAlmacenamiento) -> bool;

    /// ¿Es el verificador **inerte** (marcado, sin circuito real)? Solo dev en PT-3bc.
    fn es_inerte(&self) -> bool;
}

/// Verificador inerte: acepta toda prueba de almacenamiento bien formada.
///
/// Marcado (`es_inerte() == true`) para que ningún perfil de producción lo confunda con el real.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerificadorInerte;

impl VerificadorAlmacenamiento for VerificadorInerte {
    fn verificar_prueba(&self, op: &OperacionAlmacenamiento) -> bool {
        op.clase().es_prueba()
    }

    fn es_inerte(&self) -> bool {
        true
    }
}

/// Instancia estática del verificador inerte.
pub static VERIFICADOR_INERTE: VerificadorInerte = VerificadorInerte;

/// Verificador admitido para `red`.
///
/// **Solo `Red::Dev`** admite el inerte; cualquier otro perfil devuelve `None` y el arranque debe
/// fallar (`REVISION-PT3a` decisión 7).
#[must_use]
pub fn verificador_para(red: Red) -> Option<&'static dyn VerificadorAlmacenamiento> {
    match red {
        Red::Dev => Some(&VERIFICADOR_INERTE),
        Red::Mainnet | Red::Testnet => None,
    }
}

/// `exigir_prueba_almacenamiento` efectivo del perfil: fuera de dev se **fuerza** a `true`.
#[must_use]
pub const fn exigir_prueba_almacenamiento(red: Red, perfil: bool) -> bool {
    match red {
        Red::Dev => perfil,
        Red::Mainnet | Red::Testnet => true,
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]

    use super::{VerificadorAlmacenamiento, exigir_prueba_almacenamiento, verificador_para};
    use zx_core::{ClavePublica, OperacionAlmacenamiento, Red};

    #[test]
    fn solo_dev_admite_el_verificador_inerte() {
        assert!(
            verificador_para(Red::Dev).is_some_and(VerificadorAlmacenamiento::es_inerte),
            "dev admite el inerte marcado"
        );
        assert!(
            verificador_para(Red::Mainnet).is_none(),
            "mainnet no puede arrancar con el inerte"
        );
        assert!(
            verificador_para(Red::Testnet).is_none(),
            "testnet no puede arrancar con el inerte"
        );
    }

    #[test]
    fn fuera_de_dev_se_fuerza_la_puerta() {
        assert!(!exigir_prueba_almacenamiento(Red::Dev, false));
        assert!(exigir_prueba_almacenamiento(Red::Dev, true));
        assert!(exigir_prueba_almacenamiento(Red::Mainnet, false));
        assert!(exigir_prueba_almacenamiento(Red::Testnet, false));
    }

    #[test]
    fn el_inerte_acepta_las_pruebas_bien_formadas() {
        let op = OperacionAlmacenamiento::PoSt {
            clave: ClavePublica::desde_bytes([1; 32]),
            epoch: 1,
            n_sectores: 1,
            raiz_conjunto: [0; 32],
            prueba: vec![1, 2, 3],
        };
        let v = verificador_para(Red::Dev).expect("dev tiene verificador");
        assert!(v.verificar_prueba(&op));
        let cv = OperacionAlmacenamiento::ClaveVoto {
            clave: ClavePublica::desde_bytes([2; 32]),
            clave_bls: [0; 48],
            prueba_posesion: [0; 96],
        };
        assert!(
            !v.verificar_prueba(&cv),
            "el inerte solo verifica 0x01/0x02"
        );
    }
}
