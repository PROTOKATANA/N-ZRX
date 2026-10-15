//! B-27 · la prima de disponibilidad no cuenta mientras el verificador de almacenamiento sea inerte.
//!
//! - La tabla de votos del contrato solo puede marcar `prueba = true` si
//!   `PRIMA_DISPONIBILIDAD_ACTIVA` (hoy `false` por el verificador inerte) **y** el estado tiene una
//!   prueba vigente: `prueba_i = PRIMA_DISPONIBILIDAD_ACTIVA && Estado.pruebas.contains_key(clave)`.
//! - **M9-b2:** las dos pruebas que ejercitaban el rechazo de una tabla con `prueba = true` en el
//!   compromiso `0x06` y en el certificado `0x04` se retiraron con esas operaciones; su gemela por
//!   peso (`b27_prima_disponibilidad_peso.rs`) documenta el hueco de B-58 (el `0x09` no compara la
//!   tabla siguiente con el estado).
//! - Guardián: si alguien pone `PRIMA_DISPONIBILIDAD_ACTIVA = true` mientras
//!   `verificador_para(Red::Dev)` siga siendo el inerte, el test falla.

use zx_consensus::prueba_almacenamiento::{VerificadorAlmacenamiento, verificador_para};
use zx_consensus::transicion::votos::PRIMA_DISPONIBILIDAD_ACTIVA;
use zx_core::Red;

/// B-27 · guardián: la prima solo puede activarse cuando el verificador de dev deje de ser inerte.
#[test]
fn guardian_la_prima_no_se_activa_con_el_verificador_inerte() {
    if PRIMA_DISPONIBILIDAD_ACTIVA {
        let v = verificador_para(Red::Dev);
        assert!(
            v.is_some_and(|v| !VerificadorAlmacenamiento::es_inerte(v)),
            "B-27: PRIMA_DISPONIBILIDAD_ACTIVA no puede estar en true mientras el verificador de dev sea inerte"
        );
    }
}
