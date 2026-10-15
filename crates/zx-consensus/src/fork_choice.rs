//! Selección de cadena por mayor trabajo acumulado (SPEC §11).
//!
//! Portado de `fork_choice.rs` de `9681061`. **No es «la cadena más larga»**: es la de **mayor
//! trabajo acumulado** (`C-FORK-03`). La distinción no es pedante: «más larga» es falseable minando
//! muchos bloques de dificultad ínfima.
//!
//! # El desempate diverge de Bitcoin a propósito
//!
//! Bitcoin desempata por orden de llegada local (`nSequenceId`), lo que es **no determinista entre
//! nodos**: dos nodos que reciben los mismos bloques en distinto orden sostienen tips distintos.
//! `C-FORK-04` desempata por el **menor hash de tip**, big-endian. Zebra hace lo mismo en producción
//! en la mainnet de Zcash, documentando que se aparta de la spec a propósito.
//!
//! # Lo que **no** entra
//!
//! La profundidad máxima de reorganización (`MAX_REORG_LENGTH`) se **elimina** en esta orden
//! (`R-ZRX/MAPA-RESCATE.md`): en la fase PoW no se limita aquí. Tampoco se porta `ClaveVentana` ni
//! la mecánica de reorg, que pertenecen a la máquina de estados (W03).

use primitive_types::U256;
use zx_core::BlockHash;
use zx_core::target::{TrabajoAcumulado, hash_como_entero, trabajo_bloque};

use crate::error::ErrorPow;

/// Lo mínimo que el fork choice necesita saber de un tip.
///
/// `trabajo` es derivado y cacheable, pero **MUST** poder recalcularse desde los `bits` almacenados
/// (`C-FORK-02`). Nunca es fuente de verdad.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tip {
    /// Hash de la cabecera del tip.
    pub hash: BlockHash,
    /// Altura del tip.
    pub altura: u32,
    /// Trabajo acumulado desde el génesis hasta este bloque, inclusive.
    pub trabajo: TrabajoAcumulado,
}

/// Resultado de comparar dos tips.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Preferencia {
    /// Gana el primero.
    Primero,
    /// Gana el segundo.
    Segundo,
}

/// Compara dos tips según `C-FORK-03` y `C-FORK-04`.
///
/// Primero el trabajo acumulado; en empate **exacto**, el menor `block_hash` interpretado como
/// entero big-endian (la misma convención de `C-POW-01`).
///
/// Es **total y determinista**: dos nodos con los mismos dos tips eligen siempre lo mismo, sin
/// depender del orden de llegada ni de ningún reloj.
#[must_use]
pub fn preferir(a: &Tip, b: &Tip) -> Preferencia {
    match a.trabajo.cmp(&b.trabajo) {
        core::cmp::Ordering::Greater => Preferencia::Primero,
        core::cmp::Ordering::Less => Preferencia::Segundo,
        // C-FORK-04 · desempate determinista por menor hash.
        core::cmp::Ordering::Equal => {
            if hash_como_entero(&b.hash) < hash_como_entero(&a.hash) {
                Preferencia::Segundo
            } else {
                Preferencia::Primero
            }
        }
    }
}

/// Recalcula el trabajo acumulado de una cadena desde sus targets (`C-FORK-02`).
///
/// Existe para poder comprobar que el valor cacheado es correcto: el trabajo **MUST** poder
/// reconstruirse íntegramente desde los `bits` almacenados, así que un caché corrupto es detectable.
///
/// # Errores
/// [`ErrorPow::DesbordamientoAritmetico`] si algún target es inválido o la suma desborda.
pub fn trabajo_acumulado(targets: &[U256]) -> Result<TrabajoAcumulado, ErrorPow> {
    let mut acc = TrabajoAcumulado::cero();
    for t in targets {
        let w = trabajo_bloque(*t).ok_or(ErrorPow::DesbordamientoAritmetico)?;
        acc = acc.sumar(w).ok_or(ErrorPow::DesbordamientoAritmetico)?;
    }
    Ok(acc)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{Preferencia, Tip, preferir, trabajo_acumulado};
    use primitive_types::U256;
    use zx_core::digest::{BlockHash, Digest};
    use zx_core::target::{TrabajoAcumulado, target_inicial_testnet, trabajo_bloque};

    fn hash(primer_byte: u8) -> BlockHash {
        let mut b = [0u8; 32];
        if let Some(p) = b.first_mut() {
            *p = primer_byte;
        }
        BlockHash::from_digest(Digest::from_bytes(b))
    }

    fn tip(primer_byte: u8, altura: u32, trabajo: u64) -> Tip {
        Tip {
            hash: hash(primer_byte),
            altura,
            trabajo: TrabajoAcumulado::cero().sumar(U256::from(trabajo)).unwrap(),
        }
    }

    /// C-FORK-03: gana el trabajo, no la longitud.
    #[test]
    fn gana_el_trabajo_acumulado_no_la_altura() {
        let corta_pero_pesada = tip(1, 10, 1_000_000);
        let larga_pero_ligera = tip(2, 10_000, 999_999);
        assert_eq!(
            preferir(&corta_pero_pesada, &larga_pero_ligera),
            Preferencia::Primero,
            "10 bloques pesados ganan a 10 000 ligeros"
        );
    }

    /// C-FORK-04: el desempate es **determinista** y por el menor hash.
    #[test]
    fn el_desempate_es_por_el_menor_hash() {
        let a = tip(0x10, 5, 500);
        let b = tip(0x02, 5, 500);
        assert_eq!(preferir(&a, &b), Preferencia::Segundo, "0x02… < 0x10…");
        assert_eq!(
            preferir(&b, &a),
            Preferencia::Primero,
            "y al revés, lo mismo"
        );
    }

    /// **La propiedad que motiva C-FORK-04.** El resultado no depende del orden de los argumentos.
    #[test]
    fn el_desempate_es_independiente_del_orden_de_llegada() {
        for i in 1u8..40 {
            for j in 1u8..40 {
                if i == j {
                    continue;
                }
                let a = tip(i, 7, 1234);
                let b = tip(j, 7, 1234);
                let directo = preferir(&a, &b);
                let inverso = preferir(&b, &a);
                let coherente = matches!(
                    (directo, inverso),
                    (Preferencia::Primero, Preferencia::Segundo)
                        | (Preferencia::Segundo, Preferencia::Primero)
                );
                assert!(
                    coherente,
                    "orden inconsistente para hashes {i:#04x} y {j:#04x}"
                );
            }
        }
    }

    /// C-FORK-02: el trabajo acumulado se reconstruye desde los targets. Un caché no es la verdad.
    #[test]
    fn el_trabajo_acumulado_se_puede_recalcular() {
        let targets = vec![target_inicial_testnet(); 5];
        let acc = trabajo_acumulado(&targets).unwrap();
        let uno = trabajo_bloque(target_inicial_testnet()).unwrap();
        assert_eq!(acc.valor(), uno * U256::from(5_u32));

        let mut manual = TrabajoAcumulado::cero();
        for t in &targets {
            manual = manual.sumar(trabajo_bloque(*t).unwrap()).unwrap();
        }
        assert_eq!(manual, acc);
    }

    #[test]
    fn la_cadena_vacia_tiene_trabajo_cero() {
        assert_eq!(trabajo_acumulado(&[]).unwrap(), TrabajoAcumulado::cero());
    }
}
