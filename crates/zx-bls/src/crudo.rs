//! Capa `crudo`: la primitiva BLS **sin** la separación de dominio de ZEROX.
//!
//! ⚠️ **No usar desde ZEROX.** La API de consenso es la del crate raíz, que exige `dominio` no
//! vacío y firma `len_u16_be || dominio || mensaje`. Este módulo existe por dos motivos:
//!
//! 1. **vectores oficiales.** El borrador IETF firma el mensaje tal cual; para reproducir
//!    `ethereum/bls12-381-tests` hay que llamar a la primitiva sin prefijo;
//! 2. **capa interna** de la API con `dominio`, que solo antepone el prefijo y delega aquí.
//!
//! Los DST son los del borrador POP (decisión 1) y no cambian.

use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::{BLST_ERROR, MultiPoint, blst_fp12, blst_p1_affine, blst_p2_affine};

use crate::clave::{ClavePublica, ClaveSecreta};
use crate::error::{ErrorBLS, motivo_blst};
use crate::firma::{Firma, FirmaAgregada};

/// Longitud en bytes de cada escalar de lote (128 bits).
pub const LONGITUD_ESCALAR_LOTE: usize = 16;

/// Bits que consume `blst` de cada escalar de lote.
const BITS_ESCALAR_LOTE: usize = 8 * LONGITUD_ESCALAR_LOTE;

/// DST de firma del esquema POP (draft-irtf-cfrg-bls-signature).
pub const DST_FIRMA: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// DST de la prueba de posesión del esquema POP.
pub const DST_POSESION: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Firma `mensaje` con el DST de firma del borrador, sin prefijo de dominio.
#[must_use]
pub fn firmar(clave: &ClaveSecreta, mensaje: &[u8]) -> Firma {
    let firma = clave.interna().sign(mensaje, DST_FIRMA, &[]);
    Firma::desde_interna(firma)
}

/// Verifica una firma individual con el DST de firma del borrador.
///
/// # Errores
/// [`ErrorBLS::VerificacionFallida`] si la firma no corresponde a `(clave, mensaje)`.
pub fn verificar(clave: &ClavePublica, firma: &Firma, mensaje: &[u8]) -> Result<(), ErrorBLS> {
    let error = firma
        .interna()
        .verify(true, mensaje, DST_FIRMA, &[], clave.interna(), true);
    exito(error)
}

/// `PopProve(sk)`: firma la **propia clave pública** con el DST de prueba de posesión.
#[must_use]
pub fn firmar_posesion(clave: &ClaveSecreta) -> Firma {
    let publica = clave.clave_publica().bytes();
    let firma = clave.interna().sign(&publica, DST_POSESION, &[]);
    Firma::desde_interna(firma)
}

/// `PopVerify(pk, proof)`: la prueba debe firmar la clave pública con el DST de posesión.
///
/// # Errores
/// [`ErrorBLS::VerificacionFallida`] si la prueba no es válida para `clave`.
pub fn verificar_posesion(clave: &ClavePublica, prueba: &Firma) -> Result<(), ErrorBLS> {
    let publica = clave.bytes();
    let error = prueba
        .interna()
        .verify(true, &publica, DST_POSESION, &[], clave.interna(), true);
    exito(error)
}

/// Agrega firmas con comprobación de subgrupo de cada una.
///
/// # Errores
/// [`ErrorBLS::AgregacionVacia`] si la lista está vacía; [`ErrorBLS::FirmaInvalida`] si alguna no
/// es un punto de G2 del subgrupo.
pub fn agregar_firmas(firmas: &[&Firma]) -> Result<FirmaAgregada, ErrorBLS> {
    if firmas.is_empty() {
        return Err(ErrorBLS::AgregacionVacia);
    }
    let referencias: Vec<&Signature> = firmas.iter().map(|firma| firma.interna()).collect();
    let agregada =
        AggregateSignature::aggregate(&referencias, true).map_err(|e| ErrorBLS::FirmaInvalida {
            motivo: motivo_blst(e),
        })?;
    Ok(FirmaAgregada::desde_interna(agregada))
}

/// `fast_aggregate_verify`: un mismo mensaje y `N` claves (se agregan las claves).
///
/// Las claves se suponen **con prueba de posesión verificada** (como exige el esquema POP).
///
/// # Errores
/// [`ErrorBLS::AgregacionVacia`] si no hay claves; [`ErrorBLS::VerificacionFallida`] si el
/// certificado no verifica.
pub fn fast_aggregate_verify(
    claves: &[&ClavePublica],
    firma: &FirmaAgregada,
    mensaje: &[u8],
) -> Result<(), ErrorBLS> {
    if claves.is_empty() {
        return Err(ErrorBLS::AgregacionVacia);
    }
    let publicas: Vec<&PublicKey> = claves.iter().map(|clave| clave.interna()).collect();
    let error = firma
        .interna()
        .to_signature()
        .fast_aggregate_verify(true, mensaje, DST_FIRMA, &publicas);
    exito(error)
}

/// Verifica por lotes `N` firmas del **mismo** mensaje con escalares `r_i` dados.
///
/// Comprueba `e(Σ r_i·σ_i, g₁) == e(H(m), Σ r_i·pk_i)` con **dos multiplicaciones múltiples**
/// (Pippenger: `blst::MultiPoint::mult` sobre `[PublicKey]`/`[Signature]`, que es la
/// implementación segura de `blst::p1_affines`/`blst::p2_affines::mult`) y **dos emparejamientos**.
///
/// ## Invariante: cada punto ya está en el subgrupo de orden primo
///
/// Esta función **no** revalida el subgrupo (ni el no-infinito) de cada clave y cada firma: lo
/// **garantiza el tipo**. Una [`ClavePublica`] o una [`Firma`] solo se materializan desde bytes
/// externos por `ClavePublica::desde_bytes` / `Firma::desde_bytes`, que delegan en
/// `PublicKey::key_validate` / `Signature::sig_validate(_, true)` y **rechazan** el punto fuera del
/// subgrupo y el infinito; los demás constructores parten de puntos ya validados por `blst`
/// (`sk_to_pk`, `sign`, `aggregate`). Por eso revalidar los `2·N` puntos por lote era trabajo
/// redundante (FV-4b-1-3). El test `tests/lote.rs::un_punto_fuera_de_subgrupo_no_entra_en_los_tipos`
/// fija el invariante: los bytes de un punto de la curva fuera del subgrupo **no** se pueden
/// convertir en `Firma` ni en `ClavePublica`.
///
/// Las claves **deben** tener prueba de posesión verificada (esquema POP; la registra PT-3bc): sin
/// ella, un lote aleatorizado sigue siendo vulnerable a claves rebeldes. La aleatorización `r_i` es
/// la que impide que un **desplazamiento compensado** (`σ₁+Δ`, `σ₂−Δ`, suma intacta) pase el lote.
///
/// # Errores
/// [`ErrorBLS::LongitudesLoteIncompatibles`] si `claves`, `firmas` y `escalares` no miden lo mismo;
/// [`ErrorBLS::AgregacionVacia`] si el lote está vacío;
/// [`ErrorBLS::VerificacionFallida`] si la combinación lineal no cuadra.
pub fn verificar_lote_con_escalares(
    claves: &[&ClavePublica],
    firmas: &[&Firma],
    escalares: &[[u8; LONGITUD_ESCALAR_LOTE]],
    mensaje: &[u8],
) -> Result<(), ErrorBLS> {
    if claves.len() != firmas.len() || claves.len() != escalares.len() {
        return Err(ErrorBLS::LongitudesLoteIncompatibles {
            claves: claves.len(),
            firmas: firmas.len(),
            escalares: escalares.len(),
        });
    }
    if claves.is_empty() {
        return Err(ErrorBLS::AgregacionVacia);
    }

    // Sin revalidación por punto: `ClavePublica`/`Firma` ya garantizan subgrupo y no-infinito
    // (invariante de tipo documentado arriba). Ver `tests/lote.rs`.
    let planos = escalares_planos(escalares);
    let publicas: Vec<PublicKey> = claves.iter().map(|clave| *clave.interna()).collect();
    let firmas_blst: Vec<Signature> = firmas.iter().map(|firma| *firma.interna()).collect();

    // Σ r_i·pk_i (G1) y Σ r_i·σ_i (G2), ambos con el mismo vector de escalares.
    let producto_claves = publicas
        .as_slice()
        .mult(&planos, BITS_ESCALAR_LOTE)
        .to_public_key();
    let producto_firmas = firmas_blst
        .as_slice()
        .mult(&planos, BITS_ESCALAR_LOTE)
        .to_signature();

    // H(m) = 1 · H(m) y g₁ = 1 · g₁, para los dos emparejamientos.
    let h_m = Firma::desde_bytes(&hash_a_g2(mensaje, DST_FIRMA)?)?;
    let mut uno = [0u8; 32];
    if let Some(ultimo) = uno.last_mut() {
        *ultimo = 1;
    }
    let generador_clave = ClaveSecreta::desde_bytes(&uno)?.clave_publica();
    let generador: PublicKey = *generador_clave.interna();

    let firmas_afin: &blst_p2_affine = (&producto_firmas).into();
    let generador_afin: &blst_p1_affine = (&generador).into();
    let claves_afin: &blst_p1_affine = (&producto_claves).into();
    let h_m_afin: &blst_p2_affine = h_m.interna().into();

    let lado_firmas = blst_fp12::miller_loop(firmas_afin, generador_afin).final_exp();
    let lado_claves = blst_fp12::miller_loop(h_m_afin, claves_afin).final_exp();
    if lado_firmas == lado_claves {
        Ok(())
    } else {
        Err(ErrorBLS::VerificacionFallida)
    }
}

/// Un agregado del lote de [`verificar_lote_de_agregados_con_escalares`].
///
/// `claves` es el mapa local del agregado (las claves de **su** subred que cubre la firma agregada);
/// el orden no importa porque se suman. `firma` es la suma de las firmas individuales de esas claves
/// sobre el mensaje común del lote.
#[derive(Clone, Copy, Debug)]
pub struct AgregadoLote<'a> {
    /// Claves públicas que cubre el mapa local.
    pub claves: &'a [&'a ClavePublica],
    /// Firma agregada de esas claves sobre el mensaje común.
    pub firma: &'a FirmaAgregada,
}

/// Verifica por lotes `N` **agregados** del mismo mensaje, cada uno contra su mapa de claves, con
/// escalares `r_j` dados.
///
/// Comprueba `e(Σ_j r_j·σ_j, g₁) == e(H(m), Σ_j r_j·(Σ_{i∈S_j} pk_i))` con dos multiplicaciones
/// múltiples y dos emparejamientos, igual que [`verificar_lote_con_escalares`], pero cada firma
/// agregada `σ_j` se pondera **una vez** y su clave es la suma de las claves de su mapa `S_j`.
/// La aleatorización `r_j` impide que un **desplazamiento compensado entre agregados**
/// (`σ₁+Δ`, `σ₂−Δ`) pase el lote.
///
/// ## Invariante
///
/// Cada [`ClavePublica`] y cada [`FirmaAgregada`] del lote ya garantizan subgrupo y no-infinito (ver
/// [`verificar_lote_con_escalares`]); esta función **no** los revalida.
///
/// # Errores
/// [`ErrorBLS::LongitudesLoteIncompatibles`] si `agregados` y `escalares` no miden lo mismo;
/// [`ErrorBLS::AgregacionVacia`] si el lote está vacío o algún mapa no tiene claves;
/// [`ErrorBLS::VerificacionFallida`] si la combinación lineal no cuadra.
pub fn verificar_lote_de_agregados_con_escalares(
    agregados: &[AgregadoLote<'_>],
    escalares: &[[u8; LONGITUD_ESCALAR_LOTE]],
    mensaje: &[u8],
) -> Result<(), ErrorBLS> {
    if agregados.len() != escalares.len() {
        return Err(ErrorBLS::LongitudesLoteIncompatibles {
            claves: agregados.len(),
            firmas: agregados.len(),
            escalares: escalares.len(),
        });
    }
    if agregados.is_empty() {
        return Err(ErrorBLS::AgregacionVacia);
    }

    let total_claves: usize = agregados.iter().map(|agregado| agregado.claves.len()).sum();
    let mut publicas: Vec<PublicKey> = Vec::with_capacity(total_claves);
    let mut escalares_claves: Vec<u8> = Vec::with_capacity(total_claves * LONGITUD_ESCALAR_LOTE);
    let mut firmas_blst: Vec<Signature> = Vec::with_capacity(agregados.len());
    let mut escalares_firmas: Vec<u8> = Vec::with_capacity(agregados.len() * LONGITUD_ESCALAR_LOTE);

    for (agregado, escalar) in agregados.iter().zip(escalares) {
        if agregado.claves.is_empty() {
            return Err(ErrorBLS::AgregacionVacia);
        }
        for clave in agregado.claves {
            publicas.push(*clave.interna());
            escalares_claves.extend_from_slice(escalar);
        }
        firmas_blst.push(agregado.firma.interna().to_signature());
        escalares_firmas.extend_from_slice(escalar);
    }

    // Σ_j r_j·(Σ_{i∈S_j} pk_i) (G1) y Σ_j r_j·σ_j (G2): una sola pasada por agregado en cada lado.
    let producto_claves = publicas
        .as_slice()
        .mult(&escalares_claves, BITS_ESCALAR_LOTE)
        .to_public_key();
    let producto_firmas = firmas_blst
        .as_slice()
        .mult(&escalares_firmas, BITS_ESCALAR_LOTE)
        .to_signature();

    let h_m = Firma::desde_bytes(&hash_a_g2(mensaje, DST_FIRMA)?)?;
    let mut uno = [0u8; 32];
    if let Some(ultimo) = uno.last_mut() {
        *ultimo = 1;
    }
    let generador_clave = ClaveSecreta::desde_bytes(&uno)?.clave_publica();
    let generador: PublicKey = *generador_clave.interna();

    let firmas_afin: &blst_p2_affine = (&producto_firmas).into();
    let generador_afin: &blst_p1_affine = (&generador).into();
    let claves_afin: &blst_p1_affine = (&producto_claves).into();
    let h_m_afin: &blst_p2_affine = h_m.interna().into();

    let lado_firmas = blst_fp12::miller_loop(firmas_afin, generador_afin).final_exp();
    let lado_claves = blst_fp12::miller_loop(h_m_afin, claves_afin).final_exp();
    if lado_firmas == lado_claves {
        Ok(())
    } else {
        Err(ErrorBLS::VerificacionFallida)
    }
}

/// Aplana los escalares del lote al formato que consume `blst` (`nbits = 128`).
fn escalares_planos(escalares: &[[u8; LONGITUD_ESCALAR_LOTE]]) -> Vec<u8> {
    let mut planos = Vec::with_capacity(escalares.len() * LONGITUD_ESCALAR_LOTE);
    for escalar in escalares {
        planos.extend_from_slice(escalar);
    }
    planos
}

/// `aggregate_verify`: mensajes distintos con sus claves.
///
/// # Errores
/// [`ErrorBLS::LongitudesIncompatibles`] si `claves.len() != mensajes.len()`;
/// [`ErrorBLS::AgregacionVacia`] si no hay entradas; [`ErrorBLS::VerificacionFallida`] si no
/// verifica.
pub fn aggregate_verify(
    claves: &[&ClavePublica],
    mensajes: &[&[u8]],
    firma: &FirmaAgregada,
) -> Result<(), ErrorBLS> {
    if claves.len() != mensajes.len() {
        return Err(ErrorBLS::LongitudesIncompatibles {
            claves: claves.len(),
            mensajes: mensajes.len(),
        });
    }
    if claves.is_empty() {
        return Err(ErrorBLS::AgregacionVacia);
    }
    let publicas: Vec<&PublicKey> = claves.iter().map(|clave| clave.interna()).collect();
    let error = firma
        .interna()
        .to_signature()
        .aggregate_verify(true, mensajes, DST_FIRMA, &publicas, true);
    exito(error)
}

/// `HashToG2` de RFC 9380 con el DST indicado.
///
/// Se implementa con `blst` fijando la clave secreta en el escalar `1`: `1 · H(m) = H(m)`. Se
/// expone para reproducir los vectores de hash a curva (`BLS12381G2_XMD:SHA-256_SSWU_RO_`); no
/// forma parte de la API de firma de ZEROX.
///
/// # Errores
/// [`ErrorBLS::ClaveSecretaInvalida`] si `blst` rechazara el escalar uno (no debería ocurrir).
pub fn hash_a_g2(mensaje: &[u8], dst: &[u8]) -> Result<[u8; 96], ErrorBLS> {
    let mut uno = [0u8; 32];
    if let Some(ultimo) = uno.last_mut() {
        *ultimo = 1;
    }
    let escalar = SecretKey::from_bytes(&uno).map_err(|e| ErrorBLS::ClaveSecretaInvalida {
        motivo: motivo_blst(e),
    })?;
    let punto = escalar.sign(mensaje, dst, &[]);
    Ok(punto.to_bytes())
}

/// Deserializa una firma desde su forma **no comprimida** de 192 bytes.
///
/// Solo para los vectores de hash a curva de RFC 9380, que publican el punto como coordenadas
/// `x, y` en vez de como punto comprimido. Valida subgrupo y rechaza el infinito, como
/// [`crate::Firma::desde_bytes`], pero el formato de entrada es el de 192 bytes.
///
/// # Errores
/// [`ErrorBLS::FirmaInvalida`] si los bytes no codifican un punto válido de G2 del subgrupo.
pub fn firma_desde_uncomprimida(bytes: &[u8]) -> Result<Firma, ErrorBLS> {
    let firma = Signature::deserialize(bytes).map_err(|e| ErrorBLS::FirmaInvalida {
        motivo: motivo_blst(e),
    })?;
    firma.validate(true).map_err(|e| ErrorBLS::FirmaInvalida {
        motivo: motivo_blst(e),
    })?;
    Ok(Firma::desde_interna(firma))
}

/// Traduce el código de `blst` a `Ok`/`VerificacionFallida`.
fn exito(error: BLST_ERROR) -> Result<(), ErrorBLS> {
    if error == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(ErrorBLS::VerificacionFallida)
    }
}

#[cfg(test)]
mod pruebas {
    use super::{
        agregar_firmas, fast_aggregate_verify, firmar, firmar_posesion, verificar,
        verificar_posesion,
    };
    use crate::clave::{ClavePublica, ClaveSecreta};
    use crate::error::ErrorBLS;
    use blst::min_pk::AggregatePublicKey;

    /// Ataque de la clave rebelde (rogue key): sin POP, la verificación agregada acepta una clave
    /// que su dueño no puede probar poseer; con la prueba de posesión, no.
    #[test]
    fn el_ataque_de_clave_rebelde_se_demuestra_y_la_pop_lo_frena() -> Result<(), ErrorBLS> {
        let victima = ClaveSecreta::generar(&[0x11; 32])?;
        let atacante = ClaveSecreta::generar(&[0x22; 32])?;
        let pk_victima = victima.clave_publica();
        let pk_atacante = atacante.clave_publica();

        // pk_rebelde = pk_atacante - pk_victima.
        let mut agregada = AggregatePublicKey::from_public_key(pk_atacante.interna());
        agregada.sub_aggregate(&AggregatePublicKey::from_public_key(pk_victima.interna()));
        let rebelde = ClavePublica::desde_bytes(&agregada.to_public_key().to_bytes())?;

        let mensaje = b"mismo mensaje para todos";
        let firma = firmar(&atacante, mensaje);
        let certificado = agregar_firmas(&[&firma])?;

        // (1) La verificación agregada ingenua ACEPTA: pk_rebelde + pk_victima = pk_atacante.
        fast_aggregate_verify(&[&rebelde, &pk_victima], &certificado, mensaje)?;

        // (2) La prueba de posesión del atacante no vale para la clave rebelde...
        let prueba = firmar_posesion(&atacante);
        assert!(
            verificar_posesion(&rebelde, &prueba).is_err(),
            "la POP del atacante MUST NOT probar la clave rebelde"
        );

        // ...(3) pero sí para la clave que de verdad posee.
        verificar_posesion(&pk_atacante, &prueba)?;

        Ok(())
    }

    #[test]
    fn un_mensaje_distinto_no_verifica() -> Result<(), ErrorBLS> {
        let clave = ClaveSecreta::generar(&[0x33; 32])?;
        let publica = clave.clave_publica();
        let firma = firmar(&clave, b"uno");
        assert!(verificar(&publica, &firma, b"dos").is_err());
        Ok(())
    }
}
