//! Clave pública **agregada** (suma en G1) y su verificación.
//!
//! La pieza de agregación (A5) necesita la **suma de las claves de cada subred** calculada una sola
//! vez por ventana y la clave de cada agregado obtenida **restando** de esa suma las claves
//! ausentes cuando son menos que las presentes. Este módulo añade esas dos operaciones a `zx-bls`
//! sin tocar nada de lo que ya exporta:
//!
//! - [`ClaveAgregada::sumar`] suma una lista no vacía de [`ClavePublica`].
//! - [`ClaveAgregada::restar`] resta una clave de la suma (aritmética exacta de G1).
//! - [`ClaveAgregada::es_infinito`] detecta el punto del infinito.
//! - [`verificar_agregado_con_clave`] y [`verificar_lote_de_agregados_con_clave`] comprueban una
//!   firma agregada contra la clave **ya calculada**, sin volver a sumar el mapa de claves.
//!
//! La igualdad con la suma de las presentes es exacta: la suma en G1 es asociativa y conmutativa,
//! de modo que `Σ todas − Σ ausentes = Σ presentes`. Los veredictos no cambian. Si la clave
//! resultante es el punto del infinito, la verificación falla con [`ErrorBLS::VerificacionFallida`],
//! que es el veredicto de hoy para esa entrada.

use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use blst::{BLST_ERROR, MultiPoint, blst_fp12, blst_p1_affine, blst_p2_affine};

use crate::clave::{ClavePublica, ClaveSecreta, LONGITUD_CLAVE_PUBLICA};
use crate::crudo::{DST_FIRMA, LONGITUD_ESCALAR_LOTE, hash_a_g2};
use crate::error::{ErrorBLS, motivo_blst};
use crate::firma::{Firma, FirmaAgregada};

/// Suma de claves públicas en G1.
///
/// Guarda la suma como punto de G1. **Puede** ser el punto del infinito: al restar todas las
/// claves de una subred, o si las claves se cancelan entre sí. Las funciones de verificación
/// rechazan ese caso ([`ErrorBLS::VerificacionFallida`]), que es el veredicto de hoy.
#[derive(Clone, Copy, Debug)]
pub struct ClaveAgregada(AggregatePublicKey);

impl PartialEq for ClaveAgregada {
    fn eq(&self, otra: &Self) -> bool {
        self.bytes() == otra.bytes()
    }
}

impl Eq for ClaveAgregada {}

impl ClaveAgregada {
    /// Suma una lista **no vacía** de claves públicas.
    ///
    /// # Errores
    /// [`ErrorBLS::AgregacionVacia`] si `claves` está vacía.
    pub fn sumar(claves: &[&ClavePublica]) -> Result<Self, ErrorBLS> {
        if claves.is_empty() {
            return Err(ErrorBLS::AgregacionVacia);
        }
        let publicas: Vec<&PublicKey> = claves.iter().map(|clave| clave.interna()).collect();
        let agregada = AggregatePublicKey::aggregate(&publicas, false).map_err(|error| {
            ErrorBLS::ClaveInvalida {
                motivo: motivo_blst(error),
            }
        })?;
        Ok(Self(agregada))
    }

    /// La clave `clave` como agregado de un solo término.
    #[must_use]
    pub fn desde_clave(clave: &ClavePublica) -> Self {
        Self(AggregatePublicKey::from_public_key(clave.interna()))
    }

    /// Resta `clave` de la suma, **en el sitio**.
    pub fn restar(&mut self, clave: &ClavePublica) {
        self.0
            .sub_aggregate(&AggregatePublicKey::from_public_key(clave.interna()));
    }

    /// Resta varias claves, en orden.
    pub fn restar_varias(&mut self, claves: &[&ClavePublica]) {
        for clave in claves {
            self.restar(clave);
        }
    }

    /// Los 48 bytes comprimidos de la suma.
    #[must_use]
    pub fn bytes(&self) -> [u8; LONGITUD_CLAVE_PUBLICA] {
        self.0.to_public_key().to_bytes()
    }

    /// `true` si la suma es el punto del infinito (la identidad de G1).
    #[must_use]
    pub fn es_infinito(&self) -> bool {
        matches!(
            self.0.to_public_key().validate(),
            Err(BLST_ERROR::BLST_PK_IS_INFINITY)
        )
    }

    /// El punto de `blst` de la suma (vista interna de este crate).
    pub(crate) fn interna(&self) -> PublicKey {
        self.0.to_public_key()
    }
}

/// Verifica una firma agregada contra una clave agregada **ya calculada**.
///
/// Comprueba `e(σ, g₁) == e(H(m), K)` con la clave `K` de [`ClaveAgregada`], sin volver a sumar el
/// mapa. Es equivalente a [`crate::crudo::fast_aggregate_verify`] con las claves del mapa.
///
/// # Errores
/// [`ErrorBLS::VerificacionFallida`] si la firma no verifica o si `clave` es el punto del infinito
/// (el veredicto de hoy para esa entrada).
pub fn verificar_agregado_con_clave(
    clave: &ClaveAgregada,
    firma: &FirmaAgregada,
    mensaje: &[u8],
) -> Result<(), ErrorBLS> {
    if clave.es_infinito() {
        return Err(ErrorBLS::VerificacionFallida);
    }
    let publica = clave.interna();
    let error =
        firma
            .interna()
            .to_signature()
            .fast_aggregate_verify(true, mensaje, DST_FIRMA, &[&publica]);
    exito(error)
}

/// Verifica por lotes `N` agregados del mismo mensaje contra sus claves agregadas ya calculadas.
///
/// Equivale a [`crate::crudo::verificar_lote_de_agregados_con_escalares`] pero recibe la clave de
/// cada agregado **ya sumada** ([`ClaveAgregada`]) en vez de su mapa de claves. Comprueba
/// `e(Σ_j r_j·σ_j, g₁) == e(H(m), Σ_j r_j·K_j)`.
///
/// # Errores
/// [`ErrorBLS::LongitudesLoteIncompatibles`] si las tres listas no miden lo mismo;
/// [`ErrorBLS::AgregacionVacia`] si el lote está vacío; [`ErrorBLS::VerificacionFallida`] si la
/// combinación no cuadra o si alguna clave es el punto del infinito.
pub fn verificar_lote_de_agregados_con_clave(
    claves: &[&ClaveAgregada],
    firmas: &[&FirmaAgregada],
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
    if claves.iter().any(|clave| clave.es_infinito()) {
        return Err(ErrorBLS::VerificacionFallida);
    }

    let planos = escalares_planos(escalares);
    let publicas: Vec<PublicKey> = claves.iter().map(|clave| clave.interna()).collect();
    let firmas_blst: Vec<Signature> = firmas
        .iter()
        .map(|firma| firma.interna().to_signature())
        .collect();

    // Σ_j r_j·K_j (G1) y Σ_j r_j·σ_j (G2), con el mismo vector de escalares.
    let producto_claves = publicas
        .as_slice()
        .mult(&planos, 8 * LONGITUD_ESCALAR_LOTE)
        .to_public_key();
    let producto_firmas = firmas_blst
        .as_slice()
        .mult(&planos, 8 * LONGITUD_ESCALAR_LOTE)
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

/// Traduce el código de `blst` a `Ok`/`VerificacionFallida`.
fn exito(error: BLST_ERROR) -> Result<(), ErrorBLS> {
    if error == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(ErrorBLS::VerificacionFallida)
    }
}
