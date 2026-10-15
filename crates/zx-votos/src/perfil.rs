//! Parámetros de perfil y fuente de peso (FV-D07, FV-D08, PK-11, PK-12).
//!
//! Dos parámetros del contrato quedaron **abiertos** y se exponen como configuración de perfil, no
//! como constantes inventadas:
//!
//! - la **multa por ausencia** `m_aus = f_aus·garantia_i + m_min` (PK-11 pendiente de Katana);
//! - la **fuente de peso**, detrás del trait [`FuentePeso`], con la implementación definitiva
//!   [`FuenteSectores`] (peso = sectores registrados con garantía de la identidad de la clave,
//!   FV-D01). La fuente provisional por garantía de FV-D08 se **elimina** en FV-4b-N4.
//!
//! `N_pausa` (instancias consecutivas sin quórum para declarar pausa observable) y `T_inst` (slots
//! PoT por instancia) también son simbólicos y viajan en [`ParametrosPerfil`].

use crate::error::ErrorVotos;
use crate::tipos::Clave;

/// Parámetros de perfil simbólicos de la capa de finalidad por votos.
///
/// **Ningún valor aquí es una decisión ratificada**: `b` es FV-D05 (`b = 2`), pero `f_aus`, `m_min`,
/// `n_pausa` y `t_inst` quedaron pendientes (PK-11, C-FV-06.2). Construir el perfil es
/// responsabilidad del cableado (FV-4b); esta biblioteca solo los consume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParametrosPerfil {
    /// Prima de disponibilidad `b` (FV-D05: `b = 2`).
    pub b: u64,
    /// Numerador de `f_aus` (fracción de la garantía confiscada).
    pub f_aus_numerador: u64,
    /// Denominador de `f_aus`.
    pub f_aus_denominador: u64,
    /// Mínimo fijo de la multa `m_min`.
    pub m_min: u64,
    /// Instancias consecutivas sin quórum para declarar pausa observable `N_pausa`.
    pub n_pausa: u64,
    /// Slots PoT por instancia `T_inst` (reloj de instancias, FV-4b).
    pub t_inst: u64,
}

impl ParametrosPerfil {
    /// Perfil de `dev` que la orden FV-4b-1 fija: `b = 2`, `f_aus = 1/420 000`, `m_min = 1 brek`,
    /// `t_inst = 2` slots y `n_pausa = t_inst` (una instancia).
    ///
    /// Es **mecánica, no seguridad**: en la escala dev `floor(f_aus·G) = 0` y manda `m_min`
    /// (FV-D08, `REVISION-FV4bD.md` decisión 7). El perfil de producción lo fija FV-4b-N.
    #[must_use]
    pub const fn dev() -> Self {
        Self {
            b: 2,
            f_aus_numerador: 1,
            f_aus_denominador: 420_000,
            m_min: 1,
            n_pausa: 2,
            t_inst: 2,
        }
    }

    /// Multa por ausencia `m_aus = floor(f_aus·garantia) + m_min` (C-FV-07.2, RFT-20).
    ///
    /// # Errores
    /// [`ErrorVotos::DenominadorCero`] si `f_aus_denominador = 0`; [`ErrorVotos::Desbordamiento`]
    /// si el producto o la suma no caben en `u64`.
    #[allow(
        clippy::integer_division,
        reason = "la multa proporcional se define con la parte entera de f_aus*garantia; la division entera es la regla, no un defecto"
    )]
    pub fn multa_ausencia(&self, garantia: u64) -> Result<u64, ErrorVotos> {
        if self.f_aus_denominador == 0 {
            return Err(ErrorVotos::DenominadorCero);
        }
        let producto = garantia
            .checked_mul(self.f_aus_numerador)
            .ok_or(ErrorVotos::Desbordamiento)?;
        let parte_proporcional = producto / self.f_aus_denominador;
        parte_proporcional
            .checked_add(self.m_min)
            .ok_or(ErrorVotos::Desbordamiento)
    }
}

/// Fuente del **peso registrado** de una clave (FV-D01).
///
/// El peso de una clave de voto es el número de **sectores registrados con garantía** de su
/// identidad Ed25519 (`fuente_peso_de` de `zx-consensus`, `C-SEC-15`). Este crate es puro y no
/// conoce el estado: el llamador ya ha computado ese peso y lo entrega como `peso_registrado`.
/// Una clave con garantía pero **sin sectores** tiene `peso_registrado = 0` (peso 0).
pub trait FuentePeso {
    /// Peso registrado de `clave`; `None` si la fuente no la reconoce.
    ///
    /// `peso_registrado` es el número de sectores registrados con garantía de la identidad de la
    /// clave (no la garantía en brek): la fuente definitiva lo devuelve tal cual.
    fn peso_de(&self, clave: &[u8], peso_registrado: u64) -> Option<u64>;
}

/// Fuente definitiva `peso = sectores registrados con garantía` (FV-D01; sustituye a FV-D08).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FuenteSectores;

impl FuentePeso for FuenteSectores {
    fn peso_de(&self, _clave: &[u8], peso_registrado: u64) -> Option<u64> {
        Some(peso_registrado)
    }
}

/// Construye una [`Clave`] de tabla de poder usando una [`FuentePeso`].
///
/// # Errores
/// [`ErrorVotos::PesoNoDisponible`] si la fuente no reconoce la clave.
pub fn clave_desde_fuente(
    clave: &[u8],
    activo: bool,
    prueba: bool,
    peso_registrado: u64,
    fuente: &dyn FuentePeso,
) -> Result<Clave, ErrorVotos> {
    let peso = fuente
        .peso_de(clave, peso_registrado)
        .ok_or(ErrorVotos::PesoNoDisponible)?;
    Ok(Clave {
        clave: clave.to_vec(),
        peso,
        activo,
        prueba,
        garantia: peso_registrado,
    })
}

/// Estado de la finalidad de una instancia (C-FV-06.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EstadoFinalidad {
    /// Se alcanzó el quórum: la instancia queda certificada.
    Certificada,
    /// No se alcanzó el quórum: la finalidad **pausa** para esa instancia.
    Pausada,
    /// Se acumularon `N_pausa` instancias consecutivas sin quórum: pausa observable.
    PausaObservable,
}

/// Estado de finalidad a partir del quórum y de la racha sin quórum.
#[must_use]
pub fn estado_finalidad(
    quorum_alcanzado: bool,
    racha_sin_quorum: u64,
    perfil: &ParametrosPerfil,
) -> EstadoFinalidad {
    if quorum_alcanzado {
        EstadoFinalidad::Certificada
    } else if perfil.n_pausa > 0 && racha_sin_quorum >= perfil.n_pausa {
        EstadoFinalidad::PausaObservable
    } else {
        EstadoFinalidad::Pausada
    }
}
