//! Estado de **una** ventana de agregación para **una** tabla y **una** raíz de estado (pieza A5,
//! paso (c) y (c)-1a-2).
//!
//! [`DatosVentana`] es el **bloque inmutable** de una ventana: la tabla, sus claves públicas, sus
//! pesos, el reparto A1, la **huella `h_T` calculada una sola vez** y las **sumas de claves por
//! subred** (V2, calculadas también una sola vez). Se comparte entre los estados de la misma ventana
//! con un [`Arc`], de modo que construir un estado por raíz no vuelve a serializar ni a hashear la
//! tabla, ni a sumar las claves de sus subredes.
//!
//! [`EstadoVentana`] reúne, para **una** raíz, lo que el motor necesita entre la apertura y el
//! cierre de una ventana, sin red y sin tocar la cadena:
//!
//! - los **votos sueltos** ya verificados que se registran ([`EstadoVentana::registrar_suelto`]),
//! - los **agregados** que llegan, aceptados como mucho uno por agregadora y subred
//!   ([`EstadoVentana::recibir_agregado`], [`EstadoVentana::recibir_lote`]),
//! - el **agregado propio** de una clave que publica, una sola vez y solo si su sorteo sale
//!   ([`EstadoVentana::agregado_propio`]),
//! - la **cobertura** y el estado de quórum ([`EstadoVentana::peso_cubierto`],
//!   [`EstadoVentana::hay_quorum`]),
//! - el **certificado** verificable cuando hay quórum y, si no lo hay, el mapa de quienes constan
//!   para el acta ([`EstadoVentana::certificado`], [`EstadoVentana::mapa_constan`]).
//!
//! La elección del agregado de cada subred es **AG-R14** y vive en
//! [`crate::agregacion::elegir_mapa_firmas`], compartida con `armar_certificado`: la cobertura, el
//! mapa del acta y el certificado usan **la misma** elección.
//!
//! **Orden obligatorio al recibir un agregado:** mensaje, tabla, forma y repetido **antes** de
//! cualquier firma. Un agregado inválido **no** ocupa la plaza de su agregadora.
//!
//! [`VentanaPorRaices`]: crate::ventana_raices::VentanaPorRaices

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use zx_bls::{ClavePublica, Firma, agregar_firmas};

use crate::agregacion::{
    Agregado, ErrorAgregacion, GeneradorEscalares, MensajeVoto, MotivoAgregado, Reparto,
    SumasSubred, VeredictoAgregado, armar_certificado, elegir_mapa_firmas, sale_agregadora, subred,
    veredicto_con_huella_y_sumas, verificar_lote_con_huella_y_sumas,
};
use crate::peso::{CertificadoPeso, quorum_peso};
use crate::serial::{hash_bytes, hash_tabla};
use crate::tipos::{Hash, Tabla};

/// Bloque **inmutable** de datos de una ventana, compartido por sus estados con [`Arc`].
///
/// Reúne la tabla de poder, sus claves públicas, sus pesos (paralelos a `tabla.claves`), el reparto
/// A1, la huella `h_T` y las sumas de claves por subred, calculadas **una sola vez** en
/// [`DatosVentana::nuevo`]. Los tipos públicos no llevan parámetro de tiempo de vida: el bloque es
/// dueño de los datos.
pub struct DatosVentana {
    tabla: Tabla,
    claves: Vec<ClavePublica>,
    pesos: Vec<u128>,
    reparto: Reparto,
    huella: Hash,
    sumas: SumasSubred,
}

impl DatosVentana {
    /// Construye el bloque de datos de una ventana en `s` subredes.
    ///
    /// `claves` y `pesos` son **paralelos** a `tabla.claves`; `s` es `S`. Calcula el reparto A1 y
    /// la huella una sola vez.
    ///
    /// # Errores
    /// [`ErrorAgregacion::LongitudesIncompatibles`] si `claves` o `pesos` no son paralelos a la
    /// tabla; el de [`Reparto::construir`] si `s == 0`.
    pub fn nuevo(
        tabla: &Tabla,
        claves: &[ClavePublica],
        pesos: &[u128],
        s: u16,
    ) -> Result<Arc<Self>, ErrorAgregacion> {
        Self::construir(tabla, claves, pesos, s, hash_tabla(tabla))
    }

    /// Igual que [`DatosVentana::nuevo`] pero **fija** la huella, sin calcularla.
    ///
    /// Es un gancho de pruebas para demostrar por construcción que los estados y la ventana usan la
    /// huella del bloque compartido y no la recalculan (prueba `vr_la_huella_se_calcula_una_vez`).
    /// No debe usarse en producción.
    ///
    /// # Errores
    /// Los mismos que [`DatosVentana::nuevo`].
    #[doc(hidden)]
    pub fn con_huella(
        tabla: &Tabla,
        claves: &[ClavePublica],
        pesos: &[u128],
        s: u16,
        huella: Hash,
    ) -> Result<Arc<Self>, ErrorAgregacion> {
        Self::construir(tabla, claves, pesos, s, huella)
    }

    /// Valida longitudes, construye el reparto y fija la huella dada.
    fn construir(
        tabla: &Tabla,
        claves: &[ClavePublica],
        pesos: &[u128],
        s: u16,
        huella: Hash,
    ) -> Result<Arc<Self>, ErrorAgregacion> {
        if claves.len() != tabla.claves.len() {
            return Err(ErrorAgregacion::LongitudesIncompatibles {
                claves: claves.len(),
                plazas: tabla.claves.len(),
            });
        }
        if pesos.len() != tabla.claves.len() {
            return Err(ErrorAgregacion::LongitudesIncompatibles {
                claves: pesos.len(),
                plazas: tabla.claves.len(),
            });
        }
        let reparto = Reparto::construir(tabla, s)?;
        let sumas = SumasSubred::construir(&reparto, claves)?;
        Ok(Arc::new(Self {
            tabla: tabla.clone(),
            claves: claves.to_vec(),
            pesos: pesos.to_vec(),
            reparto,
            huella,
            sumas,
        }))
    }

    /// Tabla de poder de la ventana.
    #[must_use]
    pub fn tabla(&self) -> &Tabla {
        &self.tabla
    }

    /// Claves públicas, paralelas a `tabla.claves`.
    #[must_use]
    pub fn claves(&self) -> &[ClavePublica] {
        &self.claves
    }

    /// Pesos, paralelos a `tabla.claves` (ya con la actividad aplicada).
    #[must_use]
    pub fn pesos(&self) -> &[u128] {
        &self.pesos
    }

    /// Reparto A1 de la ventana.
    #[must_use]
    pub fn reparto(&self) -> &Reparto {
        &self.reparto
    }

    /// Huella `h_T` de la tabla, calculada una sola vez en [`DatosVentana::nuevo`].
    #[must_use]
    pub fn huella(&self) -> Hash {
        self.huella
    }

    /// Sumas de las claves de cada subred, calculadas una sola vez por ventana (V2).
    ///
    /// Se construyen junto a la huella en [`DatosVentana::construir`]; recibir agregados **no** las
    /// recalcula.
    #[must_use]
    pub fn sumas(&self) -> &SumasSubred {
        &self.sumas
    }

    /// Peso total `W` de la tabla (suma saturada de los pesos).
    #[must_use]
    pub fn peso_total(&self) -> u128 {
        self.pesos.iter().copied().fold(0u128, u128::saturating_add)
    }
}

/// Resultado de recibir un agregado en el estado de una ventana.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultadoAgregado {
    /// El agregado afirma otro mensaje: se ignora sin penalizar.
    OtroMensaje,
    /// El agregado está indexado contra otra tabla: se ignora sin penalizar.
    OtraTabla,
    /// Ya hay un agregado **válido** de esa agregadora, **o no añade ninguna clave** a lo que el
    /// estado ya tiene de su subred: se descarta **sin** criptografía.
    Repetido,
    /// Hecho objetivo: el agregado no vale, con su [`MotivoAgregado`].
    Invalido(MotivoAgregado),
    /// Agregado válido: ocupa la plaza de su agregadora.
    Aceptado,
}

/// Estado de **una** raíz de estado en **una** ventana.
///
/// Comparte con los demás estados de la misma ventana el bloque inmutable [`DatosVentana`] (la
/// tabla, sus claves, sus pesos, el reparto y la huella). Los pesos son **paralelos** a
/// `tabla.claves` (`pesos[i]` es el peso de `tabla.claves[i]`).
pub struct EstadoVentana {
    datos: Arc<DatosVentana>,
    a: u32,
    mensaje: MensajeVoto,
    /// Votos sueltos registrados: posición **1-based** en `tabla.claves` → firma A3.
    sueltos: BTreeMap<usize, Firma>,
    /// Agregados válidos aceptados: `(subred, indice_agregadora)` → agregado.
    aceptados: BTreeMap<(u16, u16), Agregado>,
    /// Claves (posición 1-based) cuyo agregado propio ya se emitió.
    propios: BTreeSet<usize>,
}

/// Lee el bit `posicion` (0-based) de un mapa.
pub(crate) fn bit_marcado(mapa: &[u8], posicion: usize) -> bool {
    mapa.get(posicion >> 3)
        .map(|byte| (byte >> (posicion & 7)) & 1 == 1)
        .unwrap_or(false)
}

/// Peso cubierto por un mapa global (mismo orden que `pesos`).
pub(crate) fn peso_de_mapa(mapa: &[u8], pesos: &[u128]) -> u128 {
    let mut total: u128 = 0;
    for (indice, peso) in pesos.iter().enumerate() {
        if bit_marcado(mapa, indice) {
            total = total.saturating_add(*peso);
        }
    }
    total
}

/// Comprueba la forma de un agregado (subred, mapa, índice y bit de la agregadora).
///
/// Es la comprobación **sin estado** que comparten [`EstadoVentana`] y
/// [`crate::ventana_raices::VentanaPorRaices`]; no toca criptografía ni la huella.
pub(crate) fn motivo_forma(reparto: &Reparto, agregado: &Agregado) -> Option<MotivoAgregado> {
    if agregado.subred >= reparto.s() {
        return Some(MotivoAgregado::Subred);
    }
    let n_s = reparto.claves_de(agregado.subred).len();
    if agregado.mapa_local.len() != n_s.div_ceil(8) {
        return Some(MotivoAgregado::Forma);
    }
    let sobrantes = n_s.rem_euclid(8);
    if sobrantes != 0 {
        let mascara = 0xFFu8 << sobrantes;
        if agregado
            .mapa_local
            .last()
            .map(|ultimo| ultimo & mascara != 0)
            .unwrap_or(false)
        {
            return Some(MotivoAgregado::Forma);
        }
    }
    let posicion = agregado.indice_agregadora as usize;
    if posicion >= n_s {
        return Some(MotivoAgregado::Indice);
    }
    if !bit_marcado(&agregado.mapa_local, posicion) {
        return Some(MotivoAgregado::AgregadoraFueraDeMapa);
    }
    None
}

/// N1 (lectura elegida): `true` si `agregado` **no añade** ninguna clave a lo que el estado ya
/// tiene de su subred.
///
/// Se decide con mapas, sin criptografía: **existe un** agregado aceptado de la misma subred cuyo
/// mapa cubre todas las claves marcadas que no tengan ya un voto suelto; o, si no hay ningún
/// agregado aceptado de esa subred, todas las claves marcadas tienen voto suelto registrado. (La
/// lectura «unión» —cada clave por un agregado distinto— rompería N4: véase `PROGRESO.md` §3.)
///
/// `es_suelto` dice si una posición **1-based** tiene voto suelto; `aceptados` recorre los
/// agregados aceptados, **incluidos los del mismo lote que van por delante**.
pub(crate) fn no_anade<'a>(
    reparto: &Reparto,
    agregado: &Agregado,
    es_suelto: impl Fn(usize) -> bool,
    aceptados: impl Iterator<Item = &'a Agregado>,
) -> bool {
    let indices_subred = reparto.claves_de(agregado.subred);
    let mut hay_aceptado = false;
    for aceptado in aceptados {
        if aceptado.subred != agregado.subred {
            continue;
        }
        hay_aceptado = true;
        let cubre = indices_subred.iter().enumerate().all(|(pos, &idx_global)| {
            !bit_marcado(&agregado.mapa_local, pos)
                || es_suelto(idx_global + 1)
                || bit_marcado(&aceptado.mapa_local, pos)
        });
        if cubre {
            return true;
        }
    }
    if !hay_aceptado {
        return indices_subred.iter().enumerate().all(|(pos, &idx_global)| {
            !bit_marcado(&agregado.mapa_local, pos) || es_suelto(idx_global + 1)
        });
    }
    false
}

impl EstadoVentana {
    /// Construye el estado de **una** raíz sobre el bloque de datos compartido.
    ///
    /// `a` es `A`; `mensaje` fija la instancia, el candidato, la tabla siguiente y la raíz de este
    /// estado. No clona la tabla: comparte el [`DatosVentana`].
    #[must_use]
    pub fn nuevo(datos: Arc<DatosVentana>, a: u32, mensaje: MensajeVoto) -> Self {
        Self {
            datos,
            a,
            mensaje,
            sueltos: BTreeMap::new(),
            aceptados: BTreeMap::new(),
            propios: BTreeSet::new(),
        }
    }

    /// Registra un voto suelto **ya verificado**, en la posición **1-based** `posicion` de la tabla.
    ///
    /// Repetido, no cambia nada (se conserva la primera firma). No comprueba la firma: el llamador
    /// es responsable de haberla verificado.
    ///
    /// # Errores
    /// [`ErrorAgregacion::ClaveNoRegistrada`] si `posicion` cae fuera de `1..=N`.
    pub fn registrar_suelto(
        &mut self,
        posicion: usize,
        firma: Firma,
    ) -> Result<(), ErrorAgregacion> {
        let n = self.datos.tabla().claves.len();
        if posicion == 0 || posicion > n {
            return Err(ErrorAgregacion::ClaveNoRegistrada);
        }
        self.sueltos.entry(posicion).or_insert(firma);
        Ok(())
    }

    /// `true` si la posición **1-based** `posicion` tiene voto suelto registrado.
    pub(crate) fn es_suelto(&self, posicion: usize) -> bool {
        self.sueltos.contains_key(&posicion)
    }

    /// Agregados aceptados, en orden de `(subred, indice_agregadora)`.
    pub(crate) fn aceptados_valores(&self) -> impl Iterator<Item = &Agregado> {
        self.aceptados.values()
    }

    /// N1: `true` si `agregado` no añade ninguna clave a lo ya aceptado ni a los sueltos.
    pub(crate) fn no_anade(&self, agregado: &Agregado) -> bool {
        no_anade(
            self.datos.reparto(),
            agregado,
            |posicion| self.sueltos.contains_key(&posicion),
            self.aceptados.values(),
        )
    }

    /// Recibe un agregado y dice qué pasó.
    ///
    /// Comprueba, en este orden y **antes** de cualquier firma: mensaje → tabla → forma → plaza →
    /// **no añade**. El que no añade ninguna clave a lo ya aceptado es [`ResultadoAgregado::Repetido`]
    /// y **no se verifica**. Solo un agregado que añade y pasa la verificación
    /// ([`veredicto_con_huella`]) ocupa la plaza de su agregadora.
    ///
    /// La huella de la tabla se toma del bloque compartido: **no** se recalcula aquí.
    ///
    /// # Errores
    /// El de BLS en la verificación del agregado, si la forma es válida.
    pub fn recibir_agregado(
        &mut self,
        agregado: &Agregado,
    ) -> Result<ResultadoAgregado, ErrorAgregacion> {
        if let Some(resultado) = self.clasificar_sin_firma(agregado) {
            return Ok(resultado);
        }
        if self.no_anade(agregado) {
            return Ok(ResultadoAgregado::Repetido);
        }
        let datos = Arc::clone(&self.datos);
        match veredicto_con_huella_y_sumas(
            agregado,
            datos.tabla(),
            datos.claves(),
            datos.reparto(),
            self.a,
            datos.huella(),
            datos.sumas(),
        )? {
            VeredictoAgregado::Valido => {
                self.aceptados.insert(
                    (agregado.subred, agregado.indice_agregadora),
                    agregado.clone(),
                );
                Ok(ResultadoAgregado::Aceptado)
            }
            VeredictoAgregado::Invalido(motivo) => Ok(ResultadoAgregado::Invalido(motivo)),
            VeredictoAgregado::OtraTabla => Ok(ResultadoAgregado::OtraTabla),
        }
    }

    /// Recibe un lote con el **mismo** resultado por agregado que [`Self::recibir_agregado`] uno a
    /// uno, sin verificar los agregados que no añaden ninguna clave (N2, N5).
    ///
    /// (a) clasifica cada agregado **sin** criptografía (mensaje, tabla, forma, plaza y **no
    /// añade** contra lo ya aceptado antes del lote); (b) recorre los pendientes **en orden** y los
    /// verifica por lotes, agrupando los que añaden con la cobertura optimista del propio lote; (c)
    /// aplica en orden el veredicto real, aceptando solo los válidos que añaden y descartando como
    /// [`ResultadoAgregado::Repetido`] los que ya no añaden. Nunca se acepta un agregado sin
    /// verificar; se puede verificar de más.
    ///
    /// # Errores
    /// El de BLS en la verificación por lotes.
    pub fn recibir_lote(
        &mut self,
        agregados: &[Agregado],
        generador: &mut impl GeneradorEscalares,
    ) -> Result<Vec<ResultadoAgregado>, ErrorAgregacion> {
        let mut resultados: Vec<Option<ResultadoAgregado>> = vec![None; agregados.len()];
        let mut pendientes: Vec<usize> = Vec::new();

        // (a) clasificación sin criptografía y descarte de lo que no añade.
        for (i, agregado) in agregados.iter().enumerate() {
            let resultado = match self.clasificar_sin_firma(agregado) {
                Some(resultado) => Some(resultado),
                None if self.no_anade(agregado) => Some(ResultadoAgregado::Repetido),
                None => {
                    pendientes.push(i);
                    None
                }
            };
            if let Some(slot) = resultados.get_mut(i) {
                *slot = resultado;
            }
        }

        // (b)+(c) procesa los pendientes en orden, verificando por lotes los que añaden.
        let mut pos = 0usize;
        while pos < pendientes.len() {
            let Some(indice) = pendientes.get(pos).copied() else {
                break;
            };
            let Some(agregado) = agregados.get(indice) else {
                pos += 1;
                continue;
            };
            // El estado pudo cambiar al aceptar pendientes anteriores.
            if self
                .aceptados
                .contains_key(&(agregado.subred, agregado.indice_agregadora))
                || self.no_anade(agregado)
            {
                if let Some(slot) = resultados.get_mut(indice) {
                    *slot = Some(ResultadoAgregado::Repetido);
                }
                pos += 1;
                continue;
            }

            // Selección optimista: los pendientes que añaden contando ya los seleccionados.
            let mut seleccion: Vec<usize> = Vec::new();
            let mut extras: Vec<Agregado> = Vec::new();
            for (j, indice_siguiente) in pendientes.iter().enumerate().skip(pos) {
                let Some(siguiente) = agregados.get(*indice_siguiente) else {
                    continue;
                };
                if self
                    .aceptados
                    .contains_key(&(siguiente.subred, siguiente.indice_agregadora))
                {
                    continue;
                }
                let cubierto = no_anade(
                    self.datos.reparto(),
                    siguiente,
                    |posicion| self.sueltos.contains_key(&posicion),
                    self.aceptados.values().chain(extras.iter()),
                );
                if !cubierto {
                    seleccion.push(j);
                    extras.push(siguiente.clone());
                }
            }
            let Some(ultimo) = seleccion.last().copied() else {
                pos += 1;
                continue;
            };

            let lote: Vec<Agregado> = seleccion
                .iter()
                .filter_map(|j| pendientes.get(*j).and_then(|k| agregados.get(*k)).cloned())
                .collect();
            let datos = Arc::clone(&self.datos);
            let veredictos = verificar_lote_con_huella_y_sumas(
                &lote,
                datos.tabla(),
                datos.claves(),
                datos.reparto(),
                self.a,
                datos.huella(),
                datos.sumas(),
                generador,
            )?;

            // (c) aplica en orden desde `pos` hasta el último verificado.
            let mut k = 0usize;
            for (j, indice_final) in pendientes.iter().enumerate().take(ultimo + 1).skip(pos) {
                let Some(agregado) = agregados.get(*indice_final) else {
                    continue;
                };
                let plaza = (agregado.subred, agregado.indice_agregadora);
                let veredicto = if seleccion.get(k).copied() == Some(j) {
                    let actual = veredictos.get(k).copied();
                    k += 1;
                    actual
                } else {
                    None
                };
                let resultado = if self.aceptados.contains_key(&plaza) || self.no_anade(agregado) {
                    ResultadoAgregado::Repetido
                } else if let Some(veredicto) = veredicto {
                    match veredicto {
                        VeredictoAgregado::Valido => {
                            if let Entry::Vacant(hueco) = self.aceptados.entry(plaza) {
                                hueco.insert(agregado.clone());
                            }
                            ResultadoAgregado::Aceptado
                        }
                        VeredictoAgregado::Invalido(motivo) => ResultadoAgregado::Invalido(motivo),
                        VeredictoAgregado::OtraTabla => ResultadoAgregado::OtraTabla,
                    }
                } else {
                    // No se seleccionó (dominado de forma optimista): se verifica ahora, solo.
                    let uno = [agregado.clone()];
                    let veredictos_uno = verificar_lote_con_huella_y_sumas(
                        &uno,
                        datos.tabla(),
                        datos.claves(),
                        datos.reparto(),
                        self.a,
                        datos.huella(),
                        datos.sumas(),
                        generador,
                    )?;
                    match veredictos_uno.first().copied() {
                        Some(VeredictoAgregado::Valido) => {
                            if let Entry::Vacant(hueco) = self.aceptados.entry(plaza) {
                                hueco.insert(agregado.clone());
                            }
                            ResultadoAgregado::Aceptado
                        }
                        Some(VeredictoAgregado::Invalido(motivo)) => {
                            ResultadoAgregado::Invalido(motivo)
                        }
                        Some(VeredictoAgregado::OtraTabla) => ResultadoAgregado::OtraTabla,
                        None => ResultadoAgregado::Invalido(MotivoAgregado::Forma),
                    }
                };
                if let Some(slot) = resultados.get_mut(*indice_final) {
                    *slot = Some(resultado);
                }
            }
            pos = ultimo + 1;
        }

        Ok(resultados
            .into_iter()
            .map(|resultado| {
                resultado.unwrap_or(ResultadoAgregado::Invalido(MotivoAgregado::Forma))
            })
            .collect())
    }

    /// Inserta un agregado **ya verificado** en la plaza de su agregadora (B2), sin volver a
    /// clasificarlo ni a verificar su criptografía.
    ///
    /// Gancho de la recepción por lotes de [`crate::ventana_raices::VentanaPorRaices`], que verifica
    /// el lote entero una sola vez: el llamador garantiza que el veredicto del agregado es
    /// `Valido` contra los datos de esta ventana y que su plaza estaba libre. Un agregado inválido
    /// **no** debe llamar a este método.
    pub(crate) fn aceptar_verificado(&mut self, agregado: &Agregado) {
        self.aceptados.insert(
            (agregado.subred, agregado.indice_agregadora),
            agregado.clone(),
        );
    }

    /// Devuelve el agregado propio de la clave en la posición **1-based** `posicion`, dada su firma
    /// de sorteo.
    ///
    /// Existe solo si la firma «sale» ([`sale_agregadora`]) y el voto suelto de esa clave está
    /// registrado; lleva **todos** los sueltos registrados de su subred. **Una sola vez por clave:**
    /// la segunda llamada devuelve `None`. La huella se toma del bloque compartido.
    ///
    /// # Errores
    /// [`ErrorAgregacion::ClaveNoRegistrada`] si la posición no está en `1..=N`; el de BLS al
    /// agregar las firmas.
    pub fn agregado_propio(
        &mut self,
        posicion: usize,
        firma_sorteo: &Firma,
    ) -> Result<Option<Agregado>, ErrorAgregacion> {
        let n = self.datos.tabla().claves.len();
        if posicion == 0 || posicion > n {
            return Err(ErrorAgregacion::ClaveNoRegistrada);
        }
        if self.propios.contains(&posicion) || !self.sueltos.contains_key(&posicion) {
            return Ok(None);
        }
        let clave = self
            .datos
            .claves()
            .get(posicion - 1)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        let sub = subred(&clave.bytes(), self.datos.reparto().s())?;
        let huella = hash_bytes(&firma_sorteo.bytes());
        if !sale_agregadora(&huella, n, self.datos.reparto().s(), self.a) {
            return Ok(None);
        }

        let indices_subred = self.datos.reparto().claves_de(sub);
        let n_s = indices_subred.len();
        let mut mapa_local = vec![0u8; n_s.div_ceil(8)];
        let mut firmas: Vec<Firma> = Vec::new();
        let mut posicion_local = None;
        for (pos, &idx_global) in indices_subred.iter().enumerate() {
            if let Some(firma) = self.sueltos.get(&(idx_global + 1)) {
                if let Some(byte) = mapa_local.get_mut(pos >> 3) {
                    *byte |= 1 << (pos & 7);
                }
                firmas.push(*firma);
                if idx_global == posicion - 1 {
                    posicion_local = Some(pos);
                }
            }
        }
        let indice_agregadora = posicion_local.ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        let referencias: Vec<&Firma> = firmas.iter().collect();
        let firma_agregada = agregar_firmas(&referencias)?;
        let agregado = Agregado {
            n: self.mensaje.n,
            candidato: self.mensaje.candidato,
            h_t_siguiente: self.mensaje.h_t_siguiente,
            raiz_estado: self.mensaje.raiz_estado,
            firma_agregada,
            huella_tabla: self.datos.huella(),
            subred: sub,
            indice_agregadora: u16::try_from(indice_agregadora)
                .map_err(|_| ErrorAgregacion::FueraDeU16)?,
            mapa_local,
            firma_sorteo: *firma_sorteo,
        };
        self.propios.insert(posicion);
        Ok(Some(agregado))
    }

    /// Peso total `W` de la tabla (suma saturada de los pesos).
    #[must_use]
    pub fn peso_total(&self) -> u128 {
        self.datos.peso_total()
    }

    /// Mapa global de quienes constan (agregados aceptados y sueltos), con la elección AG-R14.
    ///
    /// Es el mapa que el acta usa cuando no hay quórum.
    ///
    /// # Errores
    /// El de [`elegir_mapa_firmas`] si `pesos` dejara de ser paralelo (no ocurre tras `nuevo`).
    pub fn mapa_constan(&self) -> Result<Vec<u8>, ErrorAgregacion> {
        let agregados = self.agregados_aceptados();
        let sueltos = self.sueltos_lista();
        let datos = Arc::clone(&self.datos);
        let (mapa, _) = elegir_mapa_firmas(
            datos.tabla(),
            datos.pesos(),
            datos.reparto(),
            &agregados,
            &sueltos,
        )?;
        Ok(mapa)
    }

    /// Peso cubierto `C` por el mapa de [`Self::mapa_constan`], con la elección AG-R14.
    ///
    /// # Errores
    /// El de [`Self::mapa_constan`].
    pub fn peso_cubierto(&self) -> Result<u128, ErrorAgregacion> {
        let mapa = self.mapa_constan()?;
        Ok(peso_de_mapa(&mapa, self.datos.pesos()))
    }

    /// `true` si `3·C ≥ 2·W` con la cobertura actual ([`quorum_peso`]).
    ///
    /// # Errores
    /// El de [`Self::peso_cubierto`].
    pub fn hay_quorum(&self) -> Result<bool, ErrorAgregacion> {
        Ok(quorum_peso(self.peso_cubierto()?, self.peso_total()))
    }

    /// Certificado compacto del mensaje, o `None` si no hay quórum.
    ///
    /// Cuando lo hay, pasa [`crate::peso::verificar_firma_peso`] contra la tabla y sus claves.
    ///
    /// # Errores
    /// El de BLS al agregar firmas (por ejemplo, sin firmantes).
    pub fn certificado(&self) -> Result<Option<CertificadoPeso>, ErrorAgregacion> {
        if !self.hay_quorum()? {
            return Ok(None);
        }
        let agregados = self.agregados_aceptados();
        let sueltos = self.sueltos_lista();
        let datos = Arc::clone(&self.datos);
        let certificado = armar_certificado(
            self.mensaje,
            datos.tabla(),
            datos.pesos(),
            datos.reparto(),
            &agregados,
            &sueltos,
        )?;
        Ok(Some(certificado))
    }

    /// Clasificación **sin criptografía**: mensaje, tabla, forma y repetido.
    ///
    /// La huella se compara con la del bloque compartido; **no** se recalcula.
    fn clasificar_sin_firma(&self, agregado: &Agregado) -> Option<ResultadoAgregado> {
        if !self.es_nuestro_mensaje(agregado) {
            return Some(ResultadoAgregado::OtroMensaje);
        }
        if agregado.huella_tabla != self.datos.huella() {
            return Some(ResultadoAgregado::OtraTabla);
        }
        if let Some(motivo) = motivo_forma(self.datos.reparto(), agregado) {
            return Some(ResultadoAgregado::Invalido(motivo));
        }
        if self
            .aceptados
            .contains_key(&(agregado.subred, agregado.indice_agregadora))
        {
            return Some(ResultadoAgregado::Repetido);
        }
        None
    }

    /// Compara los cuatro campos del mensaje A3 con los de la ventana.
    fn es_nuestro_mensaje(&self, agregado: &Agregado) -> bool {
        self.mensaje.n == agregado.n
            && self.mensaje.candidato == agregado.candidato
            && self.mensaje.h_t_siguiente == agregado.h_t_siguiente
            && self.mensaje.raiz_estado == agregado.raiz_estado
    }

    /// Instantánea de los agregados aceptados, en orden de `(subred, indice_agregadora)`.
    fn agregados_aceptados(&self) -> Vec<Agregado> {
        self.aceptados.values().cloned().collect()
    }

    /// Instantánea de los sueltos registrados, `(posición 1-based, firma)`, en orden de posición.
    fn sueltos_lista(&self) -> Vec<(usize, Firma)> {
        self.sueltos
            .iter()
            .map(|(clave, firma)| (*clave, *firma))
            .collect()
    }
}
