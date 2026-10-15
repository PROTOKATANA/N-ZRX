//! Pieza **T** (MA-1) · marcas de tiempo del PoST sobre la cadena seleccionada del bloque.
//!
//! Reglas `C-RLJ-TS-01` (PMT por la cadena de `B`), `C-RLJ-TS-02` (FTL diferible) y
//! `C-RLJ-TS-03` (banda **solo diagnóstico**) de `ORDEN-RLJ3A`. El módulo **no conoce `Nodo`**:
//! lee los bloques por el `trait` [`BloquesPost`] y recibe todos los parámetros (hora local, `FTL`,
//! `M_ts`, banda y `τ`) como argumentos.
//!
//! La ventana son los últimos `M_ts` bloques PoST de `C(B)` partiendo del padre seleccionado que
//! **declara la cabecera** de `B` y siguiendo el padre seleccionado declarado de cada ancestro,
//! hasta `M_ts` bloques o hasta el terminal (que no entra). La admisión verifica que ese padre
//! declarado es el que calcula GHOSTDAG (`crates/zx-dag/src/bloque_dag.rs:372-379`, con el contexto
//! real `AlmacenGhostdag` en `crates/zx-dag/src/ghostdag.rs:1595`), así que la cadena declarada es
//! autenticada. Nunca se usa la punta virtual local ni una rama lateral.

use std::collections::BTreeMap;

use zx_cadena::{BloqueCadena, Cadena};
use zx_core::BlockHash;

/// Adaptador de [`Cadena`] al `trait` [`BloquesPost`]. Es **cableado** (no conoce `Nodo`) y vive
/// fuera de `impl Nodo`; no decide nada.
///
/// `seleccionada` es el índice `hash -> posición` de la cadena seleccionada **del nodo** que el
/// llamante mantiene en memoria (`Nodo::ultima_cadena_indice`); sirve para responder
/// [`BloquesPost::en_cadena_seleccionada`] en coste acotado, sin reconstruir la historia. `ancla`
/// es el primer PoST de esa cadena, ya calculado una vez por el nodo (precisión 4 de
/// `ORDEN-RLJ3A`). Con [`AdaptadorCadena::nueva`] ambos quedan vacíos y la pertenencia cae a la
/// consulta de `Cadena`.
pub struct AdaptadorCadena<'a> {
    cadena: &'a Cadena,
    seleccionada: Option<&'a BTreeMap<BlockHash, usize>>,
    ancla: Option<(u64, i64)>,
}

impl<'a> AdaptadorCadena<'a> {
    /// Envuelve una `Cadena` para que la pieza lea sus bloques PoST.
    #[must_use]
    pub const fn nueva(cadena: &'a Cadena) -> Self {
        Self {
            cadena,
            seleccionada: None,
            ancla: None,
        }
    }

    /// Adaptador con la pertenencia a la cadena seleccionada del nodo y su ancla diagnóstica.
    #[must_use]
    pub const fn con_cadena_seleccionada(
        cadena: &'a Cadena,
        seleccionada: &'a BTreeMap<BlockHash, usize>,
        ancla: Option<(u64, i64)>,
    ) -> Self {
        Self {
            cadena,
            seleccionada: Some(seleccionada),
            ancla,
        }
    }
}

impl BloquesPost for AdaptadorCadena<'_> {
    fn bloque_post(&self, hash: &BlockHash) -> Option<(u64, i64, BlockHash)> {
        let Some(BloqueCadena::Post(p)) = self.cadena.bloque(hash) else {
            return None;
        };
        let marca = i64::try_from(p.timestamp).ok()?;
        let padre = p.padres.first().copied()?;
        Some((p.slot, marca, padre))
    }

    fn en_cadena_seleccionada(&self, hash: &BlockHash) -> bool {
        match self.seleccionada {
            Some(indice) => indice.contains_key(hash),
            None => self.cadena.en_cadena_seleccionada(hash),
        }
    }

    fn ancla_post_nodo(&self, _terminal: &BlockHash) -> Option<(u64, i64)> {
        self.ancla
    }
}

/// Lectura de un bloque PoST por hash, para la pieza.
pub trait BloquesPost {
    /// `(slot, marca, padre seleccionado)` del bloque PoST `hash`.
    ///
    /// Devuelve `None` si `hash` no es un bloque PoST conocido (el terminal PoW, un ancestro
    /// ausente o una marca fuera del dominio `i64`).
    fn bloque_post(&self, hash: &BlockHash) -> Option<(u64, i64, BlockHash)>;

    /// ¿`hash` pertenece a la cadena seleccionada del nodo? (solo diagnóstico; no decide).
    ///
    /// El adaptador real lo responde con un índice en memoria: coste acotado por bloque.
    fn en_cadena_seleccionada(&self, _hash: &BlockHash) -> bool {
        false
    }

    /// Primer bloque PoST (ancla diagnóstica) de la cadena seleccionada del nodo para `terminal`.
    ///
    /// El nodo lo calcula **una vez** y lo guarda en memoria; `None` si no hay ancla.
    fn ancla_post_nodo(&self, _terminal: &BlockHash) -> Option<(u64, i64)> {
        None
    }
}

/// Falta un ancestro requerido por la ventana (contexto incompleto).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaltaContexto(pub BlockHash);

/// Ventana `W_ts(B)` de `C-RLJ-TS-01` y ancla del diagnóstico `C-RLJ-TS-03`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VentanaTs {
    marcas: Vec<(u64, i64)>,
    ancla: Option<(u64, i64)>,
    ancla_disponible: bool,
}

impl VentanaTs {
    /// Marcas de la ventana en orden de cadena (antiguo → nuevo).
    #[must_use]
    pub fn marcas(&self) -> &[(u64, i64)] {
        &self.marcas
    }

    /// Primer PoST de la cadena seleccionada del nodo, si el ancla está disponible; `None` si no.
    #[must_use]
    pub const fn ancla(&self) -> Option<(u64, i64)> {
        self.ancla
    }

    /// ¿El ancla diagnóstica está disponible? Es `true` si algún bloque recorrido por la ventana
    /// (como mucho `M_ts`) pertenece a la cadena seleccionada del nodo (precisión 4 de
    /// `ORDEN-RLJ3A`).
    #[must_use]
    pub const fn ancla_disponible(&self) -> bool {
        self.ancla_disponible
    }

    /// Constructor para pruebas de la pieza sola (dependencias falsas): ventana ya extraída.
    #[cfg(test)]
    #[must_use]
    pub fn de_prueba(marcas: Vec<(u64, i64)>, ancla: Option<(u64, i64)>) -> Self {
        Self {
            marcas,
            ancla,
            ancla_disponible: ancla.is_some(),
        }
    }
}

/// Recorre `C(B)` desde el padre seleccionado declarado de `B` y devuelve los últimos `M_ts`
/// bloques PoST, en orden de cadena.
///
/// Lee como mucho `M_ts` bloques. Si falta un ancestro que debería estar, devuelve
/// [`FaltaContexto`] con su hash: **nunca** una ventana parcial.
///
/// El ancla diagnóstica (`VentanaTs::ancla`) es el primer PoST de la cadena seleccionada del nodo
/// y está disponible para `B` si alguno de los bloques que la ventana recorre pertenece a esa
/// cadena; el lector la aporta por [`BloquesPost::ancla_post_nodo`]. No influye en ningún veredicto.
///
/// # Errores
/// [`FaltaContexto`] si un ancestro requerido no es un bloque PoST conocido o si un bloque se
/// declara padre seleccionado de sí mismo (cadena corrupta).
pub fn ventana_cadena_seleccionada<B: BloquesPost + ?Sized>(
    bloques: &B,
    terminal: &BlockHash,
    padre_seleccionado: &BlockHash,
    m_ts: usize,
) -> Result<VentanaTs, FaltaContexto> {
    let mut recientes: Vec<(u64, i64)> = Vec::with_capacity(m_ts.min(1024));
    let mut hash = *padre_seleccionado;
    let mut en_cadena_nodo = false;
    while hash != *terminal {
        if recientes.len() >= m_ts {
            break;
        }
        let Some((slot, marca, padre)) = bloques.bloque_post(&hash) else {
            return Err(FaltaContexto(hash));
        };
        if padre == hash {
            return Err(FaltaContexto(hash));
        }
        if bloques.en_cadena_seleccionada(&hash) {
            en_cadena_nodo = true;
        }
        recientes.push((slot, marca));
        hash = padre;
    }
    // Ancla disponible solo si la ventana tocó la cadena seleccionada del nodo. El ancla la
    // calcula y guarda el nodo una sola vez (`ORDEN-RLJ3A`, precisión 4); aquí no se recorre la
    // historia.
    let ancla = if en_cadena_nodo {
        bloques.ancla_post_nodo(terminal)
    } else {
        None
    };
    recientes.reverse();
    Ok(VentanaTs {
        marcas: recientes,
        ancla,
        ancla_disponible: ancla.is_some(),
    })
}

/// Parámetros de la pieza `T` que no dependen de la vista local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParametrosMarcas {
    /// `M_ts`: tamaño de la ventana de la mediana del pasado.
    pub m_ts: usize,
    /// `FTL`: límite de futuro en segundos (diferible).
    pub ftl: i64,
    /// `Banda_slot`: semiancho del diagnóstico (no es validez).
    pub banda_slot: u64,
    /// Numerador de `τ*` (segundos por slot).
    pub tau_num: i128,
    /// Denominador de `τ*` (positivo).
    pub tau_den: i128,
}

/// Diagnóstico de la banda `C-RLJ-TS-03`. **No** altera el veredicto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticoBanda {
    /// No hay ancla diagnóstica disponible (ningún bloque recorrido pertenece a la cadena
    /// seleccionada del nodo, o el nodo no tiene ancla para ese terminal).
    NoDisponible,
    /// `|δ| ≤ Banda_slot`.
    Dentro,
    /// `|δ| > Banda_slot`; `δ` entero (truncado hacia abajo) y la banda.
    Fuera {
        /// Desviación en segundos enteros.
        delta_segundos: i64,
        /// `Banda_slot`.
        banda_slot: u64,
    },
}

/// Motivo de rechazo **permanente** (determinista del bloque y de `C(B)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotivoPermanente {
    /// `timestamp(B) < PMT(B)` (`C-RLJ-TS-01`).
    PorDebajoDePmt {
        /// Marca del candidato.
        ts: i64,
        /// Mediana superior del pasado.
        pmt: i64,
    },
}

/// Motivo de retención **no permanente** (`Pendiente`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotivoPendiente {
    /// Falta un ancestro de la ventana; no penaliza.
    FaltaContexto(BlockHash),
    /// `timestamp(B) > reloj_local + FTL` (`C-RLJ-TS-02`); se reintenta.
    DemasiadoFuturo {
        /// Marca del candidato.
        ts: i64,
        /// `reloj_local + FTL`.
        limite: i64,
    },
}

/// Veredicto del receptor para `C-RLJ-TS-01` y `C-RLJ-TS-02`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VeredictoReceptor {
    /// Admisible por marcas (las puertas previas ya pasaron).
    Valido,
    /// Defecto permanente.
    Invalido(MotivoPermanente),
    /// Se retiene y se reintenta, sin penalizar.
    Pendiente(MotivoPendiente),
}

/// Resultado conjunto del receptor: veredicto de admisión y diagnóstico de banda.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultadoReceptor {
    /// Veredicto de PMT/FTL.
    pub veredicto: VeredictoReceptor,
    /// Diagnóstico `C-RLJ-TS-03` (nunca influye en el veredicto).
    pub diagnostico: DiagnosticoBanda,
}

/// Mediana superior (`floor(n/2)` desde cero) de las marcas de la ventana, o `None` si está vacía.
#[must_use]
pub fn pmt_de_marcas(marcas: &[(u64, i64)], m_ts: usize) -> Option<i64> {
    let marcas_ts: Vec<i64> = marcas.iter().map(|(_, t)| *t).collect();
    zx_consensus::pmt(&marcas_ts, m_ts).ok()
}

/// Diagnóstico `C-RLJ-TS-03` sobre una ventana ya extraída. No es condición de validez.
#[must_use]
pub fn diagnosticar_banda(
    ventana: &VentanaTs,
    ts_b: i64,
    slot_b: u64,
    p: &ParametrosMarcas,
) -> DiagnosticoBanda {
    let Some((s0, t0)) = ventana.ancla else {
        return DiagnosticoBanda::NoDisponible;
    };
    if p.tau_den <= 0 || p.tau_num <= 0 {
        return DiagnosticoBanda::NoDisponible;
    }
    let den = p.tau_den;
    let base = i128::from(t0)
        .saturating_mul(den)
        .saturating_add(i128::from(slot_b.saturating_sub(s0)).saturating_mul(p.tau_num));
    let dif = i128::from(ts_b).saturating_mul(den).saturating_sub(base);
    let margen = i128::from(p.banda_slot).saturating_mul(den);
    if dif.abs() > margen {
        let delta = i64::try_from(dif.div_euclid(den)).unwrap_or(if dif.is_negative() {
            i64::MIN
        } else {
            i64::MAX
        });
        DiagnosticoBanda::Fuera {
            delta_segundos: delta,
            banda_slot: p.banda_slot,
        }
    } else {
        DiagnosticoBanda::Dentro
    }
}

/// Veredicto del receptor `C-RLJ-TS-01` → `C-RLJ-TS-02` y diagnóstico `C-RLJ-TS-03` sobre una
/// ventana ya extraída.
///
/// El orden es el de `C-RLJ-TS-04`: primero PMT (permanente) y después FTL (diferible). El contexto
/// ausente lo señala [`ventana_cadena_seleccionada`] antes de llegar aquí.
#[must_use]
pub fn verificar_receptor_con_ventana(
    ventana: &VentanaTs,
    ts_b: i64,
    slot_b: u64,
    reloj_local: i64,
    p: &ParametrosMarcas,
) -> ResultadoReceptor {
    let diagnostico = diagnosticar_banda(ventana, ts_b, slot_b, p);
    if let Some(pmt) = pmt_de_marcas(ventana.marcas(), p.m_ts)
        && ts_b < pmt
    {
        return ResultadoReceptor {
            veredicto: VeredictoReceptor::Invalido(MotivoPermanente::PorDebajoDePmt {
                ts: ts_b,
                pmt,
            }),
            diagnostico,
        };
    }
    let limite = reloj_local.saturating_add(p.ftl);
    if ts_b > limite {
        return ResultadoReceptor {
            veredicto: VeredictoReceptor::Pendiente(MotivoPendiente::DemasiadoFuturo {
                ts: ts_b,
                limite,
            }),
            diagnostico,
        };
    }
    ResultadoReceptor {
        veredicto: VeredictoReceptor::Valido,
        diagnostico,
    }
}

/// Selector puro del productor (`§1` precisión 5): hora entera si satisface PMT y `FTL`; si la hora
/// es menor que la PMT, firma la PMT; si la PMT supera `ahora + FTL`, se abstiene (`None`).
///
/// La banda **no** interviene.
#[must_use]
pub fn seleccionar_timestamp(ahora: i64, pmt: Option<i64>, ftl: i64) -> Option<i64> {
    let maximo = ahora.saturating_add(ftl);
    let ts = match pmt {
        None => ahora,
        Some(pmt) => {
            if pmt > maximo {
                return None;
            }
            ahora.max(pmt)
        }
    };
    (ts <= maximo).then_some(ts)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division
)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use zx_core::digest::Digest;

    const TERMINAL: u8 = 0;

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn hu(n: u64) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        BlockHash::from_digest(Digest::from_bytes(bytes))
    }

    struct Falso(BTreeMap<BlockHash, (u64, i64, BlockHash)>);

    impl BloquesPost for Falso {
        fn bloque_post(&self, hash: &BlockHash) -> Option<(u64, i64, BlockHash)> {
            self.0.get(hash).copied()
        }

        fn en_cadena_seleccionada(&self, hash: &BlockHash) -> bool {
            self.0.contains_key(hash)
        }

        fn ancla_post_nodo(&self, terminal: &BlockHash) -> Option<(u64, i64)> {
            self.0
                .values()
                .find(|(_, _, padre)| padre == terminal)
                .map(|(slot, marca, _)| (*slot, *marca))
        }
    }

    struct Contador {
        mapa: BTreeMap<BlockHash, (u64, i64, BlockHash)>,
        lecturas: Cell<usize>,
    }

    impl BloquesPost for Contador {
        fn bloque_post(&self, hash: &BlockHash) -> Option<(u64, i64, BlockHash)> {
            self.lecturas.set(self.lecturas.get().saturating_add(1));
            self.mapa.get(hash).copied()
        }

        fn en_cadena_seleccionada(&self, hash: &BlockHash) -> bool {
            self.mapa.contains_key(hash)
        }

        fn ancla_post_nodo(&self, terminal: &BlockHash) -> Option<(u64, i64)> {
            self.mapa
                .values()
                .find(|(_, _, padre)| padre == terminal)
                .map(|(slot, marca, _)| (*slot, *marca))
        }
    }

    fn params(m_ts: usize) -> ParametrosMarcas {
        ParametrosMarcas {
            m_ts,
            ftl: zx_consensus::FTL_POST_DEV,
            banda_slot: zx_consensus::BANDA_SLOT_DEV,
            tau_num: 1,
            tau_den: 1,
        }
    }

    /// A1 · dos ramas fusionadas con marcas 10 y 20, padre seleccionado en la de 10: la PMT es 10.
    /// Control rojo: la unión de padres daría 20.
    #[test]
    fn a1_pmt_por_la_cadena_del_padre_seleccionado_y_no_por_la_union() {
        let x = h(1);
        let y = h(2);
        let mut m = BTreeMap::new();
        m.insert(x, (2, 10, h(TERMINAL)));
        m.insert(y, (2, 20, h(TERMINAL)));
        let f = Falso(m);
        let v = ventana_cadena_seleccionada(&f, &h(TERMINAL), &x, 264).unwrap();
        assert_eq!(v.marcas(), &[(2, 10)]);
        assert_eq!(pmt_de_marcas(v.marcas(), 264), Some(10));
        assert_eq!(zx_consensus::pmt(&[10, 20], 264).unwrap(), 20);
    }

    /// A2 · mesetas de igual slot: la ventana son exactamente los últimos `M_ts` por orden de
    /// cadena. Control rojo: ordenar por hash en la meseta cambia la elección y la PMT.
    #[test]
    fn a2_meseta_de_igual_slot_usa_el_ultimo_de_la_cadena() {
        let a = hu(200);
        let b = hu(1);
        let c = hu(2);
        let mut m = BTreeMap::new();
        m.insert(a, (5, 10, h(TERMINAL)));
        m.insert(b, (5, 20, a));
        m.insert(c, (6, 15, b));
        let f = Falso(m);
        let v = ventana_cadena_seleccionada(&f, &h(TERMINAL), &c, 2).unwrap();
        assert_eq!(
            v.marcas(),
            &[(5, 20), (6, 15)],
            "últimos 2 por orden de cadena"
        );
        assert_eq!(pmt_de_marcas(v.marcas(), 2), Some(20));
        assert_eq!(zx_consensus::pmt(&[10, 15], 2).unwrap(), 15);

        let n = 300u64;
        let m_ts = 264usize;
        let mut m = BTreeMap::new();
        for i in 1..=n {
            let padre = if i == 1 { h(TERMINAL) } else { hu(i - 1) };
            m.insert(hu(i), (i, 1000 + i as i64, padre));
        }
        let f = Falso(m);
        let v = ventana_cadena_seleccionada(&f, &h(TERMINAL), &hu(n), m_ts).unwrap();
        assert_eq!(v.marcas().len(), m_ts);
        let primera = n - m_ts as u64 + 1;
        assert_eq!(
            v.marcas().first().copied(),
            Some((primera, 1000 + primera as i64))
        );
        assert_eq!(v.marcas().last().copied(), Some((n, 1000 + n as i64)));
    }

    /// A7 · historia de 10³ y 10⁵: la ventana lee como mucho `M_ts` bloques y un ancestro ausente
    /// da «falta contexto» con su hash, nunca ventana parcial.
    #[test]
    fn a7_lectura_acotada_y_ancestro_ausente() {
        for n in [1_000u64, 100_000] {
            let mut mapa = BTreeMap::new();
            for i in 1..=n {
                let padre = if i == 1 { h(TERMINAL) } else { hu(i - 1) };
                mapa.insert(hu(i), (i, 1000 + i as i64, padre));
            }
            let f = Contador {
                mapa,
                lecturas: Cell::new(0),
            };
            let v = ventana_cadena_seleccionada(&f, &h(TERMINAL), &hu(n), 264).unwrap();
            assert_eq!(v.marcas().len(), 264);
            assert!(
                f.lecturas.get() <= 264,
                "lee como mucho M_ts: {}",
                f.lecturas.get()
            );
            assert_eq!(v.marcas().first().copied().map(|(s, _)| s), Some(n - 263));
        }
        let mut m = BTreeMap::new();
        m.insert(hu(5), (5, 1005, hu(4)));
        let f = Falso(m);
        assert_eq!(
            ventana_cadena_seleccionada(&f, &h(TERMINAL), &hu(5), 264),
            Err(FaltaContexto(hu(4)))
        );
    }

    /// A3 · hermanos locales distintos no cambian la ventana ni el veredicto.
    #[test]
    fn a3_hermanos_locales_no_cambian_el_veredicto() {
        let a = h(1);
        let b = h(2);
        let lateral = h(3);
        let mut solo = BTreeMap::new();
        solo.insert(a, (1, 100, h(TERMINAL)));
        solo.insert(b, (2, 200, a));
        let mut con = solo.clone();
        con.insert(lateral, (2, 999, h(TERMINAL)));
        let fs = Falso(solo);
        let fc = Falso(con);
        let vs = ventana_cadena_seleccionada(&fs, &h(TERMINAL), &b, 264).unwrap();
        let vc = ventana_cadena_seleccionada(&fc, &h(TERMINAL), &b, 264).unwrap();
        assert_eq!(vs.marcas(), vc.marcas());
        let rs = verificar_receptor_con_ventana(&vs, 200, 2, 1_000, &params(264));
        let rc = verificar_receptor_con_ventana(&vc, 200, 2, 1_000, &params(264));
        assert_eq!(rs.veredicto, VeredictoReceptor::Valido);
        assert_eq!(rs.veredicto, rc.veredicto);
    }

    /// A4 · banda `diagnóstico` y PMT/FTL como condiciones: fuera de banda con PMT/FTL correctos es
    /// válido y sale el diagnóstico; bajo la PMT es inválido permanente; solo FTL es pendiente.
    #[test]
    fn a4_banda_diagnostica_y_pmt_permanente() {
        let a = h(1);
        let b = h(2);
        let mut m = BTreeMap::new();
        m.insert(a, (1, 100, h(TERMINAL)));
        m.insert(b, (2, 200, a));
        let f = Falso(m);
        let v = ventana_cadena_seleccionada(&f, &h(TERMINAL), &b, 264).unwrap();
        assert_eq!(v.ancla(), Some((1, 100)));

        let r = verificar_receptor_con_ventana(&v, 300, 5, 1_000, &params(264));
        assert_eq!(r.veredicto, VeredictoReceptor::Valido);
        assert_eq!(
            r.diagnostico,
            DiagnosticoBanda::Fuera {
                delta_segundos: 196,
                banda_slot: 30
            }
        );

        let r = verificar_receptor_con_ventana(&v, 100, 5, 1_000, &params(264));
        assert!(matches!(
            r.veredicto,
            VeredictoReceptor::Invalido(MotivoPermanente::PorDebajoDePmt { pmt: 200, .. })
        ));

        // A5 · solo FTL: pendiente, sin penalización (el nodo lo clasifica `Pendiente`).
        let r = verificar_receptor_con_ventana(&v, 2_000, 5, 1_000, &params(264));
        assert!(matches!(
            r.veredicto,
            VeredictoReceptor::Pendiente(MotivoPendiente::DemasiadoFuturo { .. })
        ));
    }

    /// A6 · selector del productor: hora entera, PMT como suelo y abstención si `PMT > ahora + FTL`.
    /// El ancla diagnóstica ausente no abstiene.
    #[test]
    fn a6_productor_firma_su_hora_entera_sin_banda() {
        assert_eq!(seleccionar_timestamp(500_000, Some(1), 540), Some(500_000));
        assert_eq!(seleccionar_timestamp(500, Some(900), 540), Some(900));
        assert_eq!(seleccionar_timestamp(500, Some(2_000), 540), None);
        assert_eq!(seleccionar_timestamp(700, None, 540), Some(700));
    }

    /// A8 · deriva sostenida de 10⁵ slots con relojes 0,5 % lentos y 0,5 % rápidos: sin recorte,
    /// sin abstención, sin rechazo y con error 0 frente al reloj del productor. Control rojo: la
    /// banda fija habría recortado desde ~6 000 slots.
    #[test]
    fn a8_deriva_sostenida_sin_recorte_ni_abstencion_ni_rechazo() {
        let n = 100_000u64;
        let m_ts = 264usize;
        for (factor_num, factor_den) in [(995i64, 1000i64), (1005, 1000)] {
            let mut marcas: Vec<(u64, i64)> = Vec::with_capacity(m_ts + 1);
            let mut abstenciones = 0usize;
            let mut rechazos = 0usize;
            let mut recortes_banda_fija = 0usize;
            for i in 1..=n {
                let ahora = (i as i64) * factor_num / factor_den;
                let ventana = VentanaTs::de_prueba(marcas.clone(), None);
                let pmt = pmt_de_marcas(ventana.marcas(), m_ts);
                let Some(marca) = seleccionar_timestamp(ahora, pmt, zx_consensus::FTL_POST_DEV)
                else {
                    abstenciones += 1;
                    continue;
                };
                // Verificador con reloj real (1 s por slot): el productor honesto no se rechaza.
                let r = verificar_receptor_con_ventana(&ventana, marca, i, i as i64, &params(m_ts));
                if !matches!(r.veredicto, VeredictoReceptor::Valido) {
                    rechazos += 1;
                }
                assert_eq!(marca, ahora, "marca recortada en el slot {i}");
                if i > 6_000 && (ahora - i as i64).abs() > 30 {
                    recortes_banda_fija += 1;
                }
                marcas.push((i, marca));
                if marcas.len() > m_ts {
                    marcas.remove(0);
                }
            }
            assert_eq!(
                abstenciones, 0,
                "ninguna abstención con deriva {factor_num}/1000"
            );
            assert_eq!(rechazos, 0, "ningún rechazo con deriva {factor_num}/1000");
            assert!(
                recortes_banda_fija > 0,
                "el control rojo de banda fija debe recortar"
            );
        }
    }

    /// A4L · deriva sostenida del 5 % en una cadena de 1 000 bloques (mayor que `M_ts`): el ancla
    /// diagnóstica está **disponible** (primer PoST de la cadena seleccionada del nodo) y el bloque
    /// 1 000 sale «fuera»; el contador demuestra que la ventana lee como mucho `M_ts` bloques y no
    /// recorre la historia. Control rojo: el ancla que solo existía al alcanzar el terminal
    /// (`reloj_marcas.rs` de la ronda 1) devolvería `NoDisponible`.
    #[test]
    fn a4l_ancla_disponible_con_cadena_mayor_que_m_ts() {
        const N: u64 = 1_000;
        const M: usize = 264;
        let mut mapa = BTreeMap::new();
        // Deriva del 5 %: marca(i) = floor(105·i/100). Con τ = 1 el centro del bloque 1 000 es
        // 1 + (1000 − 1)·1 = 1000, y la marca es 1050: δ = 50 > banda 30.
        for i in 1..=N {
            let padre = if i == 1 { h(TERMINAL) } else { hu(i - 1) };
            let marca = (105 * i as i64).div_euclid(100);
            mapa.insert(hu(i), (i, marca, padre));
        }
        let f = Contador {
            mapa,
            lecturas: Cell::new(0),
        };
        let v = ventana_cadena_seleccionada(&f, &h(TERMINAL), &hu(N), M).unwrap();
        assert_eq!(v.marcas().len(), M);
        assert!(v.ancla_disponible(), "ancla disponible con > M_ts bloques");
        assert_eq!(v.ancla(), Some((1, 1)), "primer PoST de la cadena del nodo");
        let lecturas = f.lecturas.get();
        assert!(
            lecturas <= M,
            "lecturas por bloque = {lecturas} ≤ M_ts = {M}"
        );

        let ts_b = (105 * N as i64).div_euclid(100);
        let r = verificar_receptor_con_ventana(&v, ts_b, N, 10_000, &params(M));
        assert_eq!(r.veredicto, VeredictoReceptor::Valido);
        assert!(
            matches!(
                r.diagnostico,
                DiagnosticoBanda::Fuera {
                    delta_segundos: 50,
                    banda_slot: 30,
                }
            ),
            "{:?}",
            r.diagnostico
        );
    }
}
