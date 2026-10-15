//! Estado, invariantes y mutación con undo por delta.
//!
//! El motor funcional clona el estado de entrada y lo muta a través de [`Aplicador`], que registra
//! en un [`Undo`] el valor previo de cada clave tocada. `deshacer` restituye exactamente el estado
//! previo (§3.5, `I-2`).

use primitive_types::U256;
use zx_core::{Amount, ClavePublica, OutPoint};

use crate::cajas::CajaId;
use crate::sectores::SectorId;
use crate::transicion::ErrorTransicion;
use crate::transicion::tipos::{
    EnRetirada, EntradaUtxo, Escalares, Estado, Fase, Garantia, Marca, Origen, ParametrosEvidencia,
    ParametrosTransicion, Pendiente, Punto, Undo,
};

impl Estado {
    /// Estado inicial (fase génesis, todo vacío).
    #[must_use]
    pub fn inicial() -> Self {
        Self {
            utxo: std::collections::BTreeMap::new(),
            garantias: std::collections::BTreeMap::new(),
            emitido: 0,
            quemado: 0,
            fase: Fase::Genesis,
            terminal: None,
            altura: 0,
            trabajo: U256::zero(),
            slot: 0,
            s0: 0,
            peso_sufijo: 0,
            altura_terminal: None,
            subsidio_acum: 0,
            ultimo_slot_producido: std::collections::BTreeMap::new(),
            sectores: std::collections::BTreeMap::new(),
            parametros_sector: crate::sectores::ParametrosSector::dev(),
            cajas: std::collections::BTreeMap::new(),
            pruebas: std::collections::BTreeMap::new(),
            poreps: std::collections::BTreeMap::new(),
            claves_voto: std::collections::BTreeMap::new(),
            claves_voto_previas: std::collections::BTreeMap::new(),
            vencimientos_clave_voto: std::collections::BTreeMap::new(),
            finalidad_votos_n: 0,
            finalidad_votos: None,
            finalidad_votos_h_t: None,
            raiz_estado: None,
            tablas_voto: std::collections::BTreeMap::new(),
            tablas_voto_contenido: std::collections::BTreeMap::new(),
            tabla_ventana_voto: std::collections::BTreeMap::new(),
            tabla_ciclo_rearranque: std::collections::BTreeMap::new(),
            cola_tablas_voto: Vec::new(),
            ultima_ventana_derivada_sin_base: None,
            votantes_voto: std::collections::BTreeMap::new(),
            deuda_ausencia: std::collections::BTreeMap::new(),
            liquidacion_voto_hasta: None,
        }
    }

    /// Suma de garantía activa total (`Σ activo`).
    #[must_use]
    pub fn garantia_activa_total(&self) -> i128 {
        self.garantias
            .values()
            .map(|g| i128::from(g.activo.brek()))
            .sum()
    }

    /// Garantía activa de una clave (cero si no existe).
    #[must_use]
    pub fn activo_de(&self, clave: &ClavePublica) -> Amount {
        self.garantias.get(clave).map_or(Amount::CERO, |g| g.activo)
    }
}

/// Predicado de activación `Φ` (`TRN-04`, `SEC-0`): `Σ activo ≥ S_min` y `#claves ≥ K_min`.
#[must_use]
pub fn phi(estado: &Estado, params: &ParametrosTransicion) -> bool {
    let mut total: i128 = 0;
    let mut claves: u32 = 0;
    for g in estado.garantias.values() {
        total += i128::from(g.activo.brek());
        if g.activo >= params.q {
            claves += 1;
        }
    }
    total >= i128::from(params.s_min.brek()) && claves >= params.k_min
}

/// Madurez de una salida `coinbase_pow` en un punto dado (`TRN-02`, `TRN-02b`).
#[must_use]
pub fn gastable_en(
    entrada: &EntradaUtxo,
    fase: Fase,
    altura_terminal: Option<u32>,
    s0: u64,
    params: &ParametrosTransicion,
    punto: Punto,
) -> bool {
    if entrada.origen != Origen::CoinbasePow {
        return true;
    }
    let Punto::Altura(creada) = entrada.creada else {
        return true;
    };
    let Some(madura) = creada.checked_add(params.m_cb) else {
        return false;
    };
    match fase {
        Fase::PoW => punto.como_altura().is_some_and(|h| h >= madura),
        Fase::PoST => {
            if altura_terminal.is_some_and(|at| madura <= at) {
                return true;
            }
            match (punto.como_slot(), s0.checked_add(params.m_res_slots)) {
                (Some(s), Some(tope)) => s >= tope,
                _ => false,
            }
        }
        Fase::Genesis => false,
    }
}

/// Suma de valor del UTXO.
#[must_use]
pub fn suma_utxo(estado: &Estado) -> i128 {
    estado
        .utxo
        .values()
        .map(|e| i128::from(e.valor.brek()))
        .sum()
}

/// Suma de valor inmovilizado en garantías (activo, pendientes, créditos y retiradas).
///
/// SL-4a: `congelado` es un **gravamen derivado** (EV-17), no una sub-cuenta; no suma, igual que en
/// el oráculo T01 (`total_garantia`/`suma_garantias`).
#[must_use]
pub fn suma_garantias(estado: &Estado) -> i128 {
    let mut total: i128 = 0;
    for g in estado.garantias.values() {
        total += i128::from(g.activo.brek());
        for p in &g.pendientes {
            total += i128::from(p.importe.brek());
        }
        for p in &g.creditos {
            total += i128::from(p.importe.brek());
        }
        for r in &g.en_retirada {
            total += i128::from(r.importe.brek());
        }
    }
    total
}

/// `I-1`: `Σ UTXO + Σ garantías + Σ fianzas no terminales == Emitido − Quemado`.
///
/// Las fianzas de sector son dinero inmovilizado fuera de `Garantia` (`C-SEC-01`): entran en la
/// conservación igual que el oráculo extendido (`tests/soporte`), sin contar `congelado` ni las
/// cajas (caché de la fianza del sector).
#[must_use]
pub fn invariante_i1(estado: &Estado) -> bool {
    let mut total = suma_utxo(estado) + suma_garantias(estado);
    for r in estado.sectores.values() {
        if !r.es_terminal() {
            total += i128::from(r.fianza);
        }
    }
    total == estado.emitido - estado.quemado
}

/// `I-1b`: `Emitido ≤ Σ subsidios`.
#[must_use]
pub fn invariante_i1b(estado: &Estado) -> bool {
    estado.emitido <= estado.subsidio_acum
}

/// `Amount` a partir de un `i128` que ya se sabe no negativo y dentro de rango.
fn amount_brek(v: i128) -> Result<Amount, ErrorTransicion> {
    let b = i64::try_from(v).map_err(|_| ErrorTransicion::ErrDesbordamiento)?;
    Amount::nuevo(b).map_err(|_| ErrorTransicion::ErrDesbordamiento)
}

/// Suma total de una garantía (`EV-19`): `activo + pendientes + en_retirada + créditos`.
///
/// `congelado` es un gravamen derivado y **no** suma, igual que en el oráculo T01.
#[must_use]
pub fn total_garantia(g: &Garantia) -> i128 {
    let mut t = i128::from(g.activo.brek());
    for p in &g.pendientes {
        t += i128::from(p.importe.brek());
    }
    for r in &g.en_retirada {
        t += i128::from(r.importe.brek());
    }
    for p in &g.creditos {
        t += i128::from(p.importe.brek());
    }
    t
}

/// `techo_exacto(f·V) = ceil(V·f_num/f_den)` con enteros (`EV-19`).
#[must_use]
#[expect(
    clippy::integer_division,
    reason = "C-ENC-04 prohíbe floats; la división entera comprobada es la especificación de EV-19"
)]
pub fn techo_fraccion(v: i128, f_num: u64, f_den: u64) -> i128 {
    if f_den == 0 || f_num == 0 || v <= 0 {
        return 0;
    }
    let num = v
        .checked_mul(i128::from(f_num))
        .unwrap_or(i128::MAX)
        .saturating_add(i128::from(f_den) - 1);
    num / i128::from(f_den)
}

/// `RAT-2′`: `suelo(C·2/8) = C ÷ 4`, división entera **hacia abajo**.
#[must_use]
#[expect(
    clippy::integer_division,
    reason = "RAT-2′ exige división entera hacia abajo; no es aritmética de coma flotante"
)]
pub const fn suelo_dos_octavos(c: i128) -> i128 {
    if c <= 0 { 0 } else { c / 4 }
}

/// Debita `c` de las sub-cuentas en orden determinista:
/// `activo → pendientes → en_retirada → créditos` (`EV-19`/`EV-20`).
pub fn debitar_garantia(g: &mut Garantia, c: i128) -> Result<(), ErrorTransicion> {
    if c <= 0 {
        return Ok(());
    }
    let mut restante = c;

    let d = core::cmp::min(restante, i128::from(g.activo.brek()));
    g.activo = amount_brek(i128::from(g.activo.brek()) - d)?;
    restante -= d;

    let mut nuevas: Vec<Pendiente> = Vec::with_capacity(g.pendientes.len());
    for p in g.pendientes.drain(..) {
        if restante > 0 {
            let d = core::cmp::min(restante, i128::from(p.importe.brek()));
            restante -= d;
            if d == i128::from(p.importe.brek()) {
                continue;
            }
            nuevas.push(Pendiente {
                importe: amount_brek(i128::from(p.importe.brek()) - d)?,
                ..p
            });
            continue;
        }
        nuevas.push(p);
    }
    g.pendientes = nuevas;

    let mut nuevasr: Vec<EnRetirada> = Vec::with_capacity(g.en_retirada.len());
    for r in g.en_retirada.drain(..) {
        if restante > 0 {
            let d = core::cmp::min(restante, i128::from(r.importe.brek()));
            restante -= d;
            if d == i128::from(r.importe.brek()) {
                continue;
            }
            nuevasr.push(EnRetirada {
                importe: amount_brek(i128::from(r.importe.brek()) - d)?,
                inicio_slot: r.inicio_slot,
            });
            continue;
        }
        nuevasr.push(r);
    }
    g.en_retirada = nuevasr;

    let mut nuevasc: Vec<Pendiente> = Vec::with_capacity(g.creditos.len());
    for p in g.creditos.drain(..) {
        if restante > 0 {
            let d = core::cmp::min(restante, i128::from(p.importe.brek()));
            restante -= d;
            if d == i128::from(p.importe.brek()) {
                continue;
            }
            nuevasc.push(Pendiente {
                importe: amount_brek(i128::from(p.importe.brek()) - d)?,
                ..p
            });
            continue;
        }
        nuevasc.push(p);
    }
    g.creditos = nuevasc;
    Ok(())
}

/// Σ fianzas **no terminales** de `clave` (las de sector; no cuenta `congelado` ni cajas).
#[must_use]
pub(crate) fn fianza_no_terminal(estado: &Estado, clave: &ClavePublica) -> i128 {
    crate::sectores::sectores_de_clave(&estado.sectores, clave)
        .filter(|(id, r)| id.clave == *clave && !r.es_terminal())
        .map(|(_, r)| i128::from(r.fianza))
        .sum()
}

/// Total castigable por propietario: `total_garantia` + fianzas no terminales.
///
/// **No redefine** `total_garantia` (`EV-19`): la suma es explícita para no alterar su
/// significado; es el espejo de `fianza_comprometida` de `tests/soporte`.
#[must_use]
pub(crate) fn total_castigable(estado: &Estado, clave: &ClavePublica) -> i128 {
    let cuenta = estado.garantias.get(clave).map_or(0, total_garantia);
    cuenta + fianza_no_terminal(estado, clave)
}

/// Debita `c` del **total castigable** de `clave` en orden determinista:
/// `activo → pendientes → en_retirada → créditos` (vía [`debitar_garantia`]) y después las fianzas
/// de sector por `SectorId` ascendente. Devuelve el **cobro real** (`≤ c`, nunca deuda) y no deja
/// importes negativos. Toca garantía, sector y caja con el undo del [`Aplicador`] y refresca la
/// caché (`fianza`, `estado_hueco`) de las cajas afectadas en `slot`.
pub(crate) fn debitar_castigable(
    ap: &mut Aplicador,
    clave: ClavePublica,
    c: i128,
    slot: i64,
) -> Result<i128, ErrorTransicion> {
    if c <= 0 {
        return Ok(0);
    }
    let antes = ap.estado.garantias.get(&clave).map_or(0, total_garantia);
    debitar_garantia(ap.garantia_mut(clave), c)?;
    let despues = ap.estado.garantias.get(&clave).map_or(0, total_garantia);
    let mut restante = c - (antes - despues);

    let ids: Vec<SectorId> = crate::sectores::sectores_de_clave(&ap.estado.sectores, &clave)
        .filter(|(id, r)| id.clave == clave && !r.es_terminal() && r.fianza > 0)
        .map(|(id, _)| *id)
        .collect();
    let mut cajas: std::collections::BTreeSet<CajaId> = std::collections::BTreeSet::new();
    for id in ids {
        if restante <= 0 {
            break;
        }
        let Some(r) = ap.estado.sectores.get(&id) else {
            continue;
        };
        let d = core::cmp::min(restante, i128::from(r.fianza));
        if d <= 0 {
            continue;
        }
        if let Some((caja, _)) = crate::transicion::caja::caja_de_sector(&ap.estado, &id) {
            cajas.insert(caja);
        }
        ap.tocar_sector(id);
        if let Some(r) = ap.estado.sectores.get_mut(&id) {
            r.fianza -= i64::try_from(d).map_err(|_| ErrorTransicion::ErrDesbordamiento)?;
        }
        restante -= d;
    }
    for caja in cajas {
        crate::transicion::caja::refrescar_caja(ap, caja, slot);
    }
    Ok(c - restante)
}

/// Poda los incidentes cuya ventana de admisión cerró (`EV-11`): se conserva `sf` si
/// `punto < sf + Plazo_slots`; al quedarse sin incidentes se libera el gravamen (`congelado = 0`).
pub fn podar_incidentes(estado: &mut Estado, evp: &ParametrosEvidencia, punto: u64) {
    let punto = punto as i64;
    for g in estado.garantias.values_mut() {
        if g.incidentes.is_empty() {
            continue;
        }
        let antes = g.incidentes.len();
        g.incidentes
            .retain(|i| punto < i.slot_falta.saturating_add(evp.plazo_slots as i64));
        if g.incidentes.len() != antes && g.incidentes.is_empty() {
            g.congelado = Amount::CERO;
        }
    }
}

/// Restituye el estado previo a partir del undo por delta (`I-2`, `R-14`).
#[must_use]
pub fn deshacer(estado: &Estado, undo: &Undo) -> Estado {
    let mut restaurado = estado.clone();
    restaurado.emitido = undo.escalares.emitido;
    restaurado.quemado = undo.escalares.quemado;
    restaurado.fase = undo.escalares.fase;
    restaurado.terminal = undo.escalares.terminal;
    restaurado.altura = undo.escalares.altura;
    restaurado.trabajo = undo.escalares.trabajo;
    restaurado.slot = undo.escalares.slot;
    restaurado.s0 = undo.escalares.s0;
    restaurado.peso_sufijo = undo.escalares.peso_sufijo;
    restaurado.altura_terminal = undo.escalares.altura_terminal;
    restaurado.subsidio_acum = undo.escalares.subsidio_acum;
    restaurado.ultimo_slot_producido = undo.escalares.ultimo_slot_producido.clone();
    restaurado.sectores = undo.escalares.sectores.clone();
    restaurado.parametros_sector = undo.escalares.parametros_sector;
    restaurado.cajas = undo.escalares.cajas.clone();
    restaurado.pruebas = undo.escalares.pruebas.clone();
    restaurado.poreps = undo.escalares.poreps.clone();
    restaurado.claves_voto = undo.escalares.claves_voto.clone();
    restaurado.claves_voto_previas = undo.escalares.claves_voto_previas.clone();
    restaurado.vencimientos_clave_voto = undo.escalares.vencimientos_clave_voto.clone();
    restaurado.finalidad_votos_n = undo.escalares.finalidad_votos_n;
    restaurado.finalidad_votos = undo.escalares.finalidad_votos;
    restaurado.finalidad_votos_h_t = undo.escalares.finalidad_votos_h_t;
    restaurado.raiz_estado = undo.escalares.raiz_estado;
    restaurado.tablas_voto = undo.escalares.tablas_voto.clone();
    restaurado.tablas_voto_contenido = undo.escalares.tablas_voto_contenido.clone();
    restaurado.tabla_ventana_voto = undo.escalares.tabla_ventana_voto.clone();
    restaurado.tabla_ciclo_rearranque = undo.escalares.tabla_ciclo_rearranque.clone();
    restaurado.cola_tablas_voto = undo.escalares.cola_tablas_voto.clone();
    restaurado.ultima_ventana_derivada_sin_base = undo.escalares.ultima_ventana_derivada_sin_base;
    restaurado.votantes_voto = undo.escalares.votantes_voto.clone();
    restaurado.deuda_ausencia = undo.escalares.deuda_ausencia.clone();
    restaurado.liquidacion_voto_hasta = undo.escalares.liquidacion_voto_hasta;
    for (op, previa) in &undo.utxo {
        match previa {
            Some(e) => {
                restaurado.utxo.insert(*op, e.clone());
            }
            None => {
                restaurado.utxo.remove(op);
            }
        }
    }
    for (clave, previa) in &undo.garantias {
        match previa {
            Some(g) => {
                restaurado.garantias.insert(*clave, g.clone());
            }
            None => {
                restaurado.garantias.remove(clave);
            }
        }
    }
    restaurado
}

/// AUS-2a · R6 · liquida en `ap` las ventanas cuyo plazo de revelación venció **antes** de `slot`
/// (`cierre_ventana(n) + W_reveal < slot`), en orden creciente de `n`, cada una una sola vez
/// (marca `liquidacion_voto_hasta`).
///
/// A diferencia de SUS-1, no se limita a las ventanas con tabla guardada: también liquida las que no
/// la tienen (se cobran sin tabla, R4 iii) y la de la base (se cobra a su hora y conserva su tabla,
/// como hoy). El **cobro** por bloque está acotado por [`super::votos::CADUCIDAD_TABLA_VENTANAS`];
/// las ventanas vencidas que exceden el tope (saltos de slot) y las ya liquidadas se **podan sin
/// recorrer sus claves**.
///
/// La suspensión por no revelar se retiró en M9-b2 (DEC-003-A2): liquidar **no** suspende a nadie.
pub(crate) fn liquidar_ventanas_voto(ap: &mut Aplicador, slot: u64) {
    // RA-1 · Y1/Y2 · instantánea de la tabla del ciclo de rearranque **antes** de las operaciones
    // del bloque y de la liquidación: el estado de entrada es el del último bloque con slot
    // `≤ ref(j)`.
    super::votos::tomar_instantaneas_rearranque(ap, slot);
    // TB4-R1 · TB4-R2 · T1 · con o sin base, deriva la tabla de la ventana al cruzar cada ventana,
    // con el estado de entrada, y mantiene la cola `Q` (único dueño: este gancho). Se llama justo
    // después del gancho de instantáneas (mismos dos caminos de aplicación: `aplicar` y `fusion`).
    super::votos::derivar_tabla_sin_base(ap, slot);
    let Some(n_max) = ventana_max_vencida(slot) else {
        return;
    };
    let desde = match ap.estado.liquidacion_voto_hasta {
        Some(n) => n.saturating_add(1),
        None => 0,
    };
    if n_max >= desde {
        let mut n = desde;
        let mut procesadas: u64 = 0;
        while n <= n_max && procesadas < super::votos::CADUCIDAD_TABLA_VENTANAS {
            super::votos::liquidar_ventana_voto(ap, n, slot);
            procesadas += 1;
            n += 1;
        }
    }
    // R6 · las ventanas vencidas que no se recorrieron (las que exceden el tope y las ya
    // liquidadas) se dan por liquidadas sin iterar sus claves: se quitan sus entradas. La base
    // conserva su tabla, sus votantes y sus revelaciones.
    podar_ventanas_vencidas(ap, slot);
    ap.estado.liquidacion_voto_hasta = Some(n_max);
}

/// RK-2 · V6 · borra las claves de voto anteriores cuyo vencimiento ya pasó (`vencimiento < slot`)
/// al aplicar un bloque.
///
/// Recorre el índice por vencimiento ([`Estado::vencimientos_clave_voto`]): el trabajo es
/// proporcional a las anteriores que vencen en ese bloque, no al total de identidades. La anterior
/// está viva si `slot ≤ vencimiento`; las búsquedas filtran por `slot`, de modo que una vencida no se
/// devuelve aunque aún no se haya borrado. El undo por delta restaura los dos mapas exactamente.
pub(crate) fn podar_claves_voto_vencidas(ap: &mut Aplicador, slot: u64) {
    let vencidos: Vec<u64> = ap
        .estado
        .vencimientos_clave_voto
        .range(..slot)
        .map(|(v, _)| *v)
        .collect();
    for v in vencidos {
        let Some(identidades) = ap.estado.vencimientos_clave_voto.remove(&v) else {
            continue;
        };
        for ed in identidades {
            if ap
                .estado
                .claves_voto_previas
                .get(&ed)
                .is_some_and(|prev| prev.vencimiento == v)
            {
                ap.estado.claves_voto_previas.remove(&ed);
            }
        }
    }
}

/// AUS-2a · R6 · mayor ventana `n` con `cierre_ventana(n) + W_reveal < slot`, si existe.
///
/// `cierre_ventana(n) = (n+1)·T_INST`; con `T_INST = 2` y `W_reveal = 160` la condición es
/// `2·(n+1) + 160 < slot`, de donde `n_max = (slot − T_INST − W_reveal − 1) / T_INST` (división
/// entera) en cuanto `slot > T_INST + W_reveal`.
#[expect(
    clippy::integer_division,
    reason = "R6 exige la división entera del índice de ventana; C-ENC-04 prohíbe floats"
)]
fn ventana_max_vencida(slot: u64) -> Option<u64> {
    let t = super::votos::T_INST_VOTOS;
    let umbral = t.saturating_add(super::votos::W_REVEAL_SLOTS_VOTOS);
    if slot <= umbral {
        return None;
    }
    Some((slot - umbral - 1) / t)
}

/// AUS-2a · R6 · poda las entradas de toda ventana vencida (tabla, votantes, compromisos y
/// revelaciones) sin recorrer sus claves; la ventana de la base se conserva.
fn podar_ventanas_vencidas(ap: &mut Aplicador, slot: u64) {
    let hay_base = ap.estado.finalidad_votos.is_some();
    let base = ap.estado.finalidad_votos_n;
    let vencida = |n: &u64| {
        if hay_base && *n == base {
            return false;
        }
        super::votos::cierre_ventana(*n).saturating_add(super::votos::W_REVEAL_SLOTS_VOTOS) < slot
    };
    ap.estado.tablas_voto.retain(|n, _| !vencida(n));
    ap.estado.tabla_ventana_voto.retain(|n, _| !vencida(n));
    ap.estado.votantes_voto.retain(|n, _| !vencida(n));
    super::votos::podar_contenido_voto(ap);
}

/// Estado en construcción con su undo por delta.
pub(crate) struct Aplicador {
    /// Estado en curso.
    pub estado: Estado,
    /// Undo acumulado.
    pub undo: Undo,
}

impl Aplicador {
    /// Arranca desde `estado` y registra sus escalares previos.
    #[must_use]
    pub fn nuevo(estado: Estado) -> Self {
        let undo = Undo {
            escalares: Escalares::from(&estado),
            utxo: Vec::new(),
            garantias: Vec::new(),
            sectores: Vec::new(),
            cajas: Vec::new(),
            pruebas: Vec::new(),
            poreps: Vec::new(),
            claves_voto: Vec::new(),
            utxo_vistos: std::collections::BTreeSet::new(),
            garantia_vistos: std::collections::BTreeSet::new(),
            sector_vistos: std::collections::BTreeSet::new(),
            caja_vistos: std::collections::BTreeSet::new(),
            prueba_vistos: std::collections::BTreeSet::new(),
            porep_vistos: std::collections::BTreeSet::new(),
            clave_voto_vistos: std::collections::BTreeSet::new(),
        };
        Self { estado, undo }
    }

    /// Marca la posición actual del undo.
    #[must_use]
    pub fn marcar(&self) -> Marca {
        Marca {
            utxo: self.undo.utxo.len(),
            garantias: self.undo.garantias.len(),
            sectores: self.undo.sectores.len(),
            cajas: self.undo.cajas.len(),
            pruebas: self.undo.pruebas.len(),
            poreps: self.undo.poreps.len(),
            claves_voto: self.undo.claves_voto.len(),
            raiz_estado: self.estado.raiz_estado,
        }
    }

    /// Revierte las mutaciones registradas después de `marca` (usado al descartar en fusión).
    pub fn revertir_a(&mut self, marca: Marca) {
        // RE-2c · C6 · el escalar `raiz_estado` no tiene lista por toque: la marca guarda su
        // valor y se restituye aquí, igual que `deshacer` lo hace desde el delta de escalares.
        self.estado.raiz_estado = marca.raiz_estado;
        while self.undo.claves_voto.len() > marca.claves_voto {
            if let Some((clave, previa)) = self.undo.claves_voto.pop() {
                self.undo.clave_voto_vistos.remove(&clave);
                match previa {
                    Some(v) => {
                        self.estado.claves_voto.insert(clave, v);
                    }
                    None => {
                        self.estado.claves_voto.remove(&clave);
                    }
                }
            }
        }
        while self.undo.poreps.len() > marca.poreps {
            if let Some((clave, previa)) = self.undo.poreps.pop() {
                self.undo.porep_vistos.remove(&clave);
                match previa {
                    Some(v) => {
                        self.estado.poreps.insert(clave, v);
                    }
                    None => {
                        self.estado.poreps.remove(&clave);
                    }
                }
            }
        }
        while self.undo.pruebas.len() > marca.pruebas {
            if let Some((clave, previa)) = self.undo.pruebas.pop() {
                self.undo.prueba_vistos.remove(&clave);
                match previa {
                    Some(v) => {
                        self.estado.pruebas.insert(clave, v);
                    }
                    None => {
                        self.estado.pruebas.remove(&clave);
                    }
                }
            }
        }
        while self.undo.cajas.len() > marca.cajas {
            if let Some((id, previa)) = self.undo.cajas.pop() {
                self.undo.caja_vistos.remove(&id);
                match previa {
                    Some(c) => {
                        self.estado.cajas.insert(id, c);
                    }
                    None => {
                        self.estado.cajas.remove(&id);
                    }
                }
            }
        }
        while self.undo.sectores.len() > marca.sectores {
            if let Some((id, previo)) = self.undo.sectores.pop() {
                self.undo.sector_vistos.remove(&id);
                match previo {
                    Some(r) => {
                        self.estado.sectores.insert(id, r);
                    }
                    None => {
                        self.estado.sectores.remove(&id);
                    }
                }
            }
        }
        while self.undo.garantias.len() > marca.garantias {
            if let Some((clave, previa)) = self.undo.garantias.pop() {
                self.undo.garantia_vistos.remove(&clave);
                match previa {
                    Some(g) => {
                        self.estado.garantias.insert(clave, g);
                    }
                    None => {
                        self.estado.garantias.remove(&clave);
                    }
                }
            }
        }
        while self.undo.utxo.len() > marca.utxo {
            if let Some((op, previa)) = self.undo.utxo.pop() {
                self.undo.utxo_vistos.remove(&op);
                match previa {
                    Some(e) => {
                        self.estado.utxo.insert(op, e);
                    }
                    None => {
                        self.estado.utxo.remove(&op);
                    }
                }
            }
        }
    }

    fn tocar_utxo(&mut self, op: OutPoint) {
        if self.undo.utxo_vistos.insert(op) {
            let previa = self.estado.utxo.get(&op).cloned();
            self.undo.utxo.push((op, previa));
        }
    }

    fn tocar_garantia(&mut self, clave: ClavePublica) {
        if self.undo.garantia_vistos.insert(clave) {
            let previa = self.estado.garantias.get(&clave).cloned();
            self.undo.garantias.push((clave, previa));
        }
    }

    /// Registra el valor previo de un sector la primera vez que se toca en este undo.
    pub(crate) fn tocar_sector(&mut self, id: SectorId) {
        if self.undo.sector_vistos.insert(id) {
            let previo = self.estado.sectores.get(&id).copied();
            self.undo.sectores.push((id, previo));
        }
    }

    /// Registra el valor previo de una caja la primera vez que se toca en este undo (`C-CAJA-11`).
    pub(crate) fn tocar_caja(&mut self, id: CajaId) {
        if self.undo.caja_vistos.insert(id) {
            let previo = self.estado.cajas.get(&id).cloned();
            self.undo.cajas.push((id, previo));
        }
    }

    /// PT-3bc · registra la prueba de almacenamiento vigente de `clave` y la inserta (`C-SEC-15`).
    pub(crate) fn guardar_prueba(
        &mut self,
        clave: ClavePublica,
        prueba: crate::sectores::PruebaVigente,
    ) {
        if self.undo.prueba_vistos.insert(clave) {
            let previa = self.estado.pruebas.get(&clave).copied();
            self.undo.pruebas.push((clave, previa));
        }
        self.estado.pruebas.insert(clave, prueba);
    }

    /// PT-3bc · registra la atestación PoRep de `clave` y la inserta.
    pub(crate) fn guardar_porep(
        &mut self,
        clave: ClavePublica,
        porep: crate::sectores::PorepVigente,
    ) {
        if self.undo.porep_vistos.insert(clave) {
            let previa = self.estado.poreps.get(&clave).copied();
            self.undo.poreps.push((clave, previa));
        }
        self.estado.poreps.insert(clave, porep);
    }

    /// PT-3bc · registra la clave BLS de voto de `clave` y la inserta.
    pub(crate) fn guardar_clave_voto(
        &mut self,
        clave: ClavePublica,
        clave_voto: crate::sectores::ClaveVoto,
    ) {
        if self.undo.clave_voto_vistos.insert(clave) {
            let previa = self.estado.claves_voto.get(&clave).copied();
            self.undo.claves_voto.push((clave, previa));
        }
        self.estado.claves_voto.insert(clave, clave_voto);
    }

    /// Inserta una salida, registrando el valor previo (incluida su ausencia).
    pub fn insertar_utxo(&mut self, op: OutPoint, entrada: EntradaUtxo) {
        self.tocar_utxo(op);
        self.estado.utxo.insert(op, entrada);
    }

    /// Retira una salida, registrando el valor previo.
    pub fn borrar_utxo(&mut self, op: OutPoint) {
        self.tocar_utxo(op);
        self.estado.utxo.remove(&op);
    }

    /// Acceso mutable a la garantía de una clave, creándola si no existe y registrando el undo.
    pub fn garantia_mut(&mut self, clave: ClavePublica) -> &mut Garantia {
        self.tocar_garantia(clave);
        self.estado
            .garantias
            .entry(clave)
            .or_insert_with(Garantia::nueva)
    }

    /// Promueve a `activo` los pendientes y créditos madurados en `punto` (paso (b) de §3.9).
    pub fn promover(
        &mut self,
        punto: Punto,
        es_post: bool,
        params: &ParametrosTransicion,
    ) -> Result<(), crate::transicion::ErrorTransicion> {
        use crate::transicion::ErrorTransicion;
        let claves: Vec<ClavePublica> = self.estado.garantias.keys().copied().collect();
        for clave in claves {
            self.tocar_garantia(clave);
            let Some(g) = self.estado.garantias.get_mut(&clave) else {
                return Err(ErrorTransicion::ErrGenesis);
            };
            let mut quedan: Vec<Pendiente> = Vec::with_capacity(g.pendientes.len());
            for p in g.pendientes.drain(..) {
                let madura = if es_post {
                    matches!(
                        (p.madura_en_slot, punto.como_slot()),
                        (Some(s), Some(ps)) if s <= ps
                    )
                } else {
                    matches!(
                        (p.madura_en_altura, punto.como_altura()),
                        (Some(h), Some(ph)) if h <= ph
                    )
                };
                if madura {
                    g.activo = g
                        .activo
                        .suma_comprobada(p.importe)
                        .ok_or(ErrorTransicion::ErrDesbordamiento)?;
                } else {
                    quedan.push(p);
                }
            }
            g.pendientes = quedan;
            if es_post {
                let mut quedan_creditos: Vec<Pendiente> = Vec::with_capacity(g.creditos.len());
                for p in g.creditos.drain(..) {
                    let madura = matches!(
                        (p.madura_en_slot, punto.como_slot()),
                        (Some(s), Some(ps)) if s <= ps
                    );
                    if madura {
                        g.activo = g
                            .activo
                            .suma_comprobada(p.importe)
                            .ok_or(ErrorTransicion::ErrDesbordamiento)?;
                    } else {
                        quedan_creditos.push(p);
                    }
                }
                g.creditos = quedan_creditos;
            }
            let _ = params;
        }
        Ok(())
    }
}

/// Empuja un pendiente y lo promueve de inmediato si su madurez ya se cumple (`R-4`).
pub(crate) fn acreditar_pendiente(
    g: &mut Garantia,
    pendiente: Pendiente,
    punto: Punto,
    es_post: bool,
) -> Result<(), crate::transicion::ErrorTransicion> {
    use crate::transicion::ErrorTransicion;
    let madura = if es_post {
        matches!(
            (pendiente.madura_en_slot, punto.como_slot()),
            (Some(s), Some(ps)) if s <= ps
        )
    } else {
        matches!(
            (pendiente.madura_en_altura, punto.como_altura()),
            (Some(h), Some(ph)) if h <= ph
        )
    };
    if madura {
        g.activo = g
            .activo
            .suma_comprobada(pendiente.importe)
            .ok_or(ErrorTransicion::ErrDesbordamiento)?;
    } else if es_post {
        g.pendientes.push(Pendiente {
            madura_en_altura: None,
            ..pendiente
        });
    } else {
        g.pendientes.push(pendiente);
    }
    Ok(())
}

/// Acredita un **crédito** de coinbase PoST (D-T08): a `creditos` si aún no madura, a `activo` si ya
/// se cumple su slot de madurez (`R-4`).
pub(crate) fn acreditar_credito(
    g: &mut Garantia,
    pendiente: Pendiente,
    punto: Punto,
) -> Result<(), crate::transicion::ErrorTransicion> {
    use crate::transicion::ErrorTransicion;
    let madura = matches!(
        (pendiente.madura_en_slot, punto.como_slot()),
        (Some(s), Some(ps)) if s <= ps
    );
    if madura {
        g.activo = g
            .activo
            .suma_comprobada(pendiente.importe)
            .ok_or(ErrorTransicion::ErrDesbordamiento)?;
    } else {
        g.creditos.push(pendiente);
    }
    Ok(())
}

#[cfg(test)]
mod re2c_raiz_tests {
    use super::*;

    /// RE-2c · C6 · `revertir_a(marca)` del modo fusión restituye también `raiz_estado` (el escalar
    /// no tiene lista por toque: la marca guarda su valor). `deshacer` lo cubre la prueba de
    /// integración `t_raiz_02_deshacer_restaura_la_raiz`.
    #[test]
    fn t_raiz_02b_revertir_a_restaura_la_raiz() {
        let mut est = Estado::inicial();
        est.raiz_estado = Some([0x01; 32]);
        let mut ap = Aplicador::nuevo(est.clone());
        let marca = ap.marcar();
        ap.estado.raiz_estado = Some([0x02; 32]);
        ap.revertir_a(marca);
        assert_eq!(
            ap.estado.raiz_estado,
            Some([0x01; 32]),
            "revertir_a restaura la raíz de la marca"
        );
        assert_eq!(
            ap.estado, est,
            "y el estado vuelve a ser exactamente el previo"
        );
    }
}
