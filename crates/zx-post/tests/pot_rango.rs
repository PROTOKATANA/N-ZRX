//! Pruebas del **núcleo de verificación de un rango PoT** (`zx-consensus::pot_rango`, SPEC §7.1.2).
//!
//! Cubren: varios slots consecutivos, inyección en el borde exacto, cambio de `N` en `t_j`, dos
//! flujos en el mismo slot (caché), mutación de un checkpoint intermedio con el último intacto y
//! con la salida final cambiada, `pot_output` incorrecto, `d = 0`, 150 portadores y exceso
//! estructural, `slot + D` desbordado, `N` fuera de dominio, doble inyección, pasado incompleto,
//! reloj futuro, presupuesto agotado, contexto circular, génesis, separación de fases y atadura
//! del token al candidato y a su contexto.
//!
//! # Caché real, no fabricada
//!
//! [`CachePotVerificada`] tiene estado privado: sus entradas solo las registra el propio
//! verificador tras un `verificar_slot_aes` exitoso. Los tests ya **no** precargan entradas a
//! mano; calientan la caché verificando de verdad y después repiten con presupuesto cero para
//! exigir el acierto. El caso de una entrada con solo 16 B ya no existe por diseño.
//!
//! # Qué NO acreditan
//!
//! Las implementaciones de [`InstantaneaPot`] y [`PresupuestoPot`] de este archivo son **mocks**:
//! devuelven datos libres y **no** acreditan que `f`, `N(s)`, `D` ni la salida ancla provengan de
//! un pasado DAG validado. Prueban el núcleo, no la validez de un bloque. No existe todavía un
//! derivador real de `past(B)`; por eso el núcleo **no** puede producir `PotValido` en la ruta
//! activa y `wire_dag::verificar_justificacion_pot` sigue pendiente.

#![expect(clippy::expect_used, reason = "los tests fallan con panic por diseño")]

use core::num::NonZeroU32;
use std::collections::BTreeMap;

use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot};
use zx_core::wire_dag::{BUNDLE_BYTES, JustificacionPot, POT_OUTPUT_BYTES, PotCheckpoints};
use zx_core::{DagBlockHeader, PadresDag, SolucionPoas};
use zx_post::pot::{checkpoints_a_primitiva, checkpoints_a_wire, semilla_siguiente};
use zx_post::pot_rango::{
    BloqueDelPasado, CachePotVerificada, EstadoPot, FLUJO_BYTES, InstantaneaPot, InyeccionPot,
    InyeccionesPot, MotivoPotInvalido, MotivoPotPendiente, PresupuestoPot, verificar_rango_pot,
    verificar_rango_pot_fase_aes, verificar_rango_pot_fase_previa,
};
use zx_pot::tipos::PotSeed;

// ─────────────────────────────────────────────────────────────────────────────
// Mocks
// ─────────────────────────────────────────────────────────────────────────────

/// Instantánea contextual de prueba: **datos libres**, sin procedencia acreditada.
#[derive(Clone)]
struct ContextoPrueba {
    flujo: [u8; FLUJO_BYTES],
    flujos_por_slot: BTreeMap<u64, [u8; FLUJO_BYTES]>,
    pasado: Vec<BloqueDelPasado>,
    inyecciones: BTreeMap<u64, InyeccionesPot>,
    iteraciones: BTreeMap<u64, u64>,
    retardo: u64,
    salidas: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]>,
}

impl InstantaneaPot for ContextoPrueba {
    fn flujo_candidato_en(&self, slot: u64) -> Result<[u8; FLUJO_BYTES], MotivoPotPendiente> {
        Ok(self
            .flujos_por_slot
            .get(&slot)
            .copied()
            .unwrap_or(self.flujo))
    }

    fn pasado(&self) -> Result<&[BloqueDelPasado], MotivoPotPendiente> {
        Ok(&self.pasado)
    }

    fn inyecciones_en(&self, slot: u64) -> Result<InyeccionesPot, MotivoPotPendiente> {
        Ok(self
            .inyecciones
            .get(&slot)
            .cloned()
            .unwrap_or(InyeccionesPot::Ninguna))
    }

    fn iteraciones(&self, slot: u64) -> Result<u64, MotivoPotPendiente> {
        self.iteraciones
            .get(&slot)
            .copied()
            .ok_or(MotivoPotPendiente::ContextoAusente { que: "N(s)" })
    }

    fn retardo_autoria(&self) -> Result<u64, MotivoPotPendiente> {
        Ok(self.retardo)
    }

    fn salida_validada(&self, slot: u64) -> Result<[u8; POT_OUTPUT_BYTES], MotivoPotPendiente> {
        self.salidas
            .get(&slot)
            .copied()
            .ok_or(MotivoPotPendiente::ContextoAusente {
                que: "salida ancla",
            })
    }
}

/// Presupuesto de prueba: unidades enteras. `intentos` cuenta las llamadas a `consumir_slot`
/// —incluida la que falla por presupuesto cero— para poder exigir que la fase previa no toca AES.
struct PresupuestoPrueba {
    restantes: usize,
    intentos: usize,
}

impl PresupuestoPrueba {
    fn nuevo(restantes: usize) -> Self {
        Self {
            restantes,
            intentos: 0,
        }
    }
}

impl PresupuestoPot for PresupuestoPrueba {
    fn consumir_slot(&mut self, _slot: u64) -> bool {
        self.intentos += 1;
        if self.restantes == 0 {
            false
        } else {
            self.restantes -= 1;
            true
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cadena de prueba
// ─────────────────────────────────────────────────────────────────────────────

const FLUJO: [u8; FLUJO_BYTES] = [0x11; FLUJO_BYTES];
const BASE: [u8; POT_OUTPUT_BYTES] = [0xAB; POT_OUTPUT_BYTES];
/// Salida auditada de prueba cuando `d ≤ D`: es una salida del pasado validado, distinta del
/// `pot_output` futuro y del ancla del rango.
const SALIDA_AUDITADA: [u8; POT_OUTPUT_BYTES] = [0x5A; POT_OUTPUT_BYTES];
const N_FIJO: u64 = 16;
const SLOT_SP: u64 = 100;
const RETARDO: u64 = 2;
const RELOJ: u64 = 1_000;

/// Cadena de un rango construida con la primitiva real: portadores, iteraciones y salidas.
#[derive(Clone)]
struct Cadena {
    flujo: [u8; FLUJO_BYTES],
    retardo: u64,
    slot_sp: u64,
    slot_b: u64,
    inyecciones: BTreeMap<u64, InyeccionPot>,
    iteraciones: BTreeMap<u64, u64>,
    portadores: Vec<PotCheckpoints>,
    salidas: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]>,
    pot_output: [u8; POT_OUTPUT_BYTES],
}

fn generar<F: Fn(u64) -> u64>(
    flujo: [u8; FLUJO_BYTES],
    slot_sp: u64,
    retardo: u64,
    d: usize,
    base: [u8; POT_OUTPUT_BYTES],
    inyecciones: BTreeMap<u64, InyeccionPot>,
    n_de: F,
) -> Cadena {
    let mut portadores = Vec::with_capacity(d);
    let mut iteraciones = BTreeMap::new();
    let mut salidas = BTreeMap::new();
    salidas.insert(slot_sp + retardo, base);

    let mut salida = base;
    for i in 1..=u64::try_from(d).expect("d cabe en u64") {
        let slot = slot_sp + retardo + i;
        let entropia = inyecciones.get(&slot).map(|inyeccion| inyeccion.entropia);
        let semilla = semilla_siguiente(salida, entropia);
        let n = n_de(slot);
        iteraciones.insert(slot, n);
        let carrier = zx_pot::prove(
            PotSeed::from(semilla),
            NonZeroU32::new(u32::try_from(n).expect("N cabe en u32")).expect("N > 0"),
        )
        .expect("N múltiplo de 16");
        salida = *carrier.output();
        salidas.insert(slot, salida);
        portadores.push(checkpoints_a_wire(&carrier));
    }

    Cadena {
        flujo,
        retardo,
        slot_sp,
        slot_b: slot_sp + u64::try_from(d).expect("d cabe en u64"),
        inyecciones,
        iteraciones,
        portadores,
        salidas,
        pot_output: salida,
    }
}

fn hash_de(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn cabecera(
    slot: u64,
    pot_output: [u8; POT_OUTPUT_BYTES],
    sp: BlockHash,
    extras: &[BlockHash],
) -> DagBlockHeader {
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: 0xc478_80ea,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([1; 32])),
        timestamp: 1_788_480_000,
        height: 1,
        slot,
        pot_output,
        rango_solucion: 5,
        sol: SolucionPoas::default(),
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([2; 32])),
        padres: PadresDag::nuevo(sp, extras).expect("padres canónicos"),
        sello: [0u8; 64],
    }
}

fn justificacion(cadena: &Cadena) -> JustificacionPot {
    JustificacionPot::nueva(cadena.portadores.clone()).expect("≤ 150 portadores")
}

fn contexto(cadena: &Cadena, padres: &[(BlockHash, u64)]) -> ContextoPrueba {
    let pasado = padres
        .iter()
        .map(|(hash, slot)| BloqueDelPasado {
            hash: *hash,
            slot: *slot,
            timestamp: 0,
            flujo: cadena.flujo,
        })
        .collect();
    let inyecciones = cadena
        .inyecciones
        .iter()
        .map(|(slot, inyeccion)| (*slot, InyeccionesPot::Una(inyeccion.clone())))
        .collect();
    // La instantánea del pasado NO contiene las salidas del propio candidato: los portadores del
    // rango (`slot > slot(sp)+D`) no están validados por el pasado. Solo el ancla del rango y las
    // salidas anteriores sí. La salida auditada, cuando `d ≤ D`, se añade como salida de un ancestro.
    let slot_base = cadena.slot_sp + cadena.retardo;
    let mut salidas: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]> = cadena
        .salidas
        .iter()
        .filter(|(slot, _)| **slot <= slot_base)
        .map(|(slot, salida)| (*slot, *salida))
        .collect();
    if cadena.slot_b <= slot_base {
        salidas.entry(cadena.slot_b).or_insert(SALIDA_AUDITADA);
    }
    ContextoPrueba {
        flujo: cadena.flujo,
        flujos_por_slot: BTreeMap::new(),
        pasado,
        inyecciones,
        iteraciones: cadena.iteraciones.clone(),
        retardo: cadena.retardo,
        salidas,
    }
}

/// Escenario completo: cadena, cabecera y contexto coherentes.
#[derive(Clone)]
struct Escenario {
    cadena: Cadena,
    cabecera: DagBlockHeader,
    justificacion: JustificacionPot,
    contexto: ContextoPrueba,
}

fn escenario(d: usize, inyecciones: BTreeMap<u64, InyeccionPot>) -> Escenario {
    escenario_con(d, inyecciones, |_| N_FIJO)
}

fn escenario_con<F: Fn(u64) -> u64>(
    d: usize,
    inyecciones: BTreeMap<u64, InyeccionPot>,
    n_de: F,
) -> Escenario {
    escenario_con_flujo_base(FLUJO, BASE, d, inyecciones, n_de)
}

fn escenario_con_flujo_base<F: Fn(u64) -> u64>(
    flujo: [u8; FLUJO_BYTES],
    base: [u8; POT_OUTPUT_BYTES],
    d: usize,
    inyecciones: BTreeMap<u64, InyeccionPot>,
    n_de: F,
) -> Escenario {
    let cadena = generar(flujo, SLOT_SP, RETARDO, d, base, inyecciones, n_de);
    let (sp, extra) = (hash_de(0x01), hash_de(0x02));
    let cabecera = cabecera(cadena.slot_b, cadena.pot_output, sp, &[extra]);
    let justificacion = justificacion(&cadena);
    let contexto = contexto(&cadena, &[(sp, SLOT_SP), (extra, SLOT_SP)]);
    Escenario {
        cadena,
        cabecera,
        justificacion,
        contexto,
    }
}

fn verificar(escenario: &Escenario, reloj: u64) -> EstadoPot {
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);
    verificar_rango_pot(
        &escenario.cabecera,
        &escenario.justificacion,
        &escenario.contexto,
        reloj,
        &mut cache,
        &mut presupuesto,
    )
}

/// Encadena las dos fases del núcleo: **fase previa → AES (núcleo aislado)**.
///
/// **No** llama al sello ZIP-215: el sello pertenece a A3 y se inserta entre las dos fases. La fase
/// AES lee el contexto del token, por eso ya no se le pasa aquí.
fn verificar_en_fases(
    escenario: &Escenario,
    reloj: u64,
    cache: &mut CachePotVerificada,
    presupuesto: &mut PresupuestoPrueba,
) -> EstadoPot {
    let token = match verificar_rango_pot_fase_previa(
        &escenario.cabecera,
        &escenario.justificacion,
        &escenario.contexto,
    ) {
        Ok(token) => token,
        Err(estado) => return estado,
    };
    verificar_rango_pot_fase_aes(token, reloj, cache, presupuesto)
}

/// Observa que una caché **caliente** acierta **sin inspeccionarla**: repetir el mismo escenario
/// con presupuesto cero debe dar `PotValido` sin gastar una sola verificación AES. Es la lectura
/// de comportamiento que sustituye a cualquier inspector público de caché.
fn un_cache_caliente_acierta_sin_presupuesto(
    escenario: &Escenario,
    cache: &mut CachePotVerificada,
) {
    let mut presupuesto = PresupuestoPrueba::nuevo(0);
    assert!(matches!(
        verificar_en_fases(escenario, RELOJ, cache, &mut presupuesto),
        EstadoPot::PotValido(_)
    ));
    assert_eq!(presupuesto.intentos, 0, "el acierto no intenta AES");
}

/// Observa que una caché **recién creada** está vacía sin inspeccionarla: con presupuesto cero el
/// primer portador no puede acertar y el núcleo devuelve `Pendiente(PresupuestoAgotado)` tras un
/// único intento de AES.
fn un_cache_vacio_es_pendiente_sin_presupuesto(escenario: &Escenario) {
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(0);
    let slot_esperado = escenario.cadena.slot_sp + escenario.cadena.retardo + 1;
    assert_eq!(
        verificar_en_fases(escenario, RELOJ, &mut cache, &mut presupuesto),
        EstadoPot::PotPendiente(MotivoPotPendiente::PresupuestoAgotado {
            slot: slot_esperado
        })
    );
    assert_eq!(
        presupuesto.intentos, 1,
        "sin entradas, el primer portador intenta AES"
    );
}

fn portador_con_checkpoint_alterado(portador: &PotCheckpoints) -> PotCheckpoints {
    let mut outputs = portador.outputs();
    if let Some(intermedio) = outputs.get_mut(1)
        && let Some(byte) = intermedio.first_mut()
    {
        *byte ^= 0x01;
    }
    PotCheckpoints::desde_outputs(outputs)
}

fn portador_con_ultimo_alterado(portador: &PotCheckpoints) -> PotCheckpoints {
    let mut outputs = portador.outputs();
    if let Some(ultimo) = outputs.get_mut(7)
        && let Some(byte) = ultimo.first_mut()
    {
        *byte ^= 0x01;
    }
    PotCheckpoints::desde_outputs(outputs)
}

/// La salida de un portador, por la ruta pública del adaptador.
fn salida_de(portador: &PotCheckpoints) -> [u8; POT_OUTPUT_BYTES] {
    *checkpoints_a_primitiva(portador).output()
}

// ─────────────────────────────────────────────────────────────────────────────
// 1 · Varios slots consecutivos
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn un_rango_de_varios_slots_consecutivos_verifica() {
    let escenario = escenario(3, BTreeMap::new());
    assert_eq!(escenario.cadena.portadores.len(), 3);
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotValido(_)
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2 · Inyección en el borde exacto del rango
// ─────────────────────────────────────────────────────────────────────────────

fn inyeccion_en(slot: u64, ancla: BlockHash) -> BTreeMap<u64, InyeccionPot> {
    let mut mapa = BTreeMap::new();
    mapa.insert(
        slot,
        InyeccionPot {
            entropia: [0x55; 32],
            ancla,
        },
    );
    mapa
}

/// La misma inyección, ya envuelta como la entrega el contexto.
fn inyecciones_una(slot: u64, ancla: BlockHash) -> BTreeMap<u64, InyeccionesPot> {
    let mut mapa = BTreeMap::new();
    mapa.insert(
        slot,
        InyeccionesPot::Una(InyeccionPot {
            entropia: [0x55; 32],
            ancla,
        }),
    );
    mapa
}

#[test]
fn la_inyeccion_se_aplica_exactamente_en_su_slot() {
    // El primer slot del rango es `slot(sp) + D + 1 = 103`.
    let escenario = escenario(3, inyeccion_en(103, hash_de(0x30)));
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotValido(_)
    ));

    // El mismo contexto con la inyección declarada un slot más tarde: los portadores se
    // construyeron con ella en 103, así que la cadena ya no reproduce.
    let mut movida = escenario;
    movida.contexto.inyecciones = inyecciones_una(104, hash_de(0x30));
    assert_eq!(
        verificar(&movida, RELOJ),
        EstadoPot::PotInvalido(MotivoPotInvalido::AesFallido { slot: 103 })
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3 · Cambio de N en t_j
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn el_cambio_de_n_en_el_slot_de_inyeccion_se_respeta() {
    // El contexto cambia `N` exactamente en el slot de una inyección —su `t_j`— y el núcleo
    // aplica las dos cosas en ese slot y en ningún otro.
    let escenario = escenario_con(3, inyeccion_en(105, hash_de(0x30)), |slot| {
        if slot < 105 { 16 } else { 32 }
    });
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotValido(_)
    ));

    // Si el contexto declara para 105 el `N` anterior, el portador real (construido con 32) no
    // verifica.
    let mut equivocado = escenario;
    equivocado.contexto.iteraciones.insert(105, 16);
    assert_eq!(
        verificar(&equivocado, RELOJ),
        EstadoPot::PotInvalido(MotivoPotInvalido::AesFallido { slot: 105 })
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4 · Dos flujos en el mismo slot: la caché de otra clave no invalida
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn una_entrada_de_cache_de_otra_clave_no_invalida() {
    // Cadena A válida: calienta la caché con sus claves y portadores **verificados** de verdad.
    let a = escenario(3, BTreeMap::new());
    let mut cache = CachePotVerificada::nueva();
    let mut calentamiento = PresupuestoPrueba::nuevo(1_000);
    assert!(matches!(
        verificar_en_fases(&a, RELOJ, &mut cache, &mut calentamiento),
        EstadoPot::PotValido(_)
    ));
    // La caché quedó caliente: con presupuesto cero, A acierta sin AES. Observación de
    // comportamiento, sin inspector público de caché.
    un_cache_caliente_acierta_sin_presupuesto(&a, &mut cache);

    // Cadena B válida pero de OTRO flujo y con otra base, así que sus claves y sus portadores
    // difieren de los de A. Si la caché se indexara por slot, la entrada de A (con otra salida)
    // invalidaría a B; con la clave contextual, B falla de caché y verifica por AES.
    let flujo_b = [0x99; FLUJO_BYTES];
    let base_b = [0xCD; POT_OUTPUT_BYTES];
    let b = escenario_con_flujo_base(flujo_b, base_b, 3, BTreeMap::new(), |_| N_FIJO);
    let mut presupuesto_b = PresupuestoPrueba::nuevo(1_000);
    assert!(matches!(
        verificar_en_fases(&b, RELOJ, &mut cache, &mut presupuesto_b),
        EstadoPot::PotValido(_)
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 5 · Mutación de un checkpoint intermedio con el último intacto
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mutar_un_checkpoint_intermedio_con_el_ultimo_intacto_invalida() {
    let mut escenario = escenario(3, BTreeMap::new());
    let original = escenario
        .cadena
        .portadores
        .get(1)
        .copied()
        .expect("segundo");
    let alterado = portador_con_checkpoint_alterado(&original);
    assert_eq!(
        salida_de(&original),
        salida_de(&alterado),
        "el último no cambia"
    );
    if let Some(slot) = escenario.cadena.portadores.get_mut(1) {
        *slot = alterado;
    }
    escenario.justificacion = justificacion(&escenario.cadena);
    assert_eq!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotInvalido(MotivoPotInvalido::AesFallido { slot: 104 })
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6 · pot_output incorrecto
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn un_pot_output_incorrecto_invalida() {
    let mut escenario = escenario(3, BTreeMap::new());
    escenario.cabecera.pot_output = [0x00; POT_OUTPUT_BYTES];
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotInvalido(MotivoPotInvalido::PotOutputNoCoincide { .. })
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 7 · d = 0
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn un_rango_vacio_exige_que_el_ancla_acreditada_sea_pot_output() {
    // `d = 0`: el ancla en `slot(B) + D` es la salida del mismo slot y debe ser `pot_output`.
    let escenario = escenario(0, BTreeMap::new());
    assert!(escenario.justificacion.is_empty());
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotValido(_)
    ));

    let mut incorrecto = escenario;
    incorrecto.cabecera.pot_output = [0x00; POT_OUTPUT_BYTES];
    assert!(matches!(
        verificar(&incorrecto, RELOJ),
        EstadoPot::PotInvalido(MotivoPotInvalido::PotOutputNoCoincide { .. })
    ));
}

#[test]
fn un_rango_vacio_sin_ancla_en_el_contexto_es_pendiente() {
    let mut escenario = escenario(0, BTreeMap::new());
    escenario.contexto.salidas.clear();
    assert_eq!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotPendiente(MotivoPotPendiente::ContextoAusente {
            que: "salida ancla"
        })
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7b · Salida del slot auditado: portador propio (d > D) o pasado (d ≤ D)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn con_d_mayor_que_d_la_salida_auditada_no_la_aporta_el_contexto() {
    // `d = 3 > D = 2`: el slot auditado (103) cae en el rango y hay portadores posteriores. El
    // contexto no contiene `salida_validada(103)`, así que la prueba solo puede salir del portador.
    let escenario = escenario(3, BTreeMap::new());
    let slot_auditado = escenario.cabecera.slot;
    let slot_base = escenario.cadena.slot_sp + escenario.cadena.retardo;
    let slot_fin = escenario.cadena.slot_b + escenario.cadena.retardo;
    assert!(slot_auditado > slot_base, "d > D");
    assert!(
        slot_auditado < slot_fin,
        "debe haber al menos un portador después del auditado"
    );
    assert!(
        !escenario.contexto.salidas.contains_key(&slot_auditado),
        "el contexto no debe aportar la salida auditada"
    );
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotValido(_)
    ));
}

#[test]
fn con_d_menor_o_igual_que_d_la_salida_auditada_la_aporta_el_contexto() {
    // `d = 1 ≤ D = 2`: el slot auditado (101) está en el pasado validado. Quitar esa salida del
    // contexto deja `Pendiente` aunque el rango AES y el anclaje final verifiquen.
    let mut escenario = escenario(1, BTreeMap::new());
    let slot_auditado = escenario.cabecera.slot;
    let slot_base = escenario.cadena.slot_sp + escenario.cadena.retardo;
    assert!(slot_auditado <= slot_base, "d ≤ D");
    assert_eq!(
        escenario.contexto.salidas.get(&slot_auditado),
        Some(&SALIDA_AUDITADA)
    );
    assert_ne!(SALIDA_AUDITADA, escenario.cabecera.pot_output);
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotValido(_)
    ));

    escenario.contexto.salidas.remove(&slot_auditado);
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotPendiente(MotivoPotPendiente::ContextoAusente { .. })
    ));
}

#[test]
fn con_d_cero_la_salida_auditada_la_aporta_el_contexto() {
    // `d = 0`: el slot auditado (100) es anterior al ancla del rango (102) y sale del pasado.
    let mut escenario = escenario(0, BTreeMap::new());
    let slot_auditado = escenario.cabecera.slot;
    assert_eq!(
        escenario.contexto.salidas.get(&slot_auditado),
        Some(&SALIDA_AUDITADA)
    );
    assert_ne!(SALIDA_AUDITADA, escenario.cabecera.pot_output);
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotValido(_)
    ));

    escenario.contexto.salidas.remove(&slot_auditado);
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotPendiente(MotivoPotPendiente::ContextoAusente { .. })
    ));
}

#[test]
fn cambiar_solo_pot_output_no_fabrica_prueba_ni_toca_la_salida_del_contexto() {
    // Con `d ≤ D` la salida auditada viene del contexto; mutar `pot_output` solo rompe el anclaje
    // final y no debe producir una `PruebaPotValidada`.
    let mut escenario = escenario(1, BTreeMap::new());
    let salida_contexto = escenario
        .contexto
        .salidas
        .get(&escenario.cabecera.slot)
        .copied();
    assert_eq!(salida_contexto, Some(SALIDA_AUDITADA));

    escenario.cabecera.pot_output = [0x00; POT_OUTPUT_BYTES];
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotInvalido(MotivoPotInvalido::PotOutputNoCoincide { .. })
    ));
}

#[test]
fn mutar_un_portador_posterior_al_auditado_no_deja_prueba() {
    // El portador auditado (103) se captura, pero el siguiente (104) se muta en un checkpoint
    // intermedio conservando su último valor: el AES falla y no hay prueba utilizable.
    let mut escenario = escenario(3, BTreeMap::new());
    let original = escenario
        .cadena
        .portadores
        .get(1)
        .copied()
        .expect("segundo portador");
    let alterado = portador_con_checkpoint_alterado(&original);
    assert_eq!(salida_de(&original), salida_de(&alterado));
    if let Some(slot) = escenario.cadena.portadores.get_mut(1) {
        *slot = alterado;
    }
    escenario.justificacion = justificacion(&escenario.cadena);
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotInvalido(MotivoPotInvalido::AesFallido { slot: 104 })
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 8 · 150 portadores y exceso estructural
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ciento_cincuenta_portadores_verifican() {
    let escenario = escenario(150, BTreeMap::new());
    assert_eq!(escenario.cadena.portadores.len(), 150);
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotValido(_)
    ));
}

#[test]
fn una_diferencia_de_151_es_exceso_estructural() {
    // 150 portadores reales, pero `slot(B) − slot(sp) = 151`.
    let cadena = generar(FLUJO, SLOT_SP, RETARDO, 150, BASE, BTreeMap::new(), |_| {
        N_FIJO
    });
    let (sp, extra) = (hash_de(0x01), hash_de(0x02));
    let cabecera = cabecera(cadena.slot_sp + 151, cadena.pot_output, sp, &[extra]);
    let contexto = contexto(&cadena, &[(sp, SLOT_SP), (extra, SLOT_SP)]);
    let justificacion = justificacion(&cadena);
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);

    assert_eq!(
        verificar_rango_pot(
            &cabecera,
            &justificacion,
            &contexto,
            RELOJ,
            &mut cache,
            &mut presupuesto,
        ),
        EstadoPot::PotInvalido(MotivoPotInvalido::DiferenciaDeSlots(
            zx_core::wire_dag::ErrorDiferenciaSlots::ExcedeMaximo { diferencia: 151 }
        ))
    );
}

#[test]
fn un_descuadre_del_numero_de_portadores_invalida() {
    // `d = 3` con solo dos portadores reales.
    let cadena = generar(FLUJO, SLOT_SP, RETARDO, 2, BASE, BTreeMap::new(), |_| {
        N_FIJO
    });
    let (sp, extra) = (hash_de(0x01), hash_de(0x02));
    let cabecera = cabecera(cadena.slot_sp + 3, cadena.pot_output, sp, &[extra]);
    let contexto = contexto(&cadena, &[(sp, SLOT_SP), (extra, SLOT_SP)]);
    let justificacion = justificacion(&cadena);
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);

    assert_eq!(
        verificar_rango_pot(
            &cabecera,
            &justificacion,
            &contexto,
            RELOJ,
            &mut cache,
            &mut presupuesto,
        ),
        EstadoPot::PotInvalido(MotivoPotInvalido::DiferenciaDeSlots(
            zx_core::wire_dag::ErrorDiferenciaSlots::NoCoincide {
                bundles: 2,
                diferencia: 3
            }
        ))
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 9 · slot + D desbordado
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn slot_mas_d_desbordado_es_pendiente() {
    let sp = hash_de(0x01);
    let slot_sp = u64::MAX - 5;
    let cabecera = cabecera(u64::MAX - 4, [0x00; POT_OUTPUT_BYTES], sp, &[]);
    let justificacion =
        JustificacionPot::nueva(vec![PotCheckpoints::desde_bytes([0u8; BUNDLE_BYTES])])
            .expect("un portador");
    let contexto = ContextoPrueba {
        flujo: FLUJO,
        flujos_por_slot: BTreeMap::new(),
        pasado: vec![BloqueDelPasado {
            hash: sp,
            slot: slot_sp,
            timestamp: 0,
            flujo: FLUJO,
        }],
        inyecciones: BTreeMap::new(),
        iteraciones: BTreeMap::new(),
        retardo: 10,
        salidas: BTreeMap::new(),
    };
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(10);

    assert_eq!(
        verificar_rango_pot(
            &cabecera,
            &justificacion,
            &contexto,
            u64::MAX,
            &mut cache,
            &mut presupuesto,
        ),
        EstadoPot::PotPendiente(MotivoPotPendiente::AritmeticaDeSlotsDesbordada)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 10 · N fuera de dominio (sin ejecutar AES)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn n_cero_no_multiplo_o_mayor_que_u32_max_es_pendiente() {
    for n_malo in [0u64, 17, u64::from(u32::MAX) + 1] {
        let mut escenario = escenario(1, BTreeMap::new());
        escenario.contexto.iteraciones.insert(103, n_malo);
        assert!(
            matches!(
                verificar(&escenario, RELOJ),
                EstadoPot::PotPendiente(MotivoPotPendiente::IteracionesFueraDeDominio {
                    slot: 103,
                    ..
                })
            ),
            "N = {n_malo}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 11 · Doble inyección en el mismo slot
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dos_inyecciones_en_el_mismo_slot_son_pendiente() {
    let mut escenario = escenario(1, BTreeMap::new());
    escenario
        .contexto
        .inyecciones
        .insert(103, InyeccionesPot::Varias);
    assert_eq!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotPendiente(MotivoPotPendiente::InyeccionesMultiples { slot: 103 })
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 12 · Contexto circular (el ancla es el propio candidato)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn un_ancla_que_es_el_propio_candidato_es_contexto_circular() {
    let mut escenario = escenario(1, BTreeMap::new());
    let ancla = escenario.cabecera.block_hash();
    escenario.contexto.inyecciones = inyecciones_una(103, ancla);
    assert_eq!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotPendiente(MotivoPotPendiente::ContextoCircular { slot: 103 })
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 13 · Pasado incompleto y flujo discreparte
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn un_padre_ausente_del_pasado_es_pendiente() {
    let mut escenario = escenario(1, BTreeMap::new());
    escenario
        .contexto
        .pasado
        .retain(|b| b.hash != hash_de(0x02));
    assert_eq!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotPendiente(MotivoPotPendiente::PasadoIncompleto)
    );
}

#[test]
fn un_flujo_de_pasado_discrepante_invalida() {
    let mut escenario = escenario(1, BTreeMap::new());
    if let Some(entrada) = escenario.contexto.pasado.first_mut() {
        entrada.flujo = [0xEE; FLUJO_BYTES];
    }
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotInvalido(MotivoPotInvalido::FlujoDePasadoDiscrepa { .. })
    ));
}

#[test]
fn un_slot_de_padre_posterior_invalida() {
    let mut escenario = escenario(1, BTreeMap::new());
    if let Some(entrada) = escenario.contexto.pasado.get_mut(1) {
        entrada.slot = escenario.cabecera.slot + 1;
    }
    assert!(matches!(
        verificar(&escenario, RELOJ),
        EstadoPot::PotInvalido(MotivoPotInvalido::SlotDePadrePosterior { .. })
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 14 · Reloj futuro y presupuesto agotado
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn un_slot_por_delante_del_reloj_es_pendiente() {
    let escenario = escenario(3, BTreeMap::new());
    assert_eq!(
        verificar(&escenario, 104),
        EstadoPot::PotPendiente(MotivoPotPendiente::RelojFuturo {
            slot: 105,
            reloj_pot: 104
        })
    );
    assert_eq!(
        verificar(&escenario, 50),
        EstadoPot::PotPendiente(MotivoPotPendiente::RelojFuturo {
            slot: 103,
            reloj_pot: 50
        })
    );
}

#[test]
fn el_presupuesto_agotado_es_pendiente_y_nunca_invalido() {
    let escenario = escenario(3, BTreeMap::new());
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(0);
    assert_eq!(
        verificar_rango_pot(
            &escenario.cabecera,
            &escenario.justificacion,
            &escenario.contexto,
            RELOJ,
            &mut cache,
            &mut presupuesto,
        ),
        EstadoPot::PotPendiente(MotivoPotPendiente::PresupuestoAgotado { slot: 103 })
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 15 · Caché verificada: calentamiento real, acierto sin AES y discrepancia
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn un_acierto_de_cache_completo_no_gasta_aes() {
    let escenario = escenario(3, BTreeMap::new());
    let mut cache = CachePotVerificada::nueva();

    // Calentamiento real: verifica los tres portadores y registra sus entradas.
    let mut calentamiento = PresupuestoPrueba::nuevo(1_000);
    let estado_caliente = verificar_en_fases(&escenario, RELOJ, &mut cache, &mut calentamiento);
    assert!(matches!(&estado_caliente, EstadoPot::PotValido(_)));
    assert_eq!(calentamiento.intentos, 3, "tres AES en el calentamiento");

    // Presupuesto CERO: un acierto completo de clave y 128 B evita repetir AES y devuelve la
    // MISMA prueba: mismo candidato, mismo slot auditado y misma salida.
    let mut presupuesto = PresupuestoPrueba::nuevo(0);
    let estado_cache = verificar_en_fases(&escenario, RELOJ, &mut cache, &mut presupuesto);
    assert_eq!(
        estado_cache, estado_caliente,
        "la caché caliente devuelve la misma prueba"
    );
    assert_eq!(presupuesto.intentos, 0, "el acierto no intenta AES");
}

#[test]
fn el_acierto_de_cache_usa_el_flujo_del_slot_al_cruzar_una_inyeccion() {
    // La inyección de 104 cambia el flujo vigente para los dos últimos portadores.
    let mut escenario = escenario(3, inyeccion_en(104, hash_de(0x30)));
    let flujo_inyectado = [0x22; FLUJO_BYTES];
    escenario
        .contexto
        .flujos_por_slot
        .insert(104, flujo_inyectado);
    escenario
        .contexto
        .flujos_por_slot
        .insert(105, flujo_inyectado);

    let mut cache = CachePotVerificada::nueva();
    let mut calentamiento = PresupuestoPrueba::nuevo(1_000);
    assert!(matches!(
        verificar_en_fases(&escenario, RELOJ, &mut cache, &mut calentamiento),
        EstadoPot::PotValido(_)
    ));

    // Con el flujo del slot 104 cambiado, la clave contextual ya no coincide: sin presupuesto,
    // el núcleo debe quedarse en `Pendiente` en 104. Si hubiera usado el flujo de `slot(B)`
    // para todos los slots, la clave no habría cambiado y habría acertado.
    escenario
        .contexto
        .flujos_por_slot
        .insert(104, [0x33; FLUJO_BYTES]);
    escenario
        .contexto
        .flujos_por_slot
        .insert(105, [0x33; FLUJO_BYTES]);
    let mut presupuesto = PresupuestoPrueba::nuevo(0);
    assert_eq!(
        verificar_en_fases(&escenario, RELOJ, &mut cache, &mut presupuesto),
        EstadoPot::PotPendiente(MotivoPotPendiente::PresupuestoAgotado { slot: 104 })
    );
}

#[test]
fn un_portador_alterado_bajo_la_misma_clave_invalida_sin_gastar_aes() {
    // Calentamiento real con la cadena válida.
    let mut escenario = escenario(3, BTreeMap::new());
    let mut cache = CachePotVerificada::nueva();
    let mut calentamiento = PresupuestoPrueba::nuevo(1_000);
    assert!(matches!(
        verificar_en_fases(&escenario, RELOJ, &mut cache, &mut calentamiento),
        EstadoPot::PotValido(_)
    ));

    // Se muta un checkpoint intermedio del segundo portador y se conserva su salida final: la
    // clave contextual no cambia, así que la discrepancia se detecta sin AES.
    let original = escenario
        .cadena
        .portadores
        .get(1)
        .copied()
        .expect("segundo");
    let alterado = portador_con_checkpoint_alterado(&original);
    assert_eq!(salida_de(&original), salida_de(&alterado));
    if let Some(slot) = escenario.cadena.portadores.get_mut(1) {
        *slot = alterado;
    }
    escenario.justificacion = justificacion(&escenario.cadena);

    let mut presupuesto = PresupuestoPrueba::nuevo(0);
    assert_eq!(
        verificar_en_fases(&escenario, RELOJ, &mut cache, &mut presupuesto),
        EstadoPot::PotInvalido(MotivoPotInvalido::CacheDiscrepante { slot: 104 })
    );
    assert_eq!(presupuesto.intentos, 0, "la discrepancia no gasta AES");
}

#[test]
fn una_salida_distinta_bajo_la_misma_clave_invalida_sin_gastar_aes() {
    // Calentamiento real con la cadena válida.
    let mut escenario = escenario(3, BTreeMap::new());
    let mut cache = CachePotVerificada::nueva();
    let mut calentamiento = PresupuestoPrueba::nuevo(1_000);
    assert!(matches!(
        verificar_en_fases(&escenario, RELOJ, &mut cache, &mut calentamiento),
        EstadoPot::PotValido(_)
    ));

    // Se muta el último checkpoint del segundo portador: la salida final cambia, pero la clave
    // contextual —semilla y `N` del slot— no. La discrepancia se decide sin AES.
    let original = escenario
        .cadena
        .portadores
        .get(1)
        .copied()
        .expect("segundo");
    let alterado = portador_con_ultimo_alterado(&original);
    assert_ne!(salida_de(&original), salida_de(&alterado));
    if let Some(slot) = escenario.cadena.portadores.get_mut(1) {
        *slot = alterado;
    }
    escenario.justificacion = justificacion(&escenario.cadena);

    let mut presupuesto = PresupuestoPrueba::nuevo(0);
    assert_eq!(
        verificar_en_fases(&escenario, RELOJ, &mut cache, &mut presupuesto),
        EstadoPot::PotInvalido(MotivoPotInvalido::CacheDiscrepante { slot: 104 })
    );
    assert_eq!(presupuesto.intentos, 0, "la discrepancia no gasta AES");
}

#[test]
fn la_fase_previa_invalida_o_pendiente_no_toca_cache_ni_presupuesto() {
    // Una caché recién creada está vacía **por comportamiento**, no por inspección: con
    // presupuesto cero el primer portador no puede acertar y el núcleo queda `Pendiente`.
    let valido = escenario(3, BTreeMap::new());
    un_cache_vacio_es_pendiente_sin_presupuesto(&valido);

    // `d = 3` con solo dos portadores: la fase previa lo rechaza antes de poder llamar a la fase
    // AES. La fase previa ni siquiera recibe caché ni presupuesto: no puede tocarlos.
    let cadena = generar(FLUJO, SLOT_SP, RETARDO, 2, BASE, BTreeMap::new(), |_| {
        N_FIJO
    });
    let (sp, extra) = (hash_de(0x01), hash_de(0x02));
    let cabecera = cabecera(cadena.slot_sp + 3, cadena.pot_output, sp, &[extra]);
    let contexto = contexto(&cadena, &[(sp, SLOT_SP), (extra, SLOT_SP)]);
    let justificacion = justificacion(&cadena);
    let presupuesto = PresupuestoPrueba::nuevo(10);

    assert!(matches!(
        verificar_rango_pot_fase_previa(&cabecera, &justificacion, &contexto),
        Err(EstadoPot::PotInvalido(
            MotivoPotInvalido::DiferenciaDeSlots(_)
        ))
    ));
    assert_eq!(presupuesto.intentos, 0, "la fase previa no toca AES");

    // Padre ausente: `Pendiente`, tampoco hay token que llegue a la fase AES.
    let mut contexto_pendiente = contexto;
    contexto_pendiente
        .pasado
        .retain(|b| b.hash != hash_de(0x02));
    assert!(matches!(
        verificar_rango_pot_fase_previa(&cabecera, &justificacion, &contexto_pendiente),
        Err(EstadoPot::PotPendiente(
            MotivoPotPendiente::PasadoIncompleto
        ))
    ));
    assert_eq!(presupuesto.intentos, 0);
}

#[test]
fn un_token_no_sirve_para_otro_candidato() {
    let escenario = escenario(3, BTreeMap::new());
    let hash_a = escenario.cabecera.block_hash();

    // El token queda atado al `block_hash` del candidato acreditado en la fase previa.
    let token = verificar_rango_pot_fase_previa(
        &escenario.cabecera,
        &escenario.justificacion,
        &escenario.contexto,
    )
    .expect("fase previa válida");
    assert_eq!(token.bloque(), hash_a);
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);
    assert!(matches!(
        verificar_rango_pot_fase_aes(token, RELOJ, &mut cache, &mut presupuesto),
        EstadoPot::PotValido(_)
    ));

    // Otro candidato, con `pot_output` distinto, produce un token con otro `block_hash` y su
    // propio defecto: la fase AES sigue al token, no a un candidato ajeno.
    let mut otro = escenario;
    otro.cabecera.pot_output = [0x00; POT_OUTPUT_BYTES];
    let token_otro =
        verificar_rango_pot_fase_previa(&otro.cabecera, &otro.justificacion, &otro.contexto)
            .expect("fase previa válida");
    assert_eq!(token_otro.bloque(), otro.cabecera.block_hash());
    assert_ne!(token_otro.bloque(), hash_a);
    let mut cache_otro = CachePotVerificada::nueva();
    let mut presupuesto_otro = PresupuestoPrueba::nuevo(1_000);
    assert!(matches!(
        verificar_rango_pot_fase_aes(token_otro, RELOJ, &mut cache_otro, &mut presupuesto_otro),
        EstadoPot::PotInvalido(MotivoPotInvalido::PotOutputNoCoincide { .. })
    ));
}

#[test]
fn un_token_no_sirve_para_otro_contexto() {
    // Contexto A, coherente con el candidato: la fase previa acredita y devuelve el token.
    let escenario = escenario(3, BTreeMap::new());
    let token = verificar_rango_pot_fase_previa(
        &escenario.cabecera,
        &escenario.justificacion,
        &escenario.contexto,
    )
    .expect("fase previa válida");

    // Contexto B para el MISMO candidato, con un ancestro cuyo flujo discrepa: la fase previa lo
    // rechaza. Si la fase AES aceptara un contexto aparte, el token de A podría validarse contra
    // el pasado acreditado en B; la firma nueva lo impide (el token retiene `&A`).
    let mut contexto_b = escenario.contexto.clone();
    let entrada = contexto_b
        .pasado
        .first_mut()
        .expect("el escenario siempre tiene padres");
    entrada.flujo = [0xEE; FLUJO_BYTES];
    assert!(matches!(
        verificar_rango_pot_fase_previa(&escenario.cabecera, &escenario.justificacion, &contexto_b,),
        Err(EstadoPot::PotInvalido(
            MotivoPotInvalido::FlujoDePasadoDiscrepa { .. }
        ))
    ));

    // Un ancestro con `slot` posterior también produce `Inválido`, no una verificación cruzada.
    let mut contexto_b_slot = escenario.contexto.clone();
    let entrada = contexto_b_slot
        .pasado
        .first_mut()
        .expect("el escenario siempre tiene padres");
    entrada.slot = escenario.cabecera.slot + 1;
    assert!(matches!(
        verificar_rango_pot_fase_previa(
            &escenario.cabecera,
            &escenario.justificacion,
            &contexto_b_slot,
        ),
        Err(EstadoPot::PotInvalido(
            MotivoPotInvalido::SlotDePadrePosterior { .. }
        ))
    ));

    // El token de A sigue verificando contra A: B nunca entra en juego.
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(1_000);
    assert!(matches!(
        verificar_rango_pot_fase_aes(token, RELOJ, &mut cache, &mut presupuesto),
        EstadoPot::PotValido(_)
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// 16 · Génesis
// ─────────────────────────────────────────────────────────────────────────────

/// **D-P08 · sustituye a `el_genesis_no_lleva_portadores_ni_se_inventa_entropia_externa`.** No hay
/// génesis DAG: una cabecera PoST con cero padres es **inválida siempre**, lleve o no portadores, y
/// sin tocar AES.
#[test]
fn una_cabecera_sin_padres_es_invalida_y_no_toca_aes() {
    let cabecera = cabecera(0, [0x00; POT_OUTPUT_BYTES], hash_de(0x01), &[]);
    let cabecera = DagBlockHeader {
        vdf_output: [0u8; 16],
        padres: PadresDag::genesis(),
        ..cabecera
    };
    let contexto = ContextoPrueba {
        flujo: FLUJO,
        flujos_por_slot: BTreeMap::new(),
        pasado: Vec::new(),
        inyecciones: BTreeMap::new(),
        iteraciones: BTreeMap::new(),
        retardo: RETARDO,
        salidas: BTreeMap::new(),
    };
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoPrueba::nuevo(10);

    assert_eq!(
        verificar_rango_pot(
            &cabecera,
            &JustificacionPot::vacia(),
            &contexto,
            RELOJ,
            &mut cache,
            &mut presupuesto,
        ),
        EstadoPot::PotInvalido(MotivoPotInvalido::SinPadres)
    );

    let con_portadores =
        JustificacionPot::nueva(vec![PotCheckpoints::desde_bytes([0u8; BUNDLE_BYTES])])
            .expect("un portador");
    assert_eq!(
        verificar_rango_pot(
            &cabecera,
            &con_portadores,
            &contexto,
            RELOJ,
            &mut cache,
            &mut presupuesto,
        ),
        EstadoPot::PotInvalido(MotivoPotInvalido::SinPadres)
    );
    assert_eq!(
        presupuesto.restantes, 10,
        "el rechazo por D-P08 no consume presupuesto AES"
    );
    assert_eq!(presupuesto.intentos, 0, "no se ejecuta ningún AES");
}
