//! FIRC-1 · comprobación de una candidata PoST **sin sello** (IPA B-06).
//!
//! # Qué demuestra
//!
//! - **P1**: candidatas reales (bloques de tres semillas con el sello a cero) pasan
//!   [`verificar_candidata_para_firma`]; `distancia()` coincide con
//!   [`zx_poas::verificar_solucion_poas`] aparte; `pre_hash()` es el de la cabecera; el bloque
//!   sellado pasa [`verificar_cabecera_conjunta`] con el mismo `slot`, `productor`,
//!   `padre_seleccionado` y `peso`.
//! - **P2**: equivalencia por clase con la puerta de recibidos en cada defecto no dependiente del
//!   sello (tabla en `PRUEBAS.md`).
//! - **P3**: la función nueva rechaza «ya sellada» sin verificar firmas; la puerta recibida sigue
//!   exigiendo el sello real.
//! - **P5**: caché y presupuesto: la candidata paga la cadena AES; el bloque sellado del mismo
//!   rango la reutiliza.
//! - **P6** (`#[ignore]`): coste en `--release`.
//!
//! Montaje real copiado de `extremo_a_extremo.rs` (parcela, PoAS, PoT y sello reales).

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "instrumento de test: un fallo del fixture o del veredicto debe producir panic"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "índices deliberados sobre los vectores de fixture del propio test"
)]

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;

use ed25519_zebra::{SigningKey, VerificationKey};
use subspace_core_primitives::PublicKey;
use zx_consensus::{
    GENESIS_DEV, PARAMETROS_POW_DEV, Sha3Dev, construir as construir_genesis, minar,
};
use zx_core::preimage::block::BlockHeader;
use zx_core::wire_dag::{BloqueDag, JustificacionPot, MAX_BUNDLES_POT, PotCheckpoints};
use zx_core::{Amount, BlockHash, DagBlockHeader, decodificar_con};
use zx_dag::peso;
use zx_farmer::farmer::{ParcelaDisco, plotear_sector_en_disco};
use zx_farmer::productor_poas::convertir_candidatos_locales;
use zx_poas::{HistoriaGenesis, verificar_solucion_poas};
use zx_post::cabecera_conjunta::{
    EstadoCabeceraConjunta, EstadoCandidata, MotivoCabeceraInvalida, verificar_cabecera_conjunta,
    verificar_candidata_para_firma,
};
use zx_post::contexto_transicion::ContextoTransicion;
use zx_post::pot::checkpoints_a_primitiva;
use zx_post::pot_rango::{CachePotVerificada, PresupuestoPot};
use zx_post::productor::{
    FuenteSoluciones, ParametrosProductor, SolucionCandidata, clave_publica_de,
    producir_sin_firmante,
};

const N_DEV: u64 = 2_048;
const SR_DEV: u64 = u64::MAX;
const SR_DECLARADO_MAL: u64 = SR_DEV - 1;
const MAX_SLOTS: u64 = MAX_BUNDLES_POT as u64;
const ALTURA_POW: u32 = 3;
const INDICE_SECTOR: u16 = 3;
const PIEZAS: u16 = 2;

fn historia() -> &'static HistoriaGenesis {
    static HISTORIA: OnceLock<HistoriaGenesis> = OnceLock::new();
    HISTORIA.get_or_init(|| HistoriaGenesis::construir().expect("historia génesis dev"))
}

fn terminal() -> BlockHash {
    static TERMINAL: OnceLock<BlockHash> = OnceLock::new();
    *TERMINAL.get_or_init(|| {
        let (mut cabecera, _) = construir_genesis(GENESIS_DEV).expect("génesis dev");
        let target = decodificar_con(
            PARAMETROS_POW_DEV.bits_iniciales,
            &PARAMETROS_POW_DEV.limites,
        )
        .expect("bits dev válidos");
        let cancelar = AtomicBool::new(false);
        for altura in 1..=ALTURA_POW {
            let plantilla = BlockHeader {
                consensus_branch_id: cabecera.consensus_branch_id,
                prev_hash: cabecera.block_hash(),
                merkle_root: cabecera.merkle_root,
                timestamp: cabecera.timestamp + u64::from(altura) * 2,
                bits: PARAMETROS_POW_DEV.bits_iniciales,
                nonce: 0,
                height: altura,
            };
            cabecera = minar(&plantilla, target, &Sha3Dev, 50_000_000, &cancelar)
                .expect("la cadena PoW dev debe minar");
        }
        cabecera.block_hash()
    })
}

struct Fondo {
    sk: SigningKey,
    public_key: PublicKey,
    ruta: PathBuf,
    _dir: DirTemporal,
}

impl Fondo {
    fn nuevo(semilla: u8) -> Self {
        let sk = SigningKey::from([semilla; 32]);
        let bytes: [u8; 32] = VerificationKey::from(&sk).into();
        let public_key = PublicKey::from(bytes);
        let historia = historia();
        let dir = DirTemporal::nuevo("zx-post-candidata");
        let ruta = dir.unir("sector.plot");
        plotear_sector_en_disco(
            &ruta,
            &public_key,
            INDICE_SECTOR,
            PIEZAS,
            historia.historial(),
            historia.protocolo(),
            historia.erasure_coding(),
        )
        .expect("el ploteo del fixture debe funcionar");
        Self {
            sk,
            public_key,
            ruta,
            _dir: dir,
        }
    }
}

fn fondos() -> &'static [Fondo] {
    static FONDOS: OnceLock<Vec<Fondo>> = OnceLock::new();
    FONDOS.get_or_init(|| {
        [0x11u8, 0x22, 0x33, 0x44]
            .into_iter()
            .map(Fondo::nuevo)
            .collect()
    })
}

fn fondo(i: usize) -> &'static Fondo {
    fondos().get(i).expect("hay fondos de fixture")
}

struct FuenteParcela<'a> {
    parcela: &'a ParcelaDisco,
    historia: &'a HistoriaGenesis,
}

impl FuenteSoluciones for FuenteParcela<'_> {
    type Error = zx_farmer::ErrorProductorPoas;

    fn soluciones(
        &self,
        salida: [u8; 16],
        slot: u64,
        rango: u64,
    ) -> Result<Vec<SolucionCandidata>, Self::Error> {
        let params = self.historia.params_pieza();
        let resultado = convertir_candidatos_locales(
            self.parcela,
            salida,
            slot,
            rango,
            &params,
            self.historia,
            self.historia.erasure_coding(),
        )?;
        Ok(resultado
            .soluciones()
            .iter()
            .map(|c| SolucionCandidata {
                solucion: *c.solucion(),
                distancia: c.distancia(),
            })
            .collect())
    }
}

/// Presupuesto que **cuenta** las unidades AES consumidas (P5).
struct PresupuestoContable {
    consumidas: u64,
    limite: u64,
}

impl PresupuestoContable {
    fn nuevo(limite: u64) -> Self {
        Self {
            consumidas: 0,
            limite,
        }
    }
}

impl PresupuestoPot for PresupuestoContable {
    fn consumir_slot(&mut self, _slot: u64) -> bool {
        if self.consumidas >= self.limite {
            return false;
        }
        self.consumidas += 1;
        true
    }
}

fn parametros_productor() -> ParametrosProductor {
    ParametrosProductor {
        n_dev: N_DEV,
        sr_dev: SR_DEV,
        max_slots: MAX_SLOTS,
        consensus_branch_id: zx_core::CBID_RED_DEV,
        timestamp: 1_788_480_000,
        i_iter: 0,
        importe_coinbase: Amount::nuevo(5).expect("importe de coinbase > 0"),
    }
}

fn contexto() -> ContextoTransicion {
    ContextoTransicion::nuevo(terminal(), N_DEV, SR_DEV, Vec::new())
        .expect("el contexto de transición dev debe construirse")
}

fn producir_de(fondo: &Fondo) -> BloqueDag {
    let parcela =
        ParcelaDisco::abrir(&fondo.ruta, &fondo.public_key).expect("la parcela debe abrir");
    let fuente = FuenteParcela {
        parcela: &parcela,
        historia: historia(),
    };
    producir_sin_firmante(terminal(), &fuente, &fondo.sk, &parametros_productor())
        .expect("el productor debe hallar una solución en la ventana")
}

/// La candidata que se firmó: la misma cabecera con el sello a cero.
fn sin_sello(bloque: &BloqueDag) -> BloqueDag {
    let mut cabecera = bloque.cabecera;
    cabecera.sello = [0u8; 64];
    BloqueDag::nuevo(
        cabecera,
        bloque.justificacion.clone(),
        bloque.txs().to_vec(),
        bloque.testigos().to_vec(),
    )
    .expect("candidata sin sello")
}

fn refirmar(cabecera: &mut DagBlockHeader, sk: &SigningKey) {
    let pre = cabecera.pre_hash();
    cabecera.sello = sk.sign(pre.as_bytes()).into();
}

fn con_justificacion(bloque: &BloqueDag, bundles: Vec<PotCheckpoints>) -> BloqueDag {
    BloqueDag::nuevo(
        bloque.cabecera,
        JustificacionPot::nueva(bundles).expect("≤ 150 portadores"),
        bloque.txs().to_vec(),
        bloque.testigos().to_vec(),
    )
    .expect("bloque con la misma cabecera y cuerpo")
}

/// Comprueba un bloque sellado con la puerta de recibidos.
fn comprobar_recibido(bloque: &BloqueDag, reloj: u64) -> EstadoCabeceraConjunta {
    let ctx = contexto();
    let params = historia().params_pieza();
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoContable::nuevo(u64::MAX);
    verificar_cabecera_conjunta(
        bloque,
        &ctx,
        &ctx,
        &ctx,
        reloj,
        &mut cache,
        &mut presupuesto,
        Some(&params),
    )
}

/// Comprueba una candidata sin sello con la función nueva.
fn comprobar_candidata(bloque: &BloqueDag, reloj: u64) -> EstadoCandidata {
    let ctx = contexto();
    let params = historia().params_pieza();
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoContable::nuevo(u64::MAX);
    verificar_candidata_para_firma(
        bloque,
        &ctx,
        &ctx,
        &ctx,
        reloj,
        &mut cache,
        &mut presupuesto,
        Some(&params),
    )
}

/// Comprueba la candidata con un presupuesto contable y una caché dadas (P5).
fn comprobar_candidata_con(
    bloque: &BloqueDag,
    cache: &mut CachePotVerificada,
    presupuesto: &mut PresupuestoContable,
) -> EstadoCandidata {
    let ctx = contexto();
    let params = historia().params_pieza();
    verificar_candidata_para_firma(
        bloque,
        &ctx,
        &ctx,
        &ctx,
        u64::MAX,
        cache,
        presupuesto,
        Some(&params),
    )
}

fn comprobar_recibido_con(
    bloque: &BloqueDag,
    cache: &mut CachePotVerificada,
    presupuesto: &mut PresupuestoContable,
) -> EstadoCabeceraConjunta {
    let ctx = contexto();
    let params = historia().params_pieza();
    verificar_cabecera_conjunta(
        bloque,
        &ctx,
        &ctx,
        &ctx,
        u64::MAX,
        cache,
        presupuesto,
        Some(&params),
    )
}

/// Salida auditada del bloque: último checkpoint del último portador (d > D en el fixture).
fn salida_auditada_de(bloque: &BloqueDag) -> [u8; 16] {
    let ultimo = bloque
        .justificacion
        .bundles()
        .last()
        .expect("el fixture tiene portadores");
    *checkpoints_a_primitiva(ultimo).output()
}

fn pieza_invalida() -> subspace_verification::PieceCheckParams {
    use core::num::NonZeroU64;
    use subspace_core_primitives::segments::{HistorySize, SegmentCommitment};
    let h = |n: u64| HistorySize::from(NonZeroU64::new(n).expect("n > 0"));
    subspace_verification::PieceCheckParams {
        max_pieces_in_sector: 1,
        segment_commitment: SegmentCommitment::default(),
        recent_segments: h(1),
        recent_history_fraction: (h(1), h(1)),
        min_sector_lifetime: h(1),
        current_history_size: h(u64::MAX),
        sector_expiration_check_segment_commitment: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P1 · Positivo real
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn p1_candidatas_reales_sin_sello_comprueban_y_coinciden_con_el_bloque_sellado() {
    let params = historia().params_pieza();
    for indice in 0..fondos().len() {
        let f = fondo(indice);
        let sellado = producir_de(f);
        let candidata = sin_sello(&sellado);
        assert!(
            candidata.cabecera.sello.iter().all(|&b| b == 0),
            "la candidata tiene el sello a cero"
        );

        let estado = comprobar_candidata(&candidata, u64::MAX);
        let comprobada = match estado {
            EstadoCandidata::Comprobada(c) => c,
            otro => panic!("semilla {indice}: se esperaba Comprobada, llegó {otro:?}"),
        };

        // distancia() == verificar_solucion_poas con los mismos datos.
        let salida = salida_auditada_de(&candidata);
        let distancia_oraculo = verificar_solucion_poas(
            &candidata.cabecera.sol,
            candidata.cabecera.slot,
            salida,
            candidata.cabecera.rango_solucion,
            &params,
        )
        .expect("el oráculo PoAS acepta la misma solución");
        assert_eq!(
            comprobada.distancia(),
            distancia_oraculo,
            "semilla {indice}: la distancia debe ser la del verificador real"
        );

        // pre_hash() es el de la cabecera comprobada.
        assert_eq!(
            comprobada.pre_hash(),
            candidata.cabecera.pre_hash(),
            "semilla {indice}: pre_hash de la prefirma"
        );
        // La prefirma no cambia al sellar: el mismo pre_hash sirve al firmante.
        assert_eq!(comprobada.pre_hash(), sellado.cabecera.pre_hash());

        // El bloque ya sellado pasa la puerta de recibidos con los mismos hechos.
        let recibido = match comprobar_recibido(&sellado, u64::MAX) {
            EstadoCabeceraConjunta::Comprobada(h) => h,
            otro => panic!("semilla {indice}: el sellado debía Comprobarse, llegó {otro:?}"),
        };
        assert_eq!(comprobada.slot(), recibido.slot);
        assert_eq!(comprobada.productor(), &recibido.productor);
        assert_eq!(comprobada.padre_seleccionado(), recibido.padre_seleccionado);
        assert_eq!(comprobada.peso(), recibido.peso);
        assert_eq!(comprobada.peso(), peso(SR_DEV));
        assert_eq!(comprobada.productor(), &clave_publica_de(&f.sk));
        assert_eq!(comprobada.padre_seleccionado(), terminal());
    }
}

/// P1(b): candidata de `preparar_regimen_para_ensayo` (sin sello de origen).
#[test]
fn p1b_candidata_de_preparar_regimen_para_ensayo() {
    let params = historia().params_pieza();
    let f = fondo(0);
    let parcela = ParcelaDisco::abrir(&f.ruta, &f.public_key).expect("la parcela debe abrir");
    let fuente = FuenteParcela {
        parcela: &parcela,
        historia: historia(),
    };
    let mut servicio = zx_post::servicio_pot::ServicioPot::nuevo(terminal(), N_DEV, MAX_SLOTS)
        .expect("servicio PoT");
    let padres = zx_core::PadresDag::nuevo(terminal(), &[]).expect("un padre");
    let cuerpo = zx_post::productor_regimen::CuerpoProductor::vacio();
    // Buscamos el primer slot con solución, como hace el productor de régimen.
    let mut candidata = None;
    for slot in 1..=20u64 {
        match zx_post::productor_regimen::preparar_regimen_para_ensayo(
            padres,
            slot,
            &mut servicio,
            &fuente,
            &f.sk,
            &parametros_productor(),
            cuerpo.clone(),
        ) {
            Ok(b) => {
                candidata = Some(b);
                break;
            }
            Err(_) => {
                // slot sin solución: el servicio avanza y probamos el siguiente
                let _ = servicio.registrar_validado(
                    BlockHash::from_digest(zx_core::digest::Digest::from_bytes([0; 32])),
                    slot,
                );
            }
        }
    }
    let candidata = candidata.expect("algún slot del rango debe dar solución");
    assert!(
        candidata.cabecera.sello.iter().all(|&b| b == 0),
        "preparar_regimen deja la candidata sin sello"
    );

    let estado = comprobar_candidata(&candidata, u64::MAX);
    let comprobada = match estado {
        EstadoCandidata::Comprobada(c) => c,
        otro => panic!("régimen: se esperaba Comprobada, llegó {otro:?}"),
    };
    assert_eq!(comprobada.pre_hash(), candidata.cabecera.pre_hash());
    let salida = salida_auditada_de(&candidata);
    let distancia_oraculo = verificar_solucion_poas(
        &candidata.cabecera.sol,
        candidata.cabecera.slot,
        salida,
        candidata.cabecera.rango_solucion,
        &params,
    )
    .expect("oráculo PoAS de la candidata de régimen");
    assert_eq!(comprobada.distancia(), distancia_oraculo);
}

// ─────────────────────────────────────────────────────────────────────────────
// P2 · Equivalencia por clase (tabla en PRUEBAS.md)
// ─────────────────────────────────────────────────────────────────────────────

/// Ejecuta ambos caminos y devuelve `(clase_candidata, motivo_debug, clase_recibida, motivo_debug)`.
fn ambos_caminos(
    candidata: &BloqueDag,
    sellado: &BloqueDag,
    reloj_c: u64,
    reloj_r: u64,
    pieza: Option<&subspace_verification::PieceCheckParams>,
) -> (String, String, String, String) {
    let ctx = contexto();
    let mut cache_c = CachePotVerificada::nueva();
    let mut pres_c = PresupuestoContable::nuevo(u64::MAX);
    let estado_c = verificar_candidata_para_firma(
        candidata,
        &ctx,
        &ctx,
        &ctx,
        reloj_c,
        &mut cache_c,
        &mut pres_c,
        pieza,
    );
    let mut cache_r = CachePotVerificada::nueva();
    let mut pres_r = PresupuestoContable::nuevo(u64::MAX);
    let estado_r = verificar_cabecera_conjunta(
        sellado,
        &ctx,
        &ctx,
        &ctx,
        reloj_r,
        &mut cache_r,
        &mut pres_r,
        pieza,
    );
    let (clase_c, motivo_c) = match &estado_c {
        EstadoCandidata::Comprobada(_) => ("Comprobada".into(), String::new()),
        EstadoCandidata::Invalida(m) => ("Invalida".into(), format!("{m:?}")),
        EstadoCandidata::Pendiente(m) => ("Pendiente".into(), format!("{m:?}")),
        EstadoCandidata::YaSellada => ("YaSellada".into(), String::new()),
    };
    let (clase_r, motivo_r) = match &estado_r {
        EstadoCabeceraConjunta::Comprobada(_) => ("Comprobada".into(), String::new()),
        EstadoCabeceraConjunta::Invalida(m) => ("Invalida".into(), format!("{m:?}")),
        EstadoCabeceraConjunta::Pendiente(m) => ("Pendiente".into(), format!("{m:?}")),
    };
    (clase_c, motivo_c, clase_r, motivo_r)
}

fn exigir_equivalencia(etiqueta: &str, fila: (String, String, String, String)) {
    let (clase_c, motivo_c, clase_r, motivo_r) = fila;
    assert_eq!(
        clase_c, clase_r,
        "P2[{etiqueta}]: clase distinta — candidata {clase_c}/{motivo_c} vs recibida {clase_r}/{motivo_r}"
    );
    assert_eq!(
        motivo_c, motivo_r,
        "P2[{etiqueta}]: motivo distinto — candidata {motivo_c} vs recibida {motivo_r}"
    );
}

#[test]
fn p2_equivalencia_por_clase_con_la_puerta_de_recibidos() {
    let params = historia().params_pieza();
    let f = fondo(0);
    let base = producir_de(f);

    // 1 · salida PoT falsa
    {
        let mut sellado = base.clone();
        sellado.cabecera.pot_output = [0u8; 16];
        refirmar(&mut sellado.cabecera, &f.sk);
        let candidata = sin_sello(&sellado);
        exigir_equivalencia(
            "salida Pot falsa",
            ambos_caminos(&candidata, &sellado, u64::MAX, u64::MAX, Some(&params)),
        );
    }

    // 2 · portador alterado (otro flujo/salida)
    {
        let mut bundles = base.justificacion.bundles().to_vec();
        bundles[0] = PotCheckpoints::desde_outputs(bundles[0].outputs().map(|o| {
            let mut o = o;
            o[0] ^= 0xFF;
            o
        }));
        let mut sellado = con_justificacion(&base, bundles);
        refirmar(&mut sellado.cabecera, &f.sk);
        let candidata = sin_sello(&sellado);
        exigir_equivalencia(
            "portador alterado",
            ambos_caminos(&candidata, &sellado, u64::MAX, u64::MAX, Some(&params)),
        );
    }

    // 3 · solución de otra clave (el sello lo rehace la clave ajena, como en v6_*)
    {
        let mut sellado = base.clone();
        let ajena = SigningKey::from([0x55; 32]);
        sellado.cabecera.sol.public_key = clave_publica_de(&ajena);
        refirmar(&mut sellado.cabecera, &ajena);
        let candidata = sin_sello(&sellado);
        exigir_equivalencia(
            "solución de otra clave",
            ambos_caminos(&candidata, &sellado, u64::MAX, u64::MAX, Some(&params)),
        );
    }

    // 4 · solución de otro sector
    {
        let mut sellado = base.clone();
        sellado.cabecera.sol.sector_index = 0;
        refirmar(&mut sellado.cabecera, &f.sk);
        let candidata = sin_sello(&sellado);
        exigir_equivalencia(
            "solución de otro sector",
            ambos_caminos(&candidata, &sellado, u64::MAX, u64::MAX, Some(&params)),
        );
    }

    // 5 · rango distinto del esperado
    {
        let mut sellado = base.clone();
        sellado.cabecera.rango_solucion = SR_DECLARADO_MAL;
        refirmar(&mut sellado.cabecera, &f.sk);
        let candidata = sin_sello(&sellado);
        exigir_equivalencia(
            "rango distinto",
            ambos_caminos(&candidata, &sellado, u64::MAX, u64::MAX, Some(&params)),
        );
    }

    // 6 · padres extra
    {
        let mut sellado = base.clone();
        let extra = BlockHash::from_digest(zx_core::digest::Digest::from_bytes([9; 32]));
        sellado.cabecera.padres =
            zx_core::PadresDag::nuevo(terminal(), &[extra]).expect("padres canónicos");
        refirmar(&mut sellado.cabecera, &f.sk);
        let candidata = sin_sello(&sellado);
        exigir_equivalencia(
            "padres extra",
            ambos_caminos(&candidata, &sellado, u64::MAX, u64::MAX, Some(&params)),
        );
    }

    // 7 · slot cero
    {
        let mut sellado = base.clone();
        sellado.cabecera.slot = 0;
        refirmar(&mut sellado.cabecera, &f.sk);
        let candidata = sin_sello(&sellado);
        exigir_equivalencia(
            "slot cero",
            ambos_caminos(&candidata, &sellado, u64::MAX, u64::MAX, Some(&params)),
        );
    }

    // 8 · slot por delante del reloj
    {
        let sellado = base.clone();
        let candidata = sin_sello(&sellado);
        let reloj = sellado.cabecera.slot - 1;
        exigir_equivalencia(
            "slot por delante del reloj",
            ambos_caminos(&candidata, &sellado, reloj, reloj, Some(&params)),
        );
    }

    // 9 · padre desconocido
    {
        let mut sellado = base.clone();
        let desconocido = BlockHash::from_digest(zx_core::digest::Digest::from_bytes([0xEE; 32]));
        sellado.cabecera.padres = zx_core::PadresDag::nuevo(desconocido, &[]).expect("un padre");
        refirmar(&mut sellado.cabecera, &f.sk);
        let candidata = sin_sello(&sellado);
        exigir_equivalencia(
            "padre desconocido",
            ambos_caminos(&candidata, &sellado, u64::MAX, u64::MAX, Some(&params)),
        );
    }

    // 10 · sin contexto de pieza
    {
        let sellado = base.clone();
        let candidata = sin_sello(&sellado);
        exigir_equivalencia(
            "sin contexto de pieza",
            ambos_caminos(&candidata, &sellado, u64::MAX, u64::MAX, None),
        );
    }

    // 11 · contexto de pieza aritméticamente inválido
    {
        let sellado = base.clone();
        let candidata = sin_sello(&sellado);
        let mala = pieza_invalida();
        exigir_equivalencia(
            "contexto de pieza inválido",
            ambos_caminos(&candidata, &sellado, u64::MAX, u64::MAX, Some(&mala)),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P3 · El sello
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn p3_candidata_ya_sellada_se_rechaza_y_el_bloque_recibido_exige_sello_real() {
    let f = fondo(0);
    let base = producir_de(f);
    let params = historia().params_pieza();

    // (a) Sello válido y sello de basura: la función nueva dice «ya sellada».
    let sellada_valida = base.clone();
    let mut sellada_basura = base.clone();
    sellada_basura.cabecera.sello = [0xAA; 64];

    for (etiqueta, b) in [
        ("sello válido", &sellada_valida),
        ("sello de basura", &sellada_basura),
    ] {
        let ctx = contexto();
        let mut cache = CachePotVerificada::nueva();
        let mut pres = PresupuestoContable::nuevo(u64::MAX);
        let estado = verificar_candidata_para_firma(
            b,
            &ctx,
            &ctx,
            &ctx,
            u64::MAX,
            &mut cache,
            &mut pres,
            Some(&params),
        );
        assert_eq!(
            estado,
            EstadoCandidata::YaSellada,
            "{etiqueta}: la función nueva la rechaza como ya sellada"
        );
    }

    // (b) Bloque recibido con sello a cero y con sello de otra clave: Invalida(Sello).
    let mut sin_sello_real = base.clone();
    sin_sello_real.cabecera.sello = [0u8; 64];
    match comprobar_recibido(&sin_sello_real, u64::MAX) {
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Sello(_)) => {}
        otro => panic!("sello a cero: se esperaba Invalida(Sello), llegó {otro:?}"),
    }

    let ajena = SigningKey::from([0x77; 32]);
    let mut sello_ajeno = base.clone();
    refirmar(&mut sello_ajeno.cabecera, &ajena);
    match comprobar_recibido(&sello_ajeno, u64::MAX) {
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Sello(_)) => {}
        otro => panic!("sello de otra clave: se esperaba Invalida(Sello), llegó {otro:?}"),
    }

    // La puerta recibida con el sello correcto sí comprueba.
    match comprobar_recibido(&base, u64::MAX) {
        EstadoCabeceraConjunta::Comprobada(_) => {}
        otro => panic!("el sello correcto debía pasar, llegó {otro:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P5 · Caché y presupuesto (D5)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn p5_la_candidata_paga_aes_y_el_bloque_sellado_reutiliza_la_cache() {
    let f = fondo(0);
    let sellado = producir_de(f);
    let candidata = sin_sello(&sellado);

    let mut cache = CachePotVerificada::nueva();
    let mut pres = PresupuestoContable::nuevo(u64::MAX);
    let estado = comprobar_candidata_con(&candidata, &mut cache, &mut pres);
    assert!(
        matches!(estado, EstadoCandidata::Comprobada(_)),
        "la candidata debe Comprobarse, llegó {estado:?}"
    );
    let unidades_candidata = pres.consumidas;
    assert!(
        unidades_candidata > 0,
        "la candidata debe pagar la cadena AES (unidades={unidades_candidata})"
    );

    // El mismo bloque ya sellado, con la MISMA caché: reutiliza, no vuelve a pagar AES.
    let estado = comprobar_recibido_con(&sellado, &mut cache, &mut pres);
    assert!(
        matches!(estado, EstadoCabeceraConjunta::Comprobada(_)),
        "el sellado debe Comprobarse, llegó {estado:?}"
    );
    let unidades_totales = pres.consumidas;
    assert_eq!(
        unidades_totales, unidades_candidata,
        "el bloque sellado del mismo rango reutiliza la caché y no gasta más AES \
         (candidata={unidades_candidata}, totales={unidades_totales})"
    );

    // En frío, el bloque sellado solo paga lo mismo que pagó la candidata.
    let mut cache_fria = CachePotVerificada::nueva();
    let mut pres_frio = PresupuestoContable::nuevo(u64::MAX);
    let estado = comprobar_recibido_con(&sellado, &mut cache_fria, &mut pres_frio);
    assert!(matches!(estado, EstadoCabeceraConjunta::Comprobada(_)));
    assert_eq!(
        pres_frio.consumidas, unidades_candidata,
        "en frío el sellado paga las mismas unidades que la candidata"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// P6 · Coste (se corre aparte, --release)
// ─────────────────────────────────────────────────────────────────────────────

/// Mide el coste de comprobar la candidata y el bloque sellado. `--release`, un núcleo, 5 reps
/// tras calentar. **No es máquina en silencio** (se declara en `COSTE.md`).
#[test]
#[ignore = "coste: se corre aparte con --release"]
fn p6_coste_comprobacion_candidata_y_sellado() {
    let f = fondo(0);
    let sellado = producir_de(f);
    let candidata = sin_sello(&sellado);
    let params = historia().params_pieza();
    let ctx = contexto();

    // Calentamiento.
    for _ in 0..2 {
        let mut cache = CachePotVerificada::nueva();
        let mut pres = PresupuestoContable::nuevo(u64::MAX);
        let _ = verificar_candidata_para_firma(
            &candidata,
            &ctx,
            &ctx,
            &ctx,
            u64::MAX,
            &mut cache,
            &mut pres,
            Some(&params),
        );
    }

    let mut tiempos_candidata = Vec::new();
    let mut tiempos_sellado_caliente = Vec::new();
    let mut tiempos_sellado_frio = Vec::new();
    let mut cache = CachePotVerificada::nueva();
    let mut pres = PresupuestoContable::nuevo(u64::MAX);

    for _ in 0..5 {
        let t0 = std::time::Instant::now();
        let _ = verificar_candidata_para_firma(
            &candidata,
            &ctx,
            &ctx,
            &ctx,
            u64::MAX,
            &mut cache,
            &mut pres,
            Some(&params),
        );
        tiempos_candidata.push(t0.elapsed());

        let t1 = std::time::Instant::now();
        let _ = verificar_cabecera_conjunta(
            &sellado,
            &ctx,
            &ctx,
            &ctx,
            u64::MAX,
            &mut cache,
            &mut pres,
            Some(&params),
        );
        tiempos_sellado_caliente.push(t1.elapsed());
    }

    for _ in 0..5 {
        let mut cache_fria = CachePotVerificada::nueva();
        let mut pres_frio = PresupuestoContable::nuevo(u64::MAX);
        let t2 = std::time::Instant::now();
        let _ = verificar_cabecera_conjunta(
            &sellado,
            &ctx,
            &ctx,
            &ctx,
            u64::MAX,
            &mut cache_fria,
            &mut pres_frio,
            Some(&params),
        );
        tiempos_sellado_frio.push(t2.elapsed());
    }

    #[allow(
        clippy::integer_division,
        reason = "índice de la mediana de 5 repeticiones"
    )]
    fn mediana(v: &mut [std::time::Duration]) -> std::time::Duration {
        v.sort();
        v[v.len() / 2]
    }
    let mc = mediana(&mut tiempos_candidata);
    let msc = mediana(&mut tiempos_sellado_caliente);
    let msf = mediana(&mut tiempos_sellado_frio);
    eprintln!(
        "P6 coste (mediana de 5): candidata={mc:?}, sellado_caliente={msc:?}, sellado_frio={msf:?}"
    );
    assert!(mc > std::time::Duration::from_nanos(0));
}

// ─────────────────────────────────────────────────────────────────────────────
// Dir temporal (copiado de extremo_a_extremo.rs)
// ─────────────────────────────────────────────────────────────────────────────

struct DirTemporal {
    ruta: PathBuf,
}

impl DirTemporal {
    fn nuevo(nombre: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CONTADOR: AtomicU64 = AtomicU64::new(0);
        let n = CONTADOR.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("zx-post-{}-{}-{}", std::process::id(), nombre, n));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("crear directorio temporal");
        Self { ruta: base }
    }

    fn unir(&self, hijo: &str) -> PathBuf {
        self.ruta.join(hijo)
    }
}

impl Drop for DirTemporal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.ruta);
    }
}
