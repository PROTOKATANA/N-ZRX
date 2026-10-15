//! Extremo a extremo del **primer bloque PoST real** hijo de un terminal dev (V5) y negativos de
//! §5 (V6).
//!
//! # Qué demuestra
//!
//! 1. **V5**: génesis dev → cadena PoW dev minada con `minero_dev` hasta una altura dada → terminal
//!    `T` → historia génesis → sector ploteado con una clave dev → `productor` → cabecera de
//!    transición → puerta conjunta = `Comprobada` → `HechosPost` coherentes. Con **3 claves/semillas
//!    distintas**.
//! 2. **V6**: `pot_output` falso, portadores de otro flujo/slot, sello de otra clave o sobre otra
//!    prefirma, solución de otra clave/sector, `SR` distinto del esperado, padres extra, `slot = 0`
//!    y `slot` por delante del reloj, cada uno con su resultado.
//!
//! # Qué NO demuestra
//!
//! Admisión en el nodo, estado, UTXO, GHOSTDAG, red, historia de más de un segmento, ni seguridad
//! de los parámetros dev (`N_dev`, `SR_dev`, marcador S1). El `reloj_pot` y el presupuesto son
//! locales del test.

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
use zx_poas::HistoriaGenesis;
use zx_post::cabecera_conjunta::{
    EstadoCabeceraConjunta, HechosPost, MotivoCabeceraInvalida, MotivoCabeceraPendiente,
    verificar_cabecera_conjunta,
};
use zx_post::contexto_transicion::ContextoTransicion;
use zx_post::pot_rango::{
    CachePotVerificada, EstadoPot, MotivoPotInvalido, MotivoPotPendiente, PresupuestoPot,
};
use zx_post::productor::{
    FuenteSoluciones, ParametrosProductor, SolucionCandidata, clave_publica_de,
    producir_sin_firmante,
};

/// `N_dev` de prueba: pequeño y múltiplo de 16 (`C-POT-04`). **No** es el valor de red.
const N_DEV: u64 = 2_048;

/// `SR_dev` de prueba: `u64::MAX` para que los ganadores sean frecuentes (D-P11, valor de test).
const SR_DEV: u64 = u64::MAX;

/// `SR` declarado deliberadamente distinto del esperado (negativo de rango).
const SR_DECLARADO_MAL: u64 = SR_DEV - 1;

/// Ventana máxima de barrido: la cota de portadores del formato (`C-HDR-07`).
const MAX_SLOTS: u64 = MAX_BUNDLES_POT as u64;

/// Altura de la cadena PoW dev minada antes del terminal. Valor del fixture, no de consenso.
const ALTURA_POW: u32 = 3;

/// Índice de sector del fixture (distinto de cero para ejercitar el offset del archivo).
const INDICE_SECTOR: u16 = 3;

/// Piezas por sector del protocolo dev.
const PIEZAS: u16 = 2;

/// Historia génesis dev (D-P12), construida una sola vez.
fn historia() -> &'static HistoriaGenesis {
    static HISTORIA: OnceLock<HistoriaGenesis> = OnceLock::new();
    HISTORIA.get_or_init(|| HistoriaGenesis::construir().expect("historia génesis dev"))
}

/// Terminal `T`: génesis dev más `ALTURA_POW` bloques minados con `minero_dev`.
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

/// Clave dev de un fixture: plotea y firma con la **misma** clave Ed25519.
///
/// El `PublicKey` de la parcela son los 32 B de la clave de verificación Ed25519: así `sol.public_key`
/// (la identidad de la prueba de espacio) y la clave del sello (`C-HDR-04`) coinciden, y la coinbase
/// v3 puede pagar a la clave que firma (F-09).
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
        let dir = DirTemporal::nuevo("zx-post-e2e");
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

/// Tres fondos de fixture (3 claves/semillas distintas), ploteados una sola vez.
fn fondos() -> &'static [Fondo] {
    static FONDOS: OnceLock<Vec<Fondo>> = OnceLock::new();
    FONDOS.get_or_init(|| [0x11u8, 0x22, 0x33].into_iter().map(Fondo::nuevo).collect())
}

fn fondo(i: usize) -> &'static Fondo {
    fondos().get(i).expect("hay tres fondos de fixture")
}

/// Puente real `FuenteSoluciones → ParcelaDisco` por la ruta de `zx-farmer` (dev-dependency).
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

/// Presupuesto sin tope para el test (estado local, no un valor de consenso).
struct PresupuestoIlimitado;

impl PresupuestoPot for PresupuestoIlimitado {
    fn consumir_slot(&mut self, _slot: u64) -> bool {
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

/// Produce el bloque de transición de un fondo con la ruta real de `zx-farmer`.
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

/// Comprueba un bloque con la puerta conjunta y el contexto de transición dev.
fn comprobar(bloque: &BloqueDag, reloj: u64) -> EstadoCabeceraConjunta {
    let ctx = contexto();
    let params = historia().params_pieza();
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoIlimitado;
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

/// Rehace el sello sobre la prefirma actual con la clave indicada.
fn refirmar(cabecera: &mut DagBlockHeader, sk: &SigningKey) {
    let pre = cabecera.pre_hash();
    cabecera.sello = sk.sign(pre.as_bytes()).into();
}

/// Reconstruye el bloque con otra justificación (los portadores están fuera de la prefirma).
fn con_justificacion(bloque: &BloqueDag, bundles: Vec<PotCheckpoints>) -> BloqueDag {
    BloqueDag::nuevo(
        bloque.cabecera,
        JustificacionPot::nueva(bundles).expect("≤ 150 portadores"),
        bloque.txs().to_vec(),
        bloque.testigos().to_vec(),
    )
    .expect("bloque con la misma cabecera y cuerpo")
}

// ─────────────────────────────────────────────────────────────────────────────
// V5 · Extremo a extremo con tres claves/semillas
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v5_tres_semillas_construyen_y_comprueban_el_primer_bloque_post() {
    let t = terminal();
    for indice in 0..3 {
        let f = fondo(indice);
        let bloque = producir_de(f);

        // Forma dev del bloque de transición: un solo padre T, height 0 (F-03), slot en ventana.
        assert_eq!(bloque.cabecera.padres.count(), 1);
        assert_eq!(bloque.cabecera.padres.seleccionado(), t);
        assert!(bloque.cabecera.padres.extras().is_empty());
        assert_eq!(bloque.cabecera.height, 0, "F-03");
        assert!((1..=MAX_SLOTS).contains(&bloque.cabecera.slot));
        assert_eq!(bloque.justificacion.len() as u64, bloque.cabecera.slot);

        let estado = comprobar(&bloque, u64::MAX);
        let hechos: HechosPost = match estado {
            EstadoCabeceraConjunta::Comprobada(hechos) => hechos,
            otro => panic!("semilla {indice}: se esperaba Comprobada, llegó {otro:?}"),
        };

        let esperado = bloque.cabecera.block_hash();
        assert_eq!(hechos.hash, esperado);
        assert_eq!(hechos.padre_seleccionado, t);
        assert_eq!(hechos.slot, bloque.cabecera.slot);
        assert_eq!(hechos.productor, clave_publica_de(&f.sk));
        assert_eq!(hechos.peso, peso(SR_DEV));
        assert!(hechos.prueba_valida);
        assert_eq!(hechos.requisito_declarado, 0);

        // El cuerpo es una única coinbase v3 pagada a la clave de la solución (F-05, F-09, F-17).
        assert_eq!(bloque.txs().len(), 1);
        assert_eq!(bloque.txs()[0].version, 3);
        assert_eq!(
            bloque.txs()[0].extension,
            zx_core::ExtensionTx::CoinbasePost {
                clave: clave_publica_de(&f.sk),
                importe: Amount::nuevo(5).expect("importe"),
                slot: bloque.cabecera.slot,
            }
        );
        assert!(
            zx_dag::comprobar_compromisos_cuerpo_dag(
                &bloque.cabecera,
                bloque.txs(),
                bloque.testigos()
            )
            .is_ok(),
            "los compromisos del cuerpo deben cuadrar"
        );

        eprintln!(
            "[medición local, no consenso] V5 semilla {indice:#04x}: bloque en el slot {} con {} \
             portadores y peso {}",
            bloque.cabecera.slot,
            bloque.justificacion.len(),
            hechos.peso
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// V6 · Negativos de §5
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v6_pot_output_falso_es_invalido() {
    let f = fondo(0);
    let mut bloque = producir_de(f);
    bloque.cabecera.pot_output[0] ^= 0x01;
    refirmar(&mut bloque.cabecera, &f.sk);

    assert!(matches!(
        comprobar(&bloque, u64::MAX),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Pot(
            MotivoPotInvalido::PotOutputNoCoincide { .. }
        ))
    ));
}

#[test]
fn v6_portador_de_otro_flujo_es_invalido() {
    let f = fondo(0);
    let bloque = producir_de(f);
    // Sustituye el primer portador por uno de otra semilla: no es la cadena del flujo del bloque.
    let ajeno = zx_pot::prove(
        zx_pot::tipos::PotSeed::from([0x77u8; 16]),
        core::num::NonZeroU32::new(u32::try_from(N_DEV).expect("N cabe")).expect("N > 0"),
    )
    .expect("N múltiplo de 16");
    let mut bundles = bloque.justificacion.bundles().to_vec();
    bundles[0] = zx_post::pot::checkpoints_a_wire(&ajeno);
    let roto = con_justificacion(&bloque, bundles);

    assert!(matches!(
        comprobar(&roto, u64::MAX),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Pot(
            MotivoPotInvalido::AesFallido { slot: 1 }
        ))
    ));
}

#[test]
fn v6_sello_de_otra_clave_es_invalido() {
    let f = fondo(0);
    let mut bloque = producir_de(f);
    let ajena = SigningKey::from([0x99u8; 32]);
    // Se firma la misma prefirma con otra clave: el sello no verifica bajo `sol.public_key`.
    refirmar(&mut bloque.cabecera, &ajena);

    assert!(matches!(
        comprobar(&bloque, u64::MAX),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Sello(_))
    ));
}

#[test]
fn v6_sello_sobre_otra_prefirma_es_invalido() {
    let f = fondo(0);
    let mut bloque = producir_de(f);
    // El sello queda calculado sobre la prefirma anterior y después cambia un campo firmado.
    bloque.cabecera.timestamp = bloque.cabecera.timestamp.wrapping_add(1);

    assert!(matches!(
        comprobar(&bloque, u64::MAX),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Sello(_))
    ));
}

#[test]
fn v6_solucion_de_otra_clave_es_invalida() {
    let f = fondo(0);
    let mut bloque = producir_de(f);
    // Otra clave firma el sello; la prueba de espacio, sellada por la clave original, no verifica.
    let ajena = SigningKey::from([0x77u8; 32]);
    bloque.cabecera.sol.public_key = clave_publica_de(&ajena);
    refirmar(&mut bloque.cabecera, &ajena);

    assert!(matches!(
        comprobar(&bloque, u64::MAX),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Poas(_))
    ));
}

#[test]
fn v6_solucion_de_otro_sector_es_invalida() {
    let f = fondo(0);
    let mut bloque = producir_de(f);
    bloque.cabecera.sol.sector_index = bloque.cabecera.sol.sector_index.wrapping_add(1);
    refirmar(&mut bloque.cabecera, &f.sk);

    assert!(matches!(
        comprobar(&bloque, u64::MAX),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Poas(_))
    ));
}

#[test]
fn v6_rango_distinto_del_esperado_es_invalido() {
    let f = fondo(0);
    let mut bloque = producir_de(f);
    bloque.cabecera.rango_solucion = SR_DECLARADO_MAL;
    refirmar(&mut bloque.cabecera, &f.sk);

    assert!(matches!(
        comprobar(&bloque, u64::MAX),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Rango(
            zx_dag::ErrorDag::RangoIncorrecto {
                esperado: SR_DEV,
                encontrado: SR_DECLARADO_MAL
            }
        ))
    ));
}

#[test]
fn v6_padres_extra_es_invalida() {
    let f = fondo(0);
    let mut bloque = producir_de(f);
    let extra = BlockHash::from_digest(zx_core::Digest::from_bytes([0xEE; 32]));
    bloque.cabecera.padres =
        zx_core::PadresDag::nuevo(terminal(), &[extra]).expect("padres canónicos");
    refirmar(&mut bloque.cabecera, &f.sk);

    assert!(matches!(
        comprobar(&bloque, u64::MAX),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Padres(
            zx_dag::ErrorDag::TerminalConPadresExtra { .. }
        ))
    ));
}

#[test]
fn v6_slot_cero_es_invalido() {
    let f = fondo(0);
    let bloque = producir_de(f);

    // Ataque semántico: `slot = 0`, justificación vacía y `pot_output` anclado en S1. Sin la regla
    // TRN-08/CONTRATO §1 (`slot > s_0`), el núcleo PoT lo aceptaría sin ejecutar un solo AES:
    // `d = 0`, ancla del contexto en el slot 0 y `pot_output == S1`.
    let s1 = zx_post::pot::semilla_genesis(&terminal(), &[]);
    let mut cabecera = bloque.cabecera;
    cabecera.slot = 0;
    cabecera.pot_output = s1;
    refirmar(&mut cabecera, &f.sk);
    let ataque = BloqueDag::nuevo(
        cabecera,
        JustificacionPot::vacia(),
        bloque.txs().to_vec(),
        bloque.testigos().to_vec(),
    )
    .expect("bloque con la misma cabecera y cuerpo");
    assert!(matches!(
        comprobar(&ataque, u64::MAX),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::TransicionSinProgresoDeSlot {
            slot: 0,
            s0: 0
        })
    ));

    // Reetiquetado conservando la justificación: mismo rechazo, antes de tocar AES.
    let mut reetiquetado = bloque;
    reetiquetado.cabecera.slot = 0;
    refirmar(&mut reetiquetado.cabecera, &f.sk);
    assert!(matches!(
        comprobar(&reetiquetado, u64::MAX),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::TransicionSinProgresoDeSlot {
            slot: 0,
            s0: 0
        })
    ));
}

#[test]
fn v6_slot_por_delante_del_reloj_queda_pendiente() {
    let f = fondo(0);
    let bloque = producir_de(f);
    // El reloj PoT del nodo va por detrás del último slot del rango: se retiene, no se invalida.
    let estado = comprobar(&bloque, bloque.cabecera.slot - 1);
    assert!(matches!(
        estado,
        EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::Pot(
            MotivoPotPendiente::RelojFuturo { .. }
        ))
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// V7 · Pruebas espía heredadas (además de las del módulo y de cabecera_conjunta.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// El núcleo PoT con el contexto dev **sí** produce prueba sobre el bloque honesto (no hay ningún
/// `IntegracionPotPendiente` perpetuo en la nueva ruta).
#[test]
fn v7_el_nucleo_pot_produce_prueba_con_el_contexto_dev() {
    let f = fondo(0);
    let bloque = producir_de(f);
    let ctx = contexto();
    let mut cache = CachePotVerificada::nueva();
    let mut presupuesto = PresupuestoIlimitado;
    let estado = zx_post::pot_rango::verificar_rango_pot(
        &bloque.cabecera,
        &bloque.justificacion,
        &ctx,
        u64::MAX,
        &mut cache,
        &mut presupuesto,
    );
    assert!(
        matches!(estado, EstadoPot::PotValido(_)),
        "se esperaba PotValido, llegó {estado:?}"
    );
}

/// Directorio temporal con limpieza al soltar; se retiene dentro de los `static`.
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
