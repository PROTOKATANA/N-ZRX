//! V6 de `ORDEN-SL4b1`: productores `_con_firmante`.
//!
//! - (a) mismo slot y padres, segunda llamada → `Reemitido` y bloque idéntico byte a byte;
//! - (b) mismos billete y slot con otro cuerpo → `Abstenido` por conflicto, sin bloque;
//! - (c) el bloque de (a) pasa la puerta conjunta de `zx-post` igual que el de la función antigua
//!   con los mismos datos.
//!
//! El fixture es real, portado de `crates/zx-post/tests/regimen.rs`: `ServicioPot` real, GHOSTDAG
//! real y `FuenteSoluciones` sobre `zx_farmer::ParcelaDisco` (auditoría PoAS + KZG). No se usa
//! `regimen.rs` ni se modifica.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "instrumento de test: un fallo del fixture o del veredicto debe producir panic"
)]

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;

use ed25519_zebra::{SigningKey, VerificationKey};
use subspace_core_primitives::PublicKey;

use zx_consensus::{
    GENESIS_DEV, PARAMETROS_POW_DEV, Sha3Dev, construir as construir_genesis, minar,
};
use zx_core::digest::Digest;
use zx_core::preimage::block::BlockHeader;
use zx_core::wire_dag::{BloqueDag, MAX_BUNDLES_POT};
use zx_core::{
    Amount, BlockHash, ExtensionTx, Lock, OutPoint, PadresDag, Tx, TxId, TxIn, TxOut,
    bloque_dag_a_bytes, decodificar_con,
};
use zx_dag::{
    Algoritmo, AlmacenGhostdag, CandidatoSinRango, ContextoRangoDag, ErrorDag, Parametros,
    RangoSolucionValidado, peso,
};
use zx_farmer::farmer::{ParcelaDisco, plotear_sector_en_disco};
use zx_farmer::productor_poas::convertir_candidatos_locales;
use zx_poas::HistoriaGenesis;

use zx_post::cabecera_conjunta::{EstadoCabeceraConjunta, verificar_cabecera_conjunta};
use zx_post::firmante::{Firmante, Registro, Resultado as ResultadoFirmante};
use zx_post::pot_rango::{CachePotVerificada, PresupuestoPot};
use zx_post::productor::{
    FuenteSoluciones, MotivoAbstencion, ParametrosProductor, ProductoFirmado, SolucionCandidata,
    clave_publica_de,
};
use zx_post::productor_regimen::{
    CuerpoProductor, producir_en_regimen_con_firmante, producir_en_regimen_sin_firmante,
};
use zx_post::servicio_pot::ServicioPot;

/// `N_dev` de prueba: pequeño y múltiplo de 16 (`C-POT-04`).
const N_DEV: u64 = 2_048;

/// `SR_dev` de prueba: `u64::MAX` para que los ganadores sean frecuentes.
const SR_DEV: u64 = u64::MAX;

/// Ventana del servicio, mayor que el hueco máximo de 150 slots.
const VENTANA: u64 = 300;

/// Cota de búsqueda y de rango: `MAX_BUNDLES_POT`.
const MAX: u64 = MAX_BUNDLES_POT as u64;

/// Altura de la cadena PoW dev minada antes del terminal.
const ALTURA_POW: u32 = 3;

/// Índice de sector del fixture.
const INDICE_SECTOR: u16 = 3;

/// Piezas por sector del protocolo dev.
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
        let dir = DirTemporal::nuevo("zx-post-sl4b1");
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

    fn parcela(&self) -> ParcelaDisco {
        ParcelaDisco::abrir(&self.ruta, &self.public_key).expect("la parcela debe abrir")
    }
}

fn fondos() -> &'static [Fondo] {
    static FONDOS: OnceLock<Vec<Fondo>> = OnceLock::new();
    FONDOS.get_or_init(|| [0x11u8, 0x22].into_iter().map(Fondo::nuevo).collect())
}

fn fondo(i: usize) -> &'static Fondo {
    fondos().get(i % 2).expect("hay dos fondos de fixture")
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

struct PresupuestoIlimitado;

impl PresupuestoPot for PresupuestoIlimitado {
    fn consumir_slot(&mut self, _slot: u64) -> bool {
        true
    }
}

struct RangoDev;

impl ContextoRangoDag for RangoDev {
    fn rango_esperado(&self, _candidato: &CandidatoSinRango<'_>) -> Result<u64, ErrorDag> {
        Ok(SR_DEV)
    }
}

struct Cadena {
    almacen: AlmacenGhostdag,
    servicio: ServicioPot,
}

impl Cadena {
    fn nueva() -> Self {
        let t = terminal();
        let servicio = ServicioPot::nuevo(t, N_DEV, VENTANA).expect("servicio PoT dev");
        let almacen = AlmacenGhostdag::con_raiz_terminal(
            Parametros::default(),
            Algoritmo::Kernel,
            t,
            RangoSolucionValidado::para_oraculos(SR_DEV),
        );
        Self { almacen, servicio }
    }

    fn parametros(&self) -> ParametrosProductor {
        ParametrosProductor {
            n_dev: N_DEV,
            sr_dev: SR_DEV,
            max_slots: MAX,
            consensus_branch_id: zx_core::CBID_RED_DEV,
            timestamp: 1_788_480_000,
            i_iter: 0,
            importe_coinbase: Amount::nuevo(5).expect("importe de coinbase > 0"),
        }
    }

    fn comprobar(&self, bloque: &BloqueDag) -> EstadoCabeceraConjunta {
        let params = historia().params_pieza();
        let mut cache = CachePotVerificada::nueva();
        let mut presupuesto = PresupuestoIlimitado;
        verificar_cabecera_conjunta(
            bloque,
            &self.servicio,
            &self.almacen,
            &RangoDev,
            u64::MAX,
            &mut cache,
            &mut presupuesto,
            Some(&params),
        )
    }
}

/// Primer slot `s ∈ (desde, desde + max]` con solución PoAS para `f`; avanza el servicio hasta él.
fn primer_slot_con_solucion(c: &mut Cadena, f: &Fondo, desde: u64, max: u64) -> u64 {
    let parcela = f.parcela();
    let fuente = FuenteParcela {
        parcela: &parcela,
        historia: historia(),
    };
    for slot in (desde + 1)..=(desde + max) {
        if c.servicio.slot_actual() < slot {
            c.servicio.avanzar_hasta(slot).expect("avance del servicio");
        }
        let salida = c.servicio.salida_de(slot).expect("salida retenida");
        if !fuente
            .soluciones(salida, slot, SR_DEV)
            .expect("auditoría")
            .is_empty()
        {
            return slot;
        }
    }
    panic!("sin solución para el fondo en ({desde}, {}]", desde + max);
}

/// Transacción de efecto v1 (con una entrada) para el cuerpo del productor.
fn tx_de_efecto(semilla: u8, valor: i64) -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            outpoint: OutPoint {
                prev_txid: TxId::from_digest(Digest::from_bytes([semilla; 32])),
                prev_index: 0,
            },
            sequence: 0,
        }],
        outputs: vec![TxOut {
            value: Amount::nuevo(valor).expect("valor > 0"),
            lock: Lock::PubKey {
                pubkey: zx_core::ClavePublica::desde_bytes([semilla; 32]),
            },
        }],
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    }
}

/// Serializa un bloque DAG a sus bytes canónicos de wire.
fn bytes_de(bloque: &BloqueDag) -> Vec<u8> {
    let mut salida = Vec::new();
    bloque_dag_a_bytes(&mut salida, bloque);
    salida
}

/// Producir un candidato por cada ruta y devolver (antiguo, `_con_firmante`).
fn producir_par(
    c: &mut Cadena,
    f: &Fondo,
    slot: u64,
    dir: &DirTemporal,
) -> (BloqueDag, BloqueDag, ResultadoFirmante) {
    let parcela = f.parcela();
    let fuente = FuenteParcela {
        parcela: &parcela,
        historia: historia(),
    };
    let padres = PadresDag::nuevo(terminal(), &[]).expect("un padre");
    let parametros = c.parametros();

    let antiguo = producir_en_regimen_sin_firmante(
        padres,
        slot,
        &mut c.servicio,
        &fuente,
        &f.sk,
        &parametros,
        CuerpoProductor::vacio(),
    )
    .expect("productor antiguo");

    let registro = Registro::nueva(dir.unir("firmante.log")).expect("registro limpio");
    let mut firmante = Firmante::nuevo(&registro);
    let producto = producir_en_regimen_con_firmante(
        padres,
        slot,
        &mut c.servicio,
        &fuente,
        &f.sk,
        &parametros,
        CuerpoProductor::vacio(),
        &mut firmante,
    )
    .expect("productor con firmante");
    let (nuevo, resultado) = match producto {
        ProductoFirmado::Bloque(bloque, resultado) => (bloque, resultado),
        ProductoFirmado::Abstenido { motivo, .. } => panic!("no debía abstenerse: {motivo:?}"),
    };
    (antiguo, nuevo, resultado)
}

/// V6(a)+V6(c): el bloque de `_con_firmante` es idéntico al antiguo, la segunda llamada reemite, y
/// ambos pasan la puerta conjunta.
#[test]
fn v6a_v6c_bloque_identico_reemision_y_puerta_conjunta() {
    let dir = DirTemporal::nuevo("v6a");
    let f = fondo(0);
    let mut c = Cadena::nueva();
    let slot = primer_slot_con_solucion(&mut c, f, 0, MAX);

    let (antiguo, nuevo, resultado) = producir_par(&mut c, f, slot, &dir);
    assert_eq!(resultado, ResultadoFirmante::Sellado);
    assert_eq!(
        bytes_de(&antiguo),
        bytes_de(&nuevo),
        "mismos datos ⇒ bloque idéntico byte a byte"
    );
    assert_eq!(nuevo.cabecera.slot, slot);

    // La puerta conjunta acepta los dos con el mismo veredicto y los mismos hechos.
    let hechos_antiguo = match c.comprobar(&antiguo) {
        EstadoCabeceraConjunta::Comprobada(h) => h,
        otro => panic!("bloque antiguo: se esperaba Comprobada, llegó {otro:?}"),
    };
    let hechos_nuevo = match c.comprobar(&nuevo) {
        EstadoCabeceraConjunta::Comprobada(h) => h,
        otro => panic!("bloque con firmante: se esperaba Comprobada, llegó {otro:?}"),
    };
    assert_eq!(hechos_antiguo, hechos_nuevo);
    assert_eq!(hechos_nuevo.hash, nuevo.cabecera.block_hash());
    assert_eq!(hechos_nuevo.padre_seleccionado, terminal());
    assert_eq!(hechos_nuevo.slot, slot);
    assert_eq!(hechos_nuevo.productor, clave_publica_de(&f.sk));
    assert_eq!(hechos_nuevo.peso, peso(SR_DEV));
    assert!(hechos_nuevo.prueba_valida);
    assert_eq!(hechos_nuevo.requisito_declarado, 0);

    // Segunda llamada con el mismo firmante y los mismos datos: `Reemitido` y bloque idéntico.
    let parcela = f.parcela();
    let fuente = FuenteParcela {
        parcela: &parcela,
        historia: historia(),
    };
    let registro = Registro::nueva(dir.unir("firmante2.log")).expect("registro limpio");
    let mut firmante = Firmante::nuevo(&registro);
    let parametros = c.parametros();
    let padres = PadresDag::nuevo(terminal(), &[]).expect("un padre");
    let primera = producir_en_regimen_con_firmante(
        padres,
        slot,
        &mut c.servicio,
        &fuente,
        &f.sk,
        &parametros,
        CuerpoProductor::vacio(),
        &mut firmante,
    )
    .expect("primera");
    let bloque_1 = match primera {
        ProductoFirmado::Bloque(b, ResultadoFirmante::Sellado) => b,
        otro => panic!("se esperaba Bloque/Sellado, llegó {otro:?}"),
    };
    let segunda = producir_en_regimen_con_firmante(
        padres,
        slot,
        &mut c.servicio,
        &fuente,
        &f.sk,
        &parametros,
        CuerpoProductor::vacio(),
        &mut firmante,
    )
    .expect("segunda");
    let bloque_2 = match segunda {
        ProductoFirmado::Bloque(b, ResultadoFirmante::Reemitido) => b,
        otro => panic!("se esperaba Bloque/Reemitido, llegó {otro:?}"),
    };
    assert_eq!(bytes_de(&bloque_1), bytes_de(&bloque_2));
    assert_eq!(registro.entradas(), 1, "la reemisión no añade entradas");
}

/// V6(b): mismos billete y slot con otro cuerpo ⇒ `Abstenido` por conflicto.
#[test]
fn v6b_otro_cuerpo_mismo_billete_y_slot_se_abstiene() {
    let dir = DirTemporal::nuevo("v6b");
    let f = fondo(0);
    let mut c = Cadena::nueva();
    let slot = primer_slot_con_solucion(&mut c, f, 0, MAX);

    let parcela = f.parcela();
    let fuente = FuenteParcela {
        parcela: &parcela,
        historia: historia(),
    };
    let parametros = c.parametros();
    let padres = PadresDag::nuevo(terminal(), &[]).expect("un padre");
    let registro = Registro::nueva(dir.unir("firmante.log")).expect("registro limpio");
    let mut firmante = Firmante::nuevo(&registro);

    let primera = producir_en_regimen_con_firmante(
        padres,
        slot,
        &mut c.servicio,
        &fuente,
        &f.sk,
        &parametros,
        CuerpoProductor::vacio(),
        &mut firmante,
    )
    .expect("primera");
    assert!(matches!(
        primera,
        ProductoFirmado::Bloque(_, ResultadoFirmante::Sellado)
    ));

    let cuerpo = CuerpoProductor::nuevo(vec![tx_de_efecto(0x51, 7)], vec![Vec::new()])
        .expect("cuerpo con una tx");
    let segunda = producir_en_regimen_con_firmante(
        padres,
        slot,
        &mut c.servicio,
        &fuente,
        &f.sk,
        &parametros,
        cuerpo,
        &mut firmante,
    )
    .expect("segunda");
    match segunda {
        ProductoFirmado::Abstenido {
            motivo: MotivoAbstencion::Conflicto { .. },
            ..
        } => {}
        otro => panic!("se esperaba abstención por conflicto, llegó {otro:?}"),
    }
    assert_eq!(
        registro.entradas(),
        1,
        "la abstención no reserva oportunidad"
    );
}

/// El productor `_con_firmante` no cambia el comportamiento del primer bloque PoST: mismo bloque y
/// sellado con la misma clave.
#[test]
fn v6_primer_bloque_con_firmante_es_identico() {
    use zx_post::productor::{producir_con_firmante, producir_sin_firmante};

    let dir = DirTemporal::nuevo("v6-primer");
    let f = fondo(0);
    let parcela = f.parcela();
    let fuente = FuenteParcela {
        parcela: &parcela,
        historia: historia(),
    };
    let parametros = ParametrosProductor {
        n_dev: N_DEV,
        sr_dev: SR_DEV,
        max_slots: MAX,
        consensus_branch_id: zx_core::CBID_RED_DEV,
        timestamp: 1_788_480_000,
        i_iter: 0,
        importe_coinbase: Amount::nuevo(5).expect("importe"),
    };

    let antiguo = producir_sin_firmante(terminal(), &fuente, &f.sk, &parametros).expect("antiguo");
    let registro = Registro::nueva(dir.unir("firmante.log")).expect("registro limpio");
    let mut firmante = Firmante::nuevo(&registro);
    let producto = producir_con_firmante(terminal(), &fuente, &f.sk, &parametros, &mut firmante)
        .expect("nuevo");
    let nuevo = match producto {
        ProductoFirmado::Bloque(b, ResultadoFirmante::Sellado) => b,
        otro => panic!("se esperaba Bloque/Sellado, llegó {otro:?}"),
    };
    assert_eq!(bytes_de(&antiguo), bytes_de(&nuevo));
}

struct DirTemporal {
    ruta: PathBuf,
}

impl DirTemporal {
    fn nuevo(nombre: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CONTADOR: AtomicU64 = AtomicU64::new(0);
        let n = CONTADOR.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "zx-post-sl4b1-{}-{}-{}",
            std::process::id(),
            nombre,
            n
        ));
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
