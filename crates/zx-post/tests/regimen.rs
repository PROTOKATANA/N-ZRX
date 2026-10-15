//! W05b3 · V4 (escenarios positivos en régimen), V5 (negativos) y V6 (extremo a extremo con
//! `N_dev` real) del productor PoST en régimen y del `ServicioPot`.
//!
//! # Contextos reales, no mocks
//!
//! - `ContextoDag` es un [`AlmacenGhostdag`] de verdad: cada bloque producido se admite con
//!   [`AlmacenGhostdag::admitir`] (GHOSTDAG sobre los bloques reales) antes de ser padre.
//! - `InstantaneaPot` es el [`ServicioPot`] real: la cadena PoT se calcula slot a slot con
//!   `zx_pot::prove` y la justificación se arma con los portadores retenidos.
//! - `FuenteSoluciones` es el puente real a `zx_farmer::ParcelaDisco` (auditoría PoAS + KZG).
//!
//! El único contexto constante es `SR_dev` (D-P11: no hay controlador de rango); no hay ningún
//! contexto que devuelva «válido».
//!
//! # Por qué los tests buscan el slot
//!
//! El productor en régimen produce en el **slot objetivo exacto**. Con `SR_dev` de test una clave
//! no tiene solución en todos los slots (la densidad observada en W05b2 es ~2/3), así que los
//! tests **buscan** el primer slot con solución (o el primer slot común a dos claves para los
//! hermanos) avanzando el `ServicioPot`. No es un mock: la solución que se usa es la que verifica
//! la puerta.
//!
//! # Qué NO demuestra
//!
//! Admisión en el nodo, estado/UTXO, red, más de un segmento de historia, ni seguridad de los
//! parámetros dev (`N_dev`, `SR_dev`, marcador S1). El reloj PoT y el presupuesto son locales.

#![expect(
    clippy::expect_used,
    clippy::panic,
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
use zx_core::digest::{BodyCommitment, Digest, MerkleRoot};
use zx_core::preimage::block::BlockHeader;
use zx_core::wire_dag::{BloqueDag, JustificacionPot, MAX_BUNDLES_POT, PotCheckpoints};
use zx_core::{
    Amount, BlockHash, DagBlockHeader, EncodingError, ExtensionTx, Lock, OutPoint, PadresDag,
    SolucionPoas, Tx, TxId, TxIn, TxOut, dag_header_desde_bytes, decodificar_con,
};
use zx_dag::bloque_dag::ContextoDag;
use zx_dag::{
    Algoritmo, AlmacenGhostdag, CandidatoSinRango, ContextoRangoDag, ErrorDag, Parametros,
    RangoSolucionValidado, peso,
};
use zx_farmer::farmer::{ParcelaDisco, plotear_sector_en_disco};
use zx_farmer::productor_poas::convertir_candidatos_locales;
use zx_poas::HistoriaGenesis;
use zx_poas::verificar_solucion_poas;
use zx_post::cabecera_conjunta::{
    EstadoCabeceraConjunta, HechosPost, MotivoCabeceraInvalida, MotivoCabeceraPendiente,
    verificar_cabecera_conjunta,
};
use zx_post::pot_rango::{CachePotVerificada, MotivoPotInvalido, PresupuestoPot};
use zx_post::productor::{
    FuenteSoluciones, ParametrosProductor, SolucionCandidata, clave_publica_de,
};
use zx_post::productor_regimen::{CuerpoProductor, ErrorRegimen, producir_en_regimen_sin_firmante};
use zx_post::servicio_pot::ServicioPot;

/// `N_dev` de prueba: pequeño y múltiplo de 16 (`C-POT-04`). **No** es el valor de red.
const N_DEV: u64 = 2_048;

/// `N_dev` **real** del perfil dev (W05b2): el que da ≈ 1 s por slot en la máquina de referencia.
const N_DEV_REAL: u64 = 138_873_760;

/// `SR_dev` de prueba: `u64::MAX` para que los ganadores sean frecuentes (D-P11, valor de test).
const SR_DEV: u64 = u64::MAX;

/// Ventana del servicio, mayor que el hueco máximo de 150 slots.
const VENTANA: u64 = 300;

/// Cota de búsqueda y de rango: `MAX_BUNDLES_POT`.
const MAX: u64 = MAX_BUNDLES_POT as u64;

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
        let dir = DirTemporal::nuevo("zx-post-regimen");
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

    /// Abre la parcela de este fondo (lectura; sin lock de escritor).
    fn parcela(&self) -> ParcelaDisco {
        ParcelaDisco::abrir(&self.ruta, &self.public_key).expect("la parcela debe abrir")
    }
}

/// Tres fondos de fixture (3 claves/semillas distintas), ploteados una sola vez.
fn fondos() -> &'static [Fondo] {
    static FONDOS: OnceLock<Vec<Fondo>> = OnceLock::new();
    FONDOS.get_or_init(|| [0x11u8, 0x22, 0x33].into_iter().map(Fondo::nuevo).collect())
}

fn fondo(i: usize) -> &'static Fondo {
    fondos().get(i % 3).expect("hay tres fondos de fixture")
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

/// `ContextoRangoDag` dev: la constante `SR_dev` de D-P11 (no existe controlador).
struct RangoDev;

impl ContextoRangoDag for RangoDev {
    fn rango_esperado(&self, _candidato: &CandidatoSinRango<'_>) -> Result<u64, ErrorDag> {
        Ok(SR_DEV)
    }
}

/// Tipo del error del productor con la fuente real de `zx-farmer`.
type ErrReg = ErrorRegimen<zx_farmer::ErrorProductorPoas>;

/// DAG de prueba con GHOSTDAG real y servicio PoT real.
struct Cadena {
    almacen: AlmacenGhostdag,
    servicio: ServicioPot,
    n_dev: u64,
}

impl Cadena {
    fn nueva(n_dev: u64) -> Self {
        let t = terminal();
        let servicio = ServicioPot::nuevo(t, n_dev, VENTANA).expect("servicio PoT dev");
        let almacen = AlmacenGhostdag::con_raiz_terminal(
            Parametros::default(),
            Algoritmo::Kernel,
            t,
            RangoSolucionValidado::para_oraculos(SR_DEV),
        );
        Self {
            almacen,
            servicio,
            n_dev,
        }
    }

    fn parametros(&self) -> ParametrosProductor {
        ParametrosProductor {
            n_dev: self.n_dev,
            sr_dev: SR_DEV,
            max_slots: MAX,
            consensus_branch_id: zx_core::CBID_RED_DEV,
            timestamp: 1_788_480_000,
            i_iter: 0,
            importe_coinbase: Amount::nuevo(5).expect("importe de coinbase > 0"),
        }
    }

    /// `sp(B)` de C-GD-03 que calcula el almacén real sobre el conjunto de padres.
    fn sp_de(&self, padres: &PadresDag) -> BlockHash {
        ContextoDag::padre_seleccionado(&self.almacen, padres).expect("sp del almacén")
    }

    /// `slot` del padre seleccionado, según el pasado registrado del servicio.
    fn sp_slot(&self, padres: &PadresDag) -> u64 {
        self.servicio
            .slot_de(&padres.seleccionado())
            .expect("el sp está registrado")
    }

    /// Construye un `PadresDag` canónico con `sp` = el que da GHOSTDAG sobre `{a} ∪ extras`.
    fn padres_hacia(&self, a: BlockHash, extras: &[BlockHash]) -> PadresDag {
        let provisional = PadresDag::nuevo(a, extras).expect("padres provisionales");
        let sp = self.sp_de(&provisional);
        let mut otros = Vec::with_capacity(extras.len() + 1);
        otros.push(a);
        otros.extend_from_slice(extras);
        otros.retain(|h| *h != sp);
        PadresDag::nuevo(sp, &otros).expect("padres canónicos")
    }

    fn producir_intento(
        &mut self,
        f: &Fondo,
        padres: PadresDag,
        slot: u64,
    ) -> Result<BloqueDag, ErrReg> {
        let parcela = f.parcela();
        let fuente = FuenteParcela {
            parcela: &parcela,
            historia: historia(),
        };
        let parametros = self.parametros();
        producir_en_regimen_sin_firmante(
            padres,
            slot,
            &mut self.servicio,
            &fuente,
            &f.sk,
            &parametros,
            CuerpoProductor::vacio(),
        )
    }

    /// Produce con un cuerpo no vacío (transacciones sin coinbase).
    fn producir_intento_con_cuerpo(
        &mut self,
        f: &Fondo,
        padres: PadresDag,
        slot: u64,
        cuerpo: CuerpoProductor,
    ) -> Result<BloqueDag, ErrReg> {
        let parcela = f.parcela();
        let fuente = FuenteParcela {
            parcela: &parcela,
            historia: historia(),
        };
        let parametros = self.parametros();
        producir_en_regimen_sin_firmante(
            padres,
            slot,
            &mut self.servicio,
            &fuente,
            &f.sk,
            &parametros,
            cuerpo,
        )
    }

    fn producir(&mut self, f: &Fondo, padres: PadresDag, slot: u64) -> BloqueDag {
        self.producir_intento(f, padres, slot)
            .expect("el productor en régimen debe producir")
    }

    /// Admite el bloque en el GHOSTDAG real y lo registra en el pasado del servicio PoT.
    fn admitir(&mut self, bloque: &BloqueDag) {
        let distancia = verificar_solucion_poas(
            &bloque.cabecera.sol,
            bloque.cabecera.slot,
            bloque.cabecera.pot_output,
            SR_DEV,
            &historia().params_pieza(),
        )
        .expect("el PoAS del bloque producido verifica");
        self.almacen
            .admitir(&bloque.cabecera, distancia, &RangoDev)
            .expect("GHOSTDAG debe admitir el bloque");
        self.servicio
            .registrar_validado(bloque.cabecera.block_hash(), bloque.cabecera.slot)
            .expect("el servicio debe registrar el bloque");
    }

    fn producir_y_admitir(&mut self, f: &Fondo, padres: PadresDag, slot: u64) -> BloqueDag {
        let bloque = self.producir(f, padres, slot);
        self.admitir(&bloque);
        bloque
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

/// Primer slot `s ∈ (desde, desde + max]` con solución para **todas** las parcelas.
fn primer_slot_comun(c: &mut Cadena, parcelas: &[&ParcelaDisco], desde: u64, max: u64) -> u64 {
    for slot in (desde + 1)..=(desde + max) {
        if c.servicio.slot_actual() < slot {
            c.servicio.avanzar_hasta(slot).expect("avance del servicio");
        }
        let salida = c.servicio.salida_de(slot).expect("salida retenida");
        let mut todos = true;
        for &parcela in parcelas {
            let fuente = FuenteParcela {
                parcela,
                historia: historia(),
            };
            if fuente
                .soluciones(salida, slot, SR_DEV)
                .expect("auditoría")
                .is_empty()
            {
                todos = false;
                break;
            }
        }
        if todos {
            return slot;
        }
    }
    panic!("sin slot común en ({desde}, {}]", desde + max);
}

/// Busca el primer slot con solución para `f` tras `slot_padre`, produce y admite.
fn producir_buscando(c: &mut Cadena, f: &Fondo, padre: BlockHash, slot_padre: u64) -> BloqueDag {
    let slot = primer_slot_con_solucion(c, f, slot_padre, MAX);
    c.producir_y_admitir(f, PadresDag::nuevo(padre, &[]).expect("un padre"), slot)
}

/// Produce un bloque con **hueco exacto de 150** respecto de un padre, buscando un padre y una
/// clave que tengan solución en `slot_padre + 150`.
fn producir_hueco_150(c: &mut Cadena) -> BloqueDag {
    let mut padre = terminal();
    let mut slot_padre = 0;
    for _ in 0..6 {
        let candidato = producir_buscando(c, fondo(0), padre, slot_padre);
        let slot_candidato = candidato.cabecera.slot;
        let objetivo = slot_candidato + MAX;
        if c.servicio.slot_actual() < objetivo {
            c.servicio
                .avanzar_hasta(objetivo)
                .expect("avance del servicio");
        }
        let salida = c.servicio.salida_de(objetivo).expect("salida retenida");
        for f in fondos() {
            let parcela = f.parcela();
            let fuente = FuenteParcela {
                parcela: &parcela,
                historia: historia(),
            };
            if !fuente
                .soluciones(salida, objetivo, SR_DEV)
                .expect("auditoría")
                .is_empty()
            {
                let bloque = c.producir_y_admitir(
                    f,
                    PadresDag::nuevo(candidato.cabecera.block_hash(), &[]).expect("un padre"),
                    objetivo,
                );
                assert_eq!(bloque.justificacion.len() as u64, MAX, "hueco de 150");
                return bloque;
            }
        }
        padre = candidato.cabecera.block_hash();
        slot_padre = slot_candidato;
    }
    panic!("no se encontró un hueco de 150 con solución");
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

fn hash_de(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

// ─────────────────────────────────────────────────────────────────────────────
// V4 · Escenarios positivos
// ─────────────────────────────────────────────────────────────────────────────

/// V4.1 · Cadena de 8 bloques tras el terminal.
#[test]
fn v4_cadena_de_ocho_bloques_en_regimen() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let mut padre = t;
    let mut slot_padre = 0;
    for i in 0..8usize {
        let f = fondo(i);
        let bloque = producir_buscando(&mut c, f, padre, slot_padre);
        let slot = bloque.cabecera.slot;

        assert!(slot > slot_padre && slot - slot_padre <= MAX);
        assert_eq!(bloque.cabecera.height, 0, "F-03");
        assert_eq!(bloque.cabecera.padres.seleccionado(), padre);
        assert_eq!(bloque.cabecera.padres.count(), 1);
        assert_eq!(bloque.cabecera.rango_solucion, SR_DEV);
        assert_eq!(bloque.justificacion.len() as u64, slot - slot_padre);

        let hechos = match c.comprobar(&bloque) {
            EstadoCabeceraConjunta::Comprobada(h) => h,
            otro => panic!("bloque {i}: se esperaba Comprobada, llegó {otro:?}"),
        };
        assert_eq!(hechos.hash, bloque.cabecera.block_hash());
        assert_eq!(hechos.padre_seleccionado, padre);
        assert_eq!(hechos.slot, slot);
        assert_eq!(hechos.productor, clave_publica_de(&f.sk));
        assert_eq!(hechos.peso, peso(SR_DEV));
        assert!(hechos.prueba_valida);
        assert_eq!(hechos.requisito_declarado, 0);
        padre = bloque.cabecera.block_hash();
        slot_padre = slot;
    }
}

/// V4.2 · Dos hermanos del mismo slot de dos claves y su fusión.
#[test]
fn v4_hermanos_del_mismo_slot_y_fusion() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let p0 = fondo(0).parcela();
    let p1 = fondo(1).parcela();
    let slot_hermanos = primer_slot_comun(&mut c, &[&p0, &p1], 0, MAX);
    drop(p0);
    drop(p1);

    let a = c.producir_y_admitir(
        fondo(0),
        PadresDag::nuevo(t, &[]).expect("padre"),
        slot_hermanos,
    );
    let b = c.producir_y_admitir(
        fondo(1),
        PadresDag::nuevo(t, &[]).expect("padre"),
        slot_hermanos,
    );

    assert_eq!(a.cabecera.slot, b.cabecera.slot, "hermanos del mismo slot");
    assert_ne!(a.cabecera.block_hash(), b.cabecera.block_hash());
    assert_eq!(
        a.cabecera.pot_output, b.cabecera.pot_output,
        "un solo flujo: mismo slot, misma salida"
    );
    for (etiqueta, bloque) in [("A", &a), ("B", &b)] {
        assert!(
            matches!(c.comprobar(bloque), EstadoCabeceraConjunta::Comprobada(_)),
            "el hermano {etiqueta} debe ser Comprobada"
        );
    }

    let padres = c.padres_hacia(a.cabecera.block_hash(), &[b.cabecera.block_hash()]);
    assert_eq!(padres.count(), 2);
    let slot_fusion = primer_slot_con_solucion(&mut c, fondo(2), slot_hermanos, MAX);
    let fusion = c.producir_y_admitir(fondo(2), padres, slot_fusion);
    let hechos = match c.comprobar(&fusion) {
        EstadoCabeceraConjunta::Comprobada(h) => h,
        otro => panic!("la fusión debe ser Comprobada, llegó {otro:?}"),
    };
    assert_eq!(hechos.padre_seleccionado, padres.seleccionado());
    assert_eq!(hechos.slot, slot_fusion);
    assert_eq!(fusion.cabecera.padres.count(), 2);
    assert_eq!(
        fusion.justificacion.len() as u64,
        slot_fusion - c.sp_slot(&padres)
    );
}

/// W08c · V4.6: un bloque puede tener el **mismo slot** que su padre seleccionado (no terminal),
/// con `d = 0` y justificación vacía. `C-HDR-05`/`C-FLU-02` fijan la cota de slot **no estricta**
/// (`slot(p) ≤ slot(B)`) y `pot_rango` verifica `d = 0` anclando en la salida del mismo slot. Antes
/// de W08c el productor exigía `slot(B) > slot(sp)` siempre y descartaba estos bloques con
/// `SlotNoProgreso`, aunque el verificador sí los acepta.
#[test]
fn v4_mismo_slot_que_el_padre_no_terminal_es_valido() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let p0 = fondo(0).parcela();
    let p1 = fondo(1).parcela();
    let slot = primer_slot_comun(&mut c, &[&p0, &p1], 0, MAX);
    drop(p0);
    drop(p1);

    // `a`: primer bloque de régimen, con el terminal como padre (progreso estricto).
    let a = c.producir_y_admitir(fondo(0), PadresDag::nuevo(t, &[]).expect("padre"), slot);
    // `b`: **mismo slot** que `a` y con `a` (no terminal) como padre seleccionado ⇒ `d = 0`.
    let b = c
        .producir_intento(
            fondo(1),
            PadresDag::nuevo(a.cabecera.block_hash(), &[]).expect("un padre"),
            slot,
        )
        .expect("W08c: d = 0 con un padre no terminal debe producirse");
    assert_eq!(b.cabecera.slot, slot);
    assert_eq!(b.justificacion.len(), 0, "d = 0 ⇒ justificación vacía");
    c.admitir(&b);
    assert!(
        matches!(c.comprobar(&b), EstadoCabeceraConjunta::Comprobada(_)),
        "la puerta conjunta acepta el bloque con d = 0"
    );
}

/// V4.3 · Fusión de tres ramas (tres cadenas de dos bloques).
#[test]
fn v4_fusion_de_tres_ramas() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);

    let a1 = producir_buscando(&mut c, fondo(0), t, 0);
    let a2 = producir_buscando(&mut c, fondo(0), a1.cabecera.block_hash(), a1.cabecera.slot);
    let b1 = producir_buscando(&mut c, fondo(1), t, 0);
    let b2 = producir_buscando(&mut c, fondo(1), b1.cabecera.block_hash(), b1.cabecera.slot);
    let c1 = producir_buscando(&mut c, fondo(2), t, 0);
    let c2 = producir_buscando(&mut c, fondo(2), c1.cabecera.block_hash(), c1.cabecera.slot);

    let desde = a2.cabecera.slot.max(b2.cabecera.slot).max(c2.cabecera.slot);
    let padres = c.padres_hacia(
        a2.cabecera.block_hash(),
        &[b2.cabecera.block_hash(), c2.cabecera.block_hash()],
    );
    assert_eq!(padres.count(), 3, "tres ramas fusionadas");
    // El rango se mide desde `sp(B)`, no desde el máximo padre: se acota la búsqueda a
    // `(desde, slot(sp) + 150]` para no exceder `MAX_BUNDLES_POT`.
    let sp_slot = c.sp_slot(&padres);
    let margen = (sp_slot + MAX).saturating_sub(desde);
    assert!(margen > 0, "los tips caben en el rango de sp(B)");
    let slot_fusion = primer_slot_con_solucion(&mut c, fondo(2), desde, margen);
    let fusion = c.producir_y_admitir(fondo(2), padres, slot_fusion);

    let hechos = match c.comprobar(&fusion) {
        EstadoCabeceraConjunta::Comprobada(h) => h,
        otro => panic!("la fusión de 3 ramas debe ser Comprobada, llegó {otro:?}"),
    };
    assert_eq!(hechos.padre_seleccionado, padres.seleccionado());
    assert_eq!(fusion.cabecera.padres.count(), 3);
    assert_eq!(
        fusion.justificacion.len() as u64,
        slot_fusion - c.sp_slot(&padres)
    );
}

/// V4.4 · Hueco de 150 slots entre el padre seleccionado y el bloque.
#[test]
fn v4_hueco_de_150_slots() {
    let mut c = Cadena::nueva(N_DEV);
    let bloque = producir_hueco_150(&mut c);
    assert_eq!(
        bloque.cabecera.slot,
        c.sp_slot(&bloque.cabecera.padres) + MAX
    );
    assert!(
        matches!(c.comprobar(&bloque), EstadoCabeceraConjunta::Comprobada(_)),
        "el hueco máximo permitido debe ser Comprobada"
    );
}

/// V4.5 · El cuerpo que aporta el llamante se conserva detrás de la coinbase.
#[test]
fn v4_cuerpo_con_una_transaccion_extra() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let extra = tx_de_efecto(0x51, 7);
    let cuerpo = CuerpoProductor::nuevo(vec![extra.clone()], vec![Vec::new()]).expect("cuerpo");
    let slot = primer_slot_con_solucion(&mut c, fondo(0), 0, MAX);
    let bloque = c
        .producir_intento_con_cuerpo(
            fondo(0),
            PadresDag::nuevo(t, &[]).expect("padre terminal"),
            slot,
            cuerpo,
        )
        .expect("productor con cuerpo");
    c.admitir(&bloque);

    assert_eq!(bloque.txs().len(), 2);
    assert_eq!(bloque.txs().first().expect("coinbase").version, 3);
    assert_eq!(
        bloque.txs().get(1),
        Some(&extra),
        "la tx del llamante va después"
    );
    assert!(
        zx_dag::comprobar_compromisos_cuerpo_dag(&bloque.cabecera, bloque.txs(), bloque.testigos())
            .is_ok(),
        "los compromisos del cuerpo deben cuadrar"
    );
    assert!(matches!(
        c.comprobar(&bloque),
        EstadoCabeceraConjunta::Comprobada(_)
    ));
}

/// Transacción de efecto v1 (con una entrada) para los tests de cuerpo.
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

// ─────────────────────────────────────────────────────────────────────────────
// V5 · Negativos
// ─────────────────────────────────────────────────────────────────────────────

/// V5.1 · El padre seleccionado declarado no es el que da GHOSTDAG.
#[test]
fn v5_padre_seleccionado_que_no_da_ghostdag_es_invalido() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let p0 = fondo(0).parcela();
    let p1 = fondo(1).parcela();
    let slot_hermanos = primer_slot_comun(&mut c, &[&p0, &p1], 0, MAX);
    drop(p0);
    drop(p1);
    let a = c.producir_y_admitir(
        fondo(0),
        PadresDag::nuevo(t, &[]).expect("padre"),
        slot_hermanos,
    );
    let b = c.producir_y_admitir(
        fondo(1),
        PadresDag::nuevo(t, &[]).expect("padre"),
        slot_hermanos,
    );

    let conjunto =
        PadresDag::nuevo(a.cabecera.block_hash(), &[b.cabecera.block_hash()]).expect("dos padres");
    let verdadero = c.sp_de(&conjunto);
    let falso = if verdadero == a.cabecera.block_hash() {
        b.cabecera.block_hash()
    } else {
        a.cabecera.block_hash()
    };
    let padres_malos = PadresDag::nuevo(falso, &[verdadero]).expect("padres canónicos");
    let slot = primer_slot_con_solucion(&mut c, fondo(2), slot_hermanos, MAX);
    let bloque = c
        .producir_intento(fondo(2), padres_malos, slot)
        .expect("el productor no elige padres: produce el declarado");

    assert!(matches!(
        c.comprobar(&bloque),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Padres(
            ErrorDag::PadreSeleccionadoIncorrecto { esperado, encontrado }
        )) if esperado == verdadero && encontrado == falso
    ));
}

/// V5.2 · `> 15` padres se rechaza en el formato; extras no canónicos, en el parser.
#[test]
fn v5_padres_excesivos_y_no_canonicos_se_rechazan() {
    let extras: Vec<BlockHash> = (1..=15u8).map(hash_de).collect();
    assert!(matches!(
        PadresDag::nuevo(hash_de(0x01), &extras),
        Err(EncodingError::DemasiadosPadres {
            declarados: 16,
            maximo: 15
        })
    ));

    let cabecera = DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: zx_core::CBID_RED_DEV,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([1; 32])),
        timestamp: 0,
        height: 0,
        slot: 10,
        pot_output: [0; 16],
        rango_solucion: SR_DEV,
        sol: SolucionPoas::default(),
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([2; 32])),
        padres: PadresDag::nuevo(hash_de(0x01), &[hash_de(0x02), hash_de(0x03)])
            .expect("extras canónicos"),
        sello: [0; 64],
    };
    let mut bytes = cabecera.a_bytes();
    let offset = zx_core::preimage::dag::OFFSET_PADRES_EXTRA;
    let (_, resto) = bytes.split_at_mut(offset);
    let (primero, resto) = resto.split_at_mut(32);
    let (segundo, _) = resto.split_at_mut(32);
    primero.swap_with_slice(segundo);
    assert!(matches!(
        dag_header_desde_bytes(&bytes),
        Err(EncodingError::PadresNoCanonicos)
    ));
}

/// V5.3 · `slot ≤ slot(sp)` es error explícito del productor (y también de la puerta).
#[test]
fn v5_slot_que_no_progresa_es_error() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let r = c.producir_intento(
        fondo(0),
        PadresDag::nuevo(t, &[]).expect("padre terminal"),
        0,
    );
    assert!(matches!(
        r,
        Err(ErrorRegimen::SlotNoProgreso {
            slot: 0,
            slot_sp: 0
        })
    ));

    // La puerta también lo rechaza si la cabecera llegara construida: el productor no la produce.
    let mut c2 = Cadena::nueva(N_DEV);
    let bloque = producir_buscando(&mut c2, fondo(0), t, 0);
    let mut ataque = bloque;
    ataque.cabecera.slot = 0;
    refirmar(&mut ataque.cabecera, &fondo(0).sk);
    assert!(matches!(
        c2.comprobar(&ataque),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::TransicionSinProgresoDeSlot {
            slot: 0,
            s0: 0
        })
    ));
}

/// V5.4 · Hueco de 151 slots: excede `MAX_BUNDLES_POT = 150`.
#[test]
fn v5_hueco_de_151_slots_es_error() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let r = c.producir_intento(
        fondo(0),
        PadresDag::nuevo(t, &[]).expect("padre terminal"),
        151,
    );
    assert!(matches!(
        r,
        Err(ErrorRegimen::RangoExcedeMaximo { d: 151, max: 150 })
    ));
}

/// V5.5 · Un checkpoint alterado invalida el rango AES.
#[test]
fn v5_checkpoint_alterado_es_invalido() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let bloque = producir_buscando(&mut c, fondo(0), t, 0);

    let portador = bloque.justificacion.bundles().first().expect("un portador");
    let mut outputs = portador.outputs();
    outputs[0][0] ^= 0x01;
    let roto = con_justificacion(&bloque, vec![PotCheckpoints::desde_outputs(outputs)]);

    assert!(matches!(
        c.comprobar(&roto),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Pot(
            MotivoPotInvalido::AesFallido { .. }
        ))
    ));
}

/// V5.6 · Un `pot_output` alterado no ancla.
#[test]
fn v5_pot_output_alterado_es_invalido() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let mut bloque = producir_buscando(&mut c, fondo(0), t, 0);
    bloque.cabecera.pot_output[0] ^= 0x01;
    refirmar(&mut bloque.cabecera, &fondo(0).sk);

    assert!(matches!(
        c.comprobar(&bloque),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Pot(
            MotivoPotInvalido::PotOutputNoCoincide { .. }
        ))
    ));
}

/// V5.7 · Solución de otra clave: el sello pasa, la prueba de espacio no.
#[test]
fn v5_solucion_de_otra_clave_es_invalida() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let mut bloque = producir_buscando(&mut c, fondo(0), t, 0);
    let ajena = SigningKey::from([0x77u8; 32]);
    bloque.cabecera.sol.public_key = clave_publica_de(&ajena);
    refirmar(&mut bloque.cabecera, &ajena);

    assert!(matches!(
        c.comprobar(&bloque),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Poas(_))
    ));
}

/// V5.8 · Sello de otra clave.
#[test]
fn v5_sello_de_otra_clave_es_invalido() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let mut bloque = producir_buscando(&mut c, fondo(0), t, 0);
    let ajena = SigningKey::from([0x88u8; 32]);
    refirmar(&mut bloque.cabecera, &ajena);

    assert!(matches!(
        c.comprobar(&bloque),
        EstadoCabeceraConjunta::Invalida(MotivoCabeceraInvalida::Sello(_))
    ));
}

/// V5.9 · Padre desconocido: la puerta queda `Pendiente`, no inventa contexto.
#[test]
fn v5_padre_desconocido_queda_pendiente() {
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let mut bloque = producir_buscando(&mut c, fondo(0), t, 0);
    let fantasma = hash_de(0xEE);
    bloque.cabecera.padres = PadresDag::nuevo(fantasma, &[]).expect("un padre");
    refirmar(&mut bloque.cabecera, &fondo(0).sk);

    assert!(matches!(
        c.comprobar(&bloque),
        EstadoCabeceraConjunta::Pendiente(MotivoCabeceraPendiente::Padres(
            ErrorDag::PadreNoValidado { padre }
        )) if padre == fantasma
    ));
}

/// V5.10 · Coinbase v3 con `slot` ≠ bloque: la rechaza el motor de consenso (F-17),
/// **no** la puerta conjunta, que solo mira cabecera y justificación.
#[test]
fn v5_coinbase_v3_con_slot_distinto_se_rechaza_en_consenso() {
    use primitive_types::U256;
    use zx_consensus::transicion::{
        BloqueTransicion, ErrorTransicion, Estado, Fase, Garantia, HechosCabecera,
        ParametrosTransicion, aplicar,
    };

    fn subsidio_pow(_h: u32) -> Amount {
        Amount::nuevo(10).expect("importe")
    }
    fn subsidio_post(_s: u64) -> Amount {
        Amount::nuevo(3).expect("importe")
    }
    let params = ParametrosTransicion {
        h_dep: 1,
        m_cb: 1,
        m_dep: 0,
        h_corte_min: 100,
        w_min: U256::one(),
        s_min: Amount::nuevo(1).expect("importe"),
        q: Amount::nuevo(1).expect("importe"),
        k_min: 1,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 3,
        f_slots: None,
        subsidio_pow,
        subsidio_post,
    };

    let sk = SigningKey::from([48u8; 32]);
    let pk = clave_publica_de(&sk);
    let mut estado = Estado::inicial();
    estado.fase = Fase::PoST;
    estado.garantias.insert(
        pk,
        Garantia {
            activo: Amount::nuevo(10).expect("importe"),
            ..Garantia::nueva()
        },
    );
    estado.emitido = 10;
    estado.subsidio_acum = 10;

    let coinbase = |slot: u64| Tx {
        version: 3,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::CoinbasePost {
            clave: pk,
            importe: Amount::nuevo(3).expect("importe"),
            slot,
        },
    };
    let bloque = |slot_coinbase: u64| {
        BloqueTransicion::nuevo(
            HechosCabecera::PoST {
                hash: hash_de(0x02),
                padre: hash_de(0x01),
                slot: 1,
                productor: pk,
                peso: 1,
                prueba_valida: true,
                requisito_declarado: 0,
            },
            vec![(coinbase(slot_coinbase), Vec::new())],
        )
    };

    for slot in [0u64, 2, 99] {
        assert_eq!(
            aplicar(
                &estado,
                &bloque(slot),
                &params,
                zx_core::CBID_RED_DEV,
                &zx_consensus::transicion::ParametrosEvidencia::inactiva(),
            ),
            Err(ErrorTransicion::ErrEmision),
            "F-17: slot {slot} ≠ slot del bloque 1"
        );
    }
    assert!(
        aplicar(
            &estado,
            &bloque(1),
            &params,
            zx_core::CBID_RED_DEV,
            &zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        )
        .is_ok(),
        "el slot correcto sí se aplica"
    );

    // La puerta conjunta de `zx-post` **no** inspecciona el cuerpo: con la misma cabecera y la
    // misma justificación, alterar la extensión de la coinbase no cambia su veredicto. El rechazo
    // de F-17 es del motor (`aplicar_coinbase_post`, `aplicar.rs:370-373`), como prueba el bloque
    // de arriba. Se deja explícito para no confundir `Comprobada` con admisión.
    let t = terminal();
    let mut c = Cadena::nueva(N_DEV);
    let mut bloque = producir_buscando(&mut c, fondo(0), t, 0);
    let txs = {
        let mut txs = bloque.txs().to_vec();
        if let Some(t) = txs.first_mut()
            && let ExtensionTx::CoinbasePost { slot, .. } = &mut t.extension
        {
            *slot = slot.wrapping_add(1);
        }
        txs
    };
    bloque = BloqueDag::nuevo(
        bloque.cabecera,
        JustificacionPot::nueva(bloque.justificacion.bundles().to_vec()).expect("≤ 150 portadores"),
        txs,
        bloque.testigos().to_vec(),
    )
    .expect("bloque con la misma cabecera y justificación");
    assert!(
        matches!(c.comprobar(&bloque), EstadoCabeceraConjunta::Comprobada(_)),
        "la puerta conjunta no mira el cuerpo: el defecto F-17 es del motor"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// V6 · Extremo a extremo con `N_dev` real (release, `--ignored`)
// ─────────────────────────────────────────────────────────────────────────────

/// V6 · Tres bloques en régimen con el `N_dev` real del perfil dev.
///
/// Se ejecuta explícitamente en `release`:
/// `cargo test -p zx-post --release --test regimen -- --ignored --nocapture v6_`
#[test]
#[ignore = "V6: N_dev real (138 873 760); se ejecuta en release con --ignored"]
fn v6_extremo_a_extremo_con_n_dev_real() {
    let preparacion = std::time::Instant::now();
    let mut c = Cadena::nueva(N_DEV_REAL);
    let mut padre = terminal();
    let mut slot_padre = 0;
    let mut medidas = Vec::new();
    for i in 0..3usize {
        let f = fondo(i);
        // La producción incluye el avance PoT del `ServicioPot`: el temporizador arranca antes
        // de buscar el slot con solución, porque ese avance lo paga el productor.
        let inicio = std::time::Instant::now();
        let slot = primer_slot_con_solucion(&mut c, f, slot_padre, MAX);
        let bloque = c.producir_y_admitir(f, PadresDag::nuevo(padre, &[]).expect("padre"), slot);
        let t_produccion = inicio.elapsed();

        let inicio = std::time::Instant::now();
        let estado = c.comprobar(&bloque);
        let t_verificacion = inicio.elapsed();

        match estado {
            EstadoCabeceraConjunta::Comprobada(HechosPost { slot: s, .. }) if s == slot => {}
            otro => panic!("bloque {i}: se esperaba Comprobada, llegó {otro:?}"),
        }
        medidas.push((slot, t_produccion, t_verificacion));
        padre = bloque.cabecera.block_hash();
        slot_padre = slot;
    }
    eprintln!(
        "[V6] N_dev real = {N_DEV_REAL}; preparación (historia + parcelas) {:.3} s",
        preparacion.elapsed().as_secs_f64()
    );
    for (slot, produccion, verificacion) in medidas {
        eprintln!(
            "[V6] slot {slot}: producción {:.3} s, verificación {:.3} s",
            produccion.as_secs_f64(),
            verificacion.as_secs_f64()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture temporal
// ─────────────────────────────────────────────────────────────────────────────

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
