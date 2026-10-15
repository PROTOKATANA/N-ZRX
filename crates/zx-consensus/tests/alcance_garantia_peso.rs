//! FV-N6-C4-2 · alcance de la garantía: R4 (`EvidenceTx`), conservación de dinero con fianzas,
//! orden de débito determinista, subcuentas completas, límite, continuación de certificados con la
//! tabla siguiente que refleja la suspensión, y recorrido real sector→activo→Retiro→Liberación con
//! los plazos vigentes (`R_sec = 96`, `R_slots = 600`).
//!
//! **Fixtures declarados.** Los estados con fianza se montan con un estado inicial
//! **contablemente conservado** (`emitido = Σ activo + Σ fianza`, `quemado = 0`): no son altas
//! autenticadas extraídas de la red. Donde se añade un sector después se usa el **alta por API
//! real** (`aplicar_operacion_con_undo` con `OperacionSector::Alta`), que debita `Garantia.activo` y
//! no cambia `emitido`. Las claves BLS, el sorteo VRF, las firmas de voto, los sellos Ed25519 de las
//! cabeceras `PoAS_PoT_DAG` y la aceptación de las Tx v2 son reales; los registros de sector y las
//! cabeceras son **fixture**, no un proceso de red de cuatro nodos.
//!
//! La conservación en los tests **no dedicados a `I-1`** se calcula dentro del test
//! ([`conservacion`]): `UTXO` + las cuatro sub-cuentas de `Garantia` + `Σ fianza` no terminal
//! `== emitido − quemado`. Así, sobre la base limpia `cda9b836` el rojo llega a los débitos de las
//! penas y no se detiene en una `invariante_i1` que todavía no suma fianzas. El test dedicado
//! [`i1_suma_fianzas_no_terminales`] sí comprueba la `invariante_i1` productiva.
//!
//! R4 usa cabeceras `PoAS_PoT_DAG` con sellos Ed25519 reales y el camino real de bloque
//! (`aplicar_con_undo`), no una función que imite la pena.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::panic,
    dead_code,
    reason = "test de escenarios con estados construidos a mano; falla con panic por diseño"
)]

use ed25519_zebra::SigningKey;
use primitive_types::U256;
use zx_consensus::sectores::{
    ClaveVoto, EstadoEfectivo, Etapa, MotivoSector, ParametrosSector, RegistroSector, SectorId,
    estado_efectivo,
};
use zx_consensus::transicion::votos::{
    PRIMA_DISPONIBILIDAD_ACTIVA, aplicar_certificado_peso_con_undo,
    aplicar_evidencia_votos_peso_con_undo, derivar_tabla_sin_base_con_undo,
};
use zx_consensus::transicion::{
    BloqueTransicion, EnRetirada, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, Pendiente, aplicar_con_undo, aplicar_operacion_con_undo, deshacer,
    fuente_peso_de, materializar_con_undo, total_garantia,
};
use zx_core::{
    Amount, BlockHash, BodyCommitment, CBID_RED_DEV, ClavePublica, ClaveTablaVoto, DagBlockHeader,
    Digest, ExtensionTx, MerkleRoot, OperacionAlmacenamiento, OperacionSector, PadresDag,
    SolucionPoas, TipoGarantia, Tx, TxOut, VotoPesoEvidencia,
};
use zx_votos::{Clave, DOMINIO_VOTO, Firma, Tabla};

const K: u64 = 65_536;
const B: u64 = 2;
const SLOT: i64 = 100;
const Q_SEC: i64 = 140;
/// Slot de retirada del sector en la prueba de retención (antes de `apertura_ventana(1) = 2`).
const RETIRO_SLOT: i64 = 1;

type Error = Box<dyn std::error::Error>;

/// TB-1c-2 · X2 · montaje autorizado: llama al gancho de producto `derivar_tabla_sin_base` con el
/// slot del bloque (no una copia) para que la derivada que el primer certificado declara esté en `Q`.
fn preparar_cola_sin_base(est: &mut Estado, slot: u64) {
    let (nuevo, _u) = derivar_tabla_sin_base_con_undo(est, slot);
    *est = nuevo;
}

// ── fixtures de voto (mismos orígenes que los tests FV-4b-N2/N3) ─────────────

fn bls(indice: u8) -> Result<zx_votos::ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    Ok(zx_votos::ClaveSecreta::generar(&ikm)?)
}

fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
}

fn registro(p: &ParametrosSector, clave: ClavePublica, indice: u16) -> (SectorId, RegistroSector) {
    let id = SectorId {
        clave,
        sector_index: indice,
        version: 0,
    };
    let reg = RegistroSector {
        id,
        r2: [0; 4],
        history_size: 1,
        etapa: Etapa::Activo,
        alta_slot: 0,
        renovacion_slot: 0,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    };
    (id, reg)
}

fn estado_conservado(
    claves: &[(u8, usize, i64)],
) -> Result<(Estado, Vec<zx_votos::ClaveSecreta>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let mut secretas = Vec::new();
    let mut emitido: i128 = 0;
    for (indice, n_sectores, activo) in claves {
        let secreta = bls(*indice)?;
        let pk = secreta.clave_publica();
        let e = ed(*indice);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for i in 0..*n_sectores {
            let (id, reg) = registro(&p, e, u16::try_from(i)?);
            emitido += i128::from(reg.fianza);
            est.sectores.insert(id, reg);
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(*activo)?;
        emitido += i128::from(*activo);
        est.garantias.insert(e, g);
        secretas.push(secreta);
    }
    est.emitido = emitido;
    est.quemado = 0;
    Ok((est, secretas))
}

fn fianza_de(est: &Estado, clave: &ClavePublica) -> i128 {
    est.sectores
        .iter()
        .filter(|(id, r)| id.clave == *clave && !r.es_terminal())
        .map(|(_, r)| i128::from(r.fianza))
        .sum()
}

fn total_castigable_test(est: &Estado, clave: &ClavePublica) -> i128 {
    let cuenta = est.garantias.get(clave).map_or(0, total_garantia);
    cuenta + fianza_de(est, clave)
}

/// Conservación **independiente** calculada dentro del test (no llama a `invariante_i1`):
/// `UTXO` + las cuatro sub-cuentas de `Garantia` (`activo`, `pendientes`, `en_retirada`,
/// `creditos`) + `Σ fianza` no terminal `== emitido − quemado`.
///
/// Es la precondición/postcondición contable de los tests que no son el dedicado de `I-1`: en la
/// base `cda9b836` la `invariante_i1` productiva no suma fianzas y enmascararía el débito.
fn conservacion(est: &Estado) -> bool {
    let mut total: i128 = est.utxo.values().map(|e| i128::from(e.valor.brek())).sum();
    for g in est.garantias.values() {
        total += i128::from(g.activo.brek());
        total += g
            .pendientes
            .iter()
            .map(|p| i128::from(p.importe.brek()))
            .sum::<i128>();
        total += g
            .en_retirada
            .iter()
            .map(|r| i128::from(r.importe.brek()))
            .sum::<i128>();
        total += g
            .creditos
            .iter()
            .map(|p| i128::from(p.importe.brek()))
            .sum::<i128>();
    }
    for r in est.sectores.values() {
        if !r.es_terminal() {
            total += i128::from(r.fianza);
        }
    }
    total == est.emitido - est.quemado
}

/// M9-b1 · orden canónico (ascendente por bytes de clave BLS).
fn canoniza(mut claves: Vec<ClaveTablaVoto>) -> Vec<ClaveTablaVoto> {
    claves.sort_by_key(|a| a.clave_bls);
    claves
}

fn hash_payload(claves: &[ClaveTablaVoto]) -> [u8; 32] {
    zx_votos::hash_tabla(&tabla_contrato(0, claves))
}

/// M9-b1 · deja la tabla de la ventana `n` como el flujo por peso (contenido + asociación).
fn poner_tabla(est: &mut Estado, n: u64, claves: Vec<ClaveTablaVoto>) {
    let h = hash_payload(&claves);
    est.tablas_voto_contenido.insert(h, claves);
    est.tabla_ventana_voto.insert(n, h);
}

/// Certificado compacto `0x09` con firmas BLS reales sobre A3 (raíz cero).
#[allow(clippy::too_many_arguments)]
fn certificado_peso(
    secretas: &[zx_votos::ClaveSecreta],
    n: u64,
    claves_payload: &[ClaveTablaVoto],
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    firmantes: &[usize],
    _tabla_siguiente: Option<&[ClaveTablaVoto]>,
) -> Result<OperacionAlmacenamiento, Error> {
    let vigente = canoniza(claves_payload.to_vec());
    let tabla = tabla_contrato(n, &vigente);
    let mensaje = zx_votos::mensaje_voto_peso(n, &candidato, &h_t_siguiente, &[0u8; 32]);
    let mut votos: Vec<(usize, Firma)> = Vec::new();
    for (orden, secreta) in secretas.iter().enumerate() {
        if !firmantes.contains(&orden) {
            continue;
        }
        let pk = secreta.clave_publica();
        let Some(pos) = tabla
            .claves
            .iter()
            .position(|c| c.clave == pk.bytes().to_vec())
        else {
            continue;
        };
        let firma = zx_votos::firmar(secreta, DOMINIO_VOTO, &mensaje)?;
        votos.push((pos + 1, firma));
    }
    let cert =
        zx_votos::construir_certificado(n, candidato, h_t_siguiente, [0u8; 32], &tabla, &votos)?;
    Ok(OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(200),
        bytes: zx_votos::serial_certificado_peso(&cert),
    })
}

/// M9-b1 · evidencia de dos votos por peso (`0x0B`) con las dos firmas A3 reales.
fn op_doble_voto_peso(
    secreta: &zx_votos::ClaveSecreta,
    n: u64,
    h_t: [u8; 32],
    h1: [u8; 32],
    h2: [u8; 32],
) -> Result<OperacionAlmacenamiento, Error> {
    let pk = secreta.clave_publica();
    let f1 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &h1, &h_t, &h1),
    )?;
    let f2 = zx_votos::firmar(
        secreta,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &h2, &h_t, &h2),
    )?;
    Ok(OperacionAlmacenamiento::EvidenciaVotosPeso {
        clave: ed(200),
        clave_bls: pk.bytes(),
        voto1: VotoPesoEvidencia {
            n,
            candidato: h1,
            h_t_siguiente: h_t,
            raiz_estado: h1,
            firma: f1.bytes(),
        },
        voto2: VotoPesoEvidencia {
            n,
            candidato: h2,
            h_t_siguiente: h_t,
            raiz_estado: h2,
            firma: f2.bytes(),
        },
    })
}

fn param_evidencia() -> ParametrosEvidencia {
    ParametrosEvidencia {
        f_num: 1,
        f_den: 1,
        plazo_slots: 2,
        m_margen_slots: 0,
        cbid: 0,
        evp: true,
    }
}

/// `f = 1/2`: el cobro no agota toda la fianza y permite observar el orden de débito.
fn param_evidencia_medio() -> ParametrosEvidencia {
    ParametrosEvidencia {
        f_den: 2,
        ..param_evidencia()
    }
}

fn params_transicion() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 0,
        m_cb: 1,
        m_dep: 1,
        h_corte_min: 0,
        w_min: U256::zero(),
        s_min: Amount::CERO,
        q: Amount::nuevo(1).expect("q"),
        k_min: 0,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 600,
        f_slots: Some(600),
        subsidio_pow: |_| Amount::CERO,
        subsidio_post: |_| Amount::CERO,
    }
}

// ── fixtures de bloque para R4 (`EvidenceTx` v4 real) ────────────────────────

fn firmante_de(k: u64) -> SigningKey {
    let mut mensaje = b"zx-t01-clave".to_vec();
    mensaje.extend_from_slice(&k.to_le_bytes());
    let digest = zx_core::sha3_256_publico(&mensaje);
    SigningKey::from(*digest.as_bytes())
}

fn clave_firmante(k: u64) -> ClavePublica {
    let sk = firmante_de(k);
    let vk = ed25519_zebra::VerificationKey::from(&sk);
    ClavePublica::desde_bytes(vk.into())
}

fn hash_de(id: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&id.to_be_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}

fn cabecera(cbid: u32, clave: ClavePublica, slot: i64, ph: u64, sal: u64) -> DagBlockHeader {
    let sol = SolucionPoas {
        public_key: clave,
        ..Default::default()
    };
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: cbid,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0u8; 32])),
        timestamp: sal,
        height: 0,
        slot: slot as u64,
        pot_output: [0u8; 16],
        rango_solucion: ph,
        sol,
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0u8; 32])),
        padres: PadresDag::genesis(),
        sello: [0u8; 64],
    }
}

/// `EvidenceTx` v4 con dos cabeceras reales de la misma identidad y sellos reales.
fn evidencia_tx(cbid: u32, clave_idx: u64, slot: i64, ph1: u64, ph2: u64) -> Tx {
    let clave = clave_firmante(clave_idx);
    let mut h1 = cabecera(cbid, clave, slot, ph1, 0);
    let quiere_menor = ph1 < ph2;
    let mut sal = 0u64;
    let mut h2;
    loop {
        h2 = cabecera(cbid, clave, slot, ph2, sal);
        if (h1.pre_hash().as_bytes() < h2.pre_hash().as_bytes()) == quiere_menor {
            break;
        }
        sal += 1;
    }
    let sk = firmante_de(clave_idx);
    let firma1: [u8; 64] = sk.sign(h1.pre_hash().as_bytes()).into();
    h1.sello = firma1;
    let firma2: [u8; 64] = sk.sign(h2.pre_hash().as_bytes()).into();
    h2.sello = firma2;
    Tx {
        version: 4,
        inputs: Vec::new(),
        outputs: Vec::<TxOut>::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Evidencia { h1, h2 },
    }
}

fn bloque_post(
    slot: u64,
    productor: ClavePublica,
    txs: Vec<(Tx, Vec<Vec<u8>>)>,
) -> BloqueTransicion {
    BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: hash_de(slot + 100),
            padre: hash_de(1),
            slot,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        txs,
    )
}

/// Tx v2 de garantía (`Retiro`/`Liberacion`) sin entradas ni salidas.
fn tx_garantia(tipo: TipoGarantia, clave: ClavePublica, importe: i64, nonce: u64) -> Tx {
    Tx {
        version: 2,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Garantia {
            tipo,
            clave,
            importe: Amount::nuevo(importe).expect("importe"),
            nonce,
        },
    }
}

/// Firma de aceptación (último testigo) de una v2 de garantía.
fn firma_aceptacion(tx: &Tx, k: u64) -> Vec<u8> {
    let sk = firmante_de(k);
    let firma: [u8; 64] = sk
        .sign(&zx_core::mensaje_aceptacion(tx, CBID_RED_DEV))
        .into();
    firma.to_vec()
}

// ── fixtures de certificado (continuación) ──────────────────────────────────

/// Tabla de contrato (`zx-votos`) desde el payload de consenso (`zx-core`).
fn tabla_contrato(n: u64, claves: &[ClaveTablaVoto]) -> Tabla {
    Tabla {
        n,
        claves: claves
            .iter()
            .map(|c| Clave {
                clave: c.clave_bls.to_vec(),
                peso: c.peso,
                activo: c.activo,
                prueba: c.prueba,
                garantia: c.garantia,
            })
            .collect(),
    }
}

fn tabla_de(est: &Estado, n: u64, slot: i64) -> Result<(Vec<ClaveTablaVoto>, Tabla), Error> {
    let p = est.parametros_sector;
    let mut claves_payload = Vec::new();
    let mut tabla_claves = Vec::new();
    for (e, cv) in &est.claves_voto {
        let peso = fuente_peso_de(est, e, slot, &p);
        if peso <= 0 {
            continue;
        }
        let peso = u64::try_from(peso)?;
        let prueba = PRIMA_DISPONIBILIDAD_ACTIVA && est.pruebas.contains_key(e);
        claves_payload.push(ClaveTablaVoto {
            clave_bls: cv.clave_bls,
            peso,
            activo: true,
            prueba,
            garantia: peso,
        });
        tabla_claves.push(Clave {
            clave: cv.clave_bls.to_vec(),
            peso,
            activo: true,
            prueba,
            garantia: peso,
        });
    }
    Ok((
        claves_payload,
        Tabla {
            n,
            claves: tabla_claves,
        },
    ))
}

/// El débito agota en orden todas las subcuentas y después las fianzas por `SectorId` ascendente.
#[test]
fn debito_mixto_agota_cuenta_y_luego_fianzas_peso() -> Result<(), Error> {
    let (base, secretas) = estado_conservado(&[(1, 2, 0)])?;
    let mut est = base.clone();
    let g = est.garantias.get_mut(&ed(1)).ok_or("garantía")?;
    g.activo = Amount::nuevo(10)?;
    g.pendientes.push(Pendiente {
        importe: Amount::nuevo(5)?,
        madura_en_altura: None,
        madura_en_slot: Some(1_000),
    });
    g.en_retirada.push(EnRetirada {
        importe: Amount::nuevo(7)?,
        inicio_slot: 0,
    });
    g.creditos.push(Pendiente {
        importe: Amount::nuevo(3)?,
        madura_en_altura: None,
        madura_en_slot: Some(1_000),
    });
    est.emitido += 10 + 5 + 7 + 3;
    assert_eq!(
        total_castigable_test(&est, &ed(1)),
        i128::from(25 + 2 * Q_SEC)
    );
    assert!(conservacion(&est));

    let op = op_doble_voto_peso(
        secretas.first().ok_or("secreta")?,
        3,
        [0x33u8; 32],
        [0x01u8; 32],
        [0x02u8; 32],
    )?;
    let (nuevo, undo, r) = aplicar_evidencia_votos_peso_con_undo(
        &est,
        &op,
        ed(9),
        &params_transicion(),
        &param_evidencia_medio(),
        10,
    );
    r?;
    let g = nuevo.garantias.get(&ed(1)).ok_or("garantía")?;
    assert_eq!(g.activo, Amount::CERO, "activo agotado primero");
    assert!(g.pendientes.is_empty(), "pendientes después");
    assert!(g.en_retirada.is_empty(), "en_retirada después");
    assert!(g.creditos.is_empty(), "créditos después");
    let sid = |i: u16| SectorId {
        clave: ed(1),
        sector_index: i,
        version: 0,
    };
    // C = techo(305/2) = 153; 25 salen de las subcuentas y 128 del primer sector (SectorId menor).
    assert_eq!(
        nuevo.sectores[&sid(0)].fianza,
        12,
        "el primer SectorId paga el resto"
    );
    assert_eq!(
        nuevo.sectores[&sid(1)].fianza,
        Q_SEC,
        "el segundo no se toca"
    );
    assert_eq!(
        nuevo.quemado,
        i128::from(153 - 153 / 4),
        "quema el resto del cobro real"
    );
    assert!(conservacion(&nuevo));
    assert_eq!(deshacer(&nuevo, &undo), est, "undo bit a bit");
    Ok(())
}

/// El resultado no depende del orden de inserción: `BTreeMap` ordena por `SectorId`.
#[test]
fn orden_de_debito_independiente_de_insercion_peso() -> Result<(), Error> {
    let (base, secretas) = estado_conservado(&[(1, 0, 0)])?;
    let p = base.parametros_sector;
    let mut a = base.clone();
    let mut b = base.clone();
    for indice in [2u16, 0, 1] {
        let (id, reg) = registro(&p, ed(1), indice);
        a.sectores.insert(id, reg);
    }
    for indice in [1u16, 0, 2] {
        let (id, reg) = registro(&p, ed(1), indice);
        b.sectores.insert(id, reg);
    }
    a.emitido += 3 * i128::from(Q_SEC);
    b.emitido += 3 * i128::from(Q_SEC);
    assert_eq!(a.sectores, b.sectores, "mismo conjunto canónico");
    assert!(conservacion(&a) && conservacion(&b));

    let op = op_doble_voto_peso(
        secretas.first().ok_or("secreta")?,
        4,
        [0x33u8; 32],
        [0x01u8; 32],
        [0x02u8; 32],
    )?;
    let (na, _, ra) = aplicar_evidencia_votos_peso_con_undo(
        &a,
        &op,
        ed(9),
        &params_transicion(),
        &param_evidencia_medio(),
        10,
    );
    ra?;
    let (nb, _, rb) = aplicar_evidencia_votos_peso_con_undo(
        &b,
        &op,
        ed(9),
        &params_transicion(),
        &param_evidencia_medio(),
        10,
    );
    rb?;
    assert_eq!(na, nb, "débito determinista");
    let sid = |i: u16| SectorId {
        clave: ed(1),
        sector_index: i,
        version: 0,
    };
    // C = techo(420/2) = 210: se agota el índice 0, el 1 queda a 70 y el 2 intacto.
    assert_eq!(na.sectores[&sid(0)].fianza, 0);
    assert_eq!(na.sectores[&sid(1)].fianza, 70);
    assert_eq!(na.sectores[&sid(2)].fianza, Q_SEC);
    Ok(())
}

/// Límite de fondos y recompensa no ficticia: con `V = 1` el cobro es 1 y `suelo(1/4) = 0`.
#[test]
fn limite_sin_recompensa_ficticia_peso() -> Result<(), Error> {
    let (base, secretas) = estado_conservado(&[(1, 0, 0)])?;
    let mut est = base.clone();
    let p = est.parametros_sector;
    let (id, mut reg) = registro(&p, ed(1), 0);
    reg.fianza = 1; // fianza parcial: no da peso, pero es castigable
    est.sectores.insert(id, reg);
    est.emitido += 1;
    assert_eq!(total_castigable_test(&est, &ed(1)), 1);
    let op = op_doble_voto_peso(
        secretas.first().ok_or("secreta")?,
        5,
        [0x33u8; 32],
        [0x01u8; 32],
        [0x02u8; 32],
    )?;
    let (nuevo, undo, r) = aplicar_evidencia_votos_peso_con_undo(
        &est,
        &op,
        ed(9),
        &params_transicion(),
        &param_evidencia(),
        10,
    );
    r?;
    assert_eq!(fianza_de(&nuevo, &ed(1)), 0, "no hay deuda ni negativo");
    assert_eq!(nuevo.quemado, 1, "cobro real = 1, todo quemado");
    let creditos_productor = nuevo.garantias.get(&ed(9)).map_or(0, |g| {
        g.creditos.iter().map(|p| p.importe.brek()).sum::<i64>()
    });
    assert_eq!(
        creditos_productor, 0,
        "sin recompensa ficticia (suelo(1/4)=0)"
    );
    assert!(conservacion(&nuevo));
    assert_eq!(deshacer(&nuevo, &undo), est);
    Ok(())
}

/// La fianza en `EnRetirada` sigue siendo alcanzable por R3 (`P_ret`) y se libera a `activo` a
/// `retiro_slot + r_sec` por la ruta real `materializar_con_undo`.
#[test]
fn fianza_en_retirada_alcanzable_y_devolucion_a_activo_peso() -> Result<(), Error> {
    let (base, secretas) = estado_conservado(&[(1, 1, 0)])?;
    let mut est = base.clone();
    let sid = SectorId {
        clave: ed(1),
        sector_index: 0,
        version: 0,
    };
    let p = est.parametros_sector;
    {
        let r = est.sectores.get_mut(&sid).ok_or("sector")?;
        r.etapa = Etapa::EnRetirada;
        r.retiro_slot = 0;
    }
    assert_eq!(
        estado_efectivo(&est.sectores[&sid], 1, &p),
        EstadoEfectivo::EnRetirada
    );
    let op = op_doble_voto_peso(
        secretas.first().ok_or("secreta")?,
        6,
        [0x33u8; 32],
        [0x01u8; 32],
        [0x02u8; 32],
    )?;
    let (penado, _undo, r) = aplicar_evidencia_votos_peso_con_undo(
        &est,
        &op,
        ed(9),
        &params_transicion(),
        &param_evidencia(),
        10,
    );
    r?;
    assert_eq!(
        fianza_de(&penado, &ed(1)),
        0,
        "R3 alcanza la fianza en retirada"
    );

    // Ruta real de devolución (sin R3): a los 1 024 slots (`retiro + R_V`) la fianza vuelve a
    // `Garantia.activo` (RET-1b E6; antes de RET-1a se liberaba a los 96).
    let (no_96, _u96) = materializar_con_undo(&est, 96, &est.parametros_sector);
    assert_eq!(
        no_96.sectores[&sid].etapa,
        Etapa::EnRetirada,
        "no se libera a los 96"
    );
    let (no_1023, _u1023) = materializar_con_undo(&est, 1_023, &est.parametros_sector);
    assert_eq!(
        no_1023.sectores[&sid].etapa,
        Etapa::EnRetirada,
        "no se libera a los 1 023"
    );
    let (devuelto, _undo) = materializar_con_undo(&est, 1_024, &est.parametros_sector);
    assert_eq!(devuelto.sectores[&sid].etapa, Etapa::Retirado);
    assert_eq!(devuelto.sectores[&sid].fianza, 0);
    assert_eq!(devuelto.garantias[&ed(1)].activo.brek(), Q_SEC);
    assert!(conservacion(&devuelto));
    Ok(())
}

/// Retención real con plazos vigentes: el peso sale de un **sector** comprometido en tabla; el
/// sector se retira cuando es admisible (capacidad de caja 1) antes de la apertura de la ventana;
/// a `retiro + R_sec = 96` la fianza vuelve a `Garantia.activo` (no a UTXO); después `Retiro` y
/// `Liberacion` autenticadas con `R_slots = 600` llevan el saldo a UTXO. Se contrasta el alcance de
/// una `EvidenceTx` válida en su propia ventana **antes** y **después** de la salida a UTXO.
///
/// Fixture declarado: el sector y la garantía del productor son estado inicial conservado; la clave
/// BLS del dueño, los sellos Ed25519 y la aceptación de las Tx v2 son reales.
#[test]
fn retiro_y_liberacion_autenticados_limitan_el_alcance_peso() -> Result<(), Error> {
    // Capacidad 1: el retiro de un sector suelto es admisible. Se conservan `R_sec = 96` y
    // `R_slots = 600` del perfil dev; **no** se reduce `r_slots` a 3.
    let p = ParametrosSector {
        capacidad_caja: 1,
        ..ParametrosSector::dev()
    };
    let mut base = Estado::inicial();
    base.parametros_sector = p;
    base.fase = Fase::PoST;
    base.terminal = Some(hash_de(1));
    base.slot = 0;
    let dueno = clave_firmante(1);
    let productor = clave_firmante(2);
    // Clave BLS del dueño para poder comprometer su peso sectorial.
    let secreta = bls(1)?;
    base.claves_voto.insert(
        dueno,
        ClaveVoto {
            clave_bls: secreta.clave_publica().bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    let (id, reg) = registro(&p, dueno, 0);
    base.sectores.insert(id, reg);
    let mut g = Garantia::nueva();
    g.activo = Amount::CERO;
    base.garantias.insert(dueno, g);
    let mut gp = Garantia::nueva();
    gp.activo = Amount::nuevo(1)?;
    base.garantias.insert(productor, gp);
    base.emitido = i128::from(Q_SEC) + 1;
    base.quemado = 0;
    assert!(conservacion(&base), "fixture conservado");

    // (1) Compromete la tabla de la ventana 1 con el peso del sector (antes de la apertura).
    let (t1, _) = tabla_de(&base, 1, 0)?;
    assert_eq!(
        t1.iter()
            .find(|c| c.clave_bls == base.claves_voto[&dueno].clave_bls)
            .map(|c| c.peso),
        Some(1),
        "la tabla lleva el peso del sector"
    );
    let mut con_t1 = base.clone();
    poner_tabla(&mut con_t1, 1, t1.clone());
    assert!(conservacion(&con_t1));

    // (2) Retira el sector antes de `apertura_ventana(1) = 2`, con capacidad 1.
    let op_retirar = OperacionSector::Retirar {
        clave: dueno,
        sector_index: 0,
    };
    let (en_retirada, res) = aplicar_operacion_con_undo(&con_t1, &op_retirar, RETIRO_SLOT, &p);
    assert_eq!(res.motivo, MotivoSector::Ok, "retiro admisible");
    let sid = SectorId {
        clave: dueno,
        sector_index: 0,
        version: 0,
    };
    assert_eq!(en_retirada.sectores[&sid].etapa, Etapa::EnRetirada);
    assert!(conservacion(&en_retirada));

    // (3) `retiro + R_V = 1 + 1 024 = 1 025` (RET-1b E6): la fianza vuelve a `Garantia.activo`, no
    //     a UTXO. A los 96 y a los 1 023 todavía no se libera.
    let (no_96, _u96) = materializar_con_undo(&en_retirada, RETIRO_SLOT + 96, &p);
    assert_eq!(
        no_96.sectores[&sid].etapa,
        Etapa::EnRetirada,
        "96 no libera con R_V vigente"
    );
    let (no_1023, _u1023) = materializar_con_undo(&en_retirada, RETIRO_SLOT + 1_023, &p);
    assert_eq!(
        no_1023.sectores[&sid].etapa,
        Etapa::EnRetirada,
        "1 023 no libera"
    );
    let (devuelto, _u0) = materializar_con_undo(&en_retirada, RETIRO_SLOT + p.r_votos_slots, &p);
    assert_eq!(devuelto.sectores[&sid].etapa, Etapa::Retirado);
    assert_eq!(devuelto.sectores[&sid].fianza, 0);
    assert_eq!(devuelto.garantias[&dueno].activo.brek(), Q_SEC);
    assert!(
        devuelto.utxo.is_empty(),
        "R_V no lleva a UTXO: vuelve a activo"
    );
    assert!(conservacion(&devuelto));

    // (4) `Retiro` autenticado: `activo → en_retirada` en el bloque 97.
    let params = params_transicion();
    let evp = ParametrosEvidencia {
        f_num: 1,
        f_den: 1,
        plazo_slots: 2,
        m_margen_slots: 0,
        cbid: 7,
        evp: true,
    };
    let slot_retiro = RETIRO_SLOT + p.r_votos_slots;
    let tx_retiro = tx_garantia(TipoGarantia::Retiro, dueno, Q_SEC, 0);
    let testigo = firma_aceptacion(&tx_retiro, 1);
    let bloque = bloque_post(
        u64::try_from(slot_retiro)?,
        productor,
        vec![(tx_retiro, vec![testigo])],
    );
    let (tras_retiro, _u1) =
        aplicar_con_undo(&devuelto, &bloque, &params, CBID_RED_DEV, &evp).expect("retiro admitido");
    assert_eq!(tras_retiro.garantias[&dueno].activo, Amount::CERO);
    assert_eq!(tras_retiro.garantias[&dueno].en_retirada.len(), 1);
    assert!(conservacion(&tras_retiro));

    // (5) Antes de UTXO: `EvidenceTx` válida en su ventana (`sf = 97`) alcanza `en_retirada`.
    let bloque_ev = bloque_post(
        u64::try_from(slot_retiro + 1)?,
        productor,
        vec![(evidencia_tx(7, 1, slot_retiro, 11, 22), Vec::new())],
    );
    let (penado, _u2) = aplicar_con_undo(&tras_retiro, &bloque_ev, &params, CBID_RED_DEV, &evp)
        .expect("evidencia admitida");
    assert!(
        penado.garantias[&dueno].en_retirada.is_empty(),
        "R4 confisca en_retirada antes de UTXO"
    );
    assert_eq!(penado.quemado, i128::from(Q_SEC) - i128::from(Q_SEC) / 4);
    assert!(conservacion(&penado));

    // (6) `Liberacion` autenticada a UTXO (ruta real; no se inyecta UTXO). RET-1a añade
    // `R_V = r_votos_slots` (dev: 1 024) **además** de `R_slots` (600): el vencimiento real es
    // `retiro + R_V`, no `retiro + R_slots`.
    let slot_liberacion = slot_retiro + p.r_votos_slots;
    let tx_liberacion = tx_garantia(TipoGarantia::Liberacion, dueno, Q_SEC, 1);
    let testigo = firma_aceptacion(&tx_liberacion, 1);
    let bloque = bloque_post(
        u64::try_from(slot_liberacion)?,
        productor,
        vec![(tx_liberacion, vec![testigo])],
    );
    let (tras_lib, _u3) = aplicar_con_undo(&tras_retiro, &bloque, &params, CBID_RED_DEV, &evp)
        .expect("liberación admitida");
    assert!(tras_lib.garantias[&dueno].en_retirada.is_empty());
    assert_eq!(tras_lib.utxo.len(), 1, "saldo a UTXO por la ruta real");
    assert_eq!(
        tras_lib.utxo.values().next().map(|e| e.valor.brek()),
        Some(Q_SEC)
    );
    assert!(conservacion(&tras_lib));

    // (7) Después de UTXO la evidencia ya no alcanza ese saldo (`V = 0`): UTXO intacto.
    let bloque_ev2 = bloque_post(
        u64::try_from(slot_liberacion + 1)?,
        productor,
        vec![(evidencia_tx(7, 1, slot_liberacion, 11, 22), Vec::new())],
    );
    let (tras_ev2, _u4) = aplicar_con_undo(&tras_lib, &bloque_ev2, &params, CBID_RED_DEV, &evp)
        .expect("evidencia admitida");
    assert_eq!(tras_ev2.quemado, tras_lib.quemado, "C = 0 sobre el UTXO");
    assert_eq!(tras_ev2.utxo.len(), 1, "el UTXO no se toca");
    assert!(conservacion(&tras_ev2));
    Ok(())
}

/// (P) Continuación auténtica por el flujo por peso: `T_1` se sella con un `0x09` de génesis, el
/// alta real de un sector deja `T_2`, `C_1` la compromete, se repite idempotente, `C_2` encadena
/// sobre `T_2` y `C_3` usa `T_3`.
#[test]
fn continuidad_de_certificados_tras_la_multa_peso() -> Result<(), Error> {
    let (mut base, secretas) = estado_conservado(&[(1, 100, Q_SEC), (2, 1, 0)])?;
    assert!(conservacion(&base), "fixture conservado");
    let p = base.parametros_sector;
    preparar_cola_sin_base(&mut base, u64::try_from(SLOT)?);

    let (t1, _) = tabla_de(&base, 1, SLOT)?;
    let h1 = hash_payload(&t1);
    let c0 = certificado_peso(&secretas, 0, &t1, [0x01; 32], h1, &[0], None)?;
    let (con_base, _, r0) = aplicar_certificado_peso_con_undo(&base, &c0, SLOT);
    r0?;

    let op_alta = OperacionSector::Alta {
        clave: ed(1),
        sector_index: 100,
        version: 0,
        r2: [0u8; 32],
        history_size: 1,
    };
    let (con_activo, res_alta) = aplicar_operacion_con_undo(&con_base, &op_alta, 0, &p);
    assert_eq!(res_alta.motivo, MotivoSector::Ok, "alta real admitida");
    assert_eq!(
        con_activo.garantias[&ed(1)].activo.brek(),
        0,
        "el alta debitó el activo"
    );
    let emitido_antes = con_activo.emitido;
    let (con_alta, _u_alta) = materializar_con_undo(&con_activo, p.m_sec, &p);
    assert_eq!(con_alta.emitido, emitido_antes, "el alta no emite");
    assert!(conservacion(&con_alta));

    let (t2, _) = tabla_de(&con_alta, 2, SLOT)?;
    assert_eq!(
        t2.iter()
            .find(|c| c.clave_bls == con_alta.claves_voto[&ed(1)].clave_bls)
            .map(|c| c.peso),
        Some(101),
        "T_2 refleja el alta real"
    );
    let h2 = hash_payload(&t2);

    let cand1 = [0x11u8; 32];
    let op1 = certificado_peso(&secretas, 1, &t1, cand1, h2, &[0], Some(&t2))?;
    // TB-1c · T3: el estado derivó T_2 tras el alta (T1), así que `h2` está en su cola `Q`. El
    // contenido se guarda en orden canónico, como lo haría `T1`.
    let mut con_alta_q = con_alta.clone();
    con_alta_q
        .tablas_voto_contenido
        .insert(h2, canoniza(t2.clone()));
    con_alta_q.cola_tablas_voto.push((0, h2));
    let f2_antes = fianza_de(&con_alta_q, &ed(2));
    let (tras1, undo1, r1) = aplicar_certificado_peso_con_undo(&con_alta_q, &op1, SLOT);
    r1?;
    assert_eq!(
        fianza_de(&tras1, &ed(2)),
        f2_antes,
        "R7: el certificado no toca la fianza"
    );
    assert_eq!(
        fuente_peso_de(&tras1, &ed(2), SLOT, &tras1.parametros_sector),
        1,
        "R7: la clave 2 sigue con peso vivo"
    );
    assert!(conservacion(&tras1));
    assert_eq!(deshacer(&tras1, &undo1), con_alta_q, "undo de C_1 exacto");
    let guardada = tras1.tablas_voto_contenido.get(&h2).ok_or("T_2")?;
    assert_eq!(
        guardada
            .iter()
            .find(|c| c.clave_bls == tras1.claves_voto[&ed(2)].clave_bls)
            .map(|c| c.peso),
        Some(1),
        "la tabla comprometida no se recalcula"
    );

    let (repetido, _, rr) = aplicar_certificado_peso_con_undo(&tras1, &op1, SLOT);
    rr?;
    assert_eq!(repetido, tras1, "C_1 repetido es idempotente");
    assert_eq!(fianza_de(&repetido, &ed(2)), f2_antes);

    let (t3, _) = tabla_de(&tras1, 3, SLOT)?;
    assert!(
        t3.iter()
            .any(|c| c.clave_bls == tras1.claves_voto[&ed(2)].clave_bls),
        "R7: T_3 conserva la clave 2"
    );
    let h3 = hash_payload(&t3);
    let op2 = certificado_peso(&secretas, 2, &t2, [0x12u8; 32], h3, &[0], Some(&t3))?;
    let (tras2, undo2, r2) = aplicar_certificado_peso_con_undo(&repetido, &op2, SLOT);
    r2?;
    assert_eq!(tras2.finalidad_votos_n, 2);
    assert!(conservacion(&tras2));
    assert_eq!(deshacer(&tras2, &undo2), repetido, "undo bit a bit de C_2");

    let op3 = certificado_peso(&secretas, 3, &t3, [0x13u8; 32], h3, &[0], None)?;
    let (tras3, undo3, r3) = aplicar_certificado_peso_con_undo(&tras2, &op3, SLOT);
    r3?;
    assert_eq!(tras3.finalidad_votos_n, 3);
    assert!(conservacion(&tras3));
    assert_eq!(deshacer(&tras3, &undo3), tras2, "undo bit a bit de C_3");
    Ok(())
}
