#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "pruebas con fallo por panic y accesos a vectores de tamano fijo ya comprobados"
)]

use super::*;
use crate::claves::ClaveDev;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::{
    BloqueTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, Undo, aplicar_con_undo,
};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, OperacionAlmacenamiento};
use zx_votos::ClaveSecreta;

const N_AUS2B: u64 = 1;

fn bls(i: u8) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[0] = i;
    ikm[31] = 0xA5;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

fn bh(b: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([b; 32]))
}

fn params_aus2b() -> ParametrosTransicion {
    perfil::parametros_transicion_dev().expect("perfil")
}

fn param_evidencia_aus2b() -> ParametrosEvidencia {
    ParametrosEvidencia::inactiva()
}

fn motor_aus2b(sk: ClaveSecreta) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: perfil::parametros_votos_dev(),
        claves: vec![sk],
        emitir_votos: true,
    })
}

/// Nodo de prueba con las claves `indices` (mismo arranque que `nodo_de_prueba`).
fn nodo_aus2b(dir: &std::path::Path, indices: Vec<u32>) -> Nodo {
    let cfg = Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 1,
        indices_claves: indices,
        n_dev: 16,
        sr_dev: u64::MAX,
        perfil_red: perfil::perfil_red_dev(),
        parada_tras_slots: Some(0),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    };
    Nodo::arrancar(&cfg).expect("arranque limpio")
}

/// Estado PoST con `claves` registradas (BLS `secretas`), `n_sectores` activos cada una y
/// garantía activa `g`.
fn estado_con_claves(
    claves: &[ClaveDev],
    secretas: &[ClaveSecreta],
    n_sectores: usize,
    g: i64,
) -> Estado {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    for (c, sk) in claves.iter().zip(secretas) {
        est.claves_voto.insert(
            c.pk,
            ClaveVoto {
                clave_bls: sk.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for i in 0..n_sectores {
            let id = SectorId {
                clave: c.pk,
                sector_index: u16::try_from(i).expect("indice"),
                version: 0,
            };
            est.sectores.insert(
                id,
                RegistroSector {
                    id,
                    r2: [0u64; 4],
                    history_size: 1,
                    etapa: Etapa::Activo,
                    alta_slot: 0,
                    renovacion_slot: 0,
                    retiro_slot: -1,
                    fianza: p.q_sec,
                    aud_apertura: -1,
                    aud_contestada: -1,
                },
            );
        }
        let mut gg = Garantia::nueva();
        gg.activo = Amount::nuevo(g).expect("importe");
        est.garantias.insert(c.pk, gg);
    }
    est
}

fn cadena_con_estado(est: Estado, cbid: u32) -> zx_cadena::Cadena {
    zx_cadena::Cadena::nueva_con_evidencia_e_inicial(
        params_aus2b(),
        perfil::ghostdag_k(),
        cbid,
        perfil::ghostdag_max_padres(),
        param_evidencia_aus2b(),
        est,
    )
}

fn post_con_txs(
    est: &Estado,
    slot: u64,
    b: u8,
    txs: Vec<(Tx, Vec<Vec<u8>>)>,
    productor: ClavePublica,
) -> (Estado, Undo) {
    let bloque = BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: bh(b),
            padre: bh(b.wrapping_add(1)),
            slot,
            productor,
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        txs,
    );
    aplicar_con_undo(
        est,
        &bloque,
        &params_aus2b(),
        zx_core::CBID_RED_DEV,
        &param_evidencia_aus2b(),
    )
    .expect("bloque PoST admitido")
}

fn firma_voto(sk: &ClaveSecreta, n: u64, candidato: [u8; 32], h_t: [u8; 32]) -> [u8; 96] {
    let firma = zx_votos::firmar(
        sk,
        zx_votos::DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &candidato, &h_t, &[0u8; 32]),
    )
    .expect("firma");
    firma.bytes()
}

fn pendiente_voto_propio(
    c: &ClaveDev,
    sk: &ClaveSecreta,
    n: u64,
    candidato: [u8; 32],
    h_t: [u8; 32],
    cbid: u32,
) -> PendienteV6 {
    let payload = crate::votos::VotoPropioPayload {
        n,
        candidato,
        h_t_siguiente: h_t,
        raiz_estado: [0u8; 32],
        clave_bls: sk.clave_publica().bytes(),
        firma: firma_voto(sk, n, candidato, h_t),
    };
    let (tx, testigos) = crate::votos::tx_voto_propio(&payload, c.pk, &c.sk, cbid);
    let txid_ = txid(&tx, cbid);
    PendienteV6 {
        propia: true,
        clase: CLASE_VOTO_PROPIO,
        n,
        clave: c.pk,
        desde_slot: cierre_ventana(n).saturating_add(G_SLOTS_VOTOS),
        hasta_slot: cierre_ventana(n).saturating_add(W_REVEAL_SLOTS_VOTOS),
        firmantes_acta: Vec::new(),
        tx,
        testigos,
        txid: txid_,
        difundida: false,
        acta_aplicada: false,
    }
}

fn tabla_de_claves(
    claves: &[ClaveDev],
    secretas: &[ClaveSecreta],
    peso: u64,
) -> Vec<ClaveTablaVoto> {
    claves
        .iter()
        .zip(secretas)
        .map(|(_c, sk)| ClaveTablaVoto {
            clave_bls: sk.clave_publica().bytes(),
            peso,
            activo: true,
            prueba: false,
            garantia: peso,
        })
        .collect()
}

/// B1 · tras emitir el voto de `n` queda una `VotoPropio` propia pendiente con los plazos
/// `[cierre+G, cierre+W]` y la **misma** firma BLS del voto emitido.
#[test]
fn b1_al_emitir_el_voto_queda_voto_propio_pendiente_con_sus_plazos_y_firma() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_aus2b(dir.path(), vec![0]);
    let c = nodo.claves[0].clone();
    let sk = bls(1);
    let est = estado_con_claves(
        std::slice::from_ref(&c),
        std::slice::from_ref(&sk),
        100,
        1_000,
    );
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (est, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(&est, 2);
    let cbid = nodo.cbid;
    let candidato = bh(0xAB);
    nodo.cadena = cadena_con_estado(est.clone(), cbid);
    nodo.motor_votos = Some(motor_aus2b(bls(1)));
    nodo.candidato_votos_simulado = Some(candidato);
    nodo.slot_votos_simulado = Some(2);
    nodo.procesar_votos().expect("procesar_votos");

    let p = nodo
        .v6_pendientes
        .iter()
        .find(|p| p.clase == CLASE_VOTO_PROPIO)
        .expect("VotoPropio pendiente tras emitir");
    assert_eq!(p.n, N_AUS2B);
    assert_eq!(p.clave, c.pk);
    assert!(p.propia, "es de este nodo");
    assert_eq!(p.desde_slot, cierre_ventana(N_AUS2B) + G_SLOTS_VOTOS);
    assert_eq!(p.hasta_slot, cierre_ventana(N_AUS2B) + W_REVEAL_SLOTS_VOTOS);

    let firma_tx = match &p.tx.extension {
        ExtensionTx::PruebaAlmacenamiento { operacion } => match operacion {
            OperacionAlmacenamiento::VotoPropio { firma, .. } => *firma,
            _ => panic!("la pendiente no es un VotoPropio"),
        },
        _ => panic!("extension inesperada"),
    };
    // El motor es determinista: un segundo motor con la misma clave firma el mismo voto.
    let mut motor2 = motor_aus2b(bls(1));
    let paso2 = motor2
        .avanzar_con_vista(N_AUS2B, candidato, &est, 2, &nodo.cadena)
        .expect("motor");
    let voto = crate::votos::deserializar_voto_peso(&paso2.votos[0]).expect("voto");
    assert_eq!(
        firma_tx,
        voto.firma.bytes(),
        "la firma BLS es la del voto emitido"
    );
}

// B2 (AUS-2b) se sustituye por C1 (AUS-2c). La aserción de B2 montaba `estado_terminal()` con
// la clave ya admitida, es decir, el mismo estado equivocado que AUS-2c corrige; con el estado
// aplicado de la ventana el caso lo cubre C1 sobre una cadena PoST **real**, que además
// comprueba que `estado_terminal()` no basta. Lista de aserciones cambiadas: B2 → C1.

/// B3 · ventana que cierra sin certificado: dos votos propios se incluyen en un bloque de slot
/// `≥ cierre + G` y quedan aplicados; al liquidar, **solo** el tercero acumula deuda.
#[test]
fn b3_ventana_sin_certificado_solo_paga_quien_no_publico_su_voto() {
    let claves: Vec<ClaveDev> = (0..3).map(|i| ClaveDev::derivar(1, i)).collect();
    let secretas: Vec<ClaveSecreta> = (1..=3).map(bls).collect();
    let cbid = zx_core::CBID_RED_DEV;
    let n = N_AUS2B;
    let mut est = estado_con_claves(&claves, &secretas, 100, 1_000);
    est.tablas_voto
        .insert(n, tabla_de_claves(&claves, &secretas, 100));

    let pendientes: Vec<PendienteV6> = claves
        .iter()
        .zip(&secretas)
        .take(2)
        .map(|(c, sk)| pendiente_voto_propio(c, sk, n, [0x11; 32], [0x22; 32], cbid))
        .collect();
    let slot_inc = cierre_ventana(n) + G_SLOTS_VOTOS;
    let incluidas = votos_propios_para_bloque(&pendientes, &est, slot_inc);
    assert_eq!(incluidas.len(), 2, "caben las dos en plazo");
    let (con_votos, _undo) = post_con_txs(&est, slot_inc, 0x40, incluidas, claves[0].pk);
    let votantes = con_votos.votantes_voto.get(&n).cloned().unwrap_or_default();
    assert!(votantes.contains(&claves[0].pk) && votantes.contains(&claves[1].pk));
    assert!(!votantes.contains(&claves[2].pk));

    let slot_liq = cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 1;
    let (final_, _undo) = post_con_txs(&con_votos, slot_liq, 0x50, Vec::new(), claves[0].pk);
    let d = |i: usize| {
        final_
            .deuda_ausencia
            .get(&claves[i].pk)
            .copied()
            .unwrap_or(0)
    };
    assert_eq!(d(0), 0, "quien publicó su voto no acumula deuda");
    assert_eq!(d(1), 0, "quien publicó su voto no acumula deuda");
    assert!(d(2) > 0, "solo el tercero acumula deuda");
}

/// B4 · con base aplicada, las `VotoPropio` pendientes **no** se borran; compromisos y
/// revelaciones sí.
#[test]
fn b4_con_base_aplicada_se_conserva_el_voto_propio_y_se_podan_los_demas() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_aus2b(dir.path(), vec![0]);
    let c = nodo.claves[0].clone();
    let sk = bls(1);
    let mut est = estado_con_claves(
        std::slice::from_ref(&c),
        std::slice::from_ref(&sk),
        100,
        1_000,
    );
    est.finalidad_votos_n = 0;
    est.finalidad_votos_h_t = Some([0xEE; 32]);
    let cbid = nodo.cbid;
    nodo.cadena = cadena_con_estado(est, cbid);
    let bls_bytes = sk.clave_publica().bytes();
    let n = N_AUS2B;
    let tx_voto = crate::votos::tx_voto_propio(
        &crate::votos::VotoPropioPayload {
            n,
            candidato: [0x11; 32],
            h_t_siguiente: [0x22; 32],
            raiz_estado: [0u8; 32],
            clave_bls: bls_bytes,
            firma: [0u8; 96],
        },
        c.pk,
        &c.sk,
        cbid,
    )
    .0;
    nodo.encolar_v6(tx_voto, vec![], true);
    // M9-a2 · la mitad de **compromisos y revelaciones** de esta prueba desaparece: el nodo ya
    // no encola `0x06`/`0x07` (M9-a los retiró del flujo del nodo). Se conserva la mitad del
    // voto propio `0x08`, que es la que sigue viva.
    assert_eq!(
        nodo.v6_pendientes.len(),
        1,
        "solo la pendiente del voto propio"
    );

    nodo.procesar_v6_pendientes(100);
    assert_eq!(nodo.v6_pendientes.len(), 1, "solo sobrevive el voto propio");
    assert_eq!(nodo.v6_pendientes[0].clase, CLASE_VOTO_PROPIO);
}

/// B5 · el encaje de N4 respeta el tope del cuerpo: con el presupuesto lleno no entra ninguna;
/// con hueco, entran las que caben.
#[test]
fn b5_el_encaje_respeta_el_tope_del_cuerpo() {
    let c = ClaveDev::derivar(1, 0);
    let sk = bls(1);
    let cbid = zx_core::CBID_RED_DEV;
    let p = pendiente_voto_propio(&c, &sk, N_AUS2B, [0x11; 32], [0x22; 32], cbid);
    let candidatos = vec![(p.tx.clone(), p.testigos.clone())];
    let mut buf = Vec::new();
    zx_core::wire::tx_a_bytes(&mut buf, &p.tx, &p.testigos);
    let tam = buf.len() as u64;
    let dos = vec![
        (p.tx.clone(), p.testigos.clone()),
        (p.tx.clone(), p.testigos.clone()),
    ];

    assert!(
        encajar_votos_propios(dos.clone(), 2 * tam, 2 * tam).is_empty(),
        "mempool llena: no entra ninguna"
    );
    assert_eq!(
        encajar_votos_propios(dos.clone(), 2 * tam, tam).len(),
        1,
        "con hueco para una, entra una"
    );
    assert_eq!(
        encajar_votos_propios(dos, 2 * tam, 0).len(),
        2,
        "con hueco para dos, entran las dos"
    );
    let _ = candidatos;
}

/// B6 · un bloque propio nunca lleva una `VotoPropio` fuera de plazo ni duplicada; el bloque
/// que las incluye se admite.
#[test]
fn b6_no_incluye_fuera_de_plazo_ni_duplicada_y_el_bloque_se_admite() {
    let claves: Vec<ClaveDev> = (0..2).map(|i| ClaveDev::derivar(1, i)).collect();
    let secretas: Vec<ClaveSecreta> = (1..=2).map(bls).collect();
    let cbid = zx_core::CBID_RED_DEV;
    let n = N_AUS2B;
    let mut est = estado_con_claves(&claves, &secretas, 100, 1_000);
    est.tablas_voto
        .insert(n, tabla_de_claves(&claves, &secretas, 100));

    let en_plazo = pendiente_voto_propio(&claves[0], &secretas[0], n, [0x11; 32], [0x22; 32], cbid);
    // Misma `(clave, n)` con otra firma/candidato: es una duplicada.
    let duplicada =
        pendiente_voto_propio(&claves[0], &secretas[0], n, [0x33; 32], [0x44; 32], cbid);
    // Fuera de plazo: `desde` posterior al slot objetivo.
    let mut vencida =
        pendiente_voto_propio(&claves[1], &secretas[1], n, [0x11; 32], [0x22; 32], cbid);
    vencida.desde_slot = cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + 5;
    vencida.hasta_slot = vencida.desde_slot;
    let pendientes = vec![en_plazo, duplicada, vencida];

    let slot = cierre_ventana(n) + G_SLOTS_VOTOS;
    let incluidas = votos_propios_para_bloque(&pendientes, &est, slot);
    assert_eq!(
        incluidas.len(),
        1,
        "una sola: ni duplicada ni fuera de plazo"
    );
    let (con_voto, _undo) = post_con_txs(&est, slot, 0x60, incluidas, claves[0].pk);
    assert!(
        con_voto
            .votantes_voto
            .get(&n)
            .is_some_and(|v| v.contains(&claves[0].pk)),
        "el bloque con la única VotoPropio se admite"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// AUS-2c · pruebas C1–C4 de la corrección (K1–K4). Cada una muerde con AUS-2b.
// ─────────────────────────────────────────────────────────────────────────

/// AUS-2c · C1 · Cadena **real** en fase PoST con un bloque que **aplica** un `VotoPropio` de
/// `c` en la ventana `n` (con su coinbase). El `estado_terminal()` (corte PoW) queda sin
/// `votantes_voto[n]`.
fn cadena_real_con_voto_aplicado(
    c: &ClaveDev,
    sk: &ClaveSecreta,
    n: u64,
    cbid: u32,
) -> zx_cadena::Cadena {
    fn subsidio_pow(_: u32) -> Amount {
        Amount::nuevo(10).expect("importe")
    }
    fn subsidio_post(_: u64) -> Amount {
        Amount::nuevo(3).expect("importe")
    }
    let params = ParametrosTransicion {
        h_dep: 1,
        m_cb: 1,
        m_dep: 0,
        h_corte_min: 1,
        w_min: U256::one(),
        s_min: Amount::CERO,
        q: Amount::CERO,
        k_min: 0,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 1,
        f_slots: None,
        subsidio_pow,
        subsidio_post,
    };
    let mut est = estado_con_claves(
        std::slice::from_ref(c),
        std::slice::from_ref(sk),
        100,
        1_000,
    );
    // El génesis solo se admite desde `Fase::Genesis`; la cadena pasa a PoST al cortar el PoW.
    est.fase = Fase::Genesis;
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        params,
        perfil::ghostdag_k(),
        cbid,
        perfil::ghostdag_max_padres(),
        ParametrosEvidencia::inactiva(),
        est,
    );
    cadena
        .admitir(super::pruebas_eclr2::genesis())
        .expect("génesis");
    cadena
        .admitir(super::pruebas_eclr2::pow_terminal(1, 1))
        .expect("pow terminal");
    let payload = crate::votos::VotoPropioPayload {
        n,
        candidato: [0x11; 32],
        h_t_siguiente: [0x22; 32],
        raiz_estado: [0u8; 32],
        clave_bls: sk.clave_publica().bytes(),
        firma: firma_voto(sk, n, [0x11; 32], [0x22; 32]),
    };
    let (tx, tst) = crate::votos::tx_voto_propio(&payload, c.pk, &c.sk, cbid);
    let slot = zx_consensus::transicion::votos::apertura_ventana(n);
    let coinbase = super::pruebas_eclr2::tx_coinbase_post(c.pk, 1, slot);
    let bloque = super::pruebas_eclr2::post_con_txs(
        10,
        vec![super::pruebas_eclr2::hash_u32(1)],
        slot,
        10,
        c.pk,
        vec![(coinbase, Vec::new()), (tx, tst)],
    );
    cadena
        .admitir(bloque)
        .expect("bloque PoST con VotoPropio aplicado");
    // Bloque hijo: el candidato de la ventana se lee con `estado_past` (estado **antes** del
    // bloque), así que el voto aplicado tiene que quedar en un ancestro del candidato.
    let bloque_candidato = super::pruebas_eclr2::post_con_txs(
        11,
        vec![super::pruebas_eclr2::hash_u32(10)],
        slot + 1,
        10,
        c.pk,
        vec![(
            super::pruebas_eclr2::tx_coinbase_post(c.pk, 1, slot + 1),
            Vec::new(),
        )],
    );
    cadena
        .admitir(bloque_candidato)
        .expect("bloque PoST candidato");
    cadena
}

/// C1 · Parte 1 de la pregunta. El voto propio de la ventana `n` ya está aplicado en un bloque
/// PoST (`estado_terminal()` no lo tiene); el nodo **no** difunde su `VotoPropio` y registra
/// `voto_propio_descartado` con motivo `en_certificado`. Con AUS-2b la difundía.
#[test]
fn c1_el_voto_ya_aplicado_no_se_difunde_y_se_descarta_en_certificado() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_aus2b(dir.path(), vec![0]);
    let c = nodo.claves[0].clone();
    let sk = bls(1);
    let cbid = nodo.cbid;
    let n = N_AUS2B;
    nodo.cadena = cadena_real_con_voto_aplicado(&c, &sk, n, cbid);
    assert!(
        !nodo
            .cadena
            .estado_terminal()
            .votantes_voto
            .get(&n)
            .is_some_and(|v| v.contains(&c.pk)),
        "el corte PoW no contiene el voto aplicado"
    );
    // Abre la ventana 4 (t=2, LAG=4): su candidato es el bloque hijo del que aplicó el
    // `VotoPropio` de la ventana 1, de modo que `estado_past(candidato)` ya lo contiene.
    let t = perfil::parametros_votos_dev().t_inst.max(1);
    nodo.motor_votos = Some(motor_aus2b(sk));
    nodo.slot_votos_simulado = Some(4 * t);
    nodo.procesar_votos()
        .expect("abrir ventana y fijar estado de ventana");
    // Encola la `VotoPropio` propia de la ventana 1 (aún sin difundir).
    let p = pendiente_voto_propio(&c, &bls(1), n, [0x11; 32], [0x22; 32], cbid);
    nodo.encolar_v6(p.tx, p.testigos, true);
    // Una vuelta dentro del plazo: decide con el estado aplicado de la ventana abierta.
    nodo.procesar_v6_pendientes(cierre_ventana(n) + G_SLOTS_VOTOS);
    assert!(
        nodo.v6_pendientes
            .iter()
            .all(|p| !(p.clase == CLASE_VOTO_PROPIO && p.n == n)),
        "la propia ya aplicada se retira"
    );
    let registro = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    assert!(
        !registro.contains("\"tipo\":\"voto_propio_difundido\""),
        "no se difunde lo que ya consta: {registro}"
    );
    assert!(
        registro.contains("\"tipo\":\"voto_propio_descartado\"")
            && registro.contains("\"motivo\":\"en_certificado\""),
        "se registra el descarte en_certificado: {registro}"
    );
}

// C2 (`c2_solo_voto_propio_no_consulta_el_estado_virtual`) se **retira** (M9-a2 · lista J,
// salida (c)): la llamada a `Cadena::estado_virtual()` que vigilaba vivía en el bloque de
// compromisos y revelaciones que M9-a quitó de `procesar_v6_pendientes`; la función ya no la
// hace y el contador `ESTADO_VIRTUAL_DESDE_V6` (que nadie incrementaba) se ha retirado (T4d).

/// C3 · 100 vueltas dentro del plazo con el voto sin aplicar producen **una** difusión.
#[test]
fn c3_difusion_unica_en_cien_vueltas() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_aus2b(dir.path(), vec![0]);
    let c = nodo.claves[0].clone();
    let cbid = nodo.cbid;
    let n = N_AUS2B;
    let p = pendiente_voto_propio(&c, &bls(1), n, [0x11; 32], [0x22; 32], cbid);
    nodo.encolar_v6(p.tx, p.testigos, true);
    let antes = DIFUSIONES_TX_PROPIAS.with(std::cell::Cell::get);
    let slot = cierre_ventana(n) + G_SLOTS_VOTOS;
    for _ in 0..100 {
        nodo.procesar_v6_pendientes(slot);
    }
    let despues = DIFUSIONES_TX_PROPIAS.with(std::cell::Cell::get);
    assert_eq!(
        despues - antes,
        1,
        "una sola difusión en 100 vueltas dentro del plazo"
    );
    let registro = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    assert_eq!(
        registro
            .matches("\"tipo\":\"voto_propio_difundido\"")
            .count(),
        1,
        "un solo evento de difusión"
    );
}

/// C4a · difundido y después aplicado → `voto_propio_aplicado` (no `en_certificado`).
#[test]
fn c4a_difundido_y_aplicado_etiqueta_aplicado() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_aus2b(dir.path(), vec![0]);
    let c = nodo.claves[0].clone();
    let cbid = nodo.cbid;
    let n = N_AUS2B;
    let p = pendiente_voto_propio(&c, &bls(1), n, [0x11; 32], [0x22; 32], cbid);
    nodo.encolar_v6(p.tx, p.testigos, true);
    let slot_dif = cierre_ventana(n) + G_SLOTS_VOTOS;
    nodo.procesar_v6_pendientes(slot_dif);
    // El estado aplicado de la ventana pasa a incluir la clave: se descarta como aplicado (y no
    // como `en_certificado`, porque ya se había difundido). Se fija por el mismo camino que en
    // producción: `procesar_votos` con el estado terminal ya con el voto.
    let mut con_voto = estado_con_claves(std::slice::from_ref(&c), &[bls(1)], 100, 1_000);
    con_voto.finalidad_votos_n = n;
    con_voto.finalidad_votos_h_t = Some([0xCD; 32]);
    con_voto.votantes_voto.entry(n).or_default().insert(c.pk);
    nodo.cadena = cadena_con_estado(con_voto, cbid);
    nodo.motor_votos = Some(motor_aus2b(bls(1)));
    nodo.candidato_votos_simulado = Some(bh(0xAC));
    nodo.slot_votos_simulado = Some(2);
    nodo.procesar_votos().expect("fijar estado de ventana");
    nodo.procesar_v6_pendientes(slot_dif);
    let registro = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    assert!(
        registro.contains("\"tipo\":\"voto_propio_aplicado\""),
        "difundido y aplicado → voto_propio_aplicado: {registro}"
    );
}

/// C4b · nunca aplicado → `voto_propio_descartado` con motivo `vencido` tras
/// `hasta_slot + LAG_CANDIDATO_VOTOS`.
#[test]
fn c4b_nunca_aplicado_etiqueta_vencido() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_aus2b(dir.path(), vec![0]);
    let c = nodo.claves[0].clone();
    let cbid = nodo.cbid;
    let n = N_AUS2B;
    let p = pendiente_voto_propio(&c, &bls(1), n, [0x11; 32], [0x22; 32], cbid);
    nodo.encolar_v6(p.tx, p.testigos, true);
    let slot_venc = cierre_ventana(n) + W_REVEAL_SLOTS_VOTOS + LAG_CANDIDATO_VOTOS + 1;
    nodo.procesar_v6_pendientes(slot_venc);
    assert!(
        nodo.v6_pendientes.is_empty(),
        "se retira al vencer con el retardo del candidato"
    );
    let registro = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    assert!(
        registro.contains("\"tipo\":\"voto_propio_descartado\"")
            && registro.contains("\"motivo\":\"vencido\""),
        "nunca aplicado → vencido: {registro}"
    );
}

/// VS-2 · W8 · V5 · el acta `0x0A` deja rastro al encolarse (`acta_peso_encolada`), al constar
/// todos sus firmantes (`acta_peso_aplicada`) y el descarte de un voto propio porque la clave
/// consta por un acta en una ventana **sin** certificado se etiqueta `en_acta`.
#[test]
fn w8_eventos_del_acta_y_motivo_en_acta() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nodo = nodo_aus2b(dir.path(), vec![0]);
    let c = nodo.claves[0].clone();
    let cbid = nodo.cbid;
    let n = N_AUS2B;

    // Acta `0x0A` sintética: solo importa `n` en los 8 primeros bytes.
    let mut bytes = vec![0u8; 96];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    let acta_tx = Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento {
            operacion: OperacionAlmacenamiento::ActaPresencia { clave: c.pk, bytes },
        },
    };
    nodo.encolar_v6_con_firmantes(acta_tx, Vec::new(), true, vec![c.pk], 1);
    let registro = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    assert!(
        registro.contains("\"tipo\":\"acta_peso_encolada\""),
        "el acta deja rastro al encolarse: {registro}"
    );

    // La ventana no tiene certificado; el estado aplicado ya tiene a la clave por el acta.
    let mut votantes = BTreeMap::new();
    let mut conjunto = BTreeSet::new();
    conjunto.insert(c.pk);
    votantes.insert(n, conjunto);
    nodo.votantes_voto_ventana = Some(votantes);
    let p = pendiente_voto_propio(&c, &bls(1), n, [0x11; 32], [0x22; 32], cbid);
    nodo.encolar_v6(p.tx, p.testigos, true);
    nodo.procesar_v6_pendientes(cierre_ventana(n) + G_SLOTS_VOTOS);

    let registro = std::fs::read_to_string(dir.path().join("registro.jsonl")).expect("registro");
    assert!(
        registro.contains("\"tipo\":\"acta_peso_aplicada\""),
        "el acta aplicada deja rastro: {registro}"
    );
    assert!(
        registro.contains("\"tipo\":\"voto_propio_descartado\"")
            && registro.contains("\"motivo\":\"en_acta\""),
        "el descarte por acta se etiqueta en_acta: {registro}"
    );
    assert!(
        !registro.contains("\"motivo\":\"en_certificado\""),
        "no se confunde con en_certificado: {registro}"
    );
}

/// RE-2c · R6 · la `Tx` `0x08` que arma el nodo (`tx_voto_propio`) lleva la raíz del payload, tanto
/// en su operación como tras el códec canónico.
#[test]
fn t_raiz_12_tx_voto_propio_lleva_la_raiz() {
    let c = ClaveDev::derivar(1, 0);
    let sk = bls(1);
    let raiz = [0x77u8; 32];
    let payload = crate::votos::VotoPropioPayload {
        n: N_AUS2B,
        candidato: [0x11; 32],
        h_t_siguiente: [0x22; 32],
        raiz_estado: raiz,
        clave_bls: sk.clave_publica().bytes(),
        firma: [0u8; 96],
    };
    let (tx, _tst) = crate::votos::tx_voto_propio(&payload, c.pk, &c.sk, zx_core::CBID_RED_DEV);
    let ExtensionTx::PruebaAlmacenamiento { operacion } = &tx.extension else {
        panic!("extensión de prueba de almacenamiento");
    };
    let OperacionAlmacenamiento::VotoPropio { raiz_estado, .. } = operacion else {
        panic!("0x08");
    };
    assert_eq!(*raiz_estado, raiz, "la operación lleva la raíz del payload");

    let bytes = operacion.bytes_canonicos().expect("códec");
    let (vuelta, consumidos) =
        OperacionAlmacenamiento::desde_canonica(&bytes).expect("ida y vuelta");
    assert_eq!(consumidos, bytes.len());
    let OperacionAlmacenamiento::VotoPropio { raiz_estado, .. } = vuelta else {
        panic!("0x08 tras el códec");
    };
    assert_eq!(raiz_estado, raiz, "la raíz sobrevive al códec");
}
