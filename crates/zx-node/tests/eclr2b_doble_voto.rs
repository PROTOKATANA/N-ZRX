//! ECL-R2b-2 · recepción ordinaria de un doble voto auténtico por la ruta de red.
//!
//! Prueba de **integración por la API pública** del motor de votos. M9-a2 · devuelta al **modo por
//! peso** (el único que queda): los sobres son `ZXV3` (252 B, sin ancla, sin VRF y sin plazas). En el
//! código viejo `recibir_voto` rechazaba `otro_candidato` **antes** de validar; por eso aquí se exige
//! que un voto ajeno con firma manipulada se rechace por su motivo criptográfico exacto
//! (`firma_falsa`), no por `otro_candidato`. Ese es el rojo que distingue la ruta nueva de la vieja
//! sin usar API nueva.
//!
//! `voto_ajeno_con_ancla_ajena_se_rechaza_por_ancla` (lista J · salida (c)) y
//! `voto_ajeno_con_vrf_ajena_se_rechaza_por_vrf_falso` (lista B) se retiran: el voto por peso no
//! tiene ancla ni VRF. La observabilidad fina de la evidencia generada (cola privada y su drenaje) y
//! la admisión real en la mempool se cubren en los tests privados de `crates/zx-node/src/votos.rs` y
//! `crates/zx-node/src/nodo.rs`, que sí pueden ver la caché y el `Nodo` cableado.

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "el test falla con panic por diseño y trocea sobres ya comprobados"
)]

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::{Estado, Garantia};
use zx_core::{Amount, BlockHash, ClavePublica as ClaveEd, Digest};
use zx_node::votos::{ConfigMotorVotos, MotorVotos, RecepcionVoto};
use zx_votos::ClaveSecreta;

const SLOT: i64 = 100;

fn bls(indice: u8) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

fn ed(indice: u8) -> ClaveEd {
    ClaveEd::desde_bytes([indice; 32])
}

fn bh(x: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([x; 32]))
}

fn h(x: u8) -> [u8; 32] {
    [x; 32]
}

/// Estado dev con la clave `ed(1)` registrada y 100 sectores activos (peso real de la fixture).
fn estado_con(n_sectores: usize) -> Estado {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let sk = bls(1);
    let pk = sk.clave_publica();
    let e = ed(1);
    est.claves_voto.insert(
        e,
        ClaveVoto {
            clave_bls: pk.bytes(),
            prueba_posesion: [0u8; 96],
        },
    );
    for i in 0..n_sectores {
        let id = SectorId {
            clave: e,
            sector_index: u16::try_from(i).expect("indice"),
            version: 0,
        };
        est.sectores.insert(
            id,
            RegistroSector {
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
            },
        );
    }
    let mut g = Garantia::nueva();
    g.activo = Amount::nuevo(1000).expect("importe");
    est.garantias.insert(e, g);
    // TB-1c-2 · X3 · sin base, el votante firma con la última huella de la cola.
    let (con_cola, _u) = zx_consensus::transicion::votos::derivar_tabla_sin_base_con_undo(
        &est,
        u64::try_from(SLOT).expect("slot"),
    );
    con_cola
}

/// Motor con la clave registrada y emisión propia activada (como el Nodo honesto), modo por peso.
fn motor(emitir: bool) -> MotorVotos {
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: zx_node::perfil::parametros_votos_dev(),
        claves: vec![bls(1)],
        emitir_votos: emitir,
    })
}

/// Abre la instancia 0 con `candidato` y devuelve el motor y sus sobres propios.
fn abrir_cero(candidato: u8, emitir: bool, est: &Estado) -> (MotorVotos, Vec<Vec<u8>>) {
    let mut m = motor(emitir);
    let paso = m.avanzar(0, bh(candidato), est, SLOT).expect("abrir 0");
    (m, paso.votos)
}

/// Un voto ajeno **válido** (misma clave, misma tabla siguiente, otro candidato) se reconoce como
/// `otro_candidato` y no se adopta: el certificado local sigue siendo el del candidato local.
#[test]
fn voto_ajeno_valido_se_rechaza_y_no_cambia_el_certificado_local() {
    let est = estado_con(100);
    let (mut receptor, _) = abrir_cero(0x10, true, &est);
    let (_ajeno, sobres) = abrir_cero(0x11, true, &est);
    let sobre = sobres.first().expect("voto ajeno");

    assert_eq!(
        receptor.recibir_voto(sobre),
        RecepcionVoto::Rechazado {
            motivo: "otro_candidato"
        }
    );

    let cierre = receptor.cerrar().expect("cierre");
    let cert = cierre.certificado_peso.expect("certificado local");
    assert_eq!(
        cert.candidato,
        h(0x10),
        "el candidato certificado es el local"
    );
    assert_eq!(cert.n, 0);
}

/// El rojo de la ruta nueva: una firma BLS falsa en un voto de **otro** candidato se detecta por su
/// motivo criptográfico (`firma_falsa`), no por el `otro_candidato` temprano del código viejo.
#[test]
fn voto_ajeno_con_firma_falsa_se_rechaza_por_firma_falsa() {
    let est = estado_con(100);
    let (mut receptor, _) = abrir_cero(0x10, true, &est);
    let (_ajeno, sobres) = abrir_cero(0x11, true, &est);
    let mut sobre = sobres.first().expect("voto ajeno").clone();
    // Firma BLS válida de otro mensaje: punto correcto, mensaje distinto (layout `ZXV3`).
    let firma_ajena =
        zx_votos::firmar(&bls(1), zx_votos::DOMINIO_VOTO, b"otro mensaje").expect("firma");
    // M9-a2 · el voto por peso ZXV3 mide 252 B: firma BLS en `156..252`.
    sobre[156..252].copy_from_slice(&firma_ajena.bytes());

    assert_eq!(
        receptor.recibir_voto(&sobre),
        RecepcionVoto::Rechazado {
            motivo: "firma_falsa"
        }
    );
}

/// Control **futuro** genuino: un sobre que declara `n = 1` cuando la instancia abierta es `0` se
/// encola como pendiente y se rechaza por `ventana` (no es una ventana pasada; ECL-R2b-3 lo etiquetó
/// mal y ECL-R2b-4 lo renombra).
#[test]
fn voto_de_ventana_futura_se_encola_y_se_rechaza() {
    let est = estado_con(100);
    let (mut receptor, _) = abrir_cero(0x10, true, &est);
    let (_ajeno, sobres) = abrir_cero(0x11, true, &est);
    let mut sobre = sobres.first().expect("voto ajeno").clone();
    // Instancia 0 -> se declara de la instancia 1 (futura; la firma quedaría inválida, pero la
    // ventana se comprueba antes de la criptografía). `n` va tras los 4 B de cabecera de ZXV3.
    sobre[4..12].copy_from_slice(&1u64.to_be_bytes());

    assert_eq!(
        receptor.recibir_voto(&sobre),
        RecepcionVoto::Rechazado { motivo: "ventana" }
    );
}

/// **Ventana pasada genuina**: el receptor ya abrió la instancia `1` y recibe un sobre auténtico de
/// la instancia `0` de otra clave; se descarta por `ventana`, sin mutar `0→1` ni llamar pasado a un
/// control futuro.
#[test]
fn voto_de_ventana_pasada_genuina_se_descarta() {
    let est = estado_con(100);
    let (mut receptor, _) = abrir_cero(0x10, true, &est);
    let (_ajeno, sobres0) = abrir_cero(0x11, true, &est);
    let sobre0 = sobres0.first().expect("voto de la instancia 0").clone();
    let _ = receptor
        .avanzar(1, bh(0x12), &est, SLOT)
        .expect("abrir la instancia 1");

    assert_eq!(
        receptor.recibir_voto(&sobre0),
        RecepcionVoto::Rechazado { motivo: "ventana" }
    );
}
