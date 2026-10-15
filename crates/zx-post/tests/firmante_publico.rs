//! Contrato público del firmante local y del registro (SL-4b1): las rutas independientes del
//! encargo D3, portadas de `zx-consensus/tests/firmante_local.rs` y adaptadas a la identidad
//! `RAT-1`.
//!
//! Solo usa la API pública (`zx_post::firmante`). Las pruebas de recuperación interna —corrupción,
//! cola incompleta, duplicado conflictivo, envenenamiento por fallo de sincronización, sello
//! inválido y durabilidad con proceso hijo— viven en los tests unitarios de `src/firmante/`, donde
//! la inyección de E/S existe solo en `cfg(test)`.
//!
//! Los puntos de entrada `hijo_*` están `#[ignore]` a propósito y **guardados**: el padre los
//! re-ejecuta con `--ignored --exact` y una variable de entorno; sin ella no hacen nada, así que
//! `--include-ignored` no rompe el arnés.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_zebra::{SigningKey, VerificationKey};
use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
use zx_core::{BlockHash, BodyCommitment, ClavePublica, Digest, MerkleRoot};
use zx_post::firmante::{
    Firmante, FirmanteError, IdentidadTicket, OFFSET_ABSTENCION_ACTIVA, OFFSET_ABSTENER_HASTA,
    Registro, RegistroError, Resultado, TAMANO_CABECERA,
};

static CONTADOR: AtomicU64 = AtomicU64::new(0);

struct DirTemporal {
    ruta: PathBuf,
}

impl DirTemporal {
    fn nuevo(etiqueta: &str) -> Self {
        let pid = std::process::id();
        let n = CONTADOR.fetch_add(1, Ordering::Relaxed);
        let unico = format!("zx-firmante-int-{pid}-{n}-{etiqueta}");
        let ruta = std::env::temp_dir().join(unico);
        std::fs::create_dir_all(&ruta).unwrap();
        Self { ruta }
    }

    fn ruta(&self) -> &Path {
        &self.ruta
    }
}

impl Drop for DirTemporal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.ruta);
    }
}

fn sk() -> SigningKey {
    SigningKey::from([42u8; 32])
}

fn clave_publica() -> ClavePublica {
    ClavePublica::desde_bytes(VerificationKey::from(&sk()).into())
}

/// Un candidato distinto por `padre` (y opcionalmente por `chunk`/`slot`). Cambiar el padre cambia
/// el `pre_hash` y **no** cambia la identidad de oportunidad.
fn candidato(padre: u8, chunk: u8, slot: u64) -> DagBlockHeader {
    DagBlockHeader {
        vdf_output: [0u8; 16],
        consensus_branch_id: zx_core::CBID_RED_DEV,
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x22; 32])),
        timestamp: 1_700_000_000,
        height: 10,
        slot,
        pot_output: [0x11; 16],
        rango_solucion: 7,
        sol: SolucionPoas {
            public_key: clave_publica(),
            sector_index: 1,
            history_size: 1 << 20,
            chunk: [chunk; 32],
            ..SolucionPoas::default()
        },
        body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0x33; 32])),
        padres: PadresDag::nuevo(BlockHash::from_digest(Digest::from_bytes([padre; 32])), &[])
            .unwrap(),
        sello: [0u8; 64],
    }
}

/// Registro sin abstención efectiva: `abrir` sobre fichero nuevo se abstiene hasta el slot 1 y los
/// slots de prueba van muy por encima.
fn registro_sin_abstencion(ruta: &Path) -> Registro {
    Registro::abrir(ruta, 0, 1).unwrap()
}

/// **Caso 5.** Distinto padre con el mismo billete y slot se abstiene y deja el sello intacto.
#[test]
fn distinto_padre_mismo_billete_y_slot_se_abstiene() {
    let dir = DirTemporal::nuevo("caso5");
    let reg = registro_sin_abstencion(&dir.ruta().join("r.log"));
    let f = Firmante::nuevo(&reg);

    let mut a = candidato(1, 5, 100);
    assert_eq!(f.firmar(&mut a, &sk()).unwrap(), Resultado::Sellado);
    let sello_a = a.sello;
    assert_ne!(sello_a, [0u8; 64]);
    a.verificar_sello().unwrap();

    let mut b = candidato(2, 5, 100);
    assert_ne!(a.pre_hash(), b.pre_hash());
    assert_eq!(
        Firmante::identidad(&a).huella(),
        Firmante::identidad(&b).huella()
    );
    let r = f.firmar(&mut b, &sk()).unwrap();
    assert!(
        matches!(r, Resultado::AbstenidoPorConflicto { .. }),
        "{r:?}"
    );
    assert_eq!(b.sello, [0u8; 64]);
}

/// **Caso 4.** El mismo `pre_hash` se reemite incluso tras reabrir el registro desde disco.
#[test]
fn mismo_pre_hash_se_reemite_tras_reinicio() {
    let dir = DirTemporal::nuevo("caso4");
    let ruta = dir.ruta().join("r.log");
    let sello;
    {
        let reg = registro_sin_abstencion(&ruta);
        let f = Firmante::nuevo(&reg);
        let mut a = candidato(1, 5, 100);
        assert_eq!(f.firmar(&mut a, &sk()).unwrap(), Resultado::Sellado);
        sello = a.sello;
    }

    let reg = Registro::abrir(&ruta, 100, 1).unwrap();
    assert_eq!(reg.entradas(), 1);
    let f = Firmante::nuevo(&reg);
    let mut otra_vez = candidato(1, 5, 100);
    assert_eq!(
        f.firmar(&mut otra_vez, &sk()).unwrap(),
        Resultado::Reemitido
    );
    assert_eq!(otra_vez.sello, sello);
    otra_vez.verificar_sello().unwrap();
}

/// Billete (identidad) distinto o slot distinto: la oportunidad es otra y se puede firmar.
#[test]
fn billete_o_slot_diferente_puede_firmarse() {
    let dir = DirTemporal::nuevo("billete");
    let reg = registro_sin_abstencion(&dir.ruta().join("r.log"));
    let f = Firmante::nuevo(&reg);

    let mut mismo = candidato(1, 5, 100);
    assert_eq!(f.firmar(&mut mismo, &sk()).unwrap(), Resultado::Sellado);

    // Otro `chunk` ⇒ otra identidad de billete.
    let mut otro_chunk = candidato(1, 6, 100);
    assert_ne!(
        Firmante::identidad(&mismo).huella(),
        Firmante::identidad(&otro_chunk).huella()
    );
    assert_eq!(
        f.firmar(&mut otro_chunk, &sk()).unwrap(),
        Resultado::Sellado
    );

    // Otro slot ⇒ otra oportunidad.
    let mut otro_slot = candidato(1, 5, 101);
    assert_eq!(f.firmar(&mut otro_slot, &sk()).unwrap(), Resultado::Sellado);

    assert_eq!(reg.entradas(), 3);
}

/// La clave del firmador que no corresponde a la cabecera no reserva la oportunidad.
#[test]
fn la_clave_que_no_corresponde_no_ocupa_la_oportunidad() {
    let dir = DirTemporal::nuevo("clave");
    let reg = registro_sin_abstencion(&dir.ruta().join("r.log"));
    let f = Firmante::nuevo(&reg);

    let mut a = candidato(1, 5, 100);
    let ajena = SigningKey::from([9u8; 32]);
    assert!(matches!(
        f.firmar(&mut a, &ajena).unwrap_err(),
        FirmanteError::ClaveNoCoincide
    ));
    assert_eq!(a.sello, [0u8; 64]);
    assert_eq!(reg.entradas(), 0);

    assert_eq!(f.firmar(&mut a, &sk()).unwrap(), Resultado::Sellado);
}

/// Ocho hilos con la misma oportunidad y ocho `pre_hash` distintos: **solo uno** sella.
#[test]
fn dos_hilos_no_firman_dos_hashes() {
    let dir = DirTemporal::nuevo("hilos");
    let reg = registro_sin_abstencion(&dir.ruta().join("r.log"));
    let f = Firmante::nuevo(&reg);
    let slot = 2_000u64;

    let mut cabeceras: Vec<DagBlockHeader> = (1u8..=8).map(|p| candidato(p, 3, slot)).collect();
    let huella = Firmante::identidad(&cabeceras[0]).huella();

    let resultados: Vec<Resultado> = std::thread::scope(|s| {
        let mut handles = Vec::new();
        for c in cabeceras.iter_mut() {
            let f = &f;
            handles.push(s.spawn(move || f.firmar(c, &sk()).unwrap()));
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    for c in &cabeceras {
        assert_eq!(Firmante::identidad(c).huella(), huella);
    }
    let sellados = resultados
        .iter()
        .filter(|r| matches!(r, Resultado::Sellado | Resultado::Reemitido))
        .count();
    let abstenidos = resultados
        .iter()
        .filter(|r| matches!(r, Resultado::AbstenidoPorConflicto { .. }))
        .count();
    assert_eq!(sellados, 1, "exactamente uno sella: {resultados:?}");
    assert_eq!(abstenidos, 7);
    assert_eq!(cabeceras.iter().filter(|c| c.sello != [0u8; 64]).count(), 1);
}

/// La pérdida de registro se ancla al slot actual y la abstención sobrevive a **otro** reinicio.
///
/// Adaptado a `RAT-1` (SL-4b1): la abstención por pérdida es un **resultado**
/// (`AbstenidoPorPerdida`), no un error de E/S (FIR-10 / DF-3).
#[test]
fn la_abstencion_tras_perder_el_registro_persiste_tras_reinicio() {
    let dir = DirTemporal::nuevo("abstencion");
    let ruta = dir.ruta().join("r.log");
    let s_max = 150u64;
    let slot_perdida = 1_000u64;

    // `abrir` sobre fichero inexistente: alta conservadora.
    {
        let reg = Registro::abrir(&ruta, slot_perdida, s_max).unwrap();
        assert!(reg.en_abstinencia(slot_perdida + s_max));
        assert_eq!(reg.abstener_hasta(), Some(slot_perdida + s_max));
    }

    // Primer reinicio: la abstención está en la cabecera durable.
    {
        let reg = Registro::abrir(&ruta, slot_perdida, s_max).unwrap();
        assert!(reg.en_abstinencia(slot_perdida + s_max));
    }

    // Segundo reinicio: sigue; y el slot siguiente ya se firma.
    let reg = Registro::abrir(&ruta, slot_perdida, s_max).unwrap();
    let f = Firmante::nuevo(&reg);
    let mut bloqueado = candidato(1, 9, slot_perdida + s_max);
    let r = f.firmar(&mut bloqueado, &sk()).unwrap();
    assert!(
        matches!(
            r,
            Resultado::AbstenidoPorPerdida {
                hasta,
                s_max_slots,
            } if hasta == slot_perdida + s_max && s_max_slots == s_max
        ),
        "{r:?}"
    );
    assert_eq!(bloqueado.sello, [0u8; 64]);

    let mut libre = candidato(1, 9, slot_perdida + s_max + 1);
    assert_eq!(f.firmar(&mut libre, &sk()).unwrap(), Resultado::Sellado);
    assert_ne!(libre.sello, [0u8; 64]);
    assert_eq!(reg.entradas(), 1);
}

/// La identidad `RAT-1` se deriva de la cabecera, incluido el `consensus_branch_id`.
#[test]
fn la_identidad_se_deriva_de_la_cabecera() {
    let a = candidato(1, 5, 100);
    let identidad: IdentidadTicket = Firmante::identidad(&a);
    assert_eq!(identidad.slot(), 100);
    // Mismo billete, distinto padre: misma identidad.
    assert_eq!(
        Firmante::identidad(&a).huella(),
        Firmante::identidad(&candidato(2, 5, 100)).huella()
    );
    // Distinto sector: otra identidad (se construye a mano porque `candidato` fija el sector).
    let mut b = a;
    b.sol.sector_index = 2;
    assert_ne!(
        Firmante::identidad(&a).huella(),
        Firmante::identidad(&b).huella()
    );
    // Distinta red: otra identidad (RAT-1 cierra FP8).
    let mut c = a;
    c.consensus_branch_id = a.consensus_branch_id.wrapping_add(1);
    assert_ne!(
        Firmante::identidad(&a).huella(),
        Firmante::identidad(&c).huella()
    );
}

/// Un segundo **proceso** sobre el mismo fichero no puede abrir el registro: no hay dos escritores
/// descoordinados, así que no puede firmar un segundo `pre_hash`.
#[test]
fn dos_procesos_sobre_el_mismo_fichero_no_firman_dos_hashes() {
    let dir = DirTemporal::nuevo("procesos");
    let ruta = dir.ruta().join("r.log");
    let acta = dir.ruta().join("acta.txt");

    let reg = registro_sin_abstencion(&ruta);
    let f = Firmante::nuevo(&reg);
    let mut a = candidato(1, 7, 100);
    assert_eq!(f.firmar(&mut a, &sk()).unwrap(), Resultado::Sellado);

    let salida = Command::new(std::env::current_exe().unwrap())
        .arg("--ignored")
        .arg("--exact")
        .arg("hijo_intenta_abrir_y_reporta")
        .arg("--test-threads=1")
        .env("FIRMANTE_TEST_RUTA", &ruta)
        .env("FIRMANTE_TEST_ACTA", &acta)
        .output()
        .expect("lanzar el proceso hijo");
    assert!(
        salida.status.success(),
        "el hijo falló: {:?}\n{}",
        salida.status,
        String::from_utf8_lossy(&salida.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&acta).unwrap(),
        "BLOQUEADO",
        "el segundo proceso no puede abrir el registro"
    );
    // El padre sigue con una sola firma.
    assert_eq!(reg.entradas(), 1);
}

/// Cambiar un bit de la bandera de abstención o del horizonte invalida el checksum de la cabecera:
/// `abrir` falla cerrado y no hay firma posible (FIR-06, V3).
#[test]
fn una_cabecera_manipulada_falla_cerrado_y_no_firma() {
    let slot_perdida = 1_000u64;
    let s_max = 150u64;

    for (etiqueta, offset) in [
        ("bandera", OFFSET_ABSTENCION_ACTIVA),
        ("horizonte", OFFSET_ABSTENER_HASTA),
    ] {
        let dir = DirTemporal::nuevo(&format!("cabecera-{etiqueta}"));
        let ruta = dir.ruta().join("r.log");
        {
            let reg = Registro::abrir(&ruta, slot_perdida, s_max).unwrap();
            assert!(reg.en_abstinencia(slot_perdida));
        }
        let mut bytes = std::fs::read(&ruta).unwrap();
        bytes[offset] ^= 0x01;
        std::fs::write(&ruta, &bytes).unwrap();

        assert!(
            matches!(
                Registro::abrir(&ruta, slot_perdida, s_max),
                Err(RegistroError::CabeceraCorrupta { .. })
            ),
            "{etiqueta}: un bit cambiado debe fallar cerrado"
        );
        // No se anexó ni se firmó nada: el fichero sigue midiendo solo la cabecera.
        assert_eq!(std::fs::metadata(&ruta).unwrap().len(), TAMANO_CABECERA);
    }
}

/// Un registro de formato 2 (40 B, versión 2) no se migra en silencio.
#[test]
fn un_formato_dos_no_se_migra_en_silencio() {
    let dir = DirTemporal::nuevo("formato-2");
    let ruta = dir.ruta().join("r.log");
    let mut cabecera = [0u8; TAMANO_CABECERA as usize];
    cabecera[..8].copy_from_slice(b"ZXRGFIRM");
    cabecera[8..16].copy_from_slice(&2u64.to_le_bytes());
    std::fs::write(&ruta, cabecera).unwrap();
    assert!(matches!(
        Registro::abrir(&ruta, 0, 150).unwrap_err(),
        RegistroError::VersionInvalida { encontrada: 2, .. }
    ));
}

/// El horizonte de abstención sale del `s_max_slots` que se pasa a `Registro::abrir`.
#[test]
fn la_abstencion_depende_del_perfil_de_abrir() {
    let dir = DirTemporal::nuevo("perfil");
    let corto = Registro::abrir(dir.ruta().join("corto.log"), 100, 10).unwrap();
    assert_eq!(corto.abstener_hasta(), Some(110));
    let largo = Registro::abrir(dir.ruta().join("largo.log"), 100, 20).unwrap();
    assert_eq!(largo.abstener_hasta(), Some(120));
    assert!(largo.en_abstinencia(120));
    assert!(!corto.en_abstinencia(111));
}

/// Punto de entrada del proceso hijo. **Guardado**: sin `FIRMANTE_TEST_RUTA` no hace nada.
#[test]
#[ignore = "punto de entrada para el proceso hijo"]
fn hijo_intenta_abrir_y_reporta() {
    let Some(ruta) = std::env::var_os("FIRMANTE_TEST_RUTA") else {
        return;
    };
    let acta = std::env::var("FIRMANTE_TEST_ACTA").expect("acta");
    let texto = match Registro::abrir(ruta, 0, 1) {
        Ok(_) => "ABIERTO",
        Err(RegistroError::Bloqueado { .. }) => "BLOQUEADO",
        Err(_) => "OTRO",
    };
    std::fs::write(acta, texto).unwrap();
}
