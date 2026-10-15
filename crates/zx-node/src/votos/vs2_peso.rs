//! VS-2 · pruebas del motor en modo peso: voto tardío (V3, W3), descender de lo sellado (V6, W9) y
//! el caso del salto castigable (W10). W9 y W10 usan la `zx_cadena::Cadena` **real** del fixture
//! `crate::nodo::pruebas_at1a2_fixture`.
//!
//! No abre instancia: llama directo a `MotorVotos::votar_tardio`, que es el camino que el nodo usa
//! para recuperar una ventana saltada.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "pruebas de escenarios con estados construidos a mano; fallan con panic por diseño"
)]

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::T_INST_VOTOS;
use zx_consensus::transicion::{Estado, Fase, Garantia};
use zx_core::{Amount, BlockHash, ClavePublica};
use zx_votos::{ClaveSecreta, DOMINIO_VOTO};

use super::{
    ConfigMotorVotos, DiarioVotos, MotorVotos, RAIZ_ESTADO_CERO, VistaCadena, construir_tabla,
};

type Error = Box<dyn std::error::Error>;
type Hash = zx_votos::Hash;

fn bls(indice: u8) -> ClaveSecreta {
    let mut ikm = [0u8; 32];
    ikm[0] = indice;
    ikm[31] = 0xA5;
    ClaveSecreta::generar(&ikm).expect("clave BLS")
}

fn ed(indice: u8) -> ClavePublica {
    ClavePublica::desde_bytes([indice; 32])
}

fn clave_bls_de(sk: &ClaveSecreta) -> [u8; 48] {
    <[u8; 48]>::try_from(sk.clave_publica().bytes().as_slice()).expect("clave BLS de 48 B")
}

fn hash(indice: u8) -> Hash {
    [indice; 32]
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
        // Renovación lejana: los sectores siguen vigentes en slots altos (W10 usa k ≈ 300).
        renovacion_slot: 1_000_000,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    };
    (id, reg)
}

/// Estado PoST con `(clave, nº de sectores, activo de la garantía)` por clave.
fn estado_sectores(claves: &[(u8, u16, i64)]) -> Estado {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    est.fase = Fase::PoST;
    for (i, n_sectores, activo) in claves {
        let s = bls(*i);
        est.claves_voto.insert(
            ed(*i),
            ClaveVoto {
                clave_bls: s.clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        for k in 0..*n_sectores {
            let (id, reg) = registro(&p, ed(*i), k);
            est.sectores.insert(id, reg);
        }
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(*activo).expect("importe");
        est.garantias.insert(ed(*i), g);
    }
    est
}

fn motor_peso(indices: &[u8], emitir: bool) -> MotorVotos {
    let claves = indices.iter().map(|i| bls(*i)).collect();
    MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves,
        emitir_votos: emitir,
    })
}

fn diario(dir: &std::path::Path) -> DiarioVotos {
    DiarioVotos::nueva(dir.join("vs2.registro"), 0).expect("diario")
}

fn cand(indice: u8) -> Hash {
    hash(indice)
}

/// Vista que niega la cadena seleccionada y el descenso, pero conoce el DAG. Para el caso del slot
/// de la ventana tardía.
struct VistaFuera;
impl VistaCadena for VistaFuera {
    fn desciende(&self, _c: &Hash, _a: &Hash) -> bool {
        false
    }
    fn en_cadena_seleccionada(&self, _h: &Hash) -> bool {
        false
    }
    fn slot_de(&self, _h: &Hash) -> Option<u64> {
        Some(0)
    }
    fn pertenece_al_dag(&self, _h: &Hash) -> bool {
        true
    }
}

fn motivo_de(paso: &super::PasoTardio) -> &'static str {
    paso.eventos
        .iter()
        .find_map(|e| match e {
            super::EventoMotor::VotoPesoPropio { motivo, .. } => Some(*motivo),
            _ => None,
        })
        .expect("evento VotoPesoPropio")
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// W3 · voto tardío: válido y negativas
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn w3_voto_tardio_valido_reserva_y_candado() -> Result<(), Error> {
    let est = estado_sectores(&[(1, 2, 1000)]);
    let sk = bls(1);
    let clave = clave_bls_de(&sk);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut motor = motor_peso(&[1], true);
    motor.vincular_diario(diario(dir.path()));

    let c = cand(0x20);
    let paso = motor.votar_tardio(3, c, &est, &super::VistaPermisiva)?;
    assert_eq!(paso.votos.len(), 1, "firma el voto tardío válido");
    let voto = &paso.votos[0];
    assert_eq!(voto.n, 3);
    assert_eq!(voto.candidato, c);
    assert_eq!(voto.raiz_estado, RAIZ_ESTADO_CERO);
    // La firma es A3 y verifica (lo que exige `aplicar_voto_propio`).
    let mensaje = zx_votos::mensaje_voto_peso(3, &c, &voto.h_t_siguiente, &RAIZ_ESTADO_CERO);
    zx_votos::verificar(&sk.clave_publica(), &voto.firma, DOMINIO_VOTO, &mensaje)
        .expect("A3 verifica");
    // Reserva hecha y candado `(k, candidato)`.
    assert!(
        motor.reservada_para_test(&clave, 3),
        "la reserva quedó hecha"
    );
    assert_eq!(
        motor.candado_para_test(&clave),
        Some((3, c)),
        "el candado pasa a (k, candidato)"
    );
    Ok(())
}

#[test]
fn w3_negativas_con_su_motivo() -> Result<(), Error> {
    let est = estado_sectores(&[(1, 2, 1000)]);
    let sk = bls(1);
    let clave = clave_bls_de(&sk);
    let k = 3u64;
    let x = cand(0x30);

    // (1) ya reservada: se pre-reserva el mensaje exacto que el motor firmaría para `(clave, k)`.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let d = diario(dir.path());
        let (tabla_sig, pubs) = construir_tabla(
            k + 1,
            &est,
            i64::try_from((k + 1) * T_INST_VOTOS).unwrap_or(i64::MAX),
        )?;
        let (tabla_sig, _) = super::canonizar_tabla(tabla_sig, pubs);
        let h_t = zx_votos::hash_tabla(&tabla_sig);
        let mensaje = zx_votos::mensaje_voto_peso(k, &cand(0x21), &h_t, &RAIZ_ESTADO_CERO);
        d.resolver(&clave, k, &mensaje)?;
        let mut motor = motor_peso(&[1], true);
        motor.vincular_diario(d);
        let paso = motor.votar_tardio(k, cand(0x21), &est, &super::VistaPermisiva)?;
        assert!(paso.votos.is_empty());
        assert_eq!(motivo_de(&paso), "ya_reservada");
    }

    // (2) candado de la misma ventana.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let d = diario(dir.path());
        d.fijar_candado(&clave, k, &x)?;
        let mut motor = motor_peso(&[1], true);
        motor.vincular_diario(d);
        let paso = motor.votar_tardio(k, cand(0x22), &est, &super::VistaPermisiva)?;
        assert!(paso.votos.is_empty());
        assert_eq!(motivo_de(&paso), "candado_posterior");
    }

    // (3) candado de ventana posterior cuyo candidato desciende del de `k`.
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let d = diario(dir.path());
        d.fijar_candado(&clave, k + 1, &x)?;
        let mut motor = motor_peso(&[1], true);
        motor.vincular_diario(d);
        let paso = motor.votar_tardio(k, cand(0x23), &est, &super::VistaPermisiva)?;
        assert!(paso.votos.is_empty());
        assert_eq!(motivo_de(&paso), "candado_posterior");
    }

    // (4) clave fuera de la tabla (sin peso): la clave propia 1 no tiene sectores en el estado.
    {
        let est_sin = estado_sectores(&[(2, 2, 1000)]);
        let dir = tempfile::tempdir().expect("tempdir");
        let mut motor = motor_peso(&[1], true);
        motor.vincular_diario(diario(dir.path()));
        let paso = motor.votar_tardio(k, cand(0x24), &est_sin, &super::VistaPermisiva)?;
        assert!(paso.votos.is_empty());
        assert_eq!(motivo_de(&paso), "fuera_de_tabla");
    }

    // (5) slot: con la apertura de `k` el candado sigue bloqueado (aunque con el slot actual se
    //     liberaría por `F`).
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let d = diario(dir.path());
        d.fijar_candado(&clave, k - 1, &x)?;
        let mut motor = motor_peso(&[1], true);
        motor.vincular_diario(d);
        let vista = VistaFuera;
        // Con un slot actual muy avanzado, el candado estaría liberado...
        let liberado = super::candidato_permitido(
            motor.diario_para_test().expect("diario"),
            &clave,
            &cand(0x25),
            None,
            10_000,
            &vista,
        )?;
        assert!(
            matches!(liberado, super::PermisoCandado::Liberado(_)),
            "con el slot actual el candado se liberaría"
        );
        // ...pero el voto tardío usa la apertura de `k` y no firma.
        let paso = motor.votar_tardio(k, cand(0x25), &est, &vista)?;
        assert!(paso.votos.is_empty());
        assert_eq!(motivo_de(&paso), "candado");
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// W9 · V6 sobre la `Cadena` real: solo se firma si el candidato desciende del sello
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn w9_v6_descender_del_sello() -> Result<(), Error> {
    let f = crate::nodo::pruebas_at1a2_fixture::bifurcacion();
    let est_base = estado_sectores(&[(1, 2, 1000)]);

    let con_sello = |sellado: BlockHash| {
        let mut est = est_base.clone();
        est.finalidad_votos_n = 1;
        est.finalidad_votos = Some(sellado);
        est.finalidad_votos_h_t = Some([0xAB; 32]);
        est
    };

    let k = 4u64;
    let dir = tempfile::tempdir().expect("tempdir");
    let mut motor = motor_peso(&[1], true);
    motor.vincular_diario(diario(dir.path()));

    // (a) el candidato desciende del sello `A` → se firma.
    let est_a = con_sello(f.a);
    let paso = motor.votar_tardio(k, *f.c.as_bytes(), &est_a, &f.cadena)?;
    assert_eq!(paso.votos.len(), 1, "desciende de A: firma");
    // El candado queda fijado; se suelta para las siguientes comprobaciones con un candado que
    // levanta B3 o se usa un motor nuevo por caso. Se usa un motor nuevo.

    // (b) el candidato `A` no desciende del sello `C` (que es descendiente suyo) → no firma.
    let dir_b = tempfile::tempdir().expect("tempdir");
    let mut motor_b = motor_peso(&[1], true);
    motor_b.vincular_diario(diario(dir_b.path()));
    let est_c = con_sello(f.c);
    let paso_b = motor_b.votar_tardio(k, *f.a.as_bytes(), &est_c, &f.cadena)?;
    assert!(paso_b.votos.is_empty());
    assert_eq!(motivo_de(&paso_b), "no_desciende_del_sello");

    // (c) el sello no está en el DAG → no firma.
    let dir_c = tempfile::tempdir().expect("tempdir");
    let mut motor_c = motor_peso(&[1], true);
    motor_c.vincular_diario(diario(dir_c.path()));
    let est_x = con_sello(f.desconocido);
    let paso_c = motor_c.votar_tardio(k, *f.c.as_bytes(), &est_x, &f.cadena)?;
    assert!(paso_c.votos.is_empty());
    assert_eq!(motivo_de(&paso_c), "no_desciende_del_sello");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// W10 · el salto castigable: el tardío de `k` no se firma; el de `n` sí
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn w10_el_voto_tardio_de_la_ventana_saltada_no_se_firma() -> Result<(), Error> {
    let f = crate::nodo::pruebas_at1a2_fixture::bifurcacion();
    // `X` es el bloque votado (rama abandonada), `C` el sello de la rama seleccionada, en conflicto.
    let b_j = f.x;
    let s = f.c;
    assert!(!f.cadena.desciende(b_j.as_bytes(), s.as_bytes()));
    assert!(!f.cadena.desciende(s.as_bytes(), b_j.as_bytes()));
    assert!(f.cadena.pertenece_al_dag(s.as_bytes()));

    let est_base = estado_sectores(&[(1, 2, 1000)]);
    let sk = bls(1);
    let clave = clave_bls_de(&sk);

    let dir = tempfile::tempdir().expect("tempdir");
    let d = diario(dir.path());
    // La clave firmó (j, B_j) en `X`, con `j < k < n`.
    d.fijar_candado(&clave, 1, b_j.as_bytes())?;
    let mut motor = motor_peso(&[1], true);
    motor.vincular_diario(d);

    // Ventanas `k = 301` y `n = 302`: la apertura de `k` no llega a `F`, la de `n` sí.
    let k = 301u64;
    let n = 302u64;
    // Estado del pasado del candidato de `k`: **sin** la finalidad sellada todavía.
    let est_k = est_base.clone();
    let paso_k = motor.votar_tardio(k, *f.c.as_bytes(), &est_k, &f.cadena)?;
    assert!(paso_k.votos.is_empty(), "el tardío de k no se firma");
    assert_eq!(motivo_de(&paso_k), "candado");

    // Estado del pasado del candidato de `n`: **con** el certificado que sella `S = C` en `Y`.
    let mut est_n = est_base.clone();
    est_n.finalidad_votos_n = k;
    est_n.finalidad_votos = Some(s);
    est_n.finalidad_votos_h_t = Some([0xCD; 32]);
    let paso_n = motor.votar_tardio(n, *f.c.as_bytes(), &est_n, &f.cadena)?;
    assert_eq!(paso_n.votos.len(), 1, "el tardío de n sí se firma");
    assert_eq!(motor.candado_para_test(&clave), Some((n, *f.c.as_bytes())));

    // B1.3 · el sello `S` de una ventana `>= j` está en el pasado de la punta de `n` y en conflicto
    // con `B_j`: el par sería una falta **justificada** (la propiedad B1 no se satisface).
    let justificado = f.cadena.desciende(f.c.as_bytes(), s.as_bytes())
        && !f.cadena.desciende(s.as_bytes(), b_j.as_bytes())
        && !f.cadena.desciende(b_j.as_bytes(), s.as_bytes());
    assert!(justificado, "el sello justifica el par: B1 no se cumple");
    Ok(())
}
