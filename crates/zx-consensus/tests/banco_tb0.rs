//! TB-0 · banco de medida de `tabla_canonica` y de `aplicar_certificado_peso` **con base**.
//!
//! Orden `P-ZRX/P-004/ORDEN-TB0.md` §3.4. Se ejecuta a mano (bloque 0, `--release`):
//!
//! ```text
//! TB0_NS=1000,4096,10000,16384,65536 TB0_REPS=15 \
//!   cargo test --release -p zx-consensus --test banco_tb0 -- --ignored --nocapture
//! ```
//!
//! Emite una muestra por repetición `TB0 SAMPLE N <n> OP <op> REP <r> ns <t>`. El estado se monta
//! insertando directamente el `RegistroSector` activo de cada clave (lo que el peso exige) en vez
//! de aplicar N altas (cada alta clona el estado). El certificado «con base» encadena con un
//! bootstrap de la ventana 5 y aplica el de la 6, cuyas aperturas (`10` y `12`) no pasan del slot
//! `12` que usa el banco (TB-1a · T9 no los rechaza por ventana futura).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::needless_range_loop,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::manual_let_else,
    clippy::items_after_statements,
    dead_code,
    reason = "banco de medida TB-0; falla con panic por diseño y usa índices controlados"
)]

use std::time::Instant;

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::Estado;
use zx_consensus::transicion::votos::{aplicar_certificado_peso_con_undo, tabla_canonica};
use zx_core::{ClavePublica, ClaveTablaVoto, OperacionAlmacenamiento};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, Tabla};

type Error = Box<dyn std::error::Error>;

/// Clave Ed25519 sintética y distinta por índice.
fn ed_i(i: usize) -> ClavePublica {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&(i as u64).to_le_bytes());
    ClavePublica::desde_bytes(b)
}

/// Par BLS real y distinto por índice (semilla determinista).
fn par_bls_i(i: usize) -> Result<ClaveSecreta, Error> {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&(i as u64).to_le_bytes());
    ikm[30] = 0xB1;
    ikm[31] = 0x7A;
    Ok(ClaveSecreta::generar(&ikm)?)
}

/// Sector activo con la fianza exacta del perfil: pesa.
fn registro(p: &ParametrosSector, clave: ClavePublica) -> (SectorId, RegistroSector) {
    let id = SectorId {
        clave,
        sector_index: 0,
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

/// Estado con `n` claves de voto activas (peso 1) y sus secretas BLS.
fn estado_n(n: usize) -> Result<(Estado, Vec<ClaveSecreta>), Error> {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    let mut secretas = Vec::with_capacity(n);
    for i in 0..n {
        let s = par_bls_i(i)?;
        let pk = s.clave_publica();
        let e = ed_i(i);
        est.claves_voto.insert(
            e,
            ClaveVoto {
                clave_bls: pk.bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let (id, reg) = registro(&p, e);
        est.sectores.insert(id, reg);
        secretas.push(s);
    }
    Ok((est, secretas))
}

/// `ClaveTablaVoto` -> `Tabla` del contrato de `zx-votos`.
fn tabla_de(n: u64, claves: &[ClaveTablaVoto]) -> Tabla {
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

/// Orden canónico por bytes de `clave_bls` (réplica del `contenido_canonico` privado).
fn canoniza(mut claves: Vec<ClaveTablaVoto>) -> Vec<ClaveTablaVoto> {
    claves.sort_by_key(|a| a.clave_bls);
    claves
}

/// Certificado `0x09` firmado por los `firmantes` (índices 0-based sobre `secretas`).
fn certificado(
    secretas: &[ClaveSecreta],
    n: u64,
    claves_payload: &[ClaveTablaVoto],
    candidato: [u8; 32],
    h_t_siguiente: [u8; 32],
    firmantes: &[usize],
) -> Result<OperacionAlmacenamiento, Error> {
    let vigente = canoniza(claves_payload.to_vec());
    let tabla = tabla_de(n, &vigente);
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
        clave: ed_i(secretas.len() + 7),
        bytes: zx_votos::serial_certificado_peso(&cert),
    })
}

/// Mide `reps` repeticiones de `f` e imprime una muestra por repetición.
fn mide<F>(n: usize, op: &str, reps: usize, mut f: F) -> Result<(), Error>
where
    F: FnMut() -> Result<(), Error>,
{
    for rep in 0..reps {
        let inicio = Instant::now();
        f()?;
        println!(
            "TB0 SAMPLE N {n} OP {op} REP {rep} ns {}",
            inicio.elapsed().as_nanos()
        );
    }
    Ok(())
}

#[test]
#[ignore = "TB-0: banco de medida; se ejecuta a mano con TB0_NS/TB0_REPS"]
fn banco_tb0() -> Result<(), Error> {
    let ns: Vec<usize> = std::env::var("TB0_NS")
        .unwrap_or_else(|_| "1000,4096,10000,16384,65536".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let reps: usize = std::env::var("TB0_REPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);
    let slot: i64 = 12; // sectores con `renovacion_slot = 0` y `t_cad = 600`: activos.

    println!("TB0 HDR reps {reps} slot {slot} ns {}", format_lista(&ns));

    for &n in &ns {
        // ── preparación (fuera del cronómetro) ────────────────────────────────────────────────
        let t_prep = Instant::now();
        let (estado, secretas) = estado_n(n)?;
        let claves = canoniza(tabla_canonica(&estado, slot));
        assert_eq!(claves.len(), n, "tabla_canonica debe devolver N claves");
        let h = zx_votos::hash_tabla(&tabla_de(0, &claves));
        let todos: Vec<usize> = (0..n).collect();
        // Bootstrap (n=5) y certificado con base (n=6); la tabla no cambia: `h_t_siguiente = h`.
        let cert_base = certificado(&secretas, 5, &claves, [0x11; 32], h, &todos)?;
        let op = certificado(&secretas, 6, &claves, [0x12; 32], h, &todos)?;
        // El bootstrap deriva la tabla una vez; queda como ancla con base.
        let (ancla, _undo, r) = aplicar_certificado_peso_con_undo(&estado, &cert_base, slot);
        r?;
        assert_eq!(ancla.finalidad_votos_n, 5);
        let (_aplicado, _undo, r) = aplicar_certificado_peso_con_undo(&ancla, &op, slot);
        r?;
        println!(
            "TB0 PREP N {n} ns {} firmantes {}",
            t_prep.elapsed().as_nanos(),
            todos.len()
        );
        println!("TB0 OK N {n} con_base true");

        // ── 1 · tabla_canonica ─────────────────────────────────────────────────────────────────
        mide(n, "tabla_canonica", reps, || {
            let v = tabla_canonica(&estado, slot);
            std::hint::black_box(&v);
            Ok(())
        })?;

        // ── 2 · aplicar_certificado_peso con base (no deriva la tabla) ─────────────────────────
        mide(n, "aplicar_con_base", reps, || {
            let (_e, _u, r) = aplicar_certificado_peso_con_undo(&ancla, &op, slot);
            r?;
            Ok(())
        })?;
    }
    println!("TB0 FIN");
    Ok(())
}

fn format_lista(ns: &[usize]) -> String {
    ns.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",")
}
