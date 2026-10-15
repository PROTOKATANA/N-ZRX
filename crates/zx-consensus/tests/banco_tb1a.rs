//! TB-1a · banco de medida de `aplicar_certificado_peso` con base (65 536 claves, primera vez y
//! siguientes) y de `tabla_derivada` (65 536 sin recorte y 131 072 con recorte).
//!
//! Orden `P-ZRX/P-004/ORDEN-TB1A.md` §5. Se ejecuta a mano en el bloque 0, `--release`, envuelto en
//! `perf stat`:
//!
//! ```text
//! TB1A_NS=65536,131072 TB1A_REPS=15 \
//!   cargo test --release -p zx-consensus --test banco_tb1a -- --ignored --nocapture
//! ```
//!
//! Emite una muestra por repetición `TB1A SAMPLE OP <op> N <n> REP <r> ns <t>`. El estado con claves
//! reales se monta insertando directamente el `RegistroSector` activo de cada clave y derivando la
//! secreta del escalar (sin `generar`, que es más caro). Para que **dos** firmantes alcancen el
//! quórum, las claves 0 y 1 llevan `65 536` sectores cada una; la validación de las 65 536 claves
//! BLS de la tabla ocurre igual en `claves_bls_de_tabla`.

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
    dead_code,
    reason = "banco de medida TB-1a; falla con panic por diseño y usa índices controlados"
)]

use std::time::Instant;

use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::Estado;
use zx_consensus::transicion::votos::{
    aplicar_certificado_peso_con_undo, tabla_canonica, tabla_derivada,
};
use zx_core::{ClavePublica, ClaveTablaVoto, OperacionAlmacenamiento};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Firma, Tabla};

type Error = Box<dyn std::error::Error>;

/// Clave Ed25519 sintética y distinta por índice.
fn ed_i(i: usize) -> ClavePublica {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&(i as u64).to_le_bytes());
    ClavePublica::desde_bytes(b)
}

/// Par BLS determinista por índice, derivado del escalar `i + 1` (sin `generar`).
fn par_bls_i(i: usize) -> Result<ClaveSecreta, Error> {
    let mut escalar = [0u8; 32];
    escalar[24..].copy_from_slice(&(u64::try_from(i)? + 1).to_be_bytes());
    Ok(ClaveSecreta::desde_bytes(&escalar)?)
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
        renovacion_slot: 10_000,
        retiro_slot: -1,
        fianza: p.q_sec,
        aud_apertura: -1,
        aud_contestada: -1,
    };
    (id, reg)
}

/// Estado con `n` claves reales: las claves 0 y 1 llevan `65 536` sectores con índices distintos
/// (peso `65 536` cada una, de modo que **dos** firmantes alcanzan el quórum: `3·131 072 ≥
/// 2·196 606`) y las demás uno. Devuelve también las secretas.
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
        let sectores = if i < 2 { 65_536 } else { 1 };
        for k in 0..sectores {
            let (id, reg) = registro(&p, e, u16::try_from(k).unwrap_or(0));
            est.sectores.insert(id, reg);
        }
        secretas.push(s);
    }
    Ok((est, secretas))
}

/// Estado con `n` claves sintéticas (BLS de bytes, sin validar): para `tabla_derivada`.
fn estado_sintetico(n: usize) -> Estado {
    let p = ParametrosSector::dev();
    let mut est = Estado::inicial();
    est.parametros_sector = p;
    for i in 0..n {
        let mut ed_bytes = [0u8; 32];
        ed_bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let clave = ClavePublica::desde_bytes(ed_bytes);
        let mut clave_bls = [0u8; 48];
        clave_bls[..8].copy_from_slice(&(i as u64).to_le_bytes());
        est.claves_voto.insert(
            clave,
            ClaveVoto {
                clave_bls,
                prueba_posesion: [0u8; 96],
            },
        );
        let (id, reg) = registro(&p, clave, 0);
        est.sectores.insert(id, reg);
    }
    est
}

fn tabla_de(n: u64, claves: &[ClaveTablaVoto]) -> Tabla {
    Tabla {
        n,
        claves: claves.iter().map(clave_contrato).collect(),
    }
}

fn clave_contrato(c: &ClaveTablaVoto) -> Clave {
    Clave {
        clave: c.clave_bls.to_vec(),
        peso: c.peso,
        activo: c.activo,
        prueba: c.prueba,
        garantia: c.garantia,
    }
}

fn canoniza(mut claves: Vec<ClaveTablaVoto>) -> Vec<ClaveTablaVoto> {
    claves.sort_by_key(|a| a.clave_bls);
    claves
}

/// Certificado `0x09` firmado por los índices `firmantes` (0-based) de `secretas`.
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
    for &firmante in firmantes {
        let pk = secretas[firmante].clave_publica();
        let Some(pos) = tabla
            .claves
            .iter()
            .position(|c| c.clave == pk.bytes().to_vec())
        else {
            continue;
        };
        let firma: Firma = zx_votos::firmar(&secretas[firmante], DOMINIO_VOTO, &mensaje)?;
        votos.push((pos + 1, firma));
    }
    let cert =
        zx_votos::construir_certificado(n, candidato, h_t_siguiente, [0u8; 32], &tabla, &votos)?;
    Ok(OperacionAlmacenamiento::CertificadoPeso {
        clave: ed_i(secretas.len() + 7),
        bytes: zx_votos::serial_certificado_peso(&cert),
    })
}

fn variable(nombre: &str, por_defecto: &str) -> String {
    std::env::var(nombre).unwrap_or_else(|_| por_defecto.to_string())
}

fn lista(ns: &str) -> Vec<usize> {
    ns.split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

#[test]
#[ignore = "TB-1a: banco de medida; se ejecuta a mano con TB1A_NS/TB1A_REPS en el bloque 0"]
fn banco_tb1a() -> Result<(), Error> {
    let reps: usize = variable("TB1A_REPS", "15").parse().unwrap_or(15);
    let ns = lista(&variable("TB1A_NS", "65536,131072"));
    let n_aplicar: usize = variable("TB1A_APLICAR", "65536").parse().unwrap_or(65_536);
    let slot: i64 = 12; // aperturas de las ventanas 5 (10) y 6 (12): no futuras.

    println!(
        "TB1A HDR reps {reps} aplicar {n_aplicar} ns {}",
        ns.iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );

    // ── 1 · aplicar_certificado_peso con base, 65 536 claves ───────────────────────────────────
    {
        let t_prep = Instant::now();
        let (estado, secretas) = estado_n(n_aplicar)?;
        let claves = canoniza(tabla_canonica(&estado, slot));
        assert_eq!(
            claves.len(),
            n_aplicar,
            "tabla_canonica debe devolver N claves"
        );
        let h = zx_votos::hash_tabla(&tabla_de(0, &claves));
        let cert_base = certificado(&secretas, 5, &claves, [0x11; 32], h, &[0, 1])?;
        let op = certificado(&secretas, 6, &claves, [0x12; 32], h, &[0, 1])?;
        println!(
            "TB1A PREP aplicar N {n_aplicar} ns {}",
            t_prep.elapsed().as_nanos()
        );

        // Primera vez: la memoria de claves BLS está fría.
        let inicio = Instant::now();
        let (ancla, _undo, r) = aplicar_certificado_peso_con_undo(&estado, &cert_base, slot);
        let ns_primera = inicio.elapsed().as_nanos();
        r?;
        assert_eq!(ancla.finalidad_votos_n, 5);
        println!("TB1A SAMPLE OP aplicar_primera N {n_aplicar} REP 0 ns {ns_primera}");
        println!("TB1A OK aplicar_primera N {n_aplicar}");

        // Siguientes: misma tabla, memoria caliente.
        for rep in 0..reps {
            let inicio = Instant::now();
            let (_e, _u, r) = aplicar_certificado_peso_con_undo(&ancla, &op, slot);
            let ns = inicio.elapsed().as_nanos();
            r?;
            println!("TB1A SAMPLE OP aplicar_siguiente N {n_aplicar} REP {rep} ns {ns}");
        }
    }

    // ── 2 · tabla_derivada (sin recorte y con recorte) ──────────────────────────────────────────
    for &n in &ns {
        let estado = estado_sintetico(n);
        println!("TB1A OK derivada N {n}");
        for rep in 0..reps {
            let inicio = Instant::now();
            let tabla = tabla_derivada(&estado, 100);
            let ns = inicio.elapsed().as_nanos();
            let esperado = n.min(zx_consensus::transicion::votos::MAX_CLAVES_TABLA);
            assert_eq!(tabla.len(), esperado, "tope de tabla_derivada");
            println!("TB1A SAMPLE OP tabla_derivada N {n} REP {rep} ns {ns}");
        }
    }
    println!("TB1A FIN");
    Ok(())
}

fn format_lista(ns: &[usize]) -> String {
    ns.iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}
