//! Diferencial W08b: vuelca la salida GHOSTDAG de una batería de DAGs de forma determinista, para
//! comparar la implementación nueva (`ws`) con la congelada (`ws.orig`).
//!
//! Es el mismo archivo en las dos copias: el generador y el volcado son idénticos, así que la única
//! diferencia posible es la implementación. Se ejecuta con:
//!
//! ```text
//! W08B_DUMP=/ruta/salida.txt cargo test -p zx-dag --release --test diferencial_w08b --offline \
//!     --locked -- --ignored --nocapture
//! ```
//!
//! Cubre:
//! - 5 configuraciones aleatorias de 10³–10⁴ bloques (cadena lineal y anchura 3–15, `k` = 10/30)
//!   con identidades **únicas** (sintéticas y de billete real) para que la admisión no cascadee.
//! - Casos dirigidos con identidades **repetidas**: diamante U3, tres hermanas U3, U2 en cadena,
//!   U2 con billete real, y un merge ancho de 60 hermanas con el mismo billete.

#![expect(clippy::unwrap_used, reason = "el arnés falla con panic por diseño")]
#![expect(
    clippy::indexing_slicing,
    reason = "índices sobre vectores construidos en el propio arnés"
)]

use std::fmt::Write as _;
use std::fs;

use zx_core::ClavePublica;
use zx_core::digest::BlockHash;
use zx_dag::RangoSolucionValidado;
use zx_dag::ghostdag::{
    Algoritmo, AlmacenGhostdag, BloqueGhostdag, Color, IdentidadGhostdag, ModoMerge, ModoSp,
    Parametros, hash_de_id_textual,
};

struct Azar(u64);

impl Azar {
    const fn nuevo(semilla: u64) -> Self {
        Self(semilla)
    }

    fn siguiente(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn rango(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.siguiente() % (hi - lo + 1)
    }
}

/// Modo de identidad de las configuraciones aleatorias (siempre única, para no cascadear).
#[derive(Clone, Copy)]
enum Idents {
    UnicaSintetica,
    UnicaBillete,
}

fn params(k: u32) -> Parametros {
    Parametros {
        k,
        sp: ModoSp::Zerox,
        merge: ModoMerge::Terna,
        ..Parametros::default()
    }
}

fn identidad_unica(i: usize, modo: Idents) -> IdentidadGhostdag {
    match modo {
        Idents::UnicaSintetica => IdentidadGhostdag::de_fixture(i as u64 + 1),
        Idents::UnicaBillete => {
            let c = (i & 0xff) as u8;
            IdentidadGhostdag::Billete(zx_dag::IdentidadTicket::vigente(
                ClavePublica::desde_bytes([c; 32]),
                0,
                i as u64 + 1,
                [c; 32],
                i as u64 % 3,
            ))
        }
    }
}

fn generar(n: usize, ventana: usize, modo: Idents, semilla: u64) -> Vec<BloqueGhostdag> {
    let mut rng = Azar::nuevo(semilla);
    let mut nodos: Vec<BloqueGhostdag> = vec![BloqueGhostdag {
        id: hash_de_id_textual("G"),
        padres: Vec::new(),
        slot: 0,
        solution_distance: 0,
        rango_espacio: RangoSolucionValidado::para_oraculos(0),
        identidad: IdentidadGhostdag::SinBillete,
    }];
    for i in 1..n {
        let lo = i.saturating_sub(ventana);
        let disponibles = i - lo;
        let max_padres = disponibles.min(1 + rng.rango(0, 2) as usize);
        let mut padres: Vec<BlockHash> = Vec::new();
        while padres.len() < max_padres {
            let p = lo + rng.rango(0, (disponibles - 1) as u64) as usize;
            if !padres.contains(&nodos[p].id) {
                padres.push(nodos[p].id);
            }
        }
        let slot_base = padres
            .iter()
            .map(|h| {
                nodos
                    .iter()
                    .find(|b| b.id == *h)
                    .map(|b| b.slot)
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0);
        let sr = match rng.rango(0, 4) {
            0 => 0,
            1 => 1,
            2 => u64::MAX - 1,
            3 => u64::MAX,
            _ => rng.rango(0, i64::MAX as u64),
        };
        nodos.push(BloqueGhostdag {
            id: hash_de_id_textual(&format!("B{i}")),
            padres,
            slot: slot_base + 1,
            solution_distance: rng.rango(0, 1 << 16),
            rango_espacio: RangoSolucionValidado::para_oraculos(sr),
            identidad: identidad_unica(i, modo),
        });
    }
    nodos
}

fn identidad_repetida(caso: u8, semilla: u8) -> IdentidadGhostdag {
    match caso {
        0 => IdentidadGhostdag::de_fixture(u64::from(semilla)),
        _ => IdentidadGhostdag::Billete(zx_dag::IdentidadTicket::vigente(
            ClavePublica::desde_bytes([semilla; 32]),
            0,
            u64::from(semilla),
            [semilla; 32],
            u64::from(semilla) % 3,
        )),
    }
}

fn bloque(
    id: u16,
    padres: Vec<BlockHash>,
    slot: u64,
    sr: u64,
    identidad: IdentidadGhostdag,
) -> BloqueGhostdag {
    BloqueGhostdag {
        id: hash_de_id_textual(&format!("C{id}")),
        padres,
        slot,
        solution_distance: 0,
        rango_espacio: RangoSolucionValidado::para_oraculos(sr),
        identidad,
    }
}

/// Diamante con dos hermanas de la misma identidad y un merge: U3.
fn caso_u3(caso: u8) -> Vec<BloqueGhostdag> {
    let g = hash_de_id_textual("G");
    let t = identidad_repetida(caso, 7);
    vec![
        BloqueGhostdag {
            id: g,
            padres: Vec::new(),
            slot: 0,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(0),
            identidad: IdentidadGhostdag::SinBillete,
        },
        bloque(1, vec![g], 1, 5, t),
        bloque(2, vec![g], 1, 5, t),
        bloque(
            3,
            vec![hash_de_id_textual("C1"), hash_de_id_textual("C2")],
            2,
            5,
            IdentidadGhostdag::SinBillete,
        ),
    ]
}

/// Tres hermanas con la misma identidad y un merge ancho: dos U3.
fn caso_u3_tres(caso: u8) -> Vec<BloqueGhostdag> {
    let g = hash_de_id_textual("G");
    let t = identidad_repetida(caso, 9);
    vec![
        BloqueGhostdag {
            id: g,
            padres: Vec::new(),
            slot: 0,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(0),
            identidad: IdentidadGhostdag::SinBillete,
        },
        bloque(1, vec![g], 1, 5, t),
        bloque(2, vec![g], 1, 5, t),
        bloque(3, vec![g], 1, 5, t),
        bloque(
            4,
            vec![
                hash_de_id_textual("C1"),
                hash_de_id_textual("C2"),
                hash_de_id_textual("C3"),
            ],
            2,
            5,
            IdentidadGhostdag::SinBillete,
        ),
    ]
}

/// U2: el hijo de un bloque con identidad repite esa identidad.
fn caso_u2(caso: u8) -> Vec<BloqueGhostdag> {
    let g = hash_de_id_textual("G");
    let t = identidad_repetida(caso, 3);
    vec![
        BloqueGhostdag {
            id: g,
            padres: Vec::new(),
            slot: 0,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(0),
            identidad: IdentidadGhostdag::SinBillete,
        },
        bloque(1, vec![g], 1, 5, t),
        bloque(2, vec![hash_de_id_textual("C1")], 2, 5, t),
    ]
}

/// Merge ancho de 14 hermanas (tope `MAX_PADRES = 15`) con el mismo billete: 13 U3.
fn caso_u3_ancho(caso: u8) -> Vec<BloqueGhostdag> {
    let g = hash_de_id_textual("G");
    let t = identidad_repetida(caso, 5);
    let mut nodos = vec![BloqueGhostdag {
        id: g,
        padres: Vec::new(),
        slot: 0,
        solution_distance: 0,
        rango_espacio: RangoSolucionValidado::para_oraculos(0),
        identidad: IdentidadGhostdag::SinBillete,
    }];
    let mut padres = Vec::new();
    for i in 1..=14u16 {
        nodos.push(bloque(i, vec![g], 1, 5, t));
        padres.push(hash_de_id_textual(&format!("C{i}")));
    }
    nodos.push(bloque(15, padres, 2, 5, IdentidadGhostdag::SinBillete));
    nodos
}

fn color_u8(c: Color) -> u8 {
    match c {
        Color::Azul => 0,
        Color::RojoK => 1,
        Color::RojoU3 => 2,
    }
}

fn volcar_nodos(salida: &mut String, etiqueta: &str, nodos: &[BloqueGhostdag], k: u32) {
    let _ = writeln!(salida, "CONFIG {etiqueta} k={k} n={}", nodos.len());
    let mut almacen = AlmacenGhostdag::nuevo(
        params(k),
        Algoritmo::Kernel,
        nodos[0].id,
        nodos[0].slot,
        nodos[0].rango_espacio,
        0,
    );
    for (i, b) in nodos.iter().enumerate().skip(1) {
        match almacen.anadir_sintetico(b.clone()) {
            Ok(_) => {
                let _ = writeln!(salida, "I {i} ok");
            }
            Err(e) => {
                let _ = writeln!(salida, "I {i} err={e:?}");
            }
        }
    }
    // Se vuelca por índice denso de almacenamiento (el orden de aceptación), no por índice de
    // generación: un rechazo intermedio desplaza los índices.
    for i in 0..almacen.len() as u32 {
        let gd = almacen.datos(i).unwrap();
        let ms: Vec<u32> = gd.orden_mergeset.to_vec();
        let colores: Vec<(u32, u8)> = gd
            .orden_mergeset
            .iter()
            .filter_map(|x| almacen.color_en(i, *x).map(|c| (*x, color_u8(c))))
            .collect();
        let rojos: Vec<u32> = gd.rojos.to_vec();
        let _ = writeln!(
            salida,
            "B {i} id={:?} sp={:?} bs={} bw={:x} ms={ms:?} col={colores:?} roj={rojos:?}",
            almacen.id(i).unwrap(),
            gd.sp,
            gd.blue_score,
            gd.blue_work
        );
    }
}

#[test]
#[ignore = "diferencial; se lanza con --ignored y W08B_DUMP"]
fn volcar_diferencial() {
    let mut salida = String::new();
    // Configuraciones aleatorias con identidades únicas.
    let aleatorios: &[(usize, usize, u32, Idents)] = &[
        (1000, 1, 10, Idents::UnicaSintetica),
        (1000, 3, 30, Idents::UnicaSintetica),
        (1000, 15, 30, Idents::UnicaBillete),
        (3000, 3, 10, Idents::UnicaSintetica),
        (3000, 15, 30, Idents::UnicaBillete),
        (10000, 1, 30, Idents::UnicaSintetica),
        (10000, 3, 30, Idents::UnicaSintetica),
    ];
    for (i, (n, v, k, modo)) in aleatorios.iter().enumerate() {
        let nodos = generar(*n, *v, *modo, 0xB0E1 + i as u64);
        let etiqueta = format!(
            "aleatorio n={n} ventana={v} idents={}",
            match modo {
                Idents::UnicaSintetica => "sintetica-unica",
                Idents::UnicaBillete => "billete-unico",
            }
        );
        volcar_nodos(&mut salida, &etiqueta, &nodos, *k);
    }
    // Casos dirigidos con identidades repetidas (U2/U3).
    for (etiqueta, nodos) in [
        ("dirigido u3 diamante sintetica", caso_u3(0)),
        ("dirigido u3 diamante billete", caso_u3(1)),
        ("dirigido u3 tres sintetica", caso_u3_tres(0)),
        ("dirigido u3 tres billete", caso_u3_tres(1)),
        ("dirigido u2 sintetica", caso_u2(0)),
        ("dirigido u2 billete", caso_u2(1)),
        ("dirigido u3 ancho 14 sintetica", caso_u3_ancho(0)),
        ("dirigido u3 ancho 14 billete", caso_u3_ancho(1)),
    ] {
        volcar_nodos(&mut salida, etiqueta, &nodos, 30);
    }
    let destino = std::env::var("W08B_DUMP").unwrap_or_else(|_| "diferencial_w08b.txt".to_string());
    fs::write(&destino, &salida).unwrap();
    println!("volcado {} bytes en {destino}", salida.len());
}
