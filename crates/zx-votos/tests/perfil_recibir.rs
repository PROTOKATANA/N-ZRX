//! Aislante de perfil V1 (A5-c-1a-5): monta el caso desfavorable del cronómetro una vez y ejecuta
//! **solo** `recibir_lote`, imprimiendo la marca de tiempo de reloj monótono (`/proc/uptime`) al
//! empezar y al terminar. Así `perf script` puede quedarse con las muestras de la recepción sin la
//! contaminación del montaje (que en el cronómetro dura más de dos minutos).
//!
//! No es una prueba de corrección: es un instrumento de perfil. `#[ignore]`; se ejecuta a mano con
//! `--release --ignored --nocapture` bajo `perf record`.
#![allow(
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "test: los indices y divisores estan acotados por construccion"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use zx_votos::agregacion::{
    Agregado, DOMINIO_SORTEO, ErrorAgregacion, GeneradorEscalares, Reparto, sale_agregadora,
};
use zx_votos::agregador::{DatosVentana, ResultadoAgregado};
use zx_votos::serial::hash_bytes;
use zx_votos::ventana_raices::VentanaPorRaices;
use zx_votos::{
    Clave, ClavePublica, ClaveSecreta, DOMINIO_VOTO, Firma, Hash, LONGITUD_HASH, Tabla,
    agregar_firmas, firmar, hash_tabla, mensaje_voto_peso,
};

const N: u64 = 1;
const CANDIDATO: Hash = [0x11; LONGITUD_HASH];
const H_T: Hash = [0x22; LONGITUD_HASH];
const R1: Hash = [0x10; LONGITUD_HASH];

/// SplitMix64 determinista.
struct SplitMix64(u64);

impl SplitMix64 {
    fn siguiente(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl GeneradorEscalares for SplitMix64 {
    fn escalar(&mut self) -> [u8; 16] {
        let mut escalar = [0u8; 16];
        escalar[..8].copy_from_slice(&self.siguiente().to_be_bytes());
        escalar[8..].copy_from_slice(&self.siguiente().to_be_bytes());
        escalar
    }
}

fn par_bls(semilla: u64) -> Result<(ClaveSecreta, ClavePublica), ErrorAgregacion> {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&semilla.to_le_bytes());
    ikm[8] = 0x9a;
    ikm[31] = 0x37;
    let secreta = ClaveSecreta::generar(&ikm)?;
    let publica = secreta.clave_publica();
    Ok((secreta, publica))
}

struct Mundo {
    tabla: Tabla,
    claves: Vec<ClavePublica>,
    secretas: Vec<ClaveSecreta>,
    pesos: Vec<u128>,
    reparto: Reparto,
    huella: Hash,
    a: u32,
}

fn mundo_unos(num_claves: usize, s: u16, a: u32, semilla: u64) -> Result<Mundo, ErrorAgregacion> {
    let mut rng = SplitMix64(semilla);
    let mut secretas = Vec::with_capacity(num_claves);
    let mut claves = Vec::with_capacity(num_claves);
    let mut entradas = Vec::with_capacity(num_claves);
    for _ in 0..num_claves {
        let (secreta, publica) = par_bls(rng.siguiente())?;
        entradas.push(Clave {
            clave: publica.bytes().to_vec(),
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 0,
        });
        secretas.push(secreta);
        claves.push(publica);
    }
    let tabla = Tabla {
        n: 0,
        claves: entradas,
    };
    let reparto = Reparto::construir(&tabla, s)?;
    let huella = hash_tabla(&tabla);
    Ok(Mundo {
        tabla,
        claves,
        secretas,
        pesos: vec![1u128; num_claves],
        reparto,
        huella,
        a,
    })
}

fn uptime() -> f64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|texto| {
            texto
                .split_whitespace()
                .next()
                .and_then(|valor| valor.parse().ok())
        })
        .unwrap_or(0.0)
}

#[test]
#[ignore = "perfil V1: se ejecuta a mano con --release --ignored --nocapture bajo perf record"]
fn perfil_recibir_lote_desfavorable() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;

    const N_CLAVES: usize = 65_536;
    const S_CLAVES: u16 = 64;
    const A_AGREGADORAS: u32 = 62;

    let t_montaje = Instant::now();
    let m = mundo_unos(N_CLAVES, S_CLAVES, A_AGREGADORAS, 0xC10D)?;
    let mut firmas: Vec<Firma> = Vec::with_capacity(N_CLAVES);
    for global in 0..N_CLAVES {
        let secreta = m
            .secretas
            .get(global)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        firmas.push(firmar(
            secreta,
            DOMINIO_VOTO,
            mensaje_voto_peso(N, &CANDIDATO, &H_T, &R1).as_slice(),
        )?);
    }
    let mut agregados: Vec<Agregado> = Vec::new();
    for sub in 0..S_CLAVES {
        let indices = m.reparto.claves_de(sub);
        let n_s = indices.len();
        if n_s == 0 {
            continue;
        }
        let mut faltantes: BTreeSet<usize> = BTreeSet::new();
        for pos in 0..n_s {
            let global = indices[pos];
            let secreta = m
                .secretas
                .get(global)
                .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
            let sorteo = firmar(secreta, DOMINIO_SORTEO, &N.to_be_bytes())?;
            let huella = hash_bytes(&sorteo.bytes());
            if !sale_agregadora(&huella, N_CLAVES, S_CLAVES, A_AGREGADORAS) {
                continue;
            }
            let mut falta = None;
            for candidata in 0..n_s {
                if candidata != pos && !faltantes.contains(&candidata) {
                    falta = Some(candidata);
                    break;
                }
            }
            let Some(falta) = falta else {
                continue;
            };
            faltantes.insert(falta);
            let mut mapa = vec![0u8; n_s.div_ceil(8)];
            let mut firmas_agregado: Vec<Firma> = Vec::new();
            for (p, &idx_global) in indices.iter().enumerate() {
                if p == falta {
                    continue;
                }
                if let Some(byte) = mapa.get_mut(p >> 3) {
                    *byte |= 1 << (p & 7);
                }
                firmas_agregado.push(firmas[idx_global]);
            }
            let referencias: Vec<&Firma> = firmas_agregado.iter().collect();
            let firma_agregada = agregar_firmas(&referencias)?;
            agregados.push(Agregado {
                n: N,
                candidato: CANDIDATO,
                h_t_siguiente: H_T,
                raiz_estado: R1,
                firma_agregada,
                huella_tabla: m.huella,
                subred: sub,
                indice_agregadora: u16::try_from(pos).map_err(|_| ErrorAgregacion::FueraDeU16)?,
                mapa_local: mapa,
                firma_sorteo: sorteo,
            });
        }
    }
    let datos = DatosVentana::nuevo(&m.tabla, &m.claves, &m.pesos, S_CLAVES)?;
    let montaje = t_montaje.elapsed();

    let mut v = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    let mut generador = SplitMix64(0xC10D_0000);
    let ts_antes = uptime();
    let t_lote = Instant::now();
    let resultados = v.recibir_lote(&agregados, &mut generador)?;
    let lote = t_lote.elapsed();
    let ts_despues = uptime();

    println!("perfil_ts_antes {ts_antes}");
    println!("perfil_ts_despues {ts_despues}");
    println!("perfil_montaje_ms {:.3}", montaje.as_secs_f64() * 1000.0);
    println!("perfil_recibir_lote_ms {:.3}", lote.as_secs_f64() * 1000.0);
    println!("perfil_agregados {}", agregados.len());
    println!(
        "perfil_aceptados {}",
        resultados
            .iter()
            .filter(|resultado| **resultado == ResultadoAgregado::Aceptado)
            .count()
    );
    Ok(())
}
