//! Banco de medida V8 de `zx-bls`: desglose de `verificar_lote_con_escalares`.
//!
//! Mide, para `K = 1 024` firmas del **mismo** mensaje y escalares de 128 bits:
//!
//! - el total de [`verificar_lote_con_escalares`] (API pública, con prefijo de dominio);
//! - la multiplicación múltiple de las claves (Pippenger en G1);
//! - la multiplicación múltiple de las firmas (Pippenger en G2);
//! - los dos emparejamientos (`miller_loop(...).final_exp()` y su comparación);
//! - el trabajo fijo: `H(m) -> G2`, el generador `g₁` y las conversiones;
//! - la validación de subgrupo por punto que FV-4b-1-3 **eliminó**, para cuantificar el ahorro.
//!
//! Los escalares del banco son `[0; 8] ‖ (i as u128)` (128 bits no nulos); la VRF los deriva por
//! SHA-256, pero el coste de la multiplicación múltiple depende solo de sus 128 bits. Las piezas
//! internas se reproducen aquí con la API de `blst` del propio paquete para poder aislarlas; el
//! total público se mide con la función real, de modo que el desglose se puede contrastar.
//!
//! Ejecución (clase M, candado exclusivo):
//! `cargo run --release -p zx-bls --example medida_lote`
#![allow(
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    reason = "banco de medida: indexa muestras acotadas, usa percentiles enteros, convierte a f64 solo para imprimir ms y su salida es el resultado"
)]

use std::hint::black_box;
use std::time::Instant;

use blst::min_pk::{PublicKey as BlstPublicKey, Signature as BlstSignature};
use blst::{MultiPoint, blst_fp12, blst_p1_affine, blst_p2_affine};

use zx_bls::{
    ClavePublica, ClaveSecreta, Firma, LONGITUD_ESCALAR_LOTE, crudo, firmar, mensaje_con_dominio,
    verificar_lote_con_escalares,
};

/// Dominio de ZEROX de la medida (separación de dominios, decisión 2).
const DOMINIO: &[u8] = b"ZX-BLS1-MEDIDA-LOTE";
/// Mensaje del lote de la medida.
const MENSAJE: &[u8] = b"certificado-de-finalidad";
/// Repeticiones por escenario (la orden exige >= 30).
const REPETICIONES: usize = 31;
/// Calentamientos por escenario (amortiza el primer uso).
const CALENTAMIENTO: usize = 3;
/// Claves y firmas del lote medido.
const K: usize = 1024;
/// Bits que consume `blst` de cada escalar del lote.
const BITS_ESCALAR_LOTE: usize = 8 * LONGITUD_ESCALAR_LOTE;

/// Material de clave determinista y distinto por índice.
fn semilla(indice: usize) -> [u8; 32] {
    let mut ikm = [0u8; 32];
    let bytes = (indice as u64).to_le_bytes();
    for (destino, origen) in ikm.iter_mut().zip(bytes.iter()) {
        *destino = *origen;
    }
    if let Some(byte) = ikm.get_mut(8) {
        *byte = 0x6c;
    }
    if let Some(byte) = ikm.get_mut(31) {
        *byte = 0xe3;
    }
    ikm
}

/// `K` escalares de 128 bits no nulos y distintos.
fn escalares(k: usize) -> Vec<[u8; LONGITUD_ESCALAR_LOTE]> {
    (0..k)
        .map(|indice| {
            let mut escalar = [0u8; LONGITUD_ESCALAR_LOTE];
            escalar.copy_from_slice(&(indice as u128).to_be_bytes());
            escalar
        })
        .collect()
}

/// Aplana los escalares al formato que consume `blst` (`nbits = 128`).
fn planos(escalares: &[[u8; LONGITUD_ESCALAR_LOTE]]) -> Vec<u8> {
    let mut planos = Vec::with_capacity(escalares.len() * LONGITUD_ESCALAR_LOTE);
    for escalar in escalares {
        planos.extend_from_slice(escalar);
    }
    planos
}

/// Mide `f` con calentamiento y devuelve las muestras crudas en ns.
fn medir<R>(f: &mut impl FnMut() -> R, reps: usize) -> Vec<u64> {
    for _ in 0..CALENTAMIENTO {
        black_box(f());
    }
    let mut muestras = Vec::with_capacity(reps);
    for _ in 0..reps {
        let inicio = Instant::now();
        black_box(f());
        muestras.push(inicio.elapsed().as_nanos() as u64);
    }
    muestras
}

/// Mediana (elemento central) y p95 por rango más cercano, junto a min/max.
fn resumir(muestras: &mut [u64]) -> (u64, u64, u64, u64) {
    muestras.sort_unstable();
    let n = muestras.len();
    let mediana = muestras[(n - 1) / 2];
    let indice_p95 = (95 * n).div_ceil(100).saturating_sub(1).min(n - 1);
    (mediana, muestras[indice_p95], muestras[0], muestras[n - 1])
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hilos = std::thread::available_parallelism().map_or(1, |n| n.get());
    println!(
        "# zx-bls V8 — desglose del lote con escalares (mediana/p95 por rango mas cercano, ns)"
    );
    println!("# hilos_disponibles: {hilos} (el banco es monohilo; blst usa su ThreadPool interno)");
    println!("# repeticiones: {REPETICIONES}, calentamiento: {CALENTAMIENTO}, K={K}");

    let secretas: Vec<ClaveSecreta> = (0..K)
        .map(|indice| ClaveSecreta::generar(&semilla(indice)))
        .collect::<Result<_, _>>()?;
    let publicas: Vec<ClavePublica> = secretas.iter().map(ClaveSecreta::clave_publica).collect();
    let firmas: Vec<Firma> = secretas
        .iter()
        .map(|secreta| firmar(secreta, DOMINIO, MENSAJE))
        .collect::<Result<_, _>>()?;
    let escalares = escalares(K);
    let planos = planos(&escalares);
    let refs_publicas: Vec<&ClavePublica> = publicas.iter().collect();
    let refs_firmas: Vec<&Firma> = firmas.iter().collect();

    // Puntos `blst` sin comprobación de subgrupo: entran en `mult` igual que los del tipo.
    let publicas_blst: Vec<BlstPublicKey> = publicas
        .iter()
        .map(|pk| BlstPublicKey::deserialize(&pk.bytes()).map_err(|e| format!("blst pk: {e:?}")))
        .collect::<Result<_, _>>()?;
    let firmas_blst: Vec<BlstSignature> = firmas
        .iter()
        .map(|f| BlstSignature::deserialize(&f.bytes()).map_err(|e| format!("blst firma: {e:?}")))
        .collect::<Result<_, _>>()?;

    // Productos y puntos fijos, calculados una vez para aislar los emparejamientos.
    let producto_claves = publicas_blst
        .as_slice()
        .mult(&planos, BITS_ESCALAR_LOTE)
        .to_public_key();
    let producto_firmas = firmas_blst
        .as_slice()
        .mult(&planos, BITS_ESCALAR_LOTE)
        .to_signature();

    let con_dominio = mensaje_con_dominio(DOMINIO, MENSAJE)?;
    let h_m_bytes = crudo::hash_a_g2(&con_dominio, crudo::DST_FIRMA)?;
    let h_m = BlstSignature::deserialize(&h_m_bytes).map_err(|e| format!("blst H(m): {e:?}"))?;
    let mut uno = [0u8; 32];
    if let Some(ultimo) = uno.last_mut() {
        *ultimo = 1;
    }
    let generador_clave = ClaveSecreta::desde_bytes(&uno)?.clave_publica();
    let generador = BlstPublicKey::deserialize(&generador_clave.bytes())
        .map_err(|e| format!("blst g1: {e:?}"))?;

    let mut filas: Vec<(&'static str, Vec<u64>)> = Vec::new();

    let muestras = medir(
        &mut || {
            verificar_lote_con_escalares(&refs_publicas, &refs_firmas, &escalares, DOMINIO, MENSAJE)
        },
        REPETICIONES,
    );
    filas.push(("total_publico", muestras));

    let muestras = medir(
        &mut || {
            publicas_blst
                .as_slice()
                .mult(&planos, BITS_ESCALAR_LOTE)
                .to_public_key()
        },
        REPETICIONES,
    );
    filas.push(("mult_g1_claves", muestras));

    let muestras = medir(
        &mut || {
            firmas_blst
                .as_slice()
                .mult(&planos, BITS_ESCALAR_LOTE)
                .to_signature()
        },
        REPETICIONES,
    );
    filas.push(("mult_g2_firmas", muestras));

    let pf_afin: &blst_p2_affine = (&producto_firmas).into();
    let g_afin: &blst_p1_affine = (&generador).into();
    let pc_afin: &blst_p1_affine = (&producto_claves).into();
    let hm_afin: &blst_p2_affine = (&h_m).into();
    let muestras = medir(
        &mut || {
            let lado_firmas = blst_fp12::miller_loop(pf_afin, g_afin).final_exp();
            let lado_claves = blst_fp12::miller_loop(hm_afin, pc_afin).final_exp();
            lado_firmas == lado_claves
        },
        REPETICIONES,
    );
    filas.push(("dos_emparejamientos", muestras));

    let muestras = medir(
        &mut || {
            let bytes = crudo::hash_a_g2(&con_dominio, crudo::DST_FIRMA);
            if let Ok(bytes) = bytes {
                let _ = BlstSignature::deserialize(&bytes);
            }
            let _ = ClaveSecreta::desde_bytes(&uno).map(|secreta| secreta.clave_publica());
        },
        REPETICIONES,
    );
    filas.push(("trabajo_fijo_h_y_g1", muestras));

    let muestras = medir(
        &mut || {
            let claves_ok = publicas_blst.iter().all(|pk| pk.validate().is_ok());
            let firmas_ok = firmas_blst.iter().all(|firma| firma.validate(true).is_ok());
            claves_ok && firmas_ok
        },
        REPETICIONES,
    );
    filas.push(("validacion_por_punto_eliminada", muestras));

    println!("# escenario\tK\tn\tmediana_ns\tp95_ns\tmin_ns\tmax_ns");
    for (nombre, muestras) in &filas {
        let mut ordenadas = muestras.clone();
        let (mediana, p95, minimo, maximo) = resumir(&mut ordenadas);
        println!("{nombre}\t{K}\t{REPETICIONES}\t{mediana}\t{p95}\t{minimo}\t{maximo}");
    }
    println!("# crudo: escenario\tK\tindice\tns");
    for (nombre, muestras) in &filas {
        for (indice, ns) in muestras.iter().enumerate() {
            println!("crudo\t{nombre}\t{K}\t{indice}\t{ns}");
        }
    }
    Ok(())
}
