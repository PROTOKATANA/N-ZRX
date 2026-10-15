//! V5 y V6 de ORDEN-W04: cadena dev minada y retarget dev.
//!
//! V5 mina 40 bloques con `Sha3Dev` desde el génesis dev, con timestamps **simulados** a `T` (no
//! reloj real), retarget en cada bloque y validación de cada cabecera. V6 comprueba que el retarget
//! dev **baja** el target con bloques rápidos y lo **sube** con lentos, sin superar `limites.max`.
//!
//! Los intentos por bloque se derivan del `nonce` encontrado: el minero itera desde 0, así que el
//! primer acierto está en `nonce + 1`.

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#![expect(
    clippy::panic,
    reason = "el test falla ruidosamente si la cadena no valida"
)]

use core::sync::atomic::AtomicBool;
use std::time::Instant;

use primitive_types::U256;
use zx_consensus::{
    ContextoPow, GENESIS_DEV, PARAMETROS_POW_DEV, ParametrosPow, Red, Sha3Dev, VentanaRetarget,
    comprobar_al_arrancar, construir, minar, siguiente_target, validar_cabecera_pow,
};
use zx_core::preimage::block::BlockHeader;
use zx_core::target::{codificar_con, decodificar_con};
use zx_core::{CBID_RED_DEV, Digest, MerkleRoot};

/// **V5.** Génesis dev → 40 bloques minados, retarget en cada bloque y validación 40/40.
#[test]
#[expect(
    clippy::integer_division,
    reason = "la media de intentos es un conteo entero informativo; no decide ningún veredicto"
)]
fn v5_cadena_dev_minada_y_validada() {
    let p = PARAMETROS_POW_DEV;
    comprobar_al_arrancar(GENESIS_DEV).unwrap();
    let (genesis, _cb) = construir(GENESIS_DEV).unwrap();
    let target_inicial = decodificar_con(genesis.bits, &p.limites).unwrap();

    let mut ts: Vec<i64> = vec![i64::try_from(genesis.timestamp).unwrap()];
    let mut tg: Vec<U256> = vec![target_inicial];
    let mut cabezas: Vec<BlockHeader> = vec![genesis];
    let mut intentos: Vec<u64> = Vec::new();

    let cancelar = AtomicBool::new(false);
    let inicio = Instant::now();
    let bloques: usize = 40;

    for h in 1..=bloques {
        // C-DIFF-02: para 1 ≤ h ≤ N rige el bits de arranque; a partir de N+1, LWMA-1.
        let target = if h <= p.n {
            target_inicial
        } else {
            let ts_win = ts.get(h - p.n - 1..h).unwrap();
            let tg_win = tg.get(h - p.n..h).unwrap();
            siguiente_target(
                VentanaRetarget {
                    timestamps: ts_win,
                    targets: tg_win,
                },
                &p,
            )
            .unwrap()
        };
        let ts_padre = ts.get(h - 1).copied().unwrap();
        let ts_h = ts_padre + p.t;
        let padre = cabezas.get(h - 1).copied().unwrap();

        let plantilla = BlockHeader {
            consensus_branch_id: CBID_RED_DEV,
            prev_hash: padre.block_hash(),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0u8; 32])),
            timestamp: u64::try_from(ts_h).unwrap(),
            bits: codificar_con(target, &p.limites),
            nonce: 0,
            height: u32::try_from(h).unwrap(),
        };
        let ctx = ContextoPow {
            red: Red::Dev,
            parametros: p,
            altura_padre: u32::try_from(h - 1).unwrap(),
            hash_padre: padre.block_hash(),
            target_esperado: target,
            ts_padre,
            reloj_local: ts_h,
        };

        let minado = minar(&plantilla, target, &Sha3Dev, 50_000_000, &cancelar)
            .unwrap_or_else(|| panic!("el perfil dev mina cada bloque en el presupuesto"));
        validar_cabecera_pow(&minado, &ctx, &Sha3Dev).unwrap();

        intentos.push(minado.nonce.saturating_add(1));
        ts.push(ts_h);
        tg.push(target);
        cabezas.push(minado);
    }

    let pared = inicio.elapsed();
    assert_eq!(cabezas.len(), bloques + 1, "40 bloques sobre el génesis");
    assert_eq!(intentos.len(), bloques);

    let total: u64 = intentos.iter().sum();
    let divisor = u64::try_from(bloques).unwrap();
    let media = total / divisor;
    let maximo = intentos.iter().copied().max().unwrap();
    println!(
        "V5: {bloques}/{bloques} válidos; intentos/bloque media={media} max={maximo} total={total}; \
         tiempo de pared={pared:?}"
    );
}

/// Simula la cadena desde un target base y devuelve el target de cada bloque retargetado
/// (`altura > N`). `st_por_bloque[k]` es el solvetime del bloque `k+1`.
fn simular_retarget(p: &ParametrosPow, base: U256, st_por_bloque: &[i64]) -> Vec<U256> {
    let mut ts: Vec<i64> = vec![0];
    let mut tg: Vec<U256> = vec![base];
    let mut salida: Vec<U256> = Vec::new();

    for (k, st) in st_por_bloque.iter().enumerate() {
        let altura = k + 1;
        let objetivo = if altura <= p.n {
            base
        } else {
            let ts_win = ts.get(altura - p.n - 1..altura).unwrap();
            let tg_win = tg.get(altura - p.n..altura).unwrap();
            siguiente_target(
                VentanaRetarget {
                    timestamps: ts_win,
                    targets: tg_win,
                },
                p,
            )
            .unwrap()
        };
        let ultimo = ts.last().copied().unwrap();
        ts.push(ultimo + st);
        tg.push(objetivo);
        if altura > p.n {
            salida.push(objetivo);
        }
    }
    salida
}

/// **V6.** Retarget dev: rápido ⇒ baja; lento ⇒ sube; nunca supera `limites.max`.
#[test]
fn v6_retarget_dev_responde_y_no_supera_el_maximo() {
    let p = PARAMETROS_POW_DEV;
    let base = decodificar_con(p.bits_iniciales, &p.limites).unwrap();

    // `T/4 = 0,5 s` no es representable en segundos enteros; se usa `1` (el mínimo tras la
    // reconstrucción monótona de C-DIFF-03), que también es «rápido» y baja el target.
    let rapidos = simular_retarget(&p, base, &vec![1i64; p.n + 40]);
    let bajo = *rapidos.last().unwrap();
    assert!(
        bajo < base,
        "con bloques rápidos el target baja: {bajo} !< {base}"
    );

    // Tras la fase rápida, la lenta (`4T = 8 s`) lo sube, sin superar el máximo.
    let mut sts = vec![1i64; p.n + 40];
    sts.extend_from_slice(&[4 * p.t; 40]);
    let mixtos = simular_retarget(&p, base, &sts);
    let fin = *mixtos.last().unwrap();
    assert!(
        fin > bajo,
        "tras la fase lenta el target sube: {fin} > {bajo}"
    );
    assert!(fin <= base, "sin superar limites.max: {fin} <= {base}");
    assert!(
        mixtos.iter().all(|t| *t <= base && *t >= p.limites.min),
        "todos los targets dentro de los límites de la red"
    );
}
