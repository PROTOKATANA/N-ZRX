//! Casos de `validar_cabecera_pow` (ORDEN-W04 §5 y §6).
//!
//! Cada negativo lleva **su** error explícito, y el timestamp futuro se marca como **no
//! permanente**. El PoW se controla con un [`AlgoritmoPow`] fijo para poder probar el borde exacto
//! `hash_pow == target`, que con SHA3-256 costaría ~2¹⁷ hashes encontrar.

#![expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#![expect(
    clippy::panic,
    reason = "el test falla ruidosamente si el caso no encaja"
)]

use primitive_types::U256;
use zx_consensus::{
    AlgoritmoPow, ContextoPow, ErrorPow, PARAMETROS_POW_DEV, Red, Sha3Dev, siguiente_target,
    validar_cabecera_pow,
};
use zx_core::preimage::block::BlockHeader;
use zx_core::target::{LIMITES_AMPLIOS, codificar_con, decodificar_con};
use zx_core::{BlockHash, CBID_RED_DEV, Digest, MerkleRoot};

/// Devuelve siempre los mismos 32 bytes, para fijar el resultado del PoW sin minar.
struct HashFijo([u8; 32]);

impl AlgoritmoPow for HashFijo {
    fn hash_pow(&self, _: &BlockHeader) -> [u8; 32] {
        self.0
    }
}

const HASH_CERO: [u8; 32] = [0u8; 32];

fn hash_padre() -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([0x11; 32]))
}

fn target_dev() -> U256 {
    decodificar_con(
        PARAMETROS_POW_DEV.bits_iniciales,
        &PARAMETROS_POW_DEV.limites,
    )
    .unwrap()
}

/// Escenario base: un bloque hijo de la altura 0, todo correcto salvo lo que el test estropee.
fn escenario() -> (ContextoPow, BlockHeader) {
    let p = PARAMETROS_POW_DEV;
    let cabecera = BlockHeader {
        consensus_branch_id: CBID_RED_DEV,
        prev_hash: hash_padre(),
        merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x22; 32])),
        timestamp: 1_790_380_802,
        bits: p.bits_iniciales,
        nonce: 0,
        height: 1,
    };
    let ctx = ContextoPow {
        red: Red::Dev,
        parametros: p,
        altura_padre: 0,
        hash_padre: hash_padre(),
        target_esperado: target_dev(),
        ts_padre: 1_790_380_800,
        reloj_local: 1_790_380_802,
    };
    (ctx, cabecera)
}

/// Con todo correcto —y un `hash_pow` a cero— la cabecera es válida.
#[test]
fn una_cabecera_correcta_valida() {
    let (ctx, cabecera) = escenario();
    validar_cabecera_pow(&cabecera, &ctx, &HashFijo(HASH_CERO)).unwrap();
}

/// El `hash_pow` real de `Sha3Dev` también pasa cuando el nonce se ha minado.
#[test]
fn el_hash_pow_de_sha3_dev_tambien_valida() {
    let (ctx, mut cabecera) = escenario();
    let cancelar = core::sync::atomic::AtomicBool::new(false);
    let minado = zx_consensus::minar(&cabecera, target_dev(), &Sha3Dev, 5_000_000, &cancelar)
        .unwrap_or_else(|| panic!("el target dev se mina en pocos intentos"));
    cabecera = minado;
    validar_cabecera_pow(&cabecera, &ctx, &Sha3Dev).unwrap();
}

#[test]
fn un_branch_id_de_mainnet_en_la_red_dev_invalida() {
    let (ctx, mut cabecera) = escenario();
    cabecera.consensus_branch_id = zx_consensus::RAMA_V1_MAINNET.id;
    let e = validar_cabecera_pow(&cabecera, &ctx, &HashFijo(HASH_CERO)).unwrap_err();
    assert!(matches!(e, ErrorPow::BranchIdIncorrecto { .. }), "{e:?}");
}

#[test]
fn un_prev_hash_distinto_invalida() {
    let (ctx, mut cabecera) = escenario();
    cabecera.prev_hash = BlockHash::from_digest(Digest::from_bytes([0x33; 32]));
    let e = validar_cabecera_pow(&cabecera, &ctx, &HashFijo(HASH_CERO)).unwrap_err();
    assert!(matches!(e, ErrorPow::PrevHashIncorrecto { .. }), "{e:?}");
}

#[test]
fn una_altura_igual_a_la_del_padre_invalida() {
    let (ctx, mut cabecera) = escenario();
    cabecera.height = 0;
    let e = validar_cabecera_pow(&cabecera, &ctx, &HashFijo(HASH_CERO)).unwrap_err();
    assert!(
        matches!(
            e,
            ErrorPow::AlturaIncorrecta {
                esperada: 1,
                encontrada: 0
            }
        ),
        "{e:?}"
    );
}

#[test]
fn una_altura_dos_por_encima_del_padre_invalida() {
    let (ctx, mut cabecera) = escenario();
    cabecera.height = 2;
    let e = validar_cabecera_pow(&cabecera, &ctx, &HashFijo(HASH_CERO)).unwrap_err();
    assert!(
        matches!(
            e,
            ErrorPow::AlturaIncorrecta {
                esperada: 1,
                encontrada: 2
            }
        ),
        "{e:?}"
    );
}

#[test]
fn unos_bits_distintos_de_los_esperados_invalidan() {
    let (ctx, mut cabecera) = escenario();
    cabecera.bits = codificar_con(target_dev() / U256::from(2u32), &ctx.parametros.limites);
    let e = validar_cabecera_pow(&cabecera, &ctx, &HashFijo(HASH_CERO)).unwrap_err();
    assert!(matches!(e, ErrorPow::BitsIncorrectos { .. }), "{e:?}");
}

#[test]
fn unos_bits_no_canonicos_invalidan() {
    let (ctx, mut cabecera) = escenario();
    // `0x1d0000ff` representa el mismo target que `0x1b00ff00` con exponente menor: no canónico.
    cabecera.bits = 0x1d00_00ff;
    let e = validar_cabecera_pow(&cabecera, &ctx, &HashFijo(HASH_CERO)).unwrap_err();
    assert!(matches!(e, ErrorPow::BitsNoCanonicos { .. }), "{e:?}");
}

#[test]
fn unos_bits_fuera_de_los_limites_de_la_red_invalidan() {
    let (ctx, mut cabecera) = escenario();
    // `0x1f7fffff` es canónico pero su target (`0x7fffff · 2^224`) supera el máximo dev.
    let t = decodificar_con(0x1f7f_ffff, &LIMITES_AMPLIOS).unwrap();
    assert!(
        t > ctx.parametros.limites.max,
        "el vector excede el techo dev"
    );
    assert!(
        decodificar_con(0x1f7f_ffff, &ctx.parametros.limites).is_err(),
        "y por eso la red dev lo rechaza"
    );
    cabecera.bits = 0x1f7f_ffff;
    let e = validar_cabecera_pow(&cabecera, &ctx, &HashFijo(HASH_CERO)).unwrap_err();
    assert!(matches!(e, ErrorPow::TargetFueraDeRango { .. }), "{e:?}");
}

#[test]
fn un_hash_pow_igual_al_target_invalida() {
    let (ctx, cabecera) = escenario();
    let target = target_dev();
    let e = validar_cabecera_pow(&cabecera, &ctx, &HashFijo(target.to_big_endian())).unwrap_err();
    assert!(
        matches!(e, ErrorPow::PowInsuficiente),
        "C-POW-01: la comparación es estricta, igual NO cumple: {e:?}"
    );
}

#[test]
fn un_hash_pow_mayor_que_el_target_invalida() {
    let (ctx, cabecera) = escenario();
    let e =
        validar_cabecera_pow(&cabecera, &ctx, &HashFijo(U256::MAX.to_big_endian())).unwrap_err();
    assert!(matches!(e, ErrorPow::PowInsuficiente), "{e:?}");
}

#[test]
fn un_timestamp_igual_al_del_padre_invalida_permanentemente() {
    let (ctx, mut cabecera) = escenario();
    cabecera.timestamp = 1_790_380_800;
    let e = validar_cabecera_pow(&cabecera, &ctx, &HashFijo(HASH_CERO)).unwrap_err();
    assert!(matches!(e, ErrorPow::TimestampNoMonotono { .. }), "{e:?}");
    assert!(e.es_permanente(), "C-TS-01 es rechazo permanente");
}

#[test]
fn un_timestamp_futuro_es_rechazo_diferible() {
    let (ctx, mut cabecera) = escenario();
    cabecera.timestamp = 1_790_380_800 + 1_000;
    let e = validar_cabecera_pow(&cabecera, &ctx, &HashFijo(HASH_CERO)).unwrap_err();
    assert!(
        matches!(e, ErrorPow::TimestampDemasiadoFuturo { .. }),
        "{e:?}"
    );
    assert!(
        !e.es_permanente(),
        "C-TS-03: MUST NOT cachearse como inválido — se difiere y se reintenta"
    );
}

/// El retarget dev, con timestamps estables, deja el target en el máximo y no se mueve.
#[test]
fn el_target_esperado_estable_es_el_de_arranque() {
    let p = PARAMETROS_POW_DEV;
    let base = target_dev();
    let ts: Vec<i64> = (0..=p.n).map(|i| i64::try_from(i).unwrap() * p.t).collect();
    let tg: Vec<U256> = vec![base; p.n];
    let next = siguiente_target(
        zx_consensus::VentanaRetarget {
            timestamps: &ts,
            targets: &tg,
        },
        &p,
    )
    .unwrap();
    assert_eq!(next, base, "con st = T el target no se mueve");
}
