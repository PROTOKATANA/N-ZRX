//! Bloque génesis (SPEC §15, `C-GEN-01…07`).
//!
//! # Definición constructiva, no bytes hardcodeados
//!
//! El génesis se construye con una función determinista de parámetros explícitos, y su hash se
//! compara contra una constante. Es el patrón de Bitcoin y Zcash, y se eligió sobre el de Monero
//! —transacción coinbase en hexadecimal crudo— por dos razones: es **auditable**, porque se ve de
//! qué parámetros sale, y **falla duro y visible** si alguien toca un parámetro sin recalcular el
//! hash, en lugar de arrancar en silencio sobre un génesis no intencionado.
//!
//! # Redes
//!
//! Mainnet sigue **bloqueado** por P-017 (sin hash congelado). Testnet conserva sus parámetros y su
//! hash congelado de `9681061`. La **red dev** de 0.0.1 (F-12, F-13) añade sus propios parámetros y
//! congela `HASH_GENESIS_DEV`.

use zx_core::Red;
use zx_core::amount::Amount;
use zx_core::digest::{BlockHash, Digest, TxId};
use zx_core::firma::ClavePublica;
use zx_core::preimage::block::{BlockHeader, merkle_root};
use zx_core::preimage::tx::txid;
use zx_core::target::{TARGET_INICIAL_BITS_MAINNET, TARGET_INICIAL_BITS_TESTNET, decodificar_con};
use zx_core::tx::{ExtensionTx, Lock, Tx, TxOut};

use crate::activacion::rama_activa;
use crate::error::ErrorPow;
use crate::parametros::{PARAMETROS_POW_DEV, limites_de};

/// Versión de la transacción coinbase PoW en v0 (`F-05`): transferencia/coinbase, idéntica a
/// `9681061`.
pub const VERSION_TX: u32 = 1;

/// Parámetros de los que se construye un génesis (`C-GEN-01`).
///
/// Que sean explícitos es el punto: cualquiera puede reconstruir el bloque y comprobar el hash.
#[derive(Clone, Copy, Debug)]
pub struct ParametrosGenesis {
    /// Red a la que pertenece.
    pub red: Red,
    /// Mensaje simbólico de la coinbase (`C-GEN-05`).
    ///
    /// **No tiene función de consenso** — ningún nodo inspecciona su contenido. Su valor es una
    /// comprobación humana, manual y única.
    pub mensaje: &'static [u8],
    /// Segundos Unix del lanzamiento.
    pub timestamp: u64,
    /// Nonce. No hay PoW que resolver (`C-GEN-02`), así que su única función es separar redes.
    pub nonce: u64,
}

/// 🔴 **P-017.** Parámetros de mainnet — marcador de posición hasta el día del lanzamiento.
///
/// **Están diseñados para NO pasar [`comprobar`].** El `timestamp: 0` incumple `C-GEN-06` a
/// propósito, así que un nodo que intente arrancar en mainnet con estos parámetros **aborta con un
/// mensaje que nombra a P-017**.
pub const GENESIS_MAINNET: ParametrosGenesis = ParametrosGenesis {
    red: Red::Mainnet,
    mensaje: b"PENDIENTE P-017: titular verificable de la fecha de lanzamiento",
    timestamp: 0,
    nonce: 0,
};

/// ✅ Parámetros de **testnet** — reales, no marcador de posición. El timestamp es
/// **2026-09-04 00:00:00 UTC**.
pub const GENESIS_TESTNET: ParametrosGenesis = ParametrosGenesis {
    red: Red::Testnet,
    mensaje: b"ZEROX testnet 2026-09-04 - sin valor, se reinicia sin aviso",
    timestamp: 1_788_480_000,
    nonce: 1,
};

/// ✅ Parámetros de la **red dev** (`F-13`).
///
/// Mensaje `b"ZEROX hibrido red dev v0 - sin valor"`, timestamp **2026-09-26 00:00:00 UTC**
/// (`1_790_380_800 ≥ TIMESTAMP_MINIMO_GENESIS`), `nonce 0` y `bits` del perfil dev
/// (`PARAMETROS_POW_DEV.bits_iniciales`), que aplica [`target_inicial_bits`].
pub const GENESIS_DEV: ParametrosGenesis = ParametrosGenesis {
    red: Red::Dev,
    mensaje: b"ZEROX hibrido red dev v0 - sin valor",
    timestamp: 1_790_380_800,
    nonce: 0,
};

/// Hash del génesis de **testnet**, la aserción que `C-GEN-01` pide hardcodear.
pub const HASH_GENESIS_TESTNET: [u8; 32] = [
    0xfe, 0x56, 0x84, 0x5a, 0x01, 0xba, 0xfa, 0x5a, 0x51, 0xae, 0x43, 0xdd, 0x43, 0xd1, 0x65, 0x84,
    0x96, 0x6f, 0x65, 0xa2, 0xac, 0xb4, 0x1b, 0xc6, 0xfa, 0xc2, 0x81, 0x81, 0x40, 0x62, 0xb6, 0xf1,
];

/// Hash del génesis de **dev**, congelado igual que el de testnet (`C-GEN-07`, F-13).
///
/// Cambiar cualquier parámetro de [`GENESIS_DEV`] sin recalcular esta constante hace fallar el test
/// `el_hash_del_genesis_dev_esta_congelado` y el arranque del nodo.
pub const HASH_GENESIS_DEV: [u8; 32] = [
    0xc7, 0x2f, 0xdb, 0x3b, 0x37, 0xe7, 0x57, 0x1a, 0x82, 0xec, 0x1e, 0x0e, 0x97, 0x3e, 0x90, 0xd5,
    0xe9, 0x5e, 0x7a, 0xd9, 0xfc, 0x87, 0x17, 0x72, 0x26, 0x5b, 0x19, 0x94, 0x05, 0x0c, 0x2d, 0x59,
];

/// Suelo de plausibilidad del timestamp del génesis: **2026-01-01 00:00:00 UTC** (`C-GEN-06`).
pub const TIMESTAMP_MINIMO_GENESIS: u64 = 1_767_225_600;

/// Coinbase del génesis: **valor cero** (`C-GEN-03`, `C-EMIT-02`).
///
/// Sus salidas **MUST NOT** insertarse en el UTXO set. El mensaje viaja en el `lock` de una salida de
/// valor cero; es inconectable, así que no crea un UTXO no gastable.
#[must_use]
pub fn coinbase_genesis(mensaje: &[u8]) -> Tx {
    let mut marca = [0u8; 32];
    for (i, b) in mensaje.iter().enumerate() {
        if let Some(d) = marca.get_mut(i % 32) {
            *d ^= *b;
        }
    }
    Tx {
        version: VERSION_TX,
        inputs: vec![],
        outputs: vec![TxOut {
            value: Amount::CERO,
            lock: Lock::PubKey {
                pubkey: ClavePublica::desde_bytes(marca),
            },
        }],
        lock_time: 0,
        // C-EMIT-04: la coinbase declara su altura. El génesis está en la 0.
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    }
}

/// `bits` de arranque de cada red (`C-DIFF-02`, P-004c; dev en `ORDEN-W04 §3.5`).
#[must_use]
pub const fn target_inicial_bits(red: Red) -> u32 {
    match red {
        Red::Mainnet => TARGET_INICIAL_BITS_MAINNET,
        Red::Testnet => TARGET_INICIAL_BITS_TESTNET,
        Red::Dev => PARAMETROS_POW_DEV.bits_iniciales,
    }
}

/// Construye el bloque génesis a partir de sus parámetros (`C-GEN-01`).
///
/// # Errores
/// [`ErrorPow::SinRamaActiva`] si la tabla de ramas de la red está mal formada.
pub fn construir(p: ParametrosGenesis) -> Result<(BlockHeader, Tx), ErrorPow> {
    let cb = coinbase_genesis(p.mensaje);
    let branch_id = rama_activa(p.red, 0)?;
    let raiz = merkle_root(&[txid(&cb, branch_id)]);

    Ok((
        BlockHeader {
            consensus_branch_id: branch_id,
            // El génesis no tiene padre. Cero es el único valor con significado aquí.
            prev_hash: BlockHash::from_digest(Digest::from_bytes([0u8; 32])),
            merkle_root: raiz,
            timestamp: p.timestamp,
            bits: target_inicial_bits(p.red),
            nonce: p.nonce,
            height: 0,
        },
        cb,
    ))
}

/// Comprueba que un génesis construido cumple todas las invariantes de §15.
///
/// **No comprueba el PoW**: `C-GEN-02` lo exime explícitamente.
///
/// # Errores
/// [`ErrorPow::GenesisInvalido`] con el motivo concreto.
pub fn comprobar(cabecera: &BlockHeader, coinbase: &Tx, red: Red) -> Result<(), ErrorPow> {
    let malo = |motivo| ErrorPow::GenesisInvalido { motivo };

    if cabecera.height != 0 {
        return Err(malo("C-HDR-02: el génesis MUST estar en la altura 0"));
    }
    if *cabecera.prev_hash.as_bytes() != [0u8; 32] {
        return Err(malo("el génesis no tiene padre: prev_hash MUST ser cero"));
    }
    if !coinbase.inputs.is_empty() {
        return Err(malo("C-BLK-07: la coinbase no tiene entradas"));
    }
    if coinbase.expiry_height != 0 {
        return Err(malo(
            "C-EMIT-04: la coinbase del génesis declara la altura 0",
        ));
    }
    // C-GEN-03 · valor cero. Sin premine, sin dev tax, sin founder reward.
    let total: i64 = coinbase.outputs.iter().map(|s| s.value.brek()).sum();
    if total != 0 {
        return Err(malo(
            "C-GEN-03/C-EMIT-02: la coinbase del génesis MUST valer cero",
        ));
    }
    // La raíz de Merkle compromete esa coinbase y no otra.
    if merkle_root(&[txid(coinbase, cabecera.consensus_branch_id)]) != cabecera.merkle_root {
        return Err(malo(
            "C-BLK-01: la raíz de Merkle no compromete esta coinbase",
        ));
    }
    // `bits` MUST ser canónico y estar dentro de los límites de la red, aunque el PoW no se
    // compruebe. La red dev admite un máximo más fácil que `POW_LIMIT`, y por eso los límites se
    // eligen por red y no se leen de las constantes antiguas.
    decodificar_con(cabecera.bits, &limites_de(red))
        .map_err(|_| malo("C-POW-04/C-POW-05: los bits del génesis no son válidos en su red"))?;
    // C-GEN-06 · el timestamp MUST ser plausible.
    if cabecera.timestamp < TIMESTAMP_MINIMO_GENESIS {
        return Err(malo(
            "C-GEN-06: el timestamp del génesis es anterior a 2026 — ¿parámetros de marcador de \
             posición sin rellenar? Ver P-017",
        ));
    }
    Ok(())
}

/// Hash congelado de una red, o `None` si esa red todavía no lo tiene (`C-GEN-07`).
///
/// Mainnet devuelve `None` **a propósito** mientras P-017 siga abierto.
#[must_use]
pub const fn hash_congelado(red: Red) -> Option<[u8; 32]> {
    match red {
        Red::Testnet => Some(HASH_GENESIS_TESTNET),
        Red::Dev => Some(HASH_GENESIS_DEV),
        Red::Mainnet => None,
    }
}

/// **La comprobación de arranque completa (`C-GEN-01`, `C-GEN-07`).**
///
/// Hace tres cosas, en este orden: construye el génesis, comprueba las invariantes de §15 y compara
/// su hash contra la constante congelada del binario.
///
/// # Errores
/// [`ErrorPow::GenesisInvalido`] con el motivo concreto, o el error de [`construir`].
pub fn comprobar_al_arrancar(p: ParametrosGenesis) -> Result<BlockHash, ErrorPow> {
    let (cabecera, coinbase) = construir(p)?;
    comprobar(&cabecera, &coinbase, p.red)?;

    let obtenido = cabecera.block_hash();
    match hash_congelado(p.red) {
        Some(esperado) if obtenido.as_bytes() == &esperado => Ok(obtenido),
        Some(_) => Err(ErrorPow::GenesisInvalido {
            motivo: "C-GEN-07: el génesis construido NO coincide con el hash congelado del \
                     binario — o alguien tocó los parámetros, o este binario no es de esta red",
        }),
        // Una red sin hash congelado no puede arrancar. Hoy es mainnet, por P-017.
        None => Err(ErrorPow::GenesisInvalido {
            motivo: "C-GEN-07: esta red no tiene hash de génesis congelado todavía — ver P-017",
        }),
    }
}

/// Hash del génesis de una red, tal y como se hardcodearía para la aserción de `C-GEN-01`.
///
/// # Errores
/// La de [`construir`].
pub fn hash(p: ParametrosGenesis) -> Result<BlockHash, ErrorPow> {
    Ok(construir(p)?.0.block_hash())
}

/// El txid de la coinbase del génesis, que **MUST NOT** entrar en el UTXO set (`C-GEN-03`).
///
/// # Errores
/// La de [`construir`].
pub fn txid_coinbase(p: ParametrosGenesis) -> Result<TxId, ErrorPow> {
    let (cab, cb) = construir(p)?;
    Ok(txid(&cb, cab.consensus_branch_id))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::integer_division,
    reason = "los tests fallan con panic por diseño; la división de la derivación es exacta"
)]
mod tests {
    use super::target_inicial_bits;
    use super::{
        GENESIS_DEV, GENESIS_MAINNET, GENESIS_TESTNET, HASH_GENESIS_DEV, HASH_GENESIS_TESTNET,
        ParametrosGenesis, TIMESTAMP_MINIMO_GENESIS, coinbase_genesis, comprobar,
        comprobar_al_arrancar, construir, hash, hash_congelado, txid_coinbase,
    };
    use crate::activacion::Red;
    use crate::error::ErrorPow;
    use crate::parametros::{PARAMETROS_POW_ANTIGUOS, PARAMETROS_POW_DEV};
    use zx_core::amount::Amount;
    use zx_core::digest::{BlockHash, Digest};
    use zx_core::target::{TARGET_INICIAL_BITS_MAINNET, TARGET_INICIAL_BITS_TESTNET};

    #[test]
    fn el_genesis_de_testnet_es_valido() {
        let (cab, cb) = construir(GENESIS_TESTNET).unwrap();
        comprobar(&cab, &cb, Red::Testnet).unwrap_or_else(|e| panic!("testnet: {e}"));
    }

    #[test]
    fn el_genesis_dev_es_valido() {
        let (cab, cb) = construir(GENESIS_DEV).unwrap();
        comprobar(&cab, &cb, Red::Dev).unwrap_or_else(|e| panic!("dev: {e}"));
    }

    /// **C-GEN-06 · P-017.** Mainnet **MUST NOT** arrancar todavía, y esto lo demuestra.
    #[test]
    fn el_genesis_de_mainnet_todavia_no_arranca() {
        let (cab, cb) = construir(GENESIS_MAINNET).unwrap();
        let Err(e) = comprobar(&cab, &cb, Red::Mainnet) else {
            panic!("P-017 sigue abierto: el génesis de mainnet NO debe validar todavía");
        };
        let texto = format!("{e}");
        assert!(
            texto.contains("C-GEN-06") && texto.contains("P-017"),
            "el error debe decir qué falta y dónde está anotado: {texto}"
        );
    }

    #[test]
    fn el_arranque_de_testnet_valida_y_compara_el_hash() {
        let h = comprobar_al_arrancar(GENESIS_TESTNET).expect("testnet arranca");
        assert_eq!(h.as_bytes(), &HASH_GENESIS_TESTNET);
    }

    /// **C-GEN-07.** El arranque de dev valida y compara el hash congelado.
    #[test]
    fn el_arranque_dev_valida_y_compara_el_hash() {
        let h = comprobar_al_arrancar(GENESIS_DEV).expect("dev arranca");
        assert_eq!(h.as_bytes(), &HASH_GENESIS_DEV);
    }

    /// Tocar un parámetro sin recalcular el hash **impide arrancar**.
    #[test]
    fn un_parametro_tocado_impide_arrancar() {
        for tocar in [
            |mut p: ParametrosGenesis| {
                p.timestamp += 1;
                p
            },
            |mut p: ParametrosGenesis| {
                p.nonce += 1;
                p
            },
            |mut p: ParametrosGenesis| {
                p.mensaje = b"otro mensaje cualquiera";
                p
            },
        ] {
            let p = tocar(GENESIS_TESTNET);
            let Err(e) = comprobar_al_arrancar(p) else {
                panic!("un parámetro tocado MUST impedir el arranque");
            };
            assert!(format!("{e}").contains("C-GEN-07"), "{e}");
        }
    }

    #[test]
    fn mainnet_no_arranca_porque_no_tiene_hash_congelado() {
        assert!(
            hash_congelado(Red::Mainnet).is_none(),
            "P-017 sigue abierto"
        );
        assert!(comprobar_al_arrancar(GENESIS_MAINNET).is_err());
    }

    #[test]
    fn el_hash_del_genesis_de_testnet_esta_congelado() {
        let h = hash(GENESIS_TESTNET).unwrap();
        assert_eq!(
            h.as_bytes(),
            &HASH_GENESIS_TESTNET,
            "el génesis de testnet cambió — si es a propósito, actualiza HASH_GENESIS_TESTNET"
        );
    }

    /// **C-GEN-07 · F-13.** El hash del génesis dev está congelado.
    #[test]
    fn el_hash_del_genesis_dev_esta_congelado() {
        let h = hash(GENESIS_DEV).unwrap();
        assert_eq!(
            h.as_bytes(),
            &HASH_GENESIS_DEV,
            "el génesis dev cambió — si es a propósito, actualiza HASH_GENESIS_DEV"
        );
    }

    #[test]
    fn mainnet_y_testnet_no_comparten_genesis() {
        assert_ne!(
            hash(GENESIS_MAINNET).unwrap().as_bytes(),
            hash(GENESIS_TESTNET).unwrap().as_bytes(),
            "C-GEN-04: un génesis compartido dejaría a las dos redes confundirse"
        );
    }

    /// **C-GEN-04.** Ninguna red comparte génesis con la dev.
    #[test]
    fn la_red_dev_tiene_genesis_propio() {
        let dev = hash(GENESIS_DEV).unwrap();
        assert_ne!(dev, hash(GENESIS_MAINNET).unwrap());
        assert_ne!(dev, hash(GENESIS_TESTNET).unwrap());
        assert_ne!(
            txid_coinbase(GENESIS_DEV).unwrap(),
            txid_coinbase(GENESIS_TESTNET).unwrap()
        );
    }

    /// **C-GEN-06.** El suelo es un suelo: un segundo antes falla, el suelo justo pasa.
    #[test]
    fn el_borde_exacto_del_suelo_de_timestamp() {
        let mut p = GENESIS_TESTNET;

        p.timestamp = TIMESTAMP_MINIMO_GENESIS - 1;
        let (cab, cb) = construir(p).unwrap();
        assert!(
            comprobar(&cab, &cb, Red::Testnet).is_err(),
            "un segundo antes MUST fallar"
        );

        p.timestamp = TIMESTAMP_MINIMO_GENESIS;
        let (cab, cb) = construir(p).unwrap();
        assert!(
            comprobar(&cab, &cb, Red::Testnet).is_ok(),
            "el suelo justo MUST valer"
        );
    }

    /// **Por qué C-GEN-06 existe, medido.**
    #[test]
    fn un_genesis_en_el_ano_cero_sesga_el_primer_retarget() {
        let pp = PARAMETROS_POW_ANTIGUOS;
        let n = i64::try_from(pp.n).unwrap();
        let k = n * (n + 1) / 2 * pp.t;
        assert_eq!(k, pp.k().unwrap(), "K = N(N+1)T/2");

        let t_sano: i64 = (1..=n).map(|j| j * pp.t).sum();
        assert_eq!(
            t_sano, k,
            "con st = T en todos, t = k y el target no se mueve"
        );

        let st_cap = pp.st_cap().unwrap();
        let t_sesgado: i64 = st_cap + (2..=n).map(|j| j * pp.t).sum::<i64>();
        assert!(t_sesgado > k, "el target se afloja");
        assert_eq!(
            t_sesgado - k,
            st_cap - pp.t,
            "exactamente ST_CAP − T, con peso j=1"
        );

        assert!(t_sesgado * 1000 > k * 1001 && t_sesgado * 1000 < k * 1002);
    }

    #[test]
    fn el_genesis_esta_en_la_altura_cero_y_no_tiene_padre() {
        let (cab, _) = construir(GENESIS_MAINNET).unwrap();
        assert_eq!(cab.height, 0);
        assert_eq!(cab.prev_hash.as_bytes(), &[0u8; 32]);
    }

    /// **P-004c.** Cada red arranca con SU dificultad; la dev con la del perfil dev.
    #[test]
    fn cada_red_arranca_con_su_propia_dificultad() {
        for p in [GENESIS_MAINNET, GENESIS_TESTNET, GENESIS_DEV] {
            let (cab, _) = construir(p).unwrap();
            assert_eq!(
                cab.bits,
                target_inicial_bits(p.red),
                "C-DIFF-02, {:?}",
                p.red
            );
        }
        assert_eq!(
            target_inicial_bits(Red::Mainnet),
            TARGET_INICIAL_BITS_MAINNET
        );
        assert_eq!(
            target_inicial_bits(Red::Testnet),
            TARGET_INICIAL_BITS_TESTNET
        );
        assert_eq!(
            target_inicial_bits(Red::Dev),
            PARAMETROS_POW_DEV.bits_iniciales
        );
        assert_eq!(GENESIS_DEV.timestamp, 1_790_380_800);
        const {
            assert!(
                GENESIS_DEV.timestamp >= TIMESTAMP_MINIMO_GENESIS,
                "el timestamp del génesis dev MUST ser posterior al suelo de C-GEN-06"
            )
        };
        assert_eq!(GENESIS_DEV.nonce, 0);
    }

    /// **C-GEN-03 / C-EMIT-02.** Sin premine, sin dev tax, sin founder reward.
    #[test]
    fn la_coinbase_del_genesis_vale_cero() {
        let (_, cb) = construir(GENESIS_MAINNET).unwrap();
        let total: i64 = cb.outputs.iter().map(|s| s.value.brek()).sum();
        assert_eq!(total, 0, "el génesis MUST NOT crear valor");
        assert!(cb.inputs.is_empty(), "es coinbase");
    }

    #[test]
    fn se_rechaza_un_genesis_con_premine() {
        let (cab, mut cb) = construir(GENESIS_MAINNET).unwrap();
        if let Some(s) = cb.outputs.first_mut() {
            s.value = Amount::nuevo(1).unwrap();
        }
        let e = comprobar(&cab, &cb, Red::Mainnet).unwrap_err();
        assert!(matches!(e, ErrorPow::GenesisInvalido { .. }), "{e:?}");
        assert!(
            format!("{e}").contains("cero"),
            "el error debe nombrar la regla"
        );
    }

    #[test]
    fn mainnet_y_testnet_tienen_genesis_distintos() {
        let m = hash(GENESIS_MAINNET).unwrap();
        let t = hash(GENESIS_TESTNET).unwrap();
        assert_ne!(m, t, "C-GEN-04: los génesis de las dos redes MUST diferir");
        assert_ne!(
            txid_coinbase(GENESIS_MAINNET).unwrap(),
            txid_coinbase(GENESIS_TESTNET).unwrap(),
            "y sus coinbases también"
        );
    }

    #[test]
    fn el_genesis_es_determinista() {
        let a = hash(GENESIS_MAINNET).unwrap();
        for _ in 0..5 {
            assert_eq!(hash(GENESIS_MAINNET).unwrap(), a);
        }
    }

    #[test]
    fn cada_parametro_cambia_el_hash_del_genesis() {
        let base = hash(GENESIS_MAINNET).unwrap();

        let mut p = GENESIS_MAINNET;
        p.mensaje = b"otro mensaje completamente distinto";
        assert_ne!(hash(p).unwrap(), base, "mensaje");

        let mut p = GENESIS_MAINNET;
        p.timestamp = 1;
        assert_ne!(hash(p).unwrap(), base, "timestamp");

        let mut p = GENESIS_MAINNET;
        p.nonce = 1;
        assert_ne!(hash(p).unwrap(), base, "nonce");
    }

    #[test]
    fn una_coinbase_cambiada_invalida_el_genesis() {
        let (cab, _) = construir(GENESIS_MAINNET).unwrap();
        let otra = coinbase_genesis(b"una coinbase que no es la del genesis");
        assert!(matches!(
            comprobar(&cab, &otra, Red::Mainnet),
            Err(ErrorPow::GenesisInvalido { .. })
        ));
    }

    #[test]
    fn se_rechaza_un_genesis_con_padre() {
        let (mut cab, cb) = construir(GENESIS_MAINNET).unwrap();
        cab.prev_hash = BlockHash::from_digest(Digest::from_bytes([1u8; 32]));
        assert!(comprobar(&cab, &cb, Red::Mainnet).is_err());
    }

    #[test]
    fn se_rechaza_un_genesis_fuera_de_la_altura_cero() {
        let (mut cab, cb) = construir(GENESIS_MAINNET).unwrap();
        cab.height = 1;
        assert!(comprobar(&cab, &cb, Red::Mainnet).is_err());
    }

    /// **C-GEN-02: el génesis NO pasa por la comprobación de PoW.**
    #[test]
    fn el_genesis_no_necesita_resolver_el_pow() {
        let (cab, cb) = construir(GENESIS_TESTNET).unwrap();
        assert_eq!(cab.nonce, 1);
        assert!(
            comprobar(&cab, &cb, Red::Testnet).is_ok(),
            "C-GEN-02: exento del PoW"
        );
    }

    #[test]
    fn el_genesis_declara_la_rama_activa() {
        for (p, red) in [
            (GENESIS_MAINNET, Red::Mainnet),
            (GENESIS_TESTNET, Red::Testnet),
            (GENESIS_DEV, Red::Dev),
        ] {
            let (cab, _) = construir(p).unwrap();
            assert_eq!(
                cab.consensus_branch_id,
                crate::activacion::rama_activa(red, 0).unwrap()
            );
        }
    }
}
