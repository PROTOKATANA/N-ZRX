//! Target compacto, comparación de PoW y trabajo acumulado (SPEC §7.1, §7.2, §11).
//!
//! # La trampa de endianness
//!
//! `C-POW-01` compara el hash de bloque con el target interpretándolo como entero **big-endian**.
//!
//! Zebra hace lo contrario —`U256::from_little_endian`— y no está mal: Bitcoin y Zcash muestran y
//! almacenan sus hashes con los bytes invertidos por convención histórica, y Zebra respeta esa
//! convención. **ZEROX no la tiene.** Portar ese archivo tal cual compilaría, pasaría cualquier test
//! autoconsistente, y produciría una cadena distinta a la del resto de la red.
//!
//! Por eso hay un test que fija la convención con un vector asimétrico, y no un comentario pidiendo
//! cuidado.

use primitive_types::U256;

use crate::digest::BlockHash;
use crate::error::EncodingError;

/// Target máximo — la **dificultad mínima** que el protocolo admite (P-004).
///
/// `2^224 − 1`. Equivale a `2^32` ≈ 4,29·10⁹ hashes por bloque, es decir ~35,8 MH/s sostenidos para
/// mantener los 120 s.
pub fn pow_limit() -> U256 {
    (U256::one() << 224usize) - U256::one()
}

/// Target mínimo — la **dificultad máxima** (P-004).
///
/// `2^64`. Acota el error de truncamiento del retarget manteniendo al menos 64 bits significativos.
pub fn min_target() -> U256 {
    U256::one() << 64usize
}

/// `bits` inicial de **mainnet** — la dificultad de arranque (C-DIFF-02, P-004c).
///
/// `0x1c07fff8` = `0x07fff8 · 2²⁰⁰`: **exactamente 32 veces más difícil** que el mínimo
/// representable. Un bloque cuesta `2²⁵⁶/target ≈ 1,374·10¹¹` hashes esperados.
///
/// # Qué significa realmente esta constante
///
/// **Es una estimación del hashrate del día 1, escrita como un target.** No es más que eso, y no
/// debe hacer nada más que eso. Elegida para que el primer bloque tarde **`T` = 120 s** —lo mismo
/// que tardará cualquier bloque después— si el día del lanzamiento hay **≈1,15 GH/s**.
///
/// | Hashrate real el día 1 | Primer bloque | LWMA entra en |
/// |---|---|---|
/// | 0,25 GH/s | 9,2 min | 13,7 h |
/// | 0,5 GH/s | 4,6 min | 6,9 h |
/// | **1,15 GH/s** | **2,0 min** ← nominal | **3,0 h** |
/// | 2 GH/s | 69 s | 1,7 h |
/// | 3 GH/s | 46 s | 1,1 h |
/// | 10 GH/s | 14 s | 21 min |
/// | 30 GH/s | 4,6 s | 6,9 min |
///
/// 1,15 GH/s es el extremo **conservador** de lo que rinde una GPU sola en SHA3-256. Se elige ese
/// extremo y no el central por la asimetría de C-DIFF-02: si la estimación se queda **corta** los
/// bloques salen rápido y LWMA lo arregla en una hora; si se pasa de **larga**, los 90 bloques a
/// dificultad fija van lentos y **nada puede acelerarlos**.
///
/// # Dos intentos anteriores, y por qué los dos estaban mal
///
/// **`0x1d00ffff`** — el target más fácil representable. Justificado por la asimetría de arriba,
/// pero sin medir: con una GPU los bloques salen en **1-4 segundos**, no en 120.
///
/// **`0x1c00ffff`** (×256) — elegido para que el primer bloque tardase ~10 min y así encarecer la
/// carrera del día 1. **Descartado por Katana**, y con razón: hacía que esta constante tuviera dos
/// trabajos —estimar el hashrate y frenar el arranque— y cuando dos propósitos comparten una
/// constante deja de poder saberse cuál se está ajustando. Además volvía el arranque **5× más lento
/// que el régimen normal**, un comportamiento artificial que el protocolo no pide en ninguna parte.
///
/// Lo que queda es lo honesto: la constante estima el hashrate, y **nada más**. Si algún día se
/// quiere desincentivar la carrera del día 1, eso es un slow-start explícito sobre la emisión —una
/// decisión propia, visible y discutible— no un target torcido.
///
/// # El límite que no se puede quitar
///
/// Ninguna cadena conoce su hashrate antes de existir, así que este número **es un pronóstico**.
/// C-DIFF-02 lo mantiene fijo durante 90 bloques y LWMA no corrige nada hasta el 91. La única
/// defensa real es **medir en vez de estimar**: cuando `zx-miner` funcione (Fase 8) se recalibra
/// desde un benchmark. 🔶 Revisable hasta el minuto antes de crear el génesis, y solo hasta
/// entonces. P-004c.
pub const TARGET_INICIAL_BITS_MAINNET: u32 = 0x1c07_fff8;

/// `bits` inicial de **testnet** — deliberadamente el mínimo, `0x1d00ffff`.
///
/// Testnet existe para que las cosas pasen rápido: una red local de tres nodos tiene que producir
/// bloques en segundos o los tests de integración no son utilizables. Aquí el "problema" de que una
/// GPU mine 90 bloques en minutos es exactamente la propiedad que se quiere.
///
/// Que las dos redes lleven valores distintos no es una excepción: C-DIFF-02 lo contempla, y el
/// aislamiento entre redes ya lo garantizan el génesis (C-GEN-04) y el prefijo mágico (C-NET-01).
pub const TARGET_INICIAL_BITS_TESTNET: u32 = 0x1d00_ffff;

/// Target inicial de mainnet como entero. Ver [`TARGET_INICIAL_BITS_MAINNET`].
#[must_use]
pub fn target_inicial_mainnet() -> U256 {
    U256::from(0x0007_fff8_u32) << (8usize * (0x1c - 3))
}

/// Target inicial de testnet como entero. Ver [`TARGET_INICIAL_BITS_TESTNET`].
#[must_use]
pub fn target_inicial_testnet() -> U256 {
    U256::from(0x0000_ffff_u32) << (8usize * (0x1d - 3))
}

/// Límites de target de una red (C-POW-05).
///
/// El mismo `bits` puede decodificar a un target válido en una red y fuera de rango en otra: la red
/// dev elige un máximo más fácil (`PARAMETROS_POW_DEV`) para que una red local mine en segundos.
/// `min`/`max` son **consenso de esa red**, no constantes universales.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LimitesTarget {
    /// Target mínimo admitido — la **dificultad máxima** de la red.
    pub min: U256,
    /// Target máximo admitido — la **dificultad mínima** de la red.
    pub max: U256,
}

/// Límites de las redes antiguas (mainnet y testnet): `MIN_TARGET` y `POW_LIMIT` **sin cambiar**.
///
/// Se escribe en limbos —y no evaluando `min_target()`/`pow_limit()`— porque debe ser `const`; un
/// test comprueba que coincide exactamente con esas dos funciones.
pub const LIMITES_ANTIGUOS: LimitesTarget = LimitesTarget {
    min: U256([0, 1, 0, 0]),
    max: U256([u64::MAX, u64::MAX, u64::MAX, 0x0000_0000_ffff_ffff]),
};

/// Límites **abiertos**: todo target estructuralmente válido. Sirve para expandir un `bits` sin
/// aplicar la cota de una red concreta (por ejemplo, al derivar el máximo de la red dev).
pub const LIMITES_AMPLIOS: LimitesTarget = LimitesTarget {
    min: U256::zero(),
    max: U256::max_value(),
};

/// Expande un `bits` a su target exigiendo forma canónica, **sin** mirar límites de red.
fn expandir_compacto(v: u32) -> Result<U256, EncodingError> {
    let exponente = (v >> 24) as u8;
    let mantisa = v & 0x007f_ffff;
    let signo = v & 0x0080_0000 != 0;

    let malo = |motivo| EncodingError::BitsNoCanonico { bits: v, motivo };

    if signo {
        return Err(malo("el bit de signo MUST estar a cero"));
    }
    if exponente == 0 {
        return Err(malo("exponente cero"));
    }
    if mantisa == 0 {
        return Err(malo("mantisa cero"));
    }
    // El exponente cuenta bytes: mantisa × 256^(exp−3).
    if exponente < 3 {
        return Err(malo("exponente < 3 no es representable de forma canónica"));
    }
    let desplazamiento = 8usize * (exponente as usize - 3);
    // 24 bits de mantisa + desplazamiento MUST caber en 256.
    if desplazamiento + 24 > 256 {
        return Err(malo("mantisa × 256^(exp−3) desborda 256 bits"));
    }
    let target = U256::from(mantisa) << desplazamiento;

    // C-POW-04 · canonicidad, definida como punto fijo: `bits` MUST ser exactamente lo que produce
    // el codificador para ese target. La canonicidad **no depende de los límites de la red**: un
    // `bits` no canónico lo es en cualquier red.
    if codificar_con(target, &LIMITES_ANTIGUOS) != v {
        return Err(malo("no es la codificación canónica de su propio target"));
    }
    Ok(target)
}

/// Decodifica `bits` exigiendo forma **canónica** y rango **de la red** (C-POW-04, C-POW-05).
///
/// A diferencia de [`CompactBits::decodificar`] —que usa los límites antiguos— aquí el rango lo fija
/// el llamante. Es lo que permite que la red dev admita un target más fácil sin aflojar mainnet.
///
/// # Errores
/// [`EncodingError::BitsNoCanonico`] o [`EncodingError::TargetFueraDeRango`].
pub fn decodificar_con(bits: u32, limites: &LimitesTarget) -> Result<U256, EncodingError> {
    let target = expandir_compacto(bits)?;
    if target > limites.max {
        return Err(EncodingError::TargetFueraDeRango {
            motivo: "target > límite máximo de la red",
        });
    }
    if target < limites.min {
        return Err(EncodingError::TargetFueraDeRango {
            motivo: "target < límite mínimo de la red",
        });
    }
    Ok(target)
}

/// Codifica un target en su forma compacta **canónica** (C-POW-04).
///
/// La codificación **no depende de los límites**: es total sobre cualquier `U256` y la cota de red
/// se aplica al **decodificar**. `limites` se recibe por simetría con [`decodificar_con`] y para que
/// las dos mitades de la pareja tengan la misma forma.
#[must_use]
pub fn codificar_con(target: U256, _limites: &LimitesTarget) -> u32 {
    if target.is_zero() {
        return 0;
    }
    // Bytes significativos: cuántos hacen falta para representarlo.
    let bits_significativos = 256 - target.leading_zeros() as usize;
    let mut exponente = bits_significativos.div_ceil(8);
    let mut mantisa = if exponente <= 3 {
        (target << (8 * (3 - exponente))).low_u32() & 0x00ff_ffff
    } else {
        (target >> (8 * (exponente - 3))).low_u32() & 0x00ff_ffff
    };
    // Si el bit alto de la mantisa invadiría el bit de signo, se corre un byte.
    if mantisa & 0x0080_0000 != 0 {
        mantisa >>= 8;
        exponente += 1;
    }
    (u32::try_from(exponente).unwrap_or(0xFF) << 24) | mantisa
}

/// Target compacto de 32 bits (C-POW-03).
///
/// Codifica un entero de 256 bits como `mantisa (3 bytes) × 256^(exponente − 3)`, con el exponente
/// en el byte más significativo.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CompactBits(u32);

impl CompactBits {
    /// El `u32` tal cual aparece en la cabecera.
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    /// Envuelve un `u32` sin validar. La validación ocurre en [`Self::decodificar`].
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        Self(v)
    }

    /// Decodifica a target, exigiendo forma **canónica** y rango (C-POW-04, C-POW-05).
    ///
    /// Rechaza, en este orden:
    /// - bit de signo puesto,
    /// - exponente cero,
    /// - mantisa cero,
    /// - mantisa no normalizada (cabía con un exponente menor),
    /// - desbordamiento de 256 bits,
    /// - target fuera de `[MIN_TARGET, POW_LIMIT]`.
    ///
    /// La canonicidad no es estética: sin ella, un mismo target admite varias codificaciones y un
    /// minero puede probar cada una contra el filtro de dificultad. Es el mismo razonamiento que
    /// C-ENC-05 para `CompactSize`.
    ///
    /// # Errores
    /// [`EncodingError::BitsNoCanonico`] o [`EncodingError::TargetFueraDeRango`].
    pub fn decodificar(self) -> Result<U256, EncodingError> {
        decodificar_con(self.0, &LIMITES_ANTIGUOS)
    }

    /// Codifica un target en su forma compacta **canónica** (C-POW-04).
    ///
    /// Es la inversa de [`Self::decodificar`] para todo target en `[MIN_TARGET, POW_LIMIT]` —
    /// demostrado exhaustivamente por D9 sobre los 167 116 800 pares (exponente, mantisa) válidos
    /// del rango: cero fallos de identidad, cero colisiones.
    ///
    /// ⚠️ **No lo es fuera de ese rango.** Para todo `target < 2¹⁶` produce un `bits` con exponente
    /// `< 3` que `decodificar` rechaza: su propia salida no vuelve a decodificar a nada. Hoy es
    /// inalcanzable —`MIN_TARGET = 2⁶⁴` está `2⁴⁸` por encima— pero **la propiedad vale sobre el
    /// subrango, no sobre los 256 bits**, y dejaría de valer si `MIN_TARGET` bajara de `2¹⁶`.
    #[must_use]
    pub fn codificar(target: U256) -> Self {
        Self(codificar_con(target, &LIMITES_ANTIGUOS))
    }
}

/// Interpreta un hash de bloque como entero **big-endian** (C-POW-01).
///
/// Ver la nota de endianness del módulo: no es intercambiable con little-endian.
#[must_use]
pub fn hash_como_entero(h: &BlockHash) -> U256 {
    U256::from_big_endian(h.as_bytes())
}

/// C-POW-01: un bloque satisface el PoW si `block_hash < target`.
#[must_use]
pub fn cumple_pow(h: &BlockHash, target: U256) -> bool {
    hash_como_entero(h) < target
}

/// Trabajo esperado de un bloque con ese target (C-FORK-01).
///
/// ```text
/// trabajo(t) = ((2^256 − 1 − t) / (t + 1)) + 1
/// ```
///
/// Es `2^256 / (target + 1)` sin necesitar un entero de 257 bits: `!t` en `U256` ya es
/// `2^256 − 1 − t`, y `(2^256 − 1 − t) + (t + 1) = 2^256` exactamente. El mismo truco que usa
/// Bitcoin en `arith_uint256::GetBlockProof`.
///
/// Devuelve `None` si `target + 1` desborda, que solo ocurre con `target = 2^256 − 1` — imposible
/// bajo C-POW-05, pero se trata como valor en vez de dar por hecho que no pasa.
#[must_use]
pub fn trabajo_bloque(target: U256) -> Option<U256> {
    let divisor = target.checked_add(U256::one())?;
    if divisor.is_zero() {
        return None;
    }
    ((!target) / divisor).checked_add(U256::one())
}

/// Trabajo acumulado de una cadena (C-FORK-02).
///
/// Valor **derivado y cacheable**, nunca fuente de verdad: **MUST** poder recalcularse a partir de
/// los `bits` almacenados.
///
/// Se lleva en `U256`, no en `u128`. Zebra usa `u128` y le basta, pero Zcash tiene una vida acotada
/// conocida; ZEROX no tiene `MAX_MONEY` ni fin de emisión, así que 256 bits evitan tener que volver
/// a demostrar dentro de cincuenta años que el ancho seguía bastando.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct TrabajoAcumulado(U256);

impl TrabajoAcumulado {
    /// Cero.
    #[must_use]
    pub fn cero() -> Self {
        Self(U256::zero())
    }

    /// El valor acumulado.
    #[must_use]
    pub const fn valor(self) -> U256 {
        self.0
    }

    /// Suma el trabajo de un bloque. `None` si desborda (C-ENC-03: nunca en silencio).
    #[must_use]
    pub fn sumar(self, trabajo: U256) -> Option<Self> {
        self.0.checked_add(trabajo).map(Self)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::{
        CompactBits, TARGET_INICIAL_BITS_MAINNET, TARGET_INICIAL_BITS_TESTNET, TrabajoAcumulado,
        cumple_pow, hash_como_entero, min_target, pow_limit, target_inicial_mainnet,
        target_inicial_testnet, trabajo_bloque,
    };
    use crate::digest::{BlockHash, Digest};
    use primitive_types::U256;

    fn hash(bytes: [u8; 32]) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes(bytes))
    }

    /// **La trampa de Zebra.** Fija la convención con un vector deliberadamente asimétrico.
    ///
    /// Con big-endian, `0x01` en el primer byte pesa `2^248`. Con little-endian pesaría 1. Si
    /// alguien porta el archivo de Zebra tal cual y deja `from_little_endian`, este test lo caza.
    #[test]
    fn el_hash_se_interpreta_big_endian() {
        let mut b = [0u8; 32];
        *b.first_mut().unwrap() = 0x01;
        let v = hash_como_entero(&hash(b));
        assert_eq!(
            v,
            U256::one() << 248usize,
            "C-POW-01: big-endian, no little-endian"
        );

        let mut b = [0u8; 32];
        *b.last_mut().unwrap() = 0x01;
        assert_eq!(
            hash_como_entero(&hash(b)),
            U256::one(),
            "el último byte es el menos pesado"
        );
    }

    #[test]
    fn el_pow_compara_estrictamente_menor() {
        let t = U256::from(1000u32);
        assert!(cumple_pow(&hash(U256::from(999u32).to_big_endian()), t));
        assert!(
            !cumple_pow(&hash(t.to_big_endian()), t),
            "igual al target NO cumple"
        );
        assert!(!cumple_pow(&hash(U256::from(1001u32).to_big_endian()), t));
    }

    #[test]
    fn ida_y_vuelta_de_bits_canonico() {
        for t in [
            target_inicial_mainnet(),
            target_inicial_testnet(),
            min_target(),
            U256::one() << 200usize,
            U256::one() << 100usize,
        ] {
            let b = CompactBits::codificar(t);
            let d = b
                .decodificar()
                .unwrap_or_else(|e| panic!("no decodifica {t}: {e}"));
            assert_eq!(d, t, "ida y vuelta rota para {t}");
        }
    }

    /// C-POW-04. Cada uno de estos es una codificación no canónica del mismo target.
    #[test]
    fn se_rechazan_los_bits_no_canonicos() {
        // Bit de signo.
        assert!(
            CompactBits::from_u32(0x1d80_ffff).decodificar().is_err(),
            "signo"
        );
        // Exponente cero.
        assert!(
            CompactBits::from_u32(0x0000_ffff).decodificar().is_err(),
            "exp 0"
        );
        // Mantisa cero.
        assert!(
            CompactBits::from_u32(0x1d00_0000).decodificar().is_err(),
            "mantisa 0"
        );
        // No canónico: 0x1d0000ff representa el mismo target que 0x1b00ff00, con exponente menor.
        assert!(
            CompactBits::from_u32(0x1d00_00ff).decodificar().is_err(),
            "no mínimo"
        );

        // Y el contraejemplo que una regla estructural ingenua rechazaría por error: `0x1d00ffff`
        // tiene el byte alto de la mantisa a cero y **sí** es canónico — es el powLimit de Bitcoin.
        assert!(
            CompactBits::from_u32(0x1d00_ffff).decodificar().is_ok(),
            "0x1d00ffff es canónico: el byte cero sale de evitar el bit de signo"
        );
    }

    /// `TARGET_INICIAL` **MUST** ser representable en forma compacta: el génesis tiene que poder
    /// llevar un `bits` que decodifique a él. `2^224 − 1` no lo es.
    ///
    /// Se comprueba en **las dos redes**, porque desde P-004c llevan valores distintos y un error de
    /// transcripción en una no lo cazaría el test de la otra.
    #[test]
    fn el_target_inicial_es_representable_y_cabe_bajo_pow_limit() {
        for (bits_u32, target) in [
            (TARGET_INICIAL_BITS_MAINNET, target_inicial_mainnet()),
            (TARGET_INICIAL_BITS_TESTNET, target_inicial_testnet()),
        ] {
            let bits = CompactBits::from_u32(bits_u32);
            assert_eq!(bits.decodificar().unwrap(), target, "0x{bits_u32:08x}");
            assert_eq!(
                CompactBits::codificar(target).to_u32(),
                bits_u32,
                "punto fijo del codificador, 0x{bits_u32:08x}"
            );
            assert!(target < pow_limit(), "MUST estar bajo la cota");
            assert!(target > min_target(), "MUST estar sobre el suelo");
        }
        assert!(CompactBits::codificar(pow_limit()).decodificar().unwrap() <= pow_limit());
    }

    /// **P-004c.** Mainnet arranca **más difícil** que testnet, y por el factor que se decidió.
    ///
    /// El sentido de la desigualdad es lo que importa: si alguien la invirtiera, mainnet arrancaría
    /// a dificultad de juguete y los primeros 90 bloques —fijos por C-DIFF-02— se regalarían.
    ///
    /// # El ×32 es exacto, y se eligió así a propósito
    ///
    /// Un candidato anterior, `0x1c03ffff`, prometía ×64 y **daba 63,999267**: `0x03ffff` es
    /// `2¹⁸ − 1`, no `2¹⁸`. El test lo cazó afirmando la igualdad exacta y fallando. Desde entonces
    /// los candidatos se eligen entre los que **dividen exacto** al mínimo (`0x0ffff0`, `0x07fff8`,
    /// `0x03fffc`), para que la relación entre las dos redes se pueda escribir con `assert_eq!` en
    /// vez de con una cota aproximada.
    #[test]
    fn mainnet_arranca_32_veces_mas_dificil_que_testnet() {
        let m = target_inicial_mainnet();
        let t = target_inicial_testnet();
        assert!(m < t, "menos target = más difícil");
        assert_eq!(t, m * 32u32, "×32 exacto en target, sin resto");

        let w_m = trabajo_bloque(m).unwrap();
        let w_t = trabajo_bloque(t).unwrap();
        assert_eq!(w_m / w_t, U256::from(32u32), "×32 exacto en trabajo");
    }

    /// **P-004c.** La constante es una estimación de hashrate: se comprueba que dice lo que dice.
    ///
    /// `0x1c07fff8` se eligió para que el primer bloque dure `T = 120 s` con ≈1,15 GH/s. Si alguien
    /// cambia el valor sin querer, este test dice **en qué se ha convertido la suposición**, que es
    /// más útil que decir solamente que el número cambió.
    #[test]
    fn el_target_inicial_apunta_a_un_bloque_de_t_segundos() {
        // W = 2^256 / (target+1) hashes esperados por bloque.
        let w = trabajo_bloque(target_inicial_mainnet()).unwrap();

        // T = 120 s ⇒ el hashrate implícito es W/120. Se compara en hashes/s, con enteros.
        const T: u64 = 120;
        let h_implicito = w / U256::from(T);

        // 1,10-1,20 GH/s. Un rango, no un punto: el objetivo es cazar un cambio de orden de
        // magnitud, no fijar la tercera cifra.
        assert!(
            h_implicito > U256::from(1_100_000_000u64)
                && h_implicito < U256::from(1_200_000_000u64),
            "el hashrate implícito ({h_implicito}) MUST rondar 1,15 GH/s — si cambia, actualiza \
             P-004c y la tabla de C-DIFF-02"
        );
    }

    #[test]
    fn se_rechaza_el_target_fuera_de_rango() {
        // Por encima de POW_LIMIT = 2^224 − 1.
        let demasiado_facil = CompactBits::codificar(U256::one() << 240usize);
        assert!(demasiado_facil.decodificar().is_err(), "target > POW_LIMIT");

        // Por debajo de MIN_TARGET = 2^64.
        let demasiado_dificil = CompactBits::codificar(U256::one() << 32usize);
        assert!(
            demasiado_dificil.decodificar().is_err(),
            "target < MIN_TARGET"
        );
    }

    /// C-FORK-01 contra los dos extremos, calculados a mano.
    #[test]
    fn el_trabajo_es_2_elevado_256_entre_target_mas_uno() {
        // target = 2^224 − 2^208  ⇒  trabajo ≈ 2^32
        let w = trabajo_bloque(target_inicial_testnet()).unwrap();
        assert!(
            w >= (U256::one() << 32usize) && w <= (U256::one() << 33usize),
            "{w}"
        );
        // target = 2^64  ⇒  trabajo ≈ 2^192
        let t = min_target();
        let w = trabajo_bloque(t).unwrap();
        assert!(
            w >= (U256::one() << 191usize) && w <= (U256::one() << 192usize),
            "{w}"
        );
    }

    /// Más difícil (target menor) **MUST** dar más trabajo. Si se invirtiera, el fork choice
    /// premiaría la cadena más débil.
    #[test]
    fn menos_target_es_mas_trabajo() {
        let facil = trabajo_bloque(target_inicial_testnet()).unwrap();
        let medio = trabajo_bloque(U256::one() << 200usize).unwrap();
        let dificil = trabajo_bloque(min_target()).unwrap();
        assert!(facil < medio, "{facil} < {medio}");
        assert!(medio < dificil, "{medio} < {dificil}");
    }

    #[test]
    fn el_trabajo_acumulado_no_desborda_en_silencio() {
        let acc = TrabajoAcumulado::cero();
        let w = trabajo_bloque(target_inicial_testnet()).unwrap();
        let acc = acc.sumar(w).unwrap().sumar(w).unwrap();
        assert_eq!(acc.valor(), w * 2u32);

        // El borde: sumar sobre el máximo debe devolver None, no envolver.
        let lleno = TrabajoAcumulado::cero().sumar(U256::MAX).unwrap();
        assert!(
            lleno.sumar(U256::one()).is_none(),
            "C-ENC-03: nunca desbordamiento silencioso"
        );
    }

    /// 262 800 bloques al año a dificultad mínima: el acumulado ni se acerca a agotar `U256`.
    /// Es la comprobación de que 256 bits sobran para siempre.
    #[test]
    fn el_acumulado_aguanta_siglos() {
        let por_bloque = trabajo_bloque(min_target()).unwrap(); // el caso más caro
        let bloques_en_mil_anios = U256::from(262_800u32) * U256::from(1000u32);
        let total = por_bloque.checked_mul(bloques_en_mil_anios);
        assert!(
            total.is_some(),
            "mil años a dificultad máxima deben caber en U256"
        );
    }

    // ── Límites de target por red ────────────────────────────────────────────

    /// `LIMITES_ANTIGUOS` es un `const` escrito en limbos: **MUST** coincidir con las funciones.
    ///
    /// Es la lección de H-005: una constante derivada escrita a mano se comprueba, no se confía.
    #[test]
    fn los_limites_antiguos_coinciden_con_sus_funciones() {
        assert_eq!(
            super::LIMITES_ANTIGUOS.min,
            min_target(),
            "el mínimo de la red antigua es MIN_TARGET = 2^64"
        );
        assert_eq!(
            super::LIMITES_ANTIGUOS.max,
            pow_limit(),
            "el máximo de la red antigua es POW_LIMIT = 2^224 − 1"
        );
    }

    /// El rango lo fija la red: `0x1e7fffff` es canónico y válido con límites amplios, pero excede
    /// `POW_LIMIT`; la red dev lo usa como dificultad de arranque.
    #[test]
    fn decodificar_con_aplica_los_limites_de_la_red() {
        let dev = super::decodificar_con(0x1e7f_ffff, &super::LIMITES_AMPLIOS).unwrap();
        assert!(
            dev > pow_limit(),
            "el máximo dev es más fácil que POW_LIMIT"
        );
        assert_eq!(
            super::codificar_con(dev, &super::LIMITES_AMPLIOS),
            0x1e7f_ffff,
            "y sigue siendo canónico"
        );
        assert!(
            super::decodificar_con(0x1e7f_ffff, &super::LIMITES_ANTIGUOS).is_err(),
            "mainnet/testnet MUST rechazarlo: supera POW_LIMIT"
        );
    }
}
