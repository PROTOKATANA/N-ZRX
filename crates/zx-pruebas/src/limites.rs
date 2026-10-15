//! Topes del carril de pruebas recursivas (`CP-R-04` y `CP-R-05`).
//!
//! Los topes se comprueban **antes** de descomprimir, para que un marco corrupto o una bomba
//! no lleguen a reservar la memoria que declaran. El ratio declarado máximo es 8:1.

use zx_compresion::Limites;

/// Tope de la prueba comprimida, en bytes.
///
/// Es el tope del `len_comprimido` (payload) del marco ZRX-C, **no** del marco completo: la
/// cabecera ZXC1 de 27 B no cuenta. Cuenta del margen: `352 000 − 318 563 = 33 437 B` = **+10,50 %**
/// sobre la medida `REVISION-PT3j-4.md:5`.
pub const MAX_PRUEBA_COMPRIMIDA_BYTES: u64 = 352_000;

/// Tope de la prueba canónica descomprimida, en bytes.
///
/// Se aplica al objeto serializado completo (`version ‖ clase ‖ cuerpo`), de modo que un
/// `len_original = 400 001` se rechaza (`CP-T-05`). Cuenta del margen:
/// `400 000 − 330 313 = 69 687 B` = **+21,10 %** sobre `REVISION-PT3j-3.md:9`.
pub const MAX_PRUEBA_CANONICA_BYTES: u64 = 400_000;

/// Ratio máximo admitido entre bytes canónicos y comprimidos (`8:1`).
pub const MAX_RATIO_DESCOMPRESION: u32 = 8;

/// Nivel zstd por omisión para comprimir una prueba (publicación fría, 1 por ventana `K`).
///
/// `CP-R-06` propone L19. La API de `zx-compresion` no expone la ventana larga (`--long`); el
/// nivel se mantiene y el tope comprimido absorbe la diferencia.
pub const NIVEL_PRUEBA: i32 = 19;

/// Límites de descompresión de `zx-compresion` para una prueba recursiva (`CP-R-05`).
#[must_use]
pub const fn limites_prueba() -> Limites {
    Limites::nuevo(MAX_PRUEBA_CANONICA_BYTES).con_ratio(MAX_RATIO_DESCOMPRESION)
}
