# `zx-poas` — verificador PoAS, historia génesis dev y protocolo dev

Crate **nuevo** de la orden W05b1. Reúne tres piezas ancladas a D-P12:

- **`verificador.rs`** — adapta `subspace_verification::verify_solution::<ChiaTable, _>` al tipo
  [`zx_core::SolucionPoas`] (paso 5 de `C-POT-08`): prueba de espacio, distancia de solución y los
  dos compromisos KZG. Es el `crates/zx-consensus/src/poas.rs` de `9681061` **sin cambio de lógica**
  (`verificar_solucion_poas`, `ErrorPoas`, `ContextoInvalido`), con las precondiciones aritméticas
  del contexto comprobadas con `checked_*` antes de llamar a upstream.
- **`historia.rs`** — `HistoriaGenesis`: archiva **una vez** el cuerpo del génesis dev de W04
  (`zx_consensus::GENESIS_DEV`, cabecera de 92 B + coinbase con testigos vía
  `zx_core::wire::cuerpo_a_bytes`) rellenado hasta `RecordedHistorySegment::SIZE` con
  `ChaCha8Rng::from_seed(block_hash(génesis))` y `Archiver::add_block(.., BlockObjectMapping::default(), false)`.
  El **primer** `NewArchivedSegment` es el segmento 0. Su `segment_commitment` se congela en
  [`COMPROMISO_HISTORIA_GENESIS_DEV`] con un test que lo recalcula. Sustituye a `HistoriaDagDev` de
  `9681061`.
- **`protocolo_dev.rs`** — el `FarmerProtocolInfo` dev con los valores antiguos
  (`history_size = 1`, `max_pieces_in_sector = 2`, `recent_segments = 5`,
  `recent_history_fraction = (1, 10)`, `min_sector_lifetime = 4`), todos etiquetados **dev**.
- **`reto.rs`** — `reto_desde_salida` puro (`C-POT-03`), que `zx-farmer` necesita para auditar.

## Frontera

`zx-poas` depende de `zx-core`, `zx-consensus` (para el génesis dev de W04) y, por ruta al clon
fijado `terceros/autonomys` @ `f8842d0`, de `subspace-core-primitives`, `subspace-proof-of-space`,
`subspace-verification`, `subspace-kzg`, `subspace-archiving`, `subspace-erasure-coding` y
`subspace-farmer-components`. Lo vigila `ci/frontera-crates.sh` (`zx-poas → {zx-core, zx-consensus}`).

## Lo que NO demuestra

PoT (flujo, AES, `N(s)`, `D`), cabecera conjunta, sello, admisión, cuerpo, DAG, orden, historia más
allá de un segmento y parámetros de red. Los retos de auditoría de los tests son valores fijos; su
derivación desde el PoT es de W05b2.
