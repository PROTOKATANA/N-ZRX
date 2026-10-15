//! Tipos base, hash con dominio y codificación canónica de ZEROX.
//!
//! Este crate es la raíz de la que cuelga todo lo consensus-critical. Su responsabilidad es que
//! **dos nodos cualesquiera produzcan exactamente los mismos bytes y exactamente los mismos
//! digests** para el mismo objeto. Cualquier fuente de divergencia aquí es un split de cadena.
//!
//! Cada elemento cita la regla `C-XXX` del SPEC que implementa. Si el código y el SPEC discrepan,
//! el SPEC manda y el procedimiento es
//! `DETENER → INVESTIGAR → PROPONER CAMBIO → ACTUALIZAR SPEC → CONTINUAR`.
//!
//! # La invariante de diseño de este crate
//!
//! Cap'n Proto serializa para wire y disco, y **no es consensus-critical** (C-ENC-08). Lo que se
//! hashea y se firma es la preimagen canónica de §4, byte a byte, definida aquí.
//!
//! Confundir las dos sería un split silencioso, así que no se deja a la disciplina: la función de
//! hash con dominio es `pub(crate)`, y **no existe ninguna función pública que acepte `&[u8]`
//! arbitrarios y una etiqueta de dominio**. La defensa es la ausencia de una firma invocable, no un
//! comentario. `zx-core` tampoco depende de `capnp`: no puede ni nombrar un tipo de wire.

#![doc = include_str!("../README.md")]

pub mod address;
pub mod amount;
pub mod digest;
pub mod encoding;
pub mod error;
pub mod evidencia_agregados;
pub mod firma;
pub mod forma;
mod hash;
pub mod preimage;
pub mod red;
pub mod target;
pub mod tx;
pub mod wire;
pub mod wire_dag;

pub use address::Address;
pub use amount::{Amount, ZX_VALUE_SANITY_LIMIT};
pub use digest::{
    AuthDigest, BlockHash, BodyCommitment, Digest, MerkleRoot, PreHash, SigHash, TxId,
};
pub use error::{CompromisosError, CoreError, EncodingError, ErrorFormaTx};
pub use firma::{ClavePublica, Firma, verificar};
pub use forma::{validar_forma_cabecera_post, validar_forma_tx, validar_forma_tx_v4};
// El módulo `hash` sigue privado: `h_d` MUST ser inalcanzable desde fuera. Se reexporta únicamente
// `sha3_256_publico`, que no acepta etiqueta de dominio y por tanto no puede producir un digest de
// consenso. Ver la nota de diseño de `crate::hash`.
pub use hash::sha3_256_publico;
pub use preimage::dag::{
    DagBlockHeader, HASH_NULO, MAX_PADRES, MAX_PADRES_EXTRA, OFFSET_COMPROMISO_CUERPO,
    OFFSET_PADRES_EXTRA, OFFSET_PARENT_COUNT, PadresDag, SolucionPoas, TAMANO_CABECERA_MAX,
    TAMANO_CABECERA_MIN, TAMANO_PREFIJO_FIJO, body_commitment, body_commitment_de_pares,
    comprobar_compromisos, dag_header_a_bytes, dag_header_desde_bytes, tamano_cabecera,
    tamano_prefirma,
};
pub use preimage::tx::{
    HashType, auth_digest, incident_id_evidencia, mensaje_aceptacion, mensaje_almacenamiento,
    mensaje_sector, sighash, txid, verificar_aceptacion, verificar_firma_almacenamiento,
    verificar_firma_sector,
};
pub use red::{CBID_RED_DEV, MAGIC_DEV, Red};
pub use target::{
    CompactBits, LIMITES_AMPLIOS, LIMITES_ANTIGUOS, LimitesTarget, TrabajoAcumulado, codificar_con,
    cumple_pow, decodificar_con, trabajo_bloque,
};
pub use tx::{
    ClasePruebaAlmacenamiento, ClaveTablaVoto, ErrorCodecAlmacenamiento, ErrorCodecSector,
    ExtensionTx, LONGITUD_CLAVE_BLS, LONGITUD_PRUEBA_POSESION_BLS, Lock,
    MAX_CLAVES_CERTIFICADO_VOTOS, MAX_OPERACION_SECTOR_BYTES, MAX_PRUEBA_ALMACENAMIENTO_BYTES,
    MAX_PRUEBA_SECTOR_BYTES, OperacionAlmacenamiento, OperacionSector, OutPoint, SpentOutput,
    TipoGarantia, TipoOperacionSector, Tx, TxIn, TxOut, VotoPesoEvidencia,
};
pub use wire_dag::{
    BUNDLE_BYTES, BloqueDag, CHECKPOINTS_POR_BUNDLE, ContextoVerificacionPot, ErrorDiferenciaSlots,
    IntegracionPotPendiente, JustificacionPot, MAX_BLOQUE_DAG_AGREGADO, MAX_BUNDLES_POT,
    MAX_JUSTIFICACION_POT_CODIFICADA, MAX_JUSTIFICACION_POT_PAYLOAD, POT_OUTPUT_BYTES,
    PotCheckpoints, bloque_dag_a_bytes, bloque_dag_desde_bytes,
    comprobar_diferencia_slots_del_bloque, verificar_justificacion_pot,
};
