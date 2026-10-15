//! Codificación canónica de la preimagen (SPEC §2).
//!
//! **Esto no es la serialización de wire.** Cap'n Proto se encarga de wire y disco, y explícitamente
//! **no es consensus-critical** (C-ENC-08). Lo que vive aquí es la codificación byte-exacta que se
//! hashea y se firma: la canonicalización de Cap'n Proto tiene aristas, y apoyarse en ella para el
//! consenso es exactamente el error que este módulo existe para no cometer.

pub mod compact_size;
pub mod int;
