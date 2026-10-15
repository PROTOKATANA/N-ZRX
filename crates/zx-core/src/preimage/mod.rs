//! Preimagen canónica: lo que de verdad se hashea y se firma (SPEC §4).
//!
//! # Por qué existe [`PreimageWriter`]
//!
//! Un `Vec<u8>` acepta cualquier cosa. Este tipo no: **no tiene ningún constructor ni método que
//! acepte un buffer ya serializado**. No hay `From<Vec<u8>>`, no hay `write_bytes(&[u8])`, no hay
//! `Deref<Target = [u8]>`. La única forma de llenarlo es campo a campo, desde tipos de dominio.
//!
//! Eso cierra el agujero de verdad. Sellar el tipo de *salida* de un hash no sirve de nada si
//! alguien puede pasarle bytes de Cap'n Proto a la *entrada*; aquí el atajo ni siquiera se puede
//! escribir. Junto con `h_d` siendo `pub(crate)` y con que `zx-core` no dependa de `capnp`,
//! la confusión wire↔preimagen deja de ser un riesgo de disciplina y pasa a ser un error de tipos.

pub mod block;
pub mod dag;
pub mod flow;
pub mod tx;

use crate::digest::Digest;
use crate::encoding::compact_size;
use crate::firma::ClavePublica;
use crate::hash::{DomainTag, h_d};
use crate::tx::Lock;

/// Acumulador de bytes de preimagen. Solo se llena campo a campo.
pub(crate) struct PreimageWriter(Vec<u8>);

impl PreimageWriter {
    /// Un acumulador vacío.
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    /// Un acumulador con capacidad reservada. Solo afecta al rendimiento.
    pub(crate) fn con_capacidad(n: usize) -> Self {
        Self(Vec::with_capacity(n))
    }

    /// Escribe un `u8`.
    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    /// Escribe un `u32` little-endian (C-ENC-02).
    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Escribe un `u64` little-endian (C-ENC-02).
    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Escribe un `i64` little-endian, complemento a dos (C-ENC-02).
    pub(crate) fn i64(&mut self, v: i64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Escribe un `u16` little-endian (SL-4a: identidad de evidencia).
    pub(crate) fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Escribe un `CompactSize` en su forma mínima (C-ENC-05).
    pub(crate) fn compact_size(&mut self, v: u64) -> &mut Self {
        compact_size::escribir(&mut self.0, v);
        self
    }

    /// Escribe 32 bytes crudos: el hash de la preimagen de un HTLC.
    pub(crate) fn h32(&mut self, v: &[u8; 32]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }

    /// Escribe una clave pública Ed25519 (32 bytes).
    ///
    /// Existe aparte de [`Self::h32`] a propósito: los dos escriben 32 bytes, pero confundir una
    /// clave con un hash es exactamente el error que P-020 hacía posible mientras eran el mismo
    /// tipo. Aquí el tipo lo impide.
    pub(crate) fn clave(&mut self, k: &ClavePublica) -> &mut Self {
        self.0.extend_from_slice(k.bytes());
        self
    }

    /// Escribe un digest ya calculado — así se anidan los sub-árboles de §4.
    pub(crate) fn digest(&mut self, d: &Digest) -> &mut Self {
        self.0.extend_from_slice(d.as_bytes());
        self
    }

    /// Escribe los bytes de una **preimagen canónica ya serializada**.
    ///
    /// Solo lo usa SL-4a para concatenar las codificaciones canónicas de dos cabeceras
    /// `PoAS_PoT_DAG` (`DagBlockHeader::a_bytes`) dentro del `extension_digest` de la v4 (EV-03).
    /// No es un atajo genérico: no debe recibir bytes de wire.
    pub(crate) fn canonical(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }

    /// Escribe la codificación canónica de un [`Lock`] (C-TX-09).
    ///
    /// `discriminante ‖ campos`. Para `MultiSig`, la lista de claves va precedida de su longitud en
    /// `CompactSize`: es la única lectura coherente con §2.2, que define `CompactSize` justamente
    /// para "contadores y longitudes". Ver la nota de C-TX-09b en el SPEC.
    pub(crate) fn lock(&mut self, l: &Lock) -> &mut Self {
        self.u8(l.discriminante());
        match l {
            Lock::PubKey { pubkey } => {
                self.clave(pubkey);
            }
            Lock::MultiSig { k, pubkeys } => {
                self.u8(*k);
                self.compact_size(pubkeys.len() as u64);
                for p in pubkeys {
                    self.clave(p);
                }
            }
            Lock::Htlc {
                hash,
                receiver,
                sender,
                timeout,
            } => {
                self.h32(hash);
                self.clave(receiver);
                self.clave(sender);
                self.u32(*timeout);
            }
        }
        self
    }

    /// Entrega los bytes acumulados sin hashearlos.
    ///
    /// Solo para el minero: necesita el buffer de la preimagen del PoW para iterar el nonce in situ
    /// (C-HDR-04) en vez de reconstruirlo en cada intento. Consume `self`, así que no puede quedar
    /// un acumulador a medias del que alguien siga tirando.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Cierra el acumulador y devuelve `H_d(tag, bytes)`.
    ///
    /// Consume `self`: una preimagen se hashea una vez y no se reutiliza.
    pub(crate) fn finish(self, tag: DomainTag) -> Digest {
        h_d(tag, &self.0)
    }

    /// Los bytes acumulados. **Solo para tests**, nunca para alimentar otro hash.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}
