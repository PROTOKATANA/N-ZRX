//! Cabecera DAG, padres múltiples y compromiso completo del cuerpo (SPEC §6.1–§6.2).
//!
//! # Qué añade esto sobre la base PoAS lineal
//!
//! El formato lineal tiene **un** padre (`prev_hash`) y **un** hash de cabecera que también es su
//! preimagen de PoW. El destino es un DAG: un bloque tiene hasta 15 padres, el compromiso del
//! cuerpo incluye la autorización, y el hash de cabecera ya no es una preimagen de PoW de hash
//! único. Este módulo introduce el objeto, su codec y sus invariantes **sin** fingir que GHOSTDAG
//! está integrado en el nodo.
//!
//! # Una sola codificación canónica
//!
//! [`DagBlockHeader::escribir`] es la **única** descripción del formato. De ella salen, a la vez:
//!
//! - los bytes de wire ([`dag_header_a_bytes`]),
//! - la prefirma (`pre_hash`, todo menos el sello),
//! - el `block_hash` (prefirma ‖ sello),
//! - y la derivación de identificadores cortos en `zx-p2p`.
//!
//! No hay un segundo serializador que pueda divergir del primero.
//!
//! # Estrategia A de padres
//!
//! ```text
//! 1 <= parent_count <= 15
//! prev_hash        = sp(B)          (padre seleccionado; cero en génesis)
//! extra_parents    = parents(B) \ {sp(B)}, 32 B cada uno, orden ascendente estricto
//! ```
//!
//! En wire solo viajan los `parent_count - 1` padres restantes. El orden canónico es
//! estrictamente ascendente y **sin duplicados**; el parser lo rechaza, no lo normaliza. La
//! propiedad de anticadena y que `prev_hash` sea realmente `sp(B)` exigen metadatos del DAG y
//! quedan para la validación contextual (ver `zx-consensus`).

use crate::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot, PreHash, TxId};
use crate::encoding::int;
use crate::error::{CompromisosError, EncodingError};
use crate::firma::{ClavePublica, Firma, LONGITUD_FIRMA, verificar};
use crate::hash::{TAG_BLK_BODY_HASH, TAG_BLK_HEADER, TAG_BLK_PRE_HASH, h_d};
use crate::preimage::PreimageWriter;
use crate::preimage::block::merkle_root;
use crate::preimage::tx::{auth_digest, txid};
use crate::tx::Tx;

/// Anchura de cada campo de la prefirma fija, en el orden de la tabla PoAS.
mod ancho {
    pub const BRANCH_ID: usize = 4;
    pub const PREV_HASH: usize = 32;
    pub const MERKLE_ROOT: usize = 32;
    pub const TIMESTAMP: usize = 8;
    pub const HEIGHT: usize = 4;
    pub const SLOT: usize = 8;
    pub const POT_OUTPUT: usize = 16;
    /// `v_j` del segundo VDF (`C-RLJ-VDF-02`/`C-RLJ-VDF-03`); todo ceros = sin segundo VDF.
    pub const VDF_OUTPUT: usize = 16;
    pub const RANGO: usize = 8;
    pub const PUBLIC_KEY: usize = 32;
    pub const SECTOR_INDEX: usize = 2;
    pub const HISTORY_SIZE: usize = 8;
    pub const PIECE_OFFSET: usize = 2;
    pub const RECORD_COMMITMENT: usize = 32;
    pub const RECORD_WITNESS: usize = 256;
    pub const CHUNK: usize = 32;
    pub const CHUNK_WITNESS: usize = 512;
    pub const PROOF_OF_SPACE: usize = 160;
}

/// Longitud del prefijo fijo PoAS sin sello: **1 164 bytes**.
pub const TAMANO_PREFIJO_FIJO: usize = ancho::BRANCH_ID
    + ancho::PREV_HASH
    + ancho::MERKLE_ROOT
    + ancho::TIMESTAMP
    + ancho::HEIGHT
    + ancho::SLOT
    + ancho::POT_OUTPUT
    + ancho::VDF_OUTPUT
    + ancho::RANGO
    + ancho::PUBLIC_KEY
    + ancho::SECTOR_INDEX
    + ancho::HISTORY_SIZE
    + ancho::PIECE_OFFSET
    + ancho::RECORD_COMMITMENT
    + ancho::RECORD_WITNESS
    + ancho::CHUNK
    + ancho::CHUNK_WITNESS
    + ancho::PROOF_OF_SPACE;

/// Longitud del compromiso del cuerpo.
pub const TAMANO_COMPROMISO_CUERPO: usize = 32;

/// Offset del compromiso del cuerpo: `[1164, 1196)`.
pub const OFFSET_COMPROMISO_CUERPO: usize = TAMANO_PREFIJO_FIJO;

/// Offset de `parent_count`: `[1196, 1197)`.
pub const OFFSET_PARENT_COUNT: usize = OFFSET_COMPROMISO_CUERPO + TAMANO_COMPROMISO_CUERPO;

/// Offset del primer padre adicional: `[1197, …)`.
pub const OFFSET_PADRES_EXTRA: usize = OFFSET_PARENT_COUNT + 1;

/// Longitud del sello Ed25519.
pub const TAMANO_SELLO: usize = LONGITUD_FIRMA;

/// Número máximo de padres, contando el seleccionado (R-FIN-12).
pub const MAX_PADRES: usize = 15;

/// Número máximo de padres adicionales (`parent_count - 1`).
pub const MAX_PADRES_EXTRA: usize = MAX_PADRES - 1;

/// Cabecera DAG mínima: génesis o `P = 1`. **1 261 bytes**.
pub const TAMANO_CABECERA_MIN: usize = OFFSET_PADRES_EXTRA + TAMANO_SELLO;

/// Cabecera DAG máxima: `P = 15`. **1 709 bytes**.
pub const TAMANO_CABECERA_MAX: usize =
    OFFSET_PADRES_EXTRA + MAX_PADRES_EXTRA * ancho::PREV_HASH + TAMANO_SELLO;

/// El hash nulo: `prev_hash` del génesis y huecos del array fijo de padres.
pub const HASH_NULO: BlockHash = BlockHash::from_digest(Digest::from_bytes([0u8; 32]));

/// Longitud de la prefirma para `parent_count` padres.
#[must_use]
pub const fn tamano_prefirma(parent_count: u8) -> usize {
    if parent_count == 0 {
        OFFSET_PADRES_EXTRA
    } else {
        OFFSET_PADRES_EXTRA + (parent_count as usize - 1) * ancho::PREV_HASH
    }
}

/// Longitud total de la cabecera para `parent_count` padres.
#[must_use]
pub const fn tamano_cabecera(parent_count: u8) -> usize {
    tamano_prefirma(parent_count) + TAMANO_SELLO
}

/// Solución PoAS, los campos que la tabla de §6.1 marca bajo `sol.*`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SolucionPoas {
    /// Clave pública Ed25519 que firma el sello (C-HDR-04).
    pub public_key: ClavePublica,
    /// Índice de sector.
    pub sector_index: u16,
    /// Tamaño de historia.
    pub history_size: u64,
    /// Desplazamiento de pieza.
    pub piece_offset: u16,
    /// Compromiso de registro: raíz Merkle del registro (32 B, B-21).
    pub record_commitment: [u8; 32],
    /// Testigo de registro: camino Merkle registro→segmento (256 B, B-21).
    pub record_witness: [u8; 256],
    /// Chunk de la solución (32 B).
    pub chunk: [u8; 32],
    /// Testigo del chunk: camino Merkle chunk→registro (512 B, B-21).
    pub chunk_witness: [u8; 512],
    /// Prueba de espacio (160 B).
    pub proof_of_space: [u8; 160],
}

impl Default for SolucionPoas {
    fn default() -> Self {
        Self {
            public_key: ClavePublica::desde_bytes([0u8; 32]),
            sector_index: 0,
            history_size: 0,
            piece_offset: 0,
            record_commitment: [0u8; 32],
            record_witness: [0u8; 256],
            chunk: [0u8; 32],
            chunk_witness: [0u8; 512],
            proof_of_space: [0u8; 160],
        }
    }
}

impl SolucionPoas {
    fn escribir(&self, salida: &mut Vec<u8>) {
        salida.extend_from_slice(self.public_key.bytes());
        int::escribir_u16(salida, self.sector_index);
        int::escribir_u64(salida, self.history_size);
        int::escribir_u16(salida, self.piece_offset);
        salida.extend_from_slice(&self.record_commitment);
        salida.extend_from_slice(&self.record_witness);
        salida.extend_from_slice(&self.chunk);
        salida.extend_from_slice(&self.chunk_witness);
        salida.extend_from_slice(&self.proof_of_space);
    }
}

/// Padres de un bloque: el seleccionado (en `prev_hash`) y hasta 14 adicionales.
///
/// Capacidad fija y campos privados. `Copy`, pero los huecos no usados del array **no** entran en
/// la igualdad lógica ni en el wire: la comparación se hace sobre el prefijo en uso.
#[derive(Clone, Copy)]
pub struct PadresDag {
    count: u8,
    seleccionado: BlockHash,
    extra: [BlockHash; MAX_PADRES_EXTRA],
}

impl PartialEq for PadresDag {
    fn eq(&self, other: &Self) -> bool {
        if self.count != other.count || self.seleccionado != other.seleccionado {
            return false;
        }
        let n = self.count.saturating_sub(1) as usize;
        match (self.extra.get(..n), other.extra.get(..n)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for PadresDag {}

impl core::fmt::Debug for PadresDag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PadresDag")
            .field("count", &self.count)
            .field("seleccionado", &self.seleccionado)
            .field("extra", &self.extras())
            .finish()
    }
}

impl PadresDag {
    /// Padres de génesis: `parent_count = 0`, `prev_hash = 0x00 × 32`, sin adicionales.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            count: 0,
            seleccionado: HASH_NULO,
            extra: [HASH_NULO; MAX_PADRES_EXTRA],
        }
    }

    /// Construye los padres de un bloque no génesis.
    ///
    /// Ordena los adicionales en orden ascendente estricto para que la representación sea única.
    /// **Rechaza duplicados y que un adicional repita el seleccionado**; no los elimina en
    /// silencio.
    ///
    /// # Errores
    /// [`EncodingError::DemasiadosPadres`], [`EncodingError::PadreDuplicado`] o
    /// [`EncodingError::PadreRepetidoConSeleccionado`].
    pub fn nuevo(
        seleccionado: BlockHash,
        adicionales: &[BlockHash],
    ) -> Result<Self, EncodingError> {
        if adicionales.len() > MAX_PADRES_EXTRA {
            return Err(EncodingError::DemasiadosPadres {
                declarados: adicionales.len() as u64 + 1,
                maximo: MAX_PADRES as u64,
            });
        }
        let mut copia = [HASH_NULO; MAX_PADRES_EXTRA];
        for (i, p) in adicionales.iter().enumerate() {
            if *p == seleccionado {
                return Err(EncodingError::PadreRepetidoConSeleccionado);
            }
            if copia.get(..i).is_some_and(|vistos| vistos.contains(p)) {
                return Err(EncodingError::PadreDuplicado);
            }
            if let Some(slot) = copia.get_mut(i) {
                *slot = *p;
            }
        }
        if let Some(usados) = copia.get_mut(..adicionales.len()) {
            usados.sort();
        }
        Ok(Self::desde_partes(seleccionado, &copia, adicionales.len()))
    }

    fn desde_partes(
        seleccionado: BlockHash,
        copia: &[BlockHash; MAX_PADRES_EXTRA],
        n: usize,
    ) -> Self {
        Self {
            count: u8::try_from(n + 1).unwrap_or(MAX_PADRES as u8),
            seleccionado,
            extra: *copia,
        }
    }

    /// Construye desde extras **ya validados** como estrictamente ascendentes y distintos.
    ///
    /// Es la ruta del parser: no ordena ni deduplica, porque esas decisiones ya se tomaron
    /// rechazando la entrada hostil.
    fn desde_extras_canonicos(
        seleccionado: BlockHash,
        extras: &[BlockHash],
    ) -> Result<Self, EncodingError> {
        let mut copia = [HASH_NULO; MAX_PADRES_EXTRA];
        for (i, p) in extras.iter().enumerate() {
            if let Some(slot) = copia.get_mut(i) {
                *slot = *p;
            }
        }
        Ok(Self::desde_partes(seleccionado, &copia, extras.len()))
    }

    /// ¿Es el génesis estructural (cero padres)?
    #[must_use]
    pub const fn es_genesis(&self) -> bool {
        self.count == 0
    }

    /// `parent_count`: cuenta **todos** los padres.
    #[must_use]
    pub const fn count(&self) -> u8 {
        self.count
    }

    /// El padre seleccionado (`prev_hash`); nulo en génesis.
    #[must_use]
    pub const fn seleccionado(&self) -> BlockHash {
        self.seleccionado
    }

    /// Los padres adicionales, en orden canónico.
    #[must_use]
    pub fn extras(&self) -> &[BlockHash] {
        let n = self.count.saturating_sub(1) as usize;
        self.extra.get(..n).unwrap_or(&[])
    }
}

/// Cabecera DAG: base PoAS fija más compromiso, padres y sello.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DagBlockHeader {
    /// Rama de consenso activa (C-HDR-02b).
    pub consensus_branch_id: u32,
    /// Merkle de los `txid` (C-BLK-01).
    pub merkle_root: MerkleRoot,
    /// Segundos Unix declarados. **No** es el índice de PoT (`slot`).
    pub timestamp: u64,
    /// Altura declarada. Su semántica DAG sigue pendiente (C-HDR-02).
    pub height: u32,
    /// Índice de PoT (R-FIN-1a).
    pub slot: u64,
    /// Salida PoT de 16 bytes.
    pub pot_output: [u8; 16],
    /// `v_j` del segundo VDF (16 B, `C-RLJ-VDF-02`/`C-RLJ-VDF-03`). Todo ceros = sin segundo VDF.
    pub vdf_output: [u8; 16],
    /// Rango de solución.
    pub rango_solucion: u64,
    /// Solución PoAS.
    pub sol: SolucionPoas,
    /// Compromiso completo del cuerpo.
    pub body_commitment: BodyCommitment,
    /// Padres (estrategia A).
    pub padres: PadresDag,
    /// Sello Ed25519 ZIP-215 sobre `pre_hash`.
    pub sello: [u8; LONGITUD_FIRMA],
}

impl DagBlockHeader {
    /// Escribe la prefirma canónica (todo menos el sello).
    ///
    /// **Es la única descripción del formato.** De aquí salen el wire, `pre_hash`, `block_hash` y
    /// la derivación de identificadores cortos.
    pub fn escribir(&self, salida: &mut Vec<u8>) {
        int::escribir_u32(salida, self.consensus_branch_id);
        salida.extend_from_slice(self.padres.seleccionado().as_bytes());
        salida.extend_from_slice(self.merkle_root.as_bytes());
        int::escribir_u64(salida, self.timestamp);
        int::escribir_u32(salida, self.height);
        int::escribir_u64(salida, self.slot);
        salida.extend_from_slice(&self.pot_output);
        salida.extend_from_slice(&self.vdf_output);
        int::escribir_u64(salida, self.rango_solucion);
        self.sol.escribir(salida);
        salida.extend_from_slice(self.body_commitment.as_bytes());
        salida.push(self.padres.count());
        for p in self.padres.extras() {
            salida.extend_from_slice(p.as_bytes());
        }
    }

    /// La prefirma canónica, sin el sello.
    #[must_use]
    pub fn prefirma(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(tamano_prefirma(self.padres.count()));
        self.escribir(&mut v);
        v
    }

    /// La cabecera completa: prefirma ‖ sello.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(tamano_cabecera(self.padres.count()));
        self.escribir(&mut v);
        v.extend_from_slice(&self.sello);
        v
    }

    /// Longitud de la cabecera codificada.
    #[must_use]
    pub fn tamano(&self) -> usize {
        tamano_cabecera(self.padres.count())
    }

    /// `pre_hash = H_d("ZZKBlkPreHash___", prefirma)` (C-HDR-03).
    #[must_use]
    pub fn pre_hash(&self) -> PreHash {
        PreHash::from_digest(h_d(TAG_BLK_PRE_HASH, &self.prefirma()))
    }

    /// `block_hash = H_d("ZZKBlkHeader____", prefirma ‖ sello)` (C-HDR-09).
    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        BlockHash::from_digest(h_d(TAG_BLK_HEADER, &self.a_bytes()))
    }

    /// Verifica el sello Ed25519 ZIP-215 bajo `sol.public_key` (C-HDR-04).
    ///
    /// # Errores
    /// [`EncodingError::FirmaInvalida`] si el sello no verifica.
    pub fn verificar_sello(&self) -> Result<(), EncodingError> {
        let pre = self.pre_hash();
        let firma = Firma::desde_bytes(self.sello);
        verificar(&self.sol.public_key, &firma, pre.as_bytes())
    }
}

/// Escribe la cabecera DAG en su codificación canónica de wire.
#[must_use]
pub fn dag_header_a_bytes(c: &DagBlockHeader) -> Vec<u8> {
    c.a_bytes()
}

/// Lee una cabecera DAG, determinando la longitud por `parent_count` en el offset fijo 1196.
///
/// Acota antes de reservar (a lo sumo 14 padres) y **nunca entra en pánico** ante bytes
/// arbitrarios. Rechaza orden no canónico de los padres adicionales, duplicados y que un
/// adicional repita el seleccionado. Para `parent_count = 0` exige `prev_hash = 0x00 × 32`: es la
/// única codificación de génesis.
///
/// # Errores
/// [`EncodingError::Truncado`], [`EncodingError::DemasiadosPadres`],
/// [`EncodingError::PadresNoCanonicos`], [`EncodingError::PadreDuplicado`],
/// [`EncodingError::PadreRepetidoConSeleccionado`].
pub fn dag_header_desde_bytes(bytes: &[u8]) -> Result<(DagBlockHeader, &[u8]), EncodingError> {
    let (consensus_branch_id, r) = int::leer_u32(bytes)?;
    let (prev, r) = int::leer_32(r)?;
    let (merkle, r) = int::leer_32(r)?;
    let (timestamp, r) = int::leer_u64(r)?;
    let (height, r) = int::leer_u32(r)?;
    let (slot, r) = int::leer_u64(r)?;
    let (pot_output, r) = int::leer_16(r)?;
    let (vdf_output, r) = int::leer_16(r)?;
    let (rango_solucion, r) = int::leer_u64(r)?;
    let (public_key, r) = int::leer_32(r)?;
    let (sector_index, r) = int::leer_u16(r)?;
    let (history_size, r) = int::leer_u64(r)?;
    let (piece_offset, r) = int::leer_u16(r)?;
    let (record_commitment, r) = int::leer_32(r)?;
    let (record_witness, r) = int::leer_256(r)?;
    let (chunk, r) = int::leer_32(r)?;
    let (chunk_witness, r) = int::leer_512(r)?;
    let (proof_of_space, r) = int::leer_160(r)?;
    let (body, r) = int::leer_32(r)?;
    let (parent_count, r) = int::leer_u8(r)?;

    let seleccionado = BlockHash::from_digest(Digest::from_bytes(prev));
    let padres = if parent_count == 0 {
        if seleccionado != HASH_NULO {
            return Err(EncodingError::PadresNoCanonicos);
        }
        PadresDag::genesis()
    } else {
        if usize::from(parent_count) > MAX_PADRES {
            return Err(EncodingError::DemasiadosPadres {
                declarados: u64::from(parent_count),
                maximo: MAX_PADRES as u64,
            });
        }
        let n = usize::from(parent_count) - 1;
        let (bloque, resto) =
            r.split_at_checked(n * ancho::PREV_HASH)
                .ok_or(EncodingError::Truncado {
                    esperados: n * ancho::PREV_HASH,
                    disponibles: r.len(),
                })?;
        let mut extras: Vec<BlockHash> = Vec::with_capacity(n);
        let mut anterior: Option<BlockHash> = None;
        for trozo in bloque.chunks_exact(ancho::PREV_HASH) {
            let mut b = [0u8; 32];
            b.copy_from_slice(trozo);
            let p = BlockHash::from_digest(Digest::from_bytes(b));
            if p == seleccionado {
                return Err(EncodingError::PadreRepetidoConSeleccionado);
            }
            if let Some(a) = anterior
                && p <= a
            {
                return Err(EncodingError::PadresNoCanonicos);
            }
            anterior = Some(p);
            extras.push(p);
        }
        let padres = PadresDag::desde_extras_canonicos(seleccionado, &extras)?;
        let (sello, resto) = leer_sello(resto)?;
        return Ok((
            DagBlockHeader {
                vdf_output,
                consensus_branch_id,
                merkle_root: MerkleRoot::from_digest(Digest::from_bytes(merkle)),
                timestamp,
                height,
                slot,
                pot_output,
                rango_solucion,
                sol: SolucionPoas {
                    public_key: ClavePublica::desde_bytes(public_key),
                    sector_index,
                    history_size,
                    piece_offset,
                    record_commitment,
                    record_witness,
                    chunk,
                    chunk_witness,
                    proof_of_space,
                },
                body_commitment: BodyCommitment::from_digest(Digest::from_bytes(body)),
                padres,
                sello,
            },
            resto,
        ));
    };

    let (sello, resto) = leer_sello(r)?;
    Ok((
        DagBlockHeader {
            vdf_output,
            consensus_branch_id,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes(merkle)),
            timestamp,
            height,
            slot,
            pot_output,
            rango_solucion,
            sol: SolucionPoas {
                public_key: ClavePublica::desde_bytes(public_key),
                sector_index,
                history_size,
                piece_offset,
                record_commitment,
                record_witness,
                chunk,
                chunk_witness,
                proof_of_space,
            },
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes(body)),
            padres,
            sello,
        },
        resto,
    ))
}

fn leer_sello(bytes: &[u8]) -> Result<([u8; LONGITUD_FIRMA], &[u8]), EncodingError> {
    let (cabeza, resto) =
        bytes
            .split_at_checked(LONGITUD_FIRMA)
            .ok_or(EncodingError::Truncado {
                esperados: LONGITUD_FIRMA,
                disponibles: bytes.len(),
            })?;
    let mut sello = [0u8; LONGITUD_FIRMA];
    sello.copy_from_slice(cabeza);
    Ok((sello, resto))
}

/// `body_commitment` a partir de los pares ya calculados `(txid, auth_digest)`.
///
/// Es la primitiva de ensamblado: el llamante decide cómo obtuvo cada `txid` y cada
/// `auth_digest`. Existe para que la ruta de consenso pueda **recalcular los pares por su cuenta**
/// y no limitarse a llamar a [`body_commitment`], que es lo que la haría tautológica.
///
/// ```text
/// H_d("ZZKBlkBodyHash__", CompactSize(n) ‖ ⋃ᵢ(txid_i ‖ auth_digest_i))
/// ```
#[must_use]
pub fn body_commitment_de_pares(pares: &[(TxId, crate::digest::AuthDigest)]) -> BodyCommitment {
    let mut w = PreimageWriter::con_capacidad(9 + pares.len() * 64);
    w.compact_size(pares.len() as u64);
    for (t, a) in pares {
        w.digest(t.digest());
        w.digest(a.digest());
    }
    BodyCommitment::from_digest(w.finish(TAG_BLK_BODY_HASH))
}

/// Compromiso completo del cuerpo (SPEC §6.1).
///
/// ```text
/// body_commitment = H_d("ZZKBlkBodyHash__", CompactSize(n_tx) ‖ ⋃ᵢ(txid_i ‖ auth_digest_i))
/// ```
///
/// Cada par mide exactamente 64 bytes y conserva orden, multiplicidad y coinbase. El número de
/// listas de testigos **MUST** ser exactamente el de transacciones: no se sustituyen listas
/// ausentes por listas vacías.
///
/// # Errores
/// [`EncodingError::CuerpoTestigosDescuadrados`] si los dos conjuntos no cuadran.
pub fn body_commitment(
    txs: &[Tx],
    testigos: &[Vec<Vec<u8>>],
    consensus_branch_id: u32,
) -> Result<BodyCommitment, EncodingError> {
    if txs.len() != testigos.len() {
        return Err(EncodingError::CuerpoTestigosDescuadrados {
            txs: txs.len(),
            testigos: testigos.len(),
        });
    }
    let pares = txs
        .iter()
        .zip(testigos)
        .map(|(tx, tw)| (txid(tx, consensus_branch_id), auth_digest(tw)))
        .collect::<Vec<_>>();
    Ok(body_commitment_de_pares(&pares))
}

/// Comprueba los dos compromisos del cuerpo contra la cabecera.
///
/// Recalcula `merkle_root` sobre los `txid` (C-BLK-01) y `body_commitment` sobre
/// `(txid, auth_digest)`, y distingue **cuál** falla. Igualar el compromiso **no** sustituye
/// verificar firmas ni Halo2: son controles distintos.
///
/// # Errores
/// [`CompromisosError::MerkleNoCoincide`], [`CompromisosError::CuerpoNoCoincide`] o
/// [`CompromisosError::TestigosDescuadrados`].
pub fn comprobar_compromisos(
    header: &DagBlockHeader,
    txs: &[Tx],
    testigos: &[Vec<Vec<u8>>],
) -> Result<(), CompromisosError> {
    let txids = txs
        .iter()
        .map(|t| txid(t, header.consensus_branch_id))
        .collect::<Vec<_>>();
    if merkle_root(&txids) != header.merkle_root {
        return Err(CompromisosError::MerkleNoCoincide);
    }
    if body_commitment(txs, testigos, header.consensus_branch_id)? != header.body_commitment {
        return Err(CompromisosError::CuerpoNoCoincide);
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#[expect(
    clippy::indexing_slicing,
    reason = "índices y rangos constantes sobre arrays de tamaño fijo"
)]
mod tests {
    use super::{
        DagBlockHeader, MAX_PADRES, MAX_PADRES_EXTRA, OFFSET_COMPROMISO_CUERPO,
        OFFSET_PADRES_EXTRA, OFFSET_PARENT_COUNT, PadresDag, SolucionPoas, TAMANO_CABECERA_MAX,
        TAMANO_CABECERA_MIN, TAMANO_PREFIJO_FIJO, body_commitment, comprobar_compromisos,
        dag_header_a_bytes, dag_header_desde_bytes,
    };
    use crate::amount::Amount;
    use crate::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot, TxId};
    use crate::error::{CompromisosError, EncodingError};
    use crate::firma::ClavePublica;
    use crate::preimage::block::merkle_root;
    use crate::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};
    use ed25519_zebra::{SigningKey, VerificationKey};

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn cabecera_con(padres: PadresDag) -> DagBlockHeader {
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0xc478_80ea,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x22; 32])),
            timestamp: 1_788_480_000,
            height: 7,
            slot: 1234,
            pot_output: [0xAB; 16],
            rango_solucion: 999,
            sol: SolucionPoas::default(),
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0x33; 32])),
            padres,
            sello: [0u8; 64],
        }
    }

    fn cabe_1() -> DagBlockHeader {
        cabecera_con(PadresDag::nuevo(h(1), &[]).unwrap())
    }

    fn tx(n: u8) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: OutPoint {
                    prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
                    prev_index: u32::from(n),
                },
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::nuevo(i64::from(n) * 1_000).unwrap(),
                lock: Lock::PubKey {
                    pubkey: ClavePublica::desde_bytes([n; 32]),
                },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        }
    }

    #[test]
    fn los_offsets_y_tamanos_son_los_fijados() {
        assert_eq!(TAMANO_PREFIJO_FIJO, 1164);
        assert_eq!(OFFSET_COMPROMISO_CUERPO, 1164);
        assert_eq!(OFFSET_PARENT_COUNT, 1196);
        assert_eq!(OFFSET_PADRES_EXTRA, 1197);
        assert_eq!(TAMANO_CABECERA_MIN, 1261);
        assert_eq!(TAMANO_CABECERA_MAX, 1709);
        assert_eq!(MAX_PADRES, 15);
        assert_eq!(MAX_PADRES_EXTRA, 14);
    }

    #[test]
    fn los_tamanos_por_numero_de_padres() {
        assert_eq!(cabe_1().tamano(), 1261);
        let dos = cabecera_con(PadresDag::nuevo(h(1), &[h(2)]).unwrap());
        assert_eq!(dos.tamano(), 1293);

        let extras: Vec<BlockHash> = (2u8..=15).map(h).collect();
        let quince = cabecera_con(PadresDag::nuevo(h(1), &extras).unwrap());
        assert_eq!(quince.tamano(), 1709);
        assert_eq!(quince.a_bytes().len(), 1709);

        let cero = cabecera_con(PadresDag::genesis());
        assert_eq!(cero.tamano(), 1261);
    }

    #[test]
    fn el_sello_esta_al_final() {
        for extra in [0usize, 1, MAX_PADRES_EXTRA] {
            let extras: Vec<BlockHash> = (2u8..).map(h).take(extra).collect();
            let mut c = cabecera_con(PadresDag::nuevo(h(1), &extras).unwrap());
            c.sello = [0x5A; 64];
            let bytes = c.a_bytes();
            assert_eq!(&bytes[bytes.len() - 64..], &[0x5A; 64]);
            assert_eq!(bytes.len(), c.tamano());
        }
    }

    #[test]
    fn roundtrip_para_genesis_uno_dos_y_quince_padres() {
        let casos = vec![
            cabecera_con(PadresDag::genesis()),
            cabe_1(),
            cabecera_con(PadresDag::nuevo(h(1), &[h(2)]).unwrap()),
            cabecera_con(PadresDag::nuevo(h(1), &(2u8..=15).map(h).collect::<Vec<_>>()).unwrap()),
        ];
        for c in casos {
            let bytes = dag_header_a_bytes(&c);
            let (leida, resto) = dag_header_desde_bytes(&bytes).unwrap();
            assert_eq!(leida, c, "ida y vuelta rota");
            assert!(resto.is_empty());
        }
    }

    #[test]
    fn el_parser_devuelve_el_resto() {
        let mut bytes = dag_header_a_bytes(&cabe_1());
        bytes.extend_from_slice(b"cola");
        let (_, resto) = dag_header_desde_bytes(&bytes).unwrap();
        assert_eq!(resto, b"cola");
    }

    #[test]
    fn rechaza_parent_count_mayor_que_15() {
        let mut bytes = dag_header_a_bytes(&cabe_1());
        bytes[OFFSET_PARENT_COUNT] = 16;
        assert!(matches!(
            dag_header_desde_bytes(&bytes),
            Err(EncodingError::DemasiadosPadres { declarados: 16, .. })
        ));
    }

    #[test]
    fn rechaza_truncados_en_cada_frontera() {
        let c = cabecera_con(PadresDag::nuevo(h(1), &[h(2)]).unwrap());
        let bytes = c.a_bytes();
        for n in 0..bytes.len() {
            assert!(
                dag_header_desde_bytes(bytes.get(..n).unwrap()).is_err(),
                "truncado en {n} debería rechazarse"
            );
        }
        assert!(dag_header_desde_bytes(&bytes).is_ok());
    }

    #[test]
    fn rechaza_padres_desordenados() {
        // Construye el wire a mano: prev=h(1), extras [h(3), h(2)] (descendente).
        let mut c = cabe_1();
        c.padres = PadresDag::nuevo(h(1), &[h(2)]).unwrap();
        let mut bytes = c.a_bytes();
        // El único extra vive en [525, 557); lo cambiamos por uno mayor para simular desorden
        // junto con un segundo extra.
        bytes[OFFSET_PARENT_COUNT] = 3;
        bytes.truncate(OFFSET_PADRES_EXTRA);
        bytes.extend_from_slice(h(3).as_bytes());
        bytes.extend_from_slice(h(2).as_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        assert!(matches!(
            dag_header_desde_bytes(&bytes),
            Err(EncodingError::PadresNoCanonicos)
        ));
    }

    #[test]
    fn rechaza_padres_repetidos_y_repetir_el_seleccionado() {
        let mut c = cabe_1();
        c.padres = PadresDag::nuevo(h(1), &[h(2)]).unwrap();
        let mut bytes = c.a_bytes();
        bytes[OFFSET_PARENT_COUNT] = 3;
        bytes.truncate(OFFSET_PADRES_EXTRA);
        bytes.extend_from_slice(h(2).as_bytes());
        bytes.extend_from_slice(h(2).as_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        assert!(matches!(
            dag_header_desde_bytes(&bytes),
            Err(EncodingError::PadresNoCanonicos)
        ));

        let mut bytes = c.a_bytes();
        bytes[OFFSET_PARENT_COUNT] = 2;
        bytes.truncate(OFFSET_PADRES_EXTRA);
        bytes.extend_from_slice(h(1).as_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        assert!(matches!(
            dag_header_desde_bytes(&bytes),
            Err(EncodingError::PadreRepetidoConSeleccionado)
        ));
    }

    #[test]
    fn el_constructor_rechaza_duplicados_y_repeticion_del_seleccionado() {
        assert!(matches!(
            PadresDag::nuevo(h(1), &[h(2), h(2)]),
            Err(EncodingError::PadreDuplicado)
        ));
        assert!(matches!(
            PadresDag::nuevo(h(1), &[h(1)]),
            Err(EncodingError::PadreRepetidoConSeleccionado)
        ));
    }

    #[test]
    fn bytes_arbitrarios_no_hacen_entrar_en_panico() {
        let mut x: u64 = 0x243F_6A88_85A3_08D3;
        for _ in 0..2_000 {
            let mut buf = Vec::new();
            for _ in 0..(x % 1200) {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                buf.push((x >> 33) as u8);
            }
            let _ = dag_header_desde_bytes(&buf);
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        }
    }

    #[test]
    fn los_bytes_de_wire_son_los_que_se_hashean() {
        let c = cabe_1();
        let bytes = dag_header_a_bytes(&c);
        assert_eq!(&bytes[..bytes.len() - 64], &c.prefirma()[..]);
        // El hash de bloque es exactamente el SHA3-256 de la etiqueta de dominio más los MISMOS
        // bytes que viajan. Si hubiera un segundo serializador, divergirían.
        let esperado = crate::hash::h_d(crate::hash::TAG_BLK_HEADER, &bytes);
        assert_eq!(c.block_hash().as_bytes(), esperado.as_bytes());
        // Y la prefirma es exactamente los mismos bytes sin sello.
        let pre = crate::hash::h_d(crate::hash::TAG_BLK_PRE_HASH, &bytes[..bytes.len() - 64]);
        assert_eq!(c.pre_hash().as_bytes(), pre.as_bytes());
    }

    /// **H-08c.** Cada campo de `DagBlockHeader` y de `SolucionPoas` entra en `pre_hash`.
    ///
    /// La desestructuración es **exhaustiva y sin `..`**: un campo nuevo rompe la compilación de
    /// este test hasta que alguien le dé su caso de mutación. El nombre no promete más de lo que
    /// hace — cubre los nueve campos de `sol`, no uno.
    #[test]
    fn cada_campo_de_la_cabecera_y_de_solucion_entra_en_pre_hash() {
        let base = cabe_1();
        let original = base.pre_hash();

        // Congela la lista de campos: sin `..`, añadir uno no compila aquí.
        let DagBlockHeader {
            consensus_branch_id: _,
            merkle_root: _,
            timestamp: _,
            height: _,
            slot: _,
            pot_output: _,
            vdf_output: _,
            rango_solucion: _,
            sol: _,
            body_commitment: _,
            padres: _,
            sello: _,
        } = base;
        let SolucionPoas {
            public_key: _,
            sector_index: _,
            history_size: _,
            piece_offset: _,
            record_commitment: _,
            record_witness: _,
            chunk: _,
            chunk_witness: _,
            proof_of_space: _,
        } = base.sol;

        // Cabecera.
        let mut v = base;
        v.consensus_branch_id ^= 1;
        assert_ne!(v.pre_hash(), original, "consensus_branch_id");
        let mut v = base;
        v.merkle_root = MerkleRoot::from_digest(Digest::from_bytes([9; 32]));
        assert_ne!(v.pre_hash(), original, "merkle_root");
        let mut v = base;
        v.timestamp += 1;
        assert_ne!(v.pre_hash(), original, "timestamp");
        let mut v = base;
        v.height += 1;
        assert_ne!(v.pre_hash(), original, "height");
        let mut v = base;
        v.slot += 1;
        assert_ne!(v.pre_hash(), original, "slot");
        let mut v = base;
        v.pot_output[0] ^= 1;
        assert_ne!(v.pre_hash(), original, "pot_output");
        let mut v = base;
        v.vdf_output[0] ^= 1;
        assert_ne!(v.pre_hash(), original, "vdf_output");
        let mut v = base;
        v.rango_solucion += 1;
        assert_ne!(v.pre_hash(), original, "rango_solucion");
        let mut v = base;
        v.body_commitment = BodyCommitment::from_digest(Digest::from_bytes([7; 32]));
        assert_ne!(v.pre_hash(), original, "body_commitment");

        // Padres: el seleccionado y un adicional.
        let mut v = base;
        v.padres = PadresDag::nuevo(h(2), &[]).unwrap();
        assert_ne!(v.pre_hash(), original, "padre seleccionado");
        let mut v = base;
        v.padres = PadresDag::nuevo(h(1), &[h(2)]).unwrap();
        assert_ne!(v.pre_hash(), original, "padre adicional");

        // Los nueve campos de `SolucionPoas`.
        let mut v = base;
        v.sol.public_key = ClavePublica::desde_bytes([0xAA; 32]);
        assert_ne!(v.pre_hash(), original, "sol.public_key");
        let mut v = base;
        v.sol.sector_index ^= 1;
        assert_ne!(v.pre_hash(), original, "sol.sector_index");
        let mut v = base;
        v.sol.history_size += 1;
        assert_ne!(v.pre_hash(), original, "sol.history_size");
        let mut v = base;
        v.sol.piece_offset ^= 1;
        assert_ne!(v.pre_hash(), original, "sol.piece_offset");
        let mut v = base;
        v.sol.record_commitment[0] ^= 1;
        assert_ne!(v.pre_hash(), original, "sol.record_commitment");
        let mut v = base;
        v.sol.record_witness[0] ^= 1;
        assert_ne!(v.pre_hash(), original, "sol.record_witness");
        let mut v = base;
        v.sol.chunk[0] ^= 1;
        assert_ne!(v.pre_hash(), original, "sol.chunk");
        let mut v = base;
        v.sol.chunk_witness[0] ^= 1;
        assert_ne!(v.pre_hash(), original, "sol.chunk_witness");
        let mut v = base;
        v.sol.proof_of_space[0] ^= 1;
        assert_ne!(v.pre_hash(), original, "sol.proof_of_space");
    }

    #[test]
    fn mutar_el_sello_cambia_block_hash_pero_no_pre_hash() {
        let base = cabe_1();
        let pre = base.pre_hash();
        let bloque = base.block_hash();
        let mut v = base;
        v.sello[0] ^= 0x80;
        assert_eq!(v.pre_hash(), pre, "el sello no entra en pre_hash");
        assert_ne!(v.block_hash(), bloque, "el sello sí entra en block_hash");
    }

    #[test]
    fn el_sello_zip215_se_verifica() {
        let sk = SigningKey::from([7u8; 32]);
        let vk = VerificationKey::from(&sk);
        let mut c = cabe_1();
        c.sol.public_key = ClavePublica::desde_bytes(vk.into());
        let pre = c.pre_hash();
        let firma: [u8; 64] = sk.sign(pre.as_bytes()).into();
        c.sello = firma;
        assert!(c.verificar_sello().is_ok());

        // Mensaje mutado: el rango cambia y la firma deja de verificar.
        let mut otro = c;
        otro.rango_solucion += 1;
        assert!(otro.verificar_sello().is_err());

        // Clave ajena.
        let (_sk2, vk2) = {
            let sk2 = SigningKey::from([8u8; 32]);
            let vk2 = VerificationKey::from(&sk2);
            (sk2, vk2)
        };
        let mut claves = c;
        claves.sol.public_key = ClavePublica::desde_bytes(vk2.into());
        assert!(claves.verificar_sello().is_err());

        // Sello mutado.
        let mut sello = c;
        sello.sello[10] ^= 0x01;
        assert!(sello.verificar_sello().is_err());
    }

    #[test]
    fn el_compromiso_del_cuerpo_es_sensible() {
        let txs = vec![tx(1), tx(2)];
        let testigos = vec![vec![vec![0x11; 64]], vec![vec![0x22; 64]]];
        let b = body_commitment(&txs, &testigos, 0xc478_80ea).unwrap();

        // Orden.
        let rev_txs = vec![tx(2), tx(1)];
        let rev_t = vec![vec![vec![0x22; 64]], vec![vec![0x11; 64]]];
        assert_ne!(
            body_commitment(&rev_txs, &rev_t, 0xc478_80ea).unwrap(),
            b,
            "orden"
        );

        // Autorización.
        let otros_t = vec![vec![vec![0x99; 64]], vec![vec![0x22; 64]]];
        assert_ne!(
            body_commitment(&txs, &otros_t, 0xc478_80ea).unwrap(),
            b,
            "auth"
        );

        // Contador: una tx menos.
        assert_ne!(
            body_commitment(&txs[..1], &testigos[..1], 0xc478_80ea).unwrap(),
            b,
            "contador"
        );

        // Coinbase distinta.
        let mut c2 = txs.clone();
        c2[0] = tx(9);
        assert_ne!(
            body_commitment(&c2, &testigos, 0xc478_80ea).unwrap(),
            b,
            "coinbase"
        );

        // Desajuste tx/testigos.
        assert!(matches!(
            body_commitment(&txs, &testigos[..1], 0xc478_80ea),
            Err(EncodingError::CuerpoTestigosDescuadrados { .. })
        ));
    }

    /// La mutación de un testigo **no** cambia la raíz de Merkle pero **sí** el compromiso.
    #[test]
    fn merkle_ignora_testigos_y_el_compromiso_no() {
        let txs = vec![tx(1)];
        let testigos = vec![vec![vec![0x11; 64]]];
        let secuencia = vec![tx(2)];
        let t2 = vec![vec![vec![0x99; 64]]];

        let mut c = cabe_1();
        let txids = vec![crate::preimage::tx::txid(&txs[0], c.consensus_branch_id)];
        c.merkle_root = merkle_root(&txids);
        c.body_commitment = body_commitment(&txs, &testigos, c.consensus_branch_id).unwrap();
        assert!(comprobar_compromisos(&c, &txs, &testigos).is_ok());

        // Solo testigos cambian: el compromiso falla, Merkle no.
        let mut c2 = c;
        c2.body_commitment = body_commitment(&txs, &t2, c.consensus_branch_id).unwrap();
        assert_eq!(
            comprobar_compromisos(&c2, &txs, &testigos),
            Err(CompromisosError::CuerpoNoCoincide)
        );

        // Efectos cambian: Merkle falla primero.
        assert_eq!(
            comprobar_compromisos(&c, &secuencia, &t2),
            Err(CompromisosError::MerkleNoCoincide)
        );
    }
}
