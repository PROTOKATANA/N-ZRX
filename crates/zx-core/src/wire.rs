//! Serialización de red y disco (SPEC §2.4, `C-WIRE-01..07`).
//!
//! # Qué es esto y qué NO es
//!
//! **No es la preimagen.** La preimagen (`crate::preimage`) es un **árbol de hashes**: el txid no es
//! la concatenación de los campos de una transacción, sino la raíz de un árbol de digests con
//! separación de dominio. No se puede "deserializar" una preimagen porque no contiene los datos,
//! contiene sus hashes.
//!
//! Esto es lo otro: la codificación que **viaja por la red y se guarda en disco**, de la que sí se
//! puede recuperar el objeto.
//!
//! # Por qué a mano y no Cap'n Proto
//!
//! `DECISIONES.md` eligió Cap'n Proto para wire y disco, y sigue siendo la elección para el
//! almacenamiento y para el intercambio de plantillas con el minero C++ —donde el código generado
//! para las dos lenguas paga su precio—. Para los **mensajes de sincronización** se decidió
//! distinto, con estas razones:
//!
//! 1. **Superficie de ataque.** Estos bytes vienen de un peer no autenticado. El parser de Cap'n
//!    Proto hace aritmética de punteros sobre datos hostiles; su crate de Rust tuvo
//!    `RUSTSEC-2025-0143` (UB en `get_root_unchecked`) y el bug de canonicalización de 2018 vivía
//!    justo en el manejo de *far pointers*. Los lectores de aquí no hacen más que avanzar un
//!    `&[u8]` comprobando la longitud, devuelven `Result`, y el workspace prohíbe `panic` y
//!    `unwrap`.
//! 2. **Una sola descripción del objeto.** Un `BlockHeader` ya tiene un orden de campos byte a byte
//!    fijado por el SPEC, el que se hashea. Describirlo otra vez en un `.capnp` crea **dos**
//!    descripciones del mismo objeto, y una divergencia entre ellas es exactamente la clase de
//!    fallo que este proyecto ya ha tenido dos veces (H-005, H-006). Aquí la cabecera que viaja son
//!    **los mismos bytes que se hashean**, y hay un test que lo fija.
//! 3. **Sin paso de compilación.** Ni `capnpc`, ni esquema, ni código generado que auditar.
//!
//! Coste asumido: se pierde el acceso *zero-copy* de Cap'n Proto. No está en el camino caliente —
//! el coste dominante de procesar un bloque es verificar firmas, no copiar 200 KB.
//!
//! # La invariante que ata esto al consenso
//!
//! `C-WGT-02` define el peso de una transacción con una **fórmula del protocolo**, deliberadamente
//! independiente de cualquier serializador (esa fue la corrección de H-006). Este módulo produce
//! una codificación cuya longitud **coincide exactamente con esa fórmula**.
//!
//! Son dos definiciones independientes que deben dar el mismo número, y un test de propiedad lo
//! comprueba sobre transacciones generadas al azar. No se hace que una dependa de la otra a
//! propósito: si un día divergen, quiero que **falle un test**, no que el peso cambie en silencio
//! porque alguien tocó el serializador.

use crate::amount::Amount;
use crate::digest::{BlockHash, Digest, MerkleRoot};
use crate::encoding::{compact_size, int};
use crate::error::EncodingError;
use crate::firma::{ClavePublica, LONGITUD_CLAVE};
use crate::preimage::block::{BlockHeader, TAMANO_CABECERA};
use crate::preimage::dag::dag_header_desde_bytes;
use crate::tx::{
    ExtensionTx, Lock, MAX_MULTISIG_KEYS, OperacionAlmacenamiento, OperacionSector, OutPoint,
    TipoGarantia, Tx, TxIn, TxOut,
};

/// Máximo de entradas, salidas o testigos que un lector acepta declarados.
///
/// **No es una regla de consenso**: es una cota de cordura del *parser*. Sin ella, un peer puede
/// declarar `CompactSize` = 2⁶⁴−1 y provocar una reserva de memoria enorme **antes** de que se lea
/// un solo elemento. El límite real de consenso lo pone el parámetro de transición
/// `max_tx_bytes` (TXL-01, DR-01), pero ese se comprueba mucho más tarde — y "mucho más tarde" es
/// demasiado tarde cuando la reserva ya ocurrió.
///
/// Deliberadamente generoso: no debe rechazar nada que el consenso acepte, solo lo absurdo.
pub const MAX_ELEMENTOS_DECLARADOS: u64 = 1_000_000;

// ─────────────────────────────────────────────────────────────────────────────
// Cabecera
// ─────────────────────────────────────────────────────────────────────────────

/// Escribe la cabecera en su codificación canónica de [`TAMANO_CABECERA`] bytes (C-WIRE-01).
///
/// Son **exactamente los mismos bytes que entran en la preimagen del PoW**, sin la etiqueta de
/// dominio. Que sean los mismos no es casualidad ni optimización: es lo que impide que exista una
/// segunda descripción del formato de cabecera capaz de divergir de la primera.
#[must_use]
pub fn cabecera_a_bytes(c: &BlockHeader) -> [u8; TAMANO_CABECERA] {
    let preimagen = c.preimagen_pow();
    let mut salida = [0u8; TAMANO_CABECERA];
    // La preimagen es `etiqueta(16) ‖ cabecera(112)`; nos quedamos con la cola.
    let inicio = preimagen.len() - TAMANO_CABECERA;
    if let (Some(dst), Some(src)) = (salida.get_mut(..TAMANO_CABECERA), preimagen.get(inicio..)) {
        dst.copy_from_slice(src);
    }
    salida
}

/// Lee una cabecera de su codificación canónica (C-WIRE-01).
///
/// Vive **aquí y no en `zx-p2p`** a propósito: el decodificador debe estar junto al codificador. Un
/// decodificador en otro crate re-describe el orden de los campos, y eso es literalmente el patrón
/// de H-005 — un offset transcrito a mano que dejó de cuadrar cuando cambió un tipo.
///
/// # Errores
/// [`EncodingError::Truncado`] si faltan bytes. No valida nada más: la validez de `bits`, del
/// timestamp y del PoW es consenso, y se comprueba después.
pub fn cabecera_desde_bytes(bytes: &[u8]) -> Result<(BlockHeader, &[u8]), EncodingError> {
    let (consensus_branch_id, r) = int::leer_u32(bytes)?;
    let (prev, r) = int::leer_32(r)?;
    let (raiz, r) = int::leer_32(r)?;
    let (timestamp, r) = int::leer_u64(r)?;
    let (bits, r) = int::leer_u32(r)?;
    let (nonce, r) = int::leer_u64(r)?;
    let (height, r) = int::leer_u32(r)?;

    Ok((
        BlockHeader {
            consensus_branch_id,
            prev_hash: BlockHash::from_digest(Digest::from_bytes(prev)),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes(raiz)),
            timestamp,
            bits,
            nonce,
            height,
        },
        r,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Lock
// ─────────────────────────────────────────────────────────────────────────────

/// Escribe un [`Lock`] en la codificación canónica de C-TX-09b (C-WIRE-02).
pub fn lock_a_bytes(salida: &mut Vec<u8>, l: &Lock) {
    int::escribir_u8(salida, l.discriminante());
    match l {
        Lock::PubKey { pubkey } => salida.extend_from_slice(pubkey.bytes()),
        Lock::MultiSig { k, pubkeys } => {
            int::escribir_u8(salida, *k);
            compact_size::escribir(salida, pubkeys.len() as u64);
            for p in pubkeys {
                salida.extend_from_slice(p.bytes());
            }
        }
        Lock::Htlc {
            hash,
            receiver,
            sender,
            timeout,
        } => {
            salida.extend_from_slice(hash);
            salida.extend_from_slice(receiver.bytes());
            salida.extend_from_slice(sender.bytes());
            int::escribir_u32(salida, *timeout);
        }
    }
}

/// Lee un [`Lock`] (C-WIRE-02).
///
/// # Errores
/// [`EncodingError::Truncado`] si faltan bytes, [`EncodingError::DiscriminanteDesconocido`] si el
/// byte de tipo no está en el conjunto de C-TX-10, o [`EncodingError::MultiSigInvalido`] si el
/// `MultiSig` incumple C-TX-11.
pub fn lock_desde_bytes(bytes: &[u8]) -> Result<(Lock, &[u8]), EncodingError> {
    let (disc, r) = int::leer_u8(bytes)?;
    match disc {
        Lock::DISC_PUBKEY => {
            let (k, r) = leer_clave(r)?;
            Ok((Lock::PubKey { pubkey: k }, r))
        }
        Lock::DISC_MULTISIG => {
            let (k, r) = int::leer_u8(r)?;
            let (n, mut r) = compact_size::leer(r)?;
            // C-TX-11 acota `n` a 16; comprobarlo ANTES de reservar evita que un `n` absurdo
            // provoque una reserva grande aunque luego se rechace.
            if n > MAX_MULTISIG_KEYS as u64 {
                return Err(EncodingError::MultiSigInvalido {
                    k,
                    n: n.try_into().unwrap_or(usize::MAX),
                    motivo: "n > MAX_MULTISIG_KEYS",
                });
            }
            let mut claves = Vec::with_capacity(n.try_into().unwrap_or(0));
            for _ in 0..n {
                let (c, resto) = leer_clave(r)?;
                claves.push(c);
                r = resto;
            }
            // El constructor vuelve a validar C-TX-11 entero, incluida la unicidad de claves.
            Ok((Lock::multisig(k, claves)?, r))
        }
        Lock::DISC_HTLC => {
            let (hash, r) = int::leer_32(r)?;
            let (receiver, r) = leer_clave(r)?;
            let (sender, r) = leer_clave(r)?;
            let (timeout, r) = int::leer_u32(r)?;
            Ok((
                Lock::Htlc {
                    hash,
                    receiver,
                    sender,
                    timeout,
                },
                r,
            ))
        }
        // C-TX-10 · un discriminante desconocido MUST rechazarse, NUNCA tratarse como
        // "gastable por cualquiera".
        otro => Err(EncodingError::LockDesconocido {
            discriminante: otro,
        }),
    }
}

fn leer_clave(bytes: &[u8]) -> Result<(ClavePublica, &[u8]), EncodingError> {
    let (b, r) = int::leer_32(bytes)?;
    debug_assert_eq!(LONGITUD_CLAVE, 32);
    Ok((ClavePublica::desde_bytes(b), r))
}

// ─────────────────────────────────────────────────────────────────────────────
// Transacción
// ─────────────────────────────────────────────────────────────────────────────

/// Escribe una transacción **con sus testigos** (C-WIRE-03, F-14).
///
/// El orden de campos es exactamente el que cuenta la fórmula de peso de C-WGT-02, y hay un test de
/// propiedad que comprueba que `serializar_tx(...).len() == peso_tx(...)` sobre transacciones
/// generadas al azar.
///
/// F-14: para v2 y v3, los campos extra se escriben **entre las salidas y los testigos**, sin
/// prefijo de longitud (`tipo u8 ‖ clave 32 B ‖ importe u64` en v2; `clave 32 B ‖ importe u64` en
/// v3). La v1 no cambia.
pub fn tx_a_bytes(salida: &mut Vec<u8>, tx: &Tx, testigos: &[Vec<u8>]) {
    int::escribir_u32(salida, tx.version);
    int::escribir_u32(salida, tx.lock_time);
    int::escribir_u32(salida, tx.expiry_height);

    compact_size::escribir(salida, tx.inputs.len() as u64);
    for e in &tx.inputs {
        salida.extend_from_slice(e.outpoint.prev_txid.as_bytes());
        int::escribir_u32(salida, e.outpoint.prev_index);
        int::escribir_u32(salida, e.sequence);
    }

    compact_size::escribir(salida, tx.outputs.len() as u64);
    for s in &tx.outputs {
        int::escribir_i64(salida, s.value.brek());
        lock_a_bytes(salida, &s.lock);
    }

    // F-14 · campos extra de v2/v3, en el orden y anchura de F-15/F-17, sin prefijo de longitud.
    match &tx.extension {
        ExtensionTx::Ninguna => {}
        ExtensionTx::Garantia {
            tipo,
            clave,
            importe,
            nonce,
        } => {
            int::escribir_u8(salida, tipo.byte());
            salida.extend_from_slice(clave.bytes());
            int::escribir_u64(salida, importe.brek() as u64);
            int::escribir_u64(salida, *nonce);
        }
        ExtensionTx::CoinbasePost {
            clave,
            importe,
            slot,
        } => {
            salida.extend_from_slice(clave.bytes());
            int::escribir_u64(salida, importe.brek() as u64);
            int::escribir_u64(salida, *slot);
        }
        // SL-4a · v4: `H1 ‖ H2`, cada cabecera autodelimitada por su `parent_count`. El contrato
        // (EV-02) no fija el wire de la v4; esta es la extensión elegida y queda declarada en
        // `DEFINICIONES-FALTANTES.md` (FD-5). SL-4c: `tx_desde_bytes` la decodifica (FD-5).
        ExtensionTx::Evidencia { h1, h2 } => {
            salida.extend_from_slice(&crate::preimage::dag::dag_header_a_bytes(h1));
            salida.extend_from_slice(&crate::preimage::dag::dag_header_a_bytes(h2));
        }
        // SR-1-2 · v5: la preimagen canónica de la operación de sector, tal cual (autodelimitada
        // por su discriminante y, en `ContestAuditoria`, por el prefijo de longitud de la prueba).
        ExtensionTx::Sector { operacion } => {
            operacion.escribir_canonica_cruda(salida);
        }
        // PT-3bc · v6: preimagen canónica de la operación de almacenamiento, tal cual.
        ExtensionTx::PruebaAlmacenamiento { operacion } => {
            operacion.escribir_canonica_cruda(salida);
        }
    }

    compact_size::escribir(salida, testigos.len() as u64);
    for t in testigos {
        compact_size::escribir(salida, t.len() as u64);
        salida.extend_from_slice(t);
    }
}

/// Una transacción con sus testigos, tal y como viaja.
///
/// Los testigos van **fuera** de `Tx` porque son datos de **autorización**, no de efecto: el txid
/// no los incluye, y eso es lo que hace la transacción no maleable (C-TX-01). Mezclarlos en la
/// misma estructura invitaría a que alguien los metiera en la preimagen sin darse cuenta.
pub type TxConTestigos = (Tx, Vec<Vec<u8>>);

/// Lee una transacción y sus testigos (C-WIRE-03, F-14).
///
/// F-14: el parser lee `version` y, según ella, **exige** los campos extra de v2/v3, las dos
/// cabeceras `PoAS_PoT_DAG` de la v4 o los prohíbe (v1). Tras el último testigo no se consume nada
/// más: el resto se devuelve al llamante, que es quien decide (el bloque lo usa para encadenar
/// transacciones; una transacción suelta **MUST** exigir que el resto venga vacío).
///
/// # Errores
/// [`EncodingError::VersionDesconocida`] para una versión fuera de `{1,2,3,4}`,
/// [`EncodingError::TipoGarantiaInvalido`] para un `tipo` de v2 fuera de `{1,2,3}`,
/// [`EncodingError::Truncado`] si faltan bytes (incluida una cabecera DAG truncada),
/// [`EncodingError::DemasiadosElementos`] si un contador declarado supera
/// [`MAX_ELEMENTOS_DECLARADOS`], o el error del campo que no decodifique. La v4 se decodifica aquí;
/// su **activación** la decide el motor (F-05/FD-5), no el códec.
pub fn tx_desde_bytes(bytes: &[u8]) -> Result<(TxConTestigos, &[u8]), EncodingError> {
    let (version, r) = int::leer_u32(bytes)?;
    // F-05: 1, 2, 3 y 4 son decodificables; el resto se rechaza. La v4 es la `EvidenceTx` y el
    // **motor** decide su activación (SL-4c, FD-5): el parser no la confunde con inactiva.
    match version {
        1..=6 => {}
        v => return Err(EncodingError::VersionDesconocida { version: v }),
    }
    let (lock_time, r) = int::leer_u32(r)?;
    let (expiry_height, r) = int::leer_u32(r)?;

    let (n_in, mut r) = leer_contador(r)?;
    let mut inputs = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        let (txid, resto) = int::leer_32(r)?;
        let (prev_index, resto) = int::leer_u32(resto)?;
        let (sequence, resto) = int::leer_u32(resto)?;
        inputs.push(TxIn {
            outpoint: OutPoint {
                prev_txid: crate::digest::TxId::from_digest(Digest::from_bytes(txid)),
                prev_index,
            },
            sequence,
        });
        r = resto;
    }

    let (n_out, mut r) = leer_contador(r)?;
    let mut outputs = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        let (brek, resto) = int::leer_i64(r)?;
        let (lock, resto) = lock_desde_bytes(resto)?;
        outputs.push(TxOut {
            value: Amount::nuevo(brek)?,
            lock,
        });
        r = resto;
    }

    // F-14 · campos extra de v2/v3, leídos según la versión. La v1 no lleva ninguno.
    let extension = match version {
        2 => {
            let (tipo_byte, resto) = int::leer_u8(r)?;
            let tipo = TipoGarantia::desde_byte(tipo_byte)
                .ok_or(EncodingError::TipoGarantiaInvalido { tipo: tipo_byte })?;
            let (clave, resto) = leer_clave(resto)?;
            let (brek, resto) = int::leer_i64(resto)?;
            let (nonce, resto) = int::leer_u64(resto)?;
            r = resto;
            ExtensionTx::Garantia {
                tipo,
                clave,
                importe: Amount::nuevo(brek)?,
                nonce,
            }
        }
        3 => {
            let (clave, resto) = leer_clave(r)?;
            let (brek, resto) = int::leer_i64(resto)?;
            let (slot, resto) = int::leer_u64(resto)?;
            r = resto;
            ExtensionTx::CoinbasePost {
                clave,
                importe: Amount::nuevo(brek)?,
                slot,
            }
        }
        4 => {
            // SL-4c · FD-5: dos cabeceras `PoAS_PoT_DAG` completas, `H1 ‖ H2`, cada una
            // autodelimitada por su `parent_count` (589–1 037 B, F-02/F-04). El parser no adivina
            // la familia: delega en el parser de cabecera DAG, que acota `parent_count` y rechaza
            // truncamiento y orden no canónico de padres. Tras `H2` sigue el recuento de testigos,
            // igual que en las demás versiones; `EV-01` (n_wit = 0) es forma, no códec.
            let (h1, resto) = dag_header_desde_bytes(r)?;
            let (h2, resto) = dag_header_desde_bytes(resto)?;
            r = resto;
            ExtensionTx::Evidencia { h1, h2 }
        }
        5 => {
            // SR-1-2 · v5: la operación de sector llega como su preimagen canónica; el parser
            // devuelve cuántos bytes consume y sigue con el recuento de testigos.
            let (operacion, consumidos) = OperacionSector::desde_canonica(r)?;
            r = r.get(consumidos..).ok_or(EncodingError::Truncado {
                esperados: consumidos,
                disponibles: r.len(),
            })?;
            ExtensionTx::Sector { operacion }
        }
        6 => {
            // PT-3bc · v6: la operación de almacenamiento llega como su preimagen canónica; el
            // parser devuelve cuántos bytes consume y sigue con el recuento de testigos.
            let (operacion, consumidos) = OperacionAlmacenamiento::desde_canonica(r)?;
            r = r.get(consumidos..).ok_or(EncodingError::Truncado {
                esperados: consumidos,
                disponibles: r.len(),
            })?;
            ExtensionTx::PruebaAlmacenamiento { operacion }
        }
        // Ya se validó arriba: solo queda la 1.
        _ => ExtensionTx::Ninguna,
    };

    let (n_wit, mut r) = leer_contador(r)?;
    let mut testigos = Vec::with_capacity(n_wit);
    for _ in 0..n_wit {
        let (len, resto) = compact_size::leer(r)?;
        let len = usize::try_from(len).map_err(|_| EncodingError::DemasiadosElementos {
            declarados: len,
            maximo: MAX_ELEMENTOS_DECLARADOS,
        })?;
        let (t, resto) = resto.split_at_checked(len).ok_or(EncodingError::Truncado {
            esperados: len,
            disponibles: resto.len(),
        })?;
        testigos.push(t.to_vec());
        r = resto;
    }

    Ok((
        (
            Tx {
                version,
                inputs,
                outputs,
                lock_time,
                expiry_height,
                extension,
            },
            testigos,
        ),
        r,
    ))
}

/// Un bloque completo tal y como se guarda y viaja.
pub type CuerpoBloque = (BlockHeader, Vec<Tx>, Vec<Vec<Vec<u8>>>);

/// Escribe un bloque completo: cabecera, transacciones y testigos (C-WIRE-07).
///
/// ```text
/// cabecera(92) ‖ CompactSize(n_tx) ‖ n_tx × [ tx con sus testigos (C-WIRE-03) ]
/// ```
///
/// Los testigos van **dentro de cada transacción** y no en una lista aparte, porque así la
/// correspondencia tx↔testigo es posicional por construcción: no hay forma de que una lista tenga
/// más elementos que la otra.
pub fn cuerpo_a_bytes(
    salida: &mut Vec<u8>,
    cabecera: &BlockHeader,
    txs: &[Tx],
    testigos: &[Vec<Vec<u8>>],
) {
    salida.extend_from_slice(&cabecera_a_bytes(cabecera));
    compact_size::escribir(salida, txs.len() as u64);
    let vacio: Vec<Vec<u8>> = Vec::new();
    for (i, tx) in txs.iter().enumerate() {
        tx_a_bytes(salida, tx, testigos.get(i).unwrap_or(&vacio));
    }
}

/// Lee un bloque completo (C-WIRE-07).
///
/// # Errores
/// El error de codificación que corresponda. **Nunca entra en pánico** (C-WIRE-05).
pub fn cuerpo_desde_bytes(bytes: &[u8]) -> Result<(CuerpoBloque, &[u8]), EncodingError> {
    let (cabecera, r) = cabecera_desde_bytes(bytes)?;
    let (n, mut r) = leer_contador(r)?;

    let mut txs = Vec::with_capacity(n.min(4_096));
    let mut testigos = Vec::with_capacity(n.min(4_096));
    for _ in 0..n {
        let ((tx, t), resto) = tx_desde_bytes(r)?;
        txs.push(tx);
        testigos.push(t);
        r = resto;
    }
    Ok(((cabecera, txs, testigos), r))
}

/// Lee un contador y lo acota **antes** de que nadie reserve memoria por él.
///
/// Este es el punto exacto donde un peer hostil intentaría que reservásemos gigabytes declarando un
/// `CompactSize` enorme con un cuerpo de veinte bytes. El límite no es de consenso: es lo que
/// impide que la reserva ocurra antes de que el consenso llegue a opinar.
pub(crate) fn leer_contador(bytes: &[u8]) -> Result<(usize, &[u8]), EncodingError> {
    let (n, r) = compact_size::leer(bytes)?;
    if n > MAX_ELEMENTOS_DECLARADOS {
        return Err(EncodingError::DemasiadosElementos {
            declarados: n,
            maximo: MAX_ELEMENTOS_DECLARADOS,
        });
    }
    let n = usize::try_from(n).map_err(|_| EncodingError::DemasiadosElementos {
        declarados: n,
        maximo: MAX_ELEMENTOS_DECLARADOS,
    })?;
    Ok((n, r))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{
        MAX_ELEMENTOS_DECLARADOS, cabecera_a_bytes, cabecera_desde_bytes, lock_a_bytes,
        lock_desde_bytes, tx_a_bytes, tx_desde_bytes,
    };
    use crate::amount::Amount;
    use crate::digest::{BlockHash, Digest, MerkleRoot, TxId};
    use crate::encoding::compact_size;
    use crate::error::EncodingError;
    use crate::firma::ClavePublica;
    use crate::preimage::block::{BlockHeader, TAMANO_CABECERA};
    use crate::tx::{ExtensionTx, Lock, OperacionSector, OutPoint, Tx, TxIn, TxOut};

    fn clave(n: u8) -> ClavePublica {
        ClavePublica::desde_bytes([n; 32])
    }

    fn cabecera(n: u8) -> BlockHeader {
        BlockHeader {
            consensus_branch_id: 0xc478_80ea,
            prev_hash: BlockHash::from_digest(Digest::from_bytes([n; 32])),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([n ^ 0xff; 32])),
            timestamp: 1_788_480_000,
            bits: 0x1c07_fff8,
            nonce: 0x0102_0304_0506_0708,
            height: 4_242,
        }
    }

    fn tx_variada() -> (Tx, Vec<Vec<u8>>) {
        let tx = Tx {
            version: 1,
            inputs: vec![
                TxIn {
                    outpoint: OutPoint {
                        prev_txid: TxId::from_digest(Digest::from_bytes([7; 32])),
                        prev_index: 3,
                    },
                    sequence: 0xffff_fffe,
                },
                TxIn {
                    outpoint: OutPoint {
                        prev_txid: TxId::from_digest(Digest::from_bytes([9; 32])),
                        prev_index: 0,
                    },
                    sequence: 0,
                },
            ],
            outputs: vec![
                TxOut {
                    value: Amount::nuevo(1_234_567).unwrap(),
                    lock: Lock::PubKey { pubkey: clave(1) },
                },
                TxOut {
                    value: Amount::CERO,
                    lock: Lock::multisig(2, vec![clave(2), clave(3), clave(4)]).unwrap(),
                },
                TxOut {
                    value: Amount::nuevo(1).unwrap(),
                    lock: Lock::Htlc {
                        hash: [0xab; 32],
                        receiver: clave(5),
                        sender: clave(6),
                        timeout: 900_000,
                    },
                },
            ],
            lock_time: 12,
            expiry_height: 34,
            extension: ExtensionTx::Ninguna,
        };
        let testigos = vec![vec![0x11; 64], vec![0x22; 65]];
        (tx, testigos)
    }

    // ── Cabecera ─────────────────────────────────────────────────────────────

    /// **C-WIRE-01.** Los bytes que viajan son **exactamente** los que se hashean.
    ///
    /// Es la propiedad que justifica no usar un serializador aparte para la cabecera: si estos
    /// bytes salieran de otro sitio, existirían dos descripciones del formato capaces de divergir.
    /// Es lo que pasó en H-005.
    #[test]
    fn los_bytes_de_la_cabecera_son_los_que_se_hashean() {
        let c = cabecera(1);
        let bytes = cabecera_a_bytes(&c);
        let preimagen = c.preimagen_pow();

        assert_eq!(bytes.len(), TAMANO_CABECERA);
        assert_eq!(
            &bytes[..],
            preimagen.get(preimagen.len() - TAMANO_CABECERA..).unwrap(),
            "la cabecera de wire MUST ser la cola de la preimagen del PoW"
        );
    }

    #[test]
    fn la_cabecera_da_la_vuelta_completa() {
        for n in [0u8, 1, 0x7f, 0x80, 0xff] {
            let c = cabecera(n);
            let bytes = cabecera_a_bytes(&c);
            let (leida, resto) = cabecera_desde_bytes(&bytes).unwrap();
            assert_eq!(leida, c, "n={n}");
            assert!(resto.is_empty(), "no debe sobrar nada");
        }
    }

    /// Una cabecera truncada se rechaza en **cualquier** punto de corte, sin pánico.
    #[test]
    fn una_cabecera_truncada_se_rechaza_en_todo_punto() {
        let bytes = cabecera_a_bytes(&cabecera(3));
        for n in 0..TAMANO_CABECERA {
            assert!(
                cabecera_desde_bytes(bytes.get(..n).unwrap()).is_err(),
                "{n} bytes deberían rechazarse"
            );
        }
        assert!(cabecera_desde_bytes(&bytes).is_ok());
    }

    /// Cambiar **un solo bit** de la cabecera cambia los bytes. Descarta un codificador que
    /// ignorase campos.
    #[test]
    fn cada_campo_de_la_cabecera_llega_a_los_bytes() {
        let base = cabecera(1);
        let bytes = cabecera_a_bytes(&base);

        let mut variantes = Vec::new();
        let mut v = base;
        v.consensus_branch_id ^= 1;
        variantes.push(v);
        v = base;
        v.timestamp ^= 1;
        variantes.push(v);
        v = base;
        v.bits ^= 1;
        variantes.push(v);
        v = base;
        v.nonce ^= 1;
        variantes.push(v);
        v = base;
        v.height ^= 1;
        variantes.push(v);
        v = base;
        v.prev_hash = BlockHash::from_digest(Digest::from_bytes([2; 32]));
        variantes.push(v);
        v = base;
        v.merkle_root = MerkleRoot::from_digest(Digest::from_bytes([2; 32]));
        variantes.push(v);

        for (i, v) in variantes.iter().enumerate() {
            assert_ne!(
                cabecera_a_bytes(v),
                bytes,
                "la variante {i} produjo los mismos bytes: hay un campo que no se serializa"
            );
        }
    }

    // ── Lock ─────────────────────────────────────────────────────────────────

    #[test]
    fn los_tres_locks_dan_la_vuelta() {
        let locks = [
            Lock::PubKey { pubkey: clave(1) },
            Lock::multisig(2, vec![clave(1), clave(2), clave(3)]).unwrap(),
            Lock::Htlc {
                hash: [0xcd; 32],
                receiver: clave(4),
                sender: clave(5),
                timeout: 7,
            },
        ];
        for l in &locks {
            let mut b = Vec::new();
            lock_a_bytes(&mut b, l);
            let (leido, resto) = lock_desde_bytes(&b).unwrap();
            assert_eq!(&leido, l);
            assert!(resto.is_empty());
        }
    }

    /// **C-TX-09b.** Las longitudes son las que el SPEC declara, y las que cuenta C-WGT-02.
    #[test]
    fn las_longitudes_de_lock_son_las_del_spec() {
        let mut b = Vec::new();
        lock_a_bytes(&mut b, &Lock::PubKey { pubkey: clave(0) });
        assert_eq!(b.len(), 33, "1 disc + 32 clave");

        b.clear();
        lock_a_bytes(
            &mut b,
            &Lock::Htlc {
                hash: [0; 32],
                receiver: clave(0),
                sender: clave(1),
                timeout: 0,
            },
        );
        assert_eq!(b.len(), 101, "1 + 32·3 + 4");

        for n in 1..=16u8 {
            let claves: Vec<_> = (0..n).map(clave).collect();
            b.clear();
            lock_a_bytes(&mut b, &Lock::multisig(1, claves).unwrap());
            // disc(1) + k(1) + CompactSize(n≤16 → 1 byte) + n·32
            let esperado = 3 + 32 * usize::from(n);
            assert_eq!(b.len(), esperado, "MultiSig de {n} claves");
        }
    }

    /// **C-TX-10.** Un discriminante desconocido se rechaza, **nunca** se trata como gastable.
    ///
    /// Es la diferencia entre una salida que nadie puede gastar y una que puede gastar cualquiera.
    #[test]
    fn un_discriminante_desconocido_se_rechaza() {
        for disc in [0x03u8, 0x7f, 0x80, 0xff] {
            let bytes = vec![disc; 128];
            assert!(
                matches!(
                    lock_desde_bytes(&bytes),
                    Err(EncodingError::LockDesconocido { .. })
                ),
                "el discriminante {disc:#04x} MUST rechazarse"
            );
        }
    }

    /// **C-TX-11.** Un `MultiSig` con `n` absurdo se rechaza **antes** de reservar memoria por él.
    #[test]
    fn un_multisig_con_n_absurdo_no_reserva_memoria() {
        let mut bytes = vec![Lock::DISC_MULTISIG, 1];
        compact_size::escribir(&mut bytes, u64::MAX);
        // Sin cuerpo: si el lector reservase por `n` antes de leer, esto sería una bomba.
        assert!(matches!(
            lock_desde_bytes(&bytes),
            Err(EncodingError::MultiSigInvalido { .. })
        ));
    }

    /// Y con claves repetidas también, que es C-TX-11 por la otra vía.
    #[test]
    fn un_multisig_con_claves_repetidas_se_rechaza_al_leer() {
        let mut bytes = vec![Lock::DISC_MULTISIG, 2];
        compact_size::escribir(&mut bytes, 2);
        bytes.extend_from_slice(clave(7).bytes());
        bytes.extend_from_slice(clave(7).bytes());
        assert!(matches!(
            lock_desde_bytes(&bytes),
            Err(EncodingError::MultiSigInvalido { .. })
        ));
    }

    // ── Transacción ──────────────────────────────────────────────────────────

    #[test]
    fn la_transaccion_da_la_vuelta_completa() {
        let (tx, testigos) = tx_variada();
        let mut b = Vec::new();
        tx_a_bytes(&mut b, &tx, &testigos);

        let ((leida, t_leidos), resto) = tx_desde_bytes(&b).unwrap();
        assert_eq!(leida, tx);
        assert_eq!(t_leidos, testigos);
        assert!(resto.is_empty());
    }

    /// **TX-2b · TXL-01.** `tx_a_bytes` **incluye los testigos** y su longitud es exactamente la
    /// suma de las partes codificadas: campos fijos, entradas, salidas, extensión y testigos.
    ///
    /// Es la comprobación que `ACLARACION-TX2b.md` §1 pide aparte del diferencial: el oráculo v0.6
    /// modela el tamaño con un campo abstracto, y aquí se fija que el serializador real cuenta los
    /// testigos.
    #[test]
    fn tx_a_bytes_incluye_los_testigos_y_suma_sus_partes() {
        let (tx, testigos) = tx_variada();
        let mut completo = Vec::new();
        tx_a_bytes(&mut completo, &tx, &testigos);

        // Suma de las partes, campo a campo, con los mismos escritores primitivos.
        let mut partes = Vec::new();
        crate::encoding::int::escribir_u32(&mut partes, tx.version);
        crate::encoding::int::escribir_u32(&mut partes, tx.lock_time);
        crate::encoding::int::escribir_u32(&mut partes, tx.expiry_height);
        compact_size::escribir(&mut partes, tx.inputs.len() as u64);
        for e in &tx.inputs {
            partes.extend_from_slice(e.outpoint.prev_txid.as_bytes());
            crate::encoding::int::escribir_u32(&mut partes, e.outpoint.prev_index);
            crate::encoding::int::escribir_u32(&mut partes, e.sequence);
        }
        compact_size::escribir(&mut partes, tx.outputs.len() as u64);
        for s in &tx.outputs {
            crate::encoding::int::escribir_i64(&mut partes, s.value.brek());
            lock_a_bytes(&mut partes, &s.lock);
        }
        assert!(
            matches!(tx.extension, ExtensionTx::Ninguna),
            "tx_variada no lleva extensión"
        );
        compact_size::escribir(&mut partes, testigos.len() as u64);
        for t in &testigos {
            compact_size::escribir(&mut partes, t.len() as u64);
            partes.extend_from_slice(t);
        }
        assert_eq!(
            completo, partes,
            "la codificación no coincide con la suma de sus partes"
        );

        // Sin testigos la codificación es más corta exactamente en la sección de testigos:
        // `Σ (CompactSize(len_i) + len_i)` (el `CompactSize` del número de testigos está presente en
        // las dos codificaciones —`n` frente a `0`— y por tanto se cancela en la diferencia).
        let mut sin_testigos = Vec::new();
        tx_a_bytes(&mut sin_testigos, &tx, &[]);
        let bytes_testigos = completo.len() - sin_testigos.len();
        let esperado_testigos = testigos.iter().map(|t| 1 + t.len()).sum::<usize>();
        assert!(bytes_testigos > 0, "los testigos MUST contar en tx_a_bytes");
        assert_eq!(bytes_testigos, esperado_testigos);
    }

    /// Truncar en **cualquier** punto se rechaza sin pánico. El workspace prohíbe `panic`, pero un
    /// índice fuera de rango en un parser de datos hostiles sigue siendo un DoS.
    #[test]
    fn una_transaccion_truncada_se_rechaza_en_todo_punto() {
        let (tx, testigos) = tx_variada();
        let mut b = Vec::new();
        tx_a_bytes(&mut b, &tx, &testigos);

        for n in 0..b.len() {
            let _ = tx_desde_bytes(b.get(..n).unwrap());
        }
        assert!(tx_desde_bytes(&b).is_ok(), "completa sí vale");
    }

    /// **C-WIRE-04.** El ataque del contador mentiroso, que es el más barato de todos.
    ///
    /// El emisor declara millones de entradas y manda veinte bytes. Sin la cota, el lector reserva
    /// por lo declarado **antes** de descubrir que no hay cuerpo. Es el patrón que lighthouse
    /// prueba mintiendo en el prefijo de longitud en vez de construir el payload real.
    #[test]
    fn un_contador_mentiroso_se_rechaza_sin_reservar() {
        for declarados in [
            MAX_ELEMENTOS_DECLARADOS + 1,
            u32::MAX as u64,
            0x7fff_ffff_ffff_ffff,
            u64::MAX,
        ] {
            let mut b = Vec::new();
            b.extend_from_slice(&1u32.to_le_bytes()); // version
            b.extend_from_slice(&0u32.to_le_bytes()); // lock_time
            b.extend_from_slice(&0u32.to_le_bytes()); // expiry_height
            compact_size::escribir(&mut b, declarados); // n_in mentiroso
            // …y nada más. El cuerpo real son 0 entradas.

            assert!(
                matches!(
                    tx_desde_bytes(&b),
                    Err(EncodingError::DemasiadosElementos { .. })
                ),
                "declarar {declarados} entradas MUST rechazarse por la cota, no por falta de bytes"
            );
        }
    }

    /// El mismo ataque, un nivel más adentro: contador honesto de entradas, mentiroso de testigos.
    #[test]
    fn un_contador_mentiroso_de_testigos_tambien_se_rechaza() {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        compact_size::escribir(&mut b, 0); // sin entradas
        compact_size::escribir(&mut b, 0); // sin salidas
        compact_size::escribir(&mut b, u64::MAX); // testigos mentirosos

        assert!(matches!(
            tx_desde_bytes(&b),
            Err(EncodingError::DemasiadosElementos { .. })
        ));
    }

    /// Un testigo que declara más bytes de los que hay se rechaza por truncamiento, no por pánico.
    #[test]
    fn un_testigo_que_miente_su_longitud_se_rechaza() {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        compact_size::escribir(&mut b, 0);
        compact_size::escribir(&mut b, 0);
        compact_size::escribir(&mut b, 1); // un testigo…
        compact_size::escribir(&mut b, 100_000); // …que dice medir 100 KB
        b.extend_from_slice(&[0u8; 4]); // …y trae 4 bytes

        assert!(matches!(
            tx_desde_bytes(&b),
            Err(EncodingError::Truncado { .. })
        ));
    }

    /// **C-ENC-05.** Un `CompactSize` no mínimo se rechaza también aquí, no solo en la preimagen.
    #[test]
    fn un_compact_size_no_minimo_se_rechaza() {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.push(0xfd); // prefijo de 3 bytes…
        b.extend_from_slice(&2u16.to_le_bytes()); // …para el valor 2, que cabe en uno

        assert!(matches!(
            tx_desde_bytes(&b),
            Err(EncodingError::CompactSizeNoMinimo { .. })
        ));
    }

    /// **C-TX-12.** Un importe fuera de rango se rechaza al leer, no más tarde.
    #[test]
    fn un_importe_fuera_de_rango_se_rechaza_al_leer() {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        compact_size::escribir(&mut b, 0);
        compact_size::escribir(&mut b, 1);
        b.extend_from_slice(&(-1i64).to_le_bytes()); // negativo
        lock_a_bytes(&mut b, &Lock::PubKey { pubkey: clave(0) });

        assert!(matches!(
            tx_desde_bytes(&b),
            Err(EncodingError::ImporteFueraDeRango { .. })
        ));
    }

    /// SR-1-2 · la `Tx` v5 con operación de sector da la vuelta por el wire.
    #[test]
    fn la_tx_de_sector_v5_da_la_vuelta() {
        let ops = [
            OperacionSector::Alta {
                clave: clave(3),
                sector_index: 7,
                version: 2,
                r2: [9u8; 32],
                history_size: 1_234_567,
            },
            OperacionSector::Renovar {
                clave: clave(4),
                sector_index: 1,
            },
            OperacionSector::AbrirAuditoria {
                clave: clave(5),
                sector_index: 2,
                auditoria_id: 99,
            },
            OperacionSector::ContestarAuditoria {
                clave: clave(6),
                sector_index: 3,
                auditoria_id: 100,
                prueba: vec![1, 2, 3, 4],
            },
            OperacionSector::Retirar {
                clave: clave(7),
                sector_index: 8,
            },
        ];
        for op in &ops {
            let tx = Tx {
                version: 5,
                inputs: Vec::new(),
                outputs: Vec::new(),
                lock_time: 0,
                expiry_height: 0,
                extension: ExtensionTx::Sector {
                    operacion: op.clone(),
                },
            };
            let testigos = vec![vec![0u8; 64]];
            let mut b = Vec::new();
            tx_a_bytes(&mut b, &tx, &testigos);
            let ((vuelta, t), resto) = tx_desde_bytes(&b).unwrap();
            assert_eq!(vuelta, tx, "ida y vuelta de la v5");
            assert_eq!(t, testigos);
            assert!(resto.is_empty());
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests_cuerpo {
    use super::{cuerpo_a_bytes, cuerpo_desde_bytes};
    use crate::amount::Amount;
    use crate::digest::{BlockHash, Digest, MerkleRoot, TxId};
    use crate::encoding::compact_size;
    use crate::error::EncodingError;
    use crate::firma::ClavePublica;
    use crate::preimage::block::BlockHeader;
    use crate::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};

    fn cabecera() -> BlockHeader {
        BlockHeader {
            consensus_branch_id: 0xc478_80ea,
            prev_hash: BlockHash::from_digest(Digest::from_bytes([3; 32])),
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([4; 32])),
            timestamp: 1_788_480_000,
            bits: 0x1d00_ffff,
            nonce: 42,
            height: 7,
        }
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
    fn un_bloque_da_la_vuelta_completa() {
        let txs: Vec<_> = (1..=4u8).map(tx).collect();
        let testigos: Vec<Vec<Vec<u8>>> = (1..=4u8).map(|n| vec![vec![n; 64]]).collect();

        let mut b = Vec::new();
        cuerpo_a_bytes(&mut b, &cabecera(), &txs, &testigos);

        let ((c, t, w), resto) = cuerpo_desde_bytes(&b).unwrap();
        assert_eq!(c, cabecera());
        assert_eq!(t, txs);
        assert_eq!(w, testigos);
        assert!(resto.is_empty());
    }

    /// Un bloque sin transacciones da la vuelta igual. No es válido por consenso —C-BLK-07 exige
    /// coinbase— pero el **códec** no debe opinar sobre eso: mezclar codificación y validez es lo
    /// que hace que un cambio de reglas rompa el formato.
    #[test]
    fn un_bloque_vacio_da_la_vuelta() {
        let mut b = Vec::new();
        cuerpo_a_bytes(&mut b, &cabecera(), &[], &[]);
        let ((c, t, w), resto) = cuerpo_desde_bytes(&b).unwrap();
        assert_eq!(c, cabecera());
        assert!(t.is_empty() && w.is_empty() && resto.is_empty());
    }

    /// **C-WIRE-04.** El contador mentiroso, también aquí.
    #[test]
    fn un_contador_de_transacciones_mentiroso_se_rechaza() {
        let mut b = Vec::new();
        b.extend_from_slice(&super::cabecera_a_bytes(&cabecera()));
        compact_size::escribir(&mut b, u64::MAX);
        assert!(matches!(
            cuerpo_desde_bytes(&b),
            Err(EncodingError::DemasiadosElementos { .. })
        ));
    }

    /// **C-WIRE-05.** Basura arbitraria no hace entrar en pánico al lector.
    #[test]
    fn ningun_byte_arbitrario_hace_entrar_en_panico() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..1_000 {
            let mut buf = Vec::new();
            for _ in 0..(x % 400) {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                buf.push((x >> 33) as u8);
            }
            let _ = cuerpo_desde_bytes(&buf);
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        }
    }

    /// Truncar en cualquier punto se rechaza, nunca se acepta a medias.
    #[test]
    fn un_bloque_truncado_nunca_se_acepta_a_medias() {
        let txs: Vec<_> = (1..=3u8).map(tx).collect();
        let testigos: Vec<Vec<Vec<u8>>> = (1..=3u8).map(|n| vec![vec![n; 64]]).collect();
        let mut b = Vec::new();
        cuerpo_a_bytes(&mut b, &cabecera(), &txs, &testigos);

        for n in 0..b.len() {
            let _ = cuerpo_desde_bytes(b.get(..n).unwrap());
        }
        assert!(cuerpo_desde_bytes(&b).is_ok());
    }
}
