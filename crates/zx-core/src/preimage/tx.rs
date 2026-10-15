//! Árboles del txid, del sighash y del auth digest (SPEC §4.2, §4.3, §4.4).
//!
//! # La forma del árbol, y por qué
//!
//! Cada nodo es `H_d(etiqueta, concatenación de los hijos)`. Un sub-digest **vacío** es
//! `H_d(etiqueta, ⟨⟩)` — el hash con dominio de la cadena vacía — y **nunca** ceros (C-TX-04).
//! ZIP-143/243 usaban `uint256(0)` para los campos ausentes, con lo que "campo ausente" y "campo
//! cuyo hash dio cero" eran indistinguibles y **todos los ausentes colisionaban entre sí**.

use crate::digest::{AuthDigest, Digest, SigHash, TxId};
use crate::error::{EncodingError, ErrorFormaTx};
use crate::firma::{Firma, LONGITUD_FIRMA};
use crate::hash::{
    DomainTag, TAG_EVP_INCIDENTE, TAG_TX_AUTH, TAG_TXID_ALMACEN, TAG_TXID_EVP, TAG_TXID_GARANTIA,
    TAG_TXID_HEADER, TAG_TXID_INPUTS, TAG_TXID_OUTPUTS, TAG_TXID_PREVOUT, TAG_TXID_SECTOR,
    TAG_TXID_SEQUENCE, TAG_TXSIG_ALMACEN, TAG_TXSIG_AMOUNTS, TAG_TXSIG_GARANT, TAG_TXSIG_LOCKS,
    TAG_TXSIG_SECTOR, TAG_TXSIG_THIS_IN, h_d,
};
use crate::preimage::PreimageWriter;
use crate::preimage::dag::dag_header_a_bytes;
use crate::tx::{ExtensionTx, SpentOutput, Tx, TxOut};

/// Modo de firma (C-SIG-03). Conjunto **cerrado**: cualquier otro byte es inválido.
///
/// Los bits no definidos **MUST NOT** ignorarse. Aceptar `0x04` como si fuera `0x01` daría dos
/// codificaciones del mismo compromiso, que es maleabilidad.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HashType {
    /// Compromete todas las entradas y todas las salidas.
    All,
    /// Compromete las entradas, ninguna salida.
    None,
    /// Compromete las entradas y **solo** la salida del mismo índice.
    Single,
    /// `All`, comprometiendo solo la entrada que se firma.
    AllAnyoneCanPay,
    /// `None`, comprometiendo solo la entrada que se firma.
    NoneAnyoneCanPay,
    /// `Single`, comprometiendo solo la entrada que se firma.
    SingleAnyoneCanPay,
}

impl HashType {
    /// Decodifica el byte de `hash_type` (C-SIG-03).
    ///
    /// # Errores
    /// [`EncodingError::HashTypeInvalido`] para cualquier valor fuera del conjunto.
    pub const fn desde_byte(v: u8) -> Result<Self, EncodingError> {
        match v {
            0x01 => Ok(Self::All),
            0x02 => Ok(Self::None),
            0x03 => Ok(Self::Single),
            0x81 => Ok(Self::AllAnyoneCanPay),
            0x82 => Ok(Self::NoneAnyoneCanPay),
            0x83 => Ok(Self::SingleAnyoneCanPay),
            _ => Err(EncodingError::HashTypeInvalido { valor: v }),
        }
    }

    /// El byte canónico de este modo.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::All => 0x01,
            Self::None => 0x02,
            Self::Single => 0x03,
            Self::AllAnyoneCanPay => 0x81,
            Self::NoneAnyoneCanPay => 0x82,
            Self::SingleAnyoneCanPay => 0x83,
        }
    }

    /// ¿Compromete solo la entrada que se firma?
    #[must_use]
    pub const fn anyone_can_pay(self) -> bool {
        matches!(
            self,
            Self::AllAnyoneCanPay | Self::NoneAnyoneCanPay | Self::SingleAnyoneCanPay
        )
    }

    /// ¿Es un modo `SINGLE`?
    #[must_use]
    pub const fn single(self) -> bool {
        matches!(self, Self::Single | Self::SingleAnyoneCanPay)
    }

    /// ¿Es un modo `NONE`?
    #[must_use]
    pub const fn none(self) -> bool {
        matches!(self, Self::None | Self::NoneAnyoneCanPay)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §4.2 · Árbol del txid
// ─────────────────────────────────────────────────────────────────────────────

/// `H_d("ZZKTxIdHeader___", version ‖ lock_time ‖ expiry_height)`.
fn header_digest(tx: &Tx) -> Digest {
    let mut w = PreimageWriter::con_capacidad(12);
    w.u32(tx.version).u32(tx.lock_time).u32(tx.expiry_height);
    w.finish(TAG_TXID_HEADER)
}

/// `H_d("ZZKTxIdPrevout__", ⋃ᵢ (txid_i ‖ index_i))` — 36 bytes por entrada.
fn prevouts_digest(tx: &Tx) -> Digest {
    let mut w = PreimageWriter::con_capacidad(tx.inputs.len() * 36);
    // C-TX-05 · el orden de concatenación es el de índice, por construcción del bucle.
    for e in &tx.inputs {
        w.h32(e.outpoint.prev_txid.as_bytes())
            .u32(e.outpoint.prev_index);
    }
    w.finish(TAG_TXID_PREVOUT)
}

/// `H_d("ZZKTxIdSequence_", ⋃ᵢ sequence_i)` — 4 bytes por entrada.
fn sequence_digest(tx: &Tx) -> Digest {
    let mut w = PreimageWriter::con_capacidad(tx.inputs.len() * 4);
    for e in &tx.inputs {
        w.u32(e.sequence);
    }
    w.finish(TAG_TXID_SEQUENCE)
}

/// `H_d("ZZKTxIdOutputs__", ⋃ⱼ (value_j ‖ lock_j))` sobre las salidas dadas.
fn outputs_digest_de(salidas: &[TxOut]) -> Digest {
    let mut w = PreimageWriter::new();
    for s in salidas {
        w.i64(s.value.brek()).lock(&s.lock);
    }
    w.finish(TAG_TXID_OUTPUTS)
}

/// `H_d("ZZKTxIdInputs___", prevouts_digest ‖ sequence_digest)`.
fn inputs_digest(tx: &Tx) -> Digest {
    let mut w = PreimageWriter::con_capacidad(64);
    w.digest(&prevouts_digest(tx)).digest(&sequence_digest(tx));
    w.finish(TAG_TXID_INPUTS)
}

/// `extension_digest` de las versiones 2 y 3 (F-06, F-07, F-15, F-17):
/// `H_d("ZZKTxIdGarantia_", campos extra de F-15/F-17)`.
///
/// - v2: `tipo u8 ‖ clave 32 B ‖ importe u64 ‖ nonce u64` LE (F-15).
/// - v3: `clave 32 B ‖ importe u64 ‖ slot u64` LE (F-17).
/// - v1 (`Ninguna`): `None`; su `txid` queda byte a byte igual al de `9681061`.
///
/// Los campos se escriben aunque el `importe` sea `u64` (F-05); el `importe` de las salidas sigue
/// siendo `i64` (el árbol de `9681061`). Como `importe > 0`, los bytes no difieren.
fn extension_digest(tx: &Tx) -> Option<Digest> {
    match &tx.extension {
        ExtensionTx::Ninguna => None,
        ExtensionTx::Garantia {
            tipo,
            clave,
            importe,
            nonce,
        } => {
            let mut w = PreimageWriter::con_capacidad(1 + 32 + 8 + 8);
            w.u8(tipo.byte())
                .clave(clave)
                .u64(importe.brek() as u64)
                .u64(*nonce);
            Some(w.finish(TAG_TXID_GARANTIA))
        }
        ExtensionTx::CoinbasePost {
            clave,
            importe,
            slot,
        } => {
            let mut w = PreimageWriter::con_capacidad(32 + 8 + 8);
            w.clave(clave).u64(importe.brek() as u64).u64(*slot);
            Some(w.finish(TAG_TXID_GARANTIA))
        }
        // EV-03: `H_d("ZZKTxIdEvidencia", dag_header_a_bytes(H1) ‖ dag_header_a_bytes(H2))`.
        ExtensionTx::Evidencia { h1, h2 } => {
            let b1 = dag_header_a_bytes(h1);
            let b2 = dag_header_a_bytes(h2);
            let mut w = PreimageWriter::con_capacidad(b1.len() + b2.len());
            w.canonical(&b1).canonical(&b2);
            Some(w.finish(TAG_TXID_EVP))
        }
        // SR-1-2 · `H_d("ZZKTxIdSector__", bytes_canonicos(OperacionSector))`: la operación entera
        // queda comprometida por el `txid`. Se usa la forma cruda para que el compromiso sea
        // exactamente lo que transporta el wire; `validar_forma_tx` rechaza la operación si excede
        // el tope, así que un `tx` válido siempre cabe.
        ExtensionTx::Sector { operacion } => {
            let bytes = operacion.bytes_canonicos_crudos();
            Some(h_d(TAG_TXID_SECTOR, &bytes))
        }
        // PT-3bc · `H_d("ZZKTxIdAlmacen__", bytes_canonicos(OperacionAlmacenamiento))`.
        ExtensionTx::PruebaAlmacenamiento { operacion } => {
            let bytes = operacion.bytes_canonicos_crudos();
            Some(h_d(TAG_TXID_ALMACEN, &bytes))
        }
    }
}

/// `incident_id` de la identidad de una `EvidenceTx` (`EV-10`, `RAT-1`).
///
/// `H_d("ZZKEvpIncidente_", cbid ‖ public_key ‖ sector_index ‖ history_size ‖ chunk ‖ slot)`,
/// con todos los enteros en little-endian. La identidad es la de `C-EVP-01` más el
/// `consensus_branch_id` (RAT-1). Es un digest **opaco**: solo se compara por igualdad.
#[must_use]
pub fn incident_id_evidencia(
    cbid: u32,
    public_key: &[u8; 32],
    sector_index: u16,
    history_size: u64,
    chunk: &[u8; 32],
    slot: u64,
) -> Digest {
    let mut w = PreimageWriter::con_capacidad(4 + 32 + 2 + 8 + 32 + 8);
    w.u32(cbid)
        .h32(public_key)
        .u16(sector_index)
        .u64(history_size)
        .h32(chunk)
        .u64(slot);
    w.finish(TAG_EVP_INCIDENTE)
}

/// El **txid** (C-TX-01): solo datos de efecto, **sin firmas**.
///
/// Que excluya las firmas es lo que lo hace no maleable, y por tanto lo que permite construir una
/// transacción B que gasta salidas de A antes de que A esté minada — necesario para HTLC y canales
/// de pago.
///
/// `consensus_branch_id` entra en la etiqueta raíz (C-UPG-04): una transacción de una rama de
/// consenso no puede repetirse en otra.
///
/// Para v2/v3 se añade `extension_digest` al final (F-06). Para v1 no se añade nada.
#[must_use]
pub fn txid(tx: &Tx, consensus_branch_id: u32) -> TxId {
    let mut w = PreimageWriter::con_capacidad(128);
    w.digest(&header_digest(tx))
        .digest(&inputs_digest(tx))
        .digest(&outputs_digest_de(&tx.outputs));
    if let Some(ext) = extension_digest(tx) {
        w.digest(&ext);
    }
    TxId::from_digest(w.finish(DomainTag::raiz(consensus_branch_id)))
}

/// Mensaje de la **firma de aceptación** de v2 (F-08): `H_d("ZZKTxSigGarant__", txid(tx, CBID))`.
///
/// Es el mensaje Ed25519 que firma `clave` (la de la extensión de garantía). El `txid` ya
/// compromete todos los datos de efecto y el `CBID`; para retiro y liberación, que no tienen
/// entradas, es la única atadura disponible.
#[must_use]
pub fn mensaje_aceptacion(tx: &Tx, consensus_branch_id: u32) -> [u8; 32] {
    *h_d(TAG_TXSIG_GARANT, txid(tx, consensus_branch_id).as_bytes()).as_bytes()
}

/// Verifica la firma de aceptación de v2 (F-08) con las reglas ZIP-215 de [`crate::firma`].
///
/// `testigo_aceptacion` es el último testigo y **MUST** medir [`LONGITUD_FIRMA`] = 64 B.
///
/// # Errores
/// - [`ErrorFormaTx::ExtensionIncoherente`] si `tx` no es una v2 con extensión `Garantia`.
/// - [`ErrorFormaTx::TestigoAceptacionLongitud`] si el testigo no mide 64 B.
/// - [`ErrorFormaTx::Codificacion`] con [`EncodingError::FirmaInvalida`] si la firma no verifica.
pub fn verificar_aceptacion(
    tx: &Tx,
    testigo_aceptacion: &[u8],
    consensus_branch_id: u32,
) -> Result<(), ErrorFormaTx> {
    let ExtensionTx::Garantia { clave, .. } = &tx.extension else {
        return Err(ErrorFormaTx::ExtensionIncoherente {
            version: tx.version,
            esperada: "Garantia",
        });
    };

    let bytes: [u8; LONGITUD_FIRMA] =
        testigo_aceptacion
            .try_into()
            .map_err(|_| ErrorFormaTx::TestigoAceptacionLongitud {
                obtenidos: testigo_aceptacion.len(),
            })?;

    let firma = Firma::desde_bytes(bytes);
    let mensaje = mensaje_aceptacion(tx, consensus_branch_id);
    crate::firma::verificar(clave, &firma, &mensaje)?;
    Ok(())
}

/// Mensaje de la **firma de la operación de sector** (v5):
/// `H_d("ZZKTxSigSector__", txid(tx, CBID))`.
///
/// El `txid` incluye `H_d("ZZKTxIdSector__", bytes_canonicos(OperacionSector))`, así que la firma
/// compromete la operación de sector **entera**. La firma la produce `operacion.clave`.
#[must_use]
pub fn mensaje_sector(tx: &Tx, consensus_branch_id: u32) -> [u8; 32] {
    *h_d(TAG_TXSIG_SECTOR, txid(tx, consensus_branch_id).as_bytes()).as_bytes()
}

/// Verifica la firma Ed25519 de una operación de sector v5.
///
/// # Errores
/// - [`ErrorFormaTx::ExtensionIncoherente`] si `tx` no es una v5 con `ExtensionTx::Sector`.
/// - [`ErrorFormaTx::TestigoAceptacionLongitud`] si el testigo no mide [`LONGITUD_FIRMA`] = 64 B.
/// - [`ErrorFormaTx::Codificacion`] con [`crate::error::EncodingError::FirmaInvalida`] si no
///   verifica bajo `operacion.clave`.
pub fn verificar_firma_sector(
    tx: &Tx,
    testigo: &[u8],
    consensus_branch_id: u32,
) -> Result<(), ErrorFormaTx> {
    let ExtensionTx::Sector { operacion } = &tx.extension else {
        return Err(ErrorFormaTx::ExtensionIncoherente {
            version: tx.version,
            esperada: "Sector",
        });
    };
    let bytes: [u8; LONGITUD_FIRMA] =
        testigo
            .try_into()
            .map_err(|_| ErrorFormaTx::TestigoAceptacionLongitud {
                obtenidos: testigo.len(),
            })?;
    let firma = Firma::desde_bytes(bytes);
    let mensaje = mensaje_sector(tx, consensus_branch_id);
    crate::firma::verificar(&operacion.clave(), &firma, &mensaje)?;
    Ok(())
}

/// Mensaje de la **firma de la operación de almacenamiento** (v6):
/// `H_d("ZZKTxSigAlmacen_", txid(tx, CBID))`.
///
/// El `txid` incluye `H_d("ZZKTxIdAlmacen__", bytes_canonicos(OperacionAlmacenamiento))`, así que la
/// firma compromete la operación entera. La firma la produce `operacion.clave`.
#[must_use]
pub fn mensaje_almacenamiento(tx: &Tx, consensus_branch_id: u32) -> [u8; 32] {
    *h_d(TAG_TXSIG_ALMACEN, txid(tx, consensus_branch_id).as_bytes()).as_bytes()
}

/// Verifica la firma Ed25519 de una operación de almacenamiento v6.
///
/// # Errores
/// - [`ErrorFormaTx::ExtensionIncoherente`] si `tx` no es una v6 con `PruebaAlmacenamiento`.
/// - [`ErrorFormaTx::TestigoAceptacionLongitud`] si el testigo no mide [`LONGITUD_FIRMA`] = 64 B.
/// - [`ErrorFormaTx::Codificacion`] con [`crate::error::EncodingError::FirmaInvalida`] si no
///   verifica bajo `operacion.clave`.
pub fn verificar_firma_almacenamiento(
    tx: &Tx,
    testigo: &[u8],
    consensus_branch_id: u32,
) -> Result<(), ErrorFormaTx> {
    let ExtensionTx::PruebaAlmacenamiento { operacion } = &tx.extension else {
        return Err(ErrorFormaTx::ExtensionIncoherente {
            version: tx.version,
            esperada: "PruebaAlmacenamiento",
        });
    };
    let bytes: [u8; LONGITUD_FIRMA] =
        testigo
            .try_into()
            .map_err(|_| ErrorFormaTx::TestigoAceptacionLongitud {
                obtenidos: testigo.len(),
            })?;
    let firma = Firma::desde_bytes(bytes);
    let mensaje = mensaje_almacenamiento(tx, consensus_branch_id);
    crate::firma::verificar(&operacion.clave(), &firma, &mensaje)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// §4.3 · Árbol del sighash
// ─────────────────────────────────────────────────────────────────────────────

/// `H_d("ZZKTxSigAmounts_", ⋃ᵢ value_i)` sobre **las salidas gastadas** (C-SIG-02).
fn amounts_digest(gastadas: &[SpentOutput]) -> Digest {
    let mut w = PreimageWriter::con_capacidad(gastadas.len() * 8);
    for s in gastadas {
        w.i64(s.value.brek());
    }
    w.finish(TAG_TXSIG_AMOUNTS)
}

/// `H_d("ZZKTxSigLocks___", ⋃ᵢ lock_i)` sobre **las salidas gastadas** (C-SIG-02).
fn scripts_digest(gastadas: &[SpentOutput]) -> Digest {
    let mut w = PreimageWriter::new();
    for s in gastadas {
        w.lock(&s.lock);
    }
    w.finish(TAG_TXSIG_LOCKS)
}

/// `H_d("ZZKTxSigThisIn__", prevout(36) ‖ value(8) ‖ lock ‖ sequence(4))`.
fn this_input_digest(tx: &Tx, gastadas: &[SpentOutput], k: usize) -> Result<Digest, EncodingError> {
    let fuera = || EncodingError::IndiceDeEntradaFueraDeRango {
        indice: k,
        entradas: tx.inputs.len(),
    };
    let entrada = tx.inputs.get(k).ok_or_else(fuera)?;
    let gastada = gastadas.get(k).ok_or_else(fuera)?;

    let mut w = PreimageWriter::new();
    w.h32(entrada.outpoint.prev_txid.as_bytes())
        .u32(entrada.outpoint.prev_index)
        .i64(gastada.value.brek())
        .lock(&gastada.lock)
        .u32(entrada.sequence);
    Ok(w.finish(TAG_TXSIG_THIS_IN))
}

/// El digest de salidas que corresponde a este `hash_type` (C-SIG-05).
///
/// - ni `SINGLE` ni `NONE` → todas las salidas
/// - `SINGLE` → solo la salida del índice de la entrada firmada
/// - `NONE` → hash con dominio del vacío
fn outputs_digest_modulado(tx: &Tx, ht: HashType, k: usize) -> Result<Digest, EncodingError> {
    if ht.none() {
        return Ok(outputs_digest_de(&[]));
    }
    if ht.single() {
        // C-SIG-04: SIGHASH_SINGLE sin salida correspondiente MUST fallar. Sin esta regla esas
        // entradas usarían de facto SIGHASH_NONE, en silencio y de forma engañosa.
        let salida = tx.outputs.get(k).ok_or(EncodingError::SingleSinSalida {
            indice: k,
            salidas: tx.outputs.len(),
        })?;
        return Ok(outputs_digest_de(core::slice::from_ref(salida)));
    }
    Ok(outputs_digest_de(&tx.outputs))
}

/// `inputs_sig_digest(k)` — 193 bytes de contenido (C-SIG-01).
fn inputs_sig_digest(
    tx: &Tx,
    gastadas: &[SpentOutput],
    ht: HashType,
    k: usize,
    outputs_mod: &Digest,
) -> Result<Digest, EncodingError> {
    // C-SIG-05: con ANYONECANPAY, los cuatro digests que abarcan "todas las entradas" pasan a ser
    // el hash con dominio del vacío. Nótese que `sequence_digest` se incluye entero incluso con
    // SINGLE o NONE — solo ANYONECANPAY lo vacía.
    let (prevouts, amounts, scripts, sequence) = if ht.anyone_can_pay() {
        let vacio = Tx {
            inputs: Vec::new(),
            ..tx.clone()
        };
        (
            prevouts_digest(&vacio),
            amounts_digest(&[]),
            scripts_digest(&[]),
            sequence_digest(&vacio),
        )
    } else {
        (
            prevouts_digest(tx),
            amounts_digest(gastadas),
            scripts_digest(gastadas),
            sequence_digest(tx),
        )
    };

    let mut w = PreimageWriter::con_capacidad(1 + 6 * 32);
    w.u8(ht.byte())
        .digest(&prevouts)
        .digest(&amounts)
        .digest(&scripts)
        .digest(&sequence)
        .digest(outputs_mod)
        .digest(&this_input_digest(tx, gastadas, k)?);
    Ok(w.finish(TAG_TXID_INPUTS))
}

/// El `signature_digest` de la entrada `k` (C-SIG-01).
///
/// `gastadas[i]` **MUST** ser la salida que consume `tx.inputs[i]`, en el mismo orden.
///
/// # ⚠️ Lectura de C-SIG-01 que este código fija
///
/// C-SIG-01 dice que el sighash es «idéntico al txid salvo que `inputs_digest` se sustituye por
/// `inputs_sig_digest`». Leído al pie de la letra, el `outputs_digest` **de la raíz** sería el de
/// todas las salidas, sin modular. Aquí se usa el **modulado**, en la raíz y dentro de
/// `inputs_sig_digest`, porque con la lectura literal `SIGHASH_NONE` y `SIGHASH_SINGLE` **no
/// harían nada**: la firma seguiría comprometiendo todas las salidas por la rama de la raíz, y la
/// tabla de C-SIG-05 sería letra muerta.
///
/// Bajo `SIGHASH_ALL` —el caso normal— ambas lecturas coinciden byte a byte. Anotado como **P-021**
/// para confirmación humana. Ver `SPEC.md` §4.3.
///
/// # Errores
/// - [`EncodingError::IndiceDeEntradaFueraDeRango`] si `k` no indexa una entrada.
/// - [`EncodingError::SingleSinSalida`] si es `SINGLE` y no hay salida en el índice `k` (C-SIG-04).
pub fn sighash(
    tx: &Tx,
    gastadas: &[SpentOutput],
    ht: HashType,
    k: usize,
    consensus_branch_id: u32,
) -> Result<SigHash, EncodingError> {
    let outputs_mod = outputs_digest_modulado(tx, ht, k)?;
    let inputs_sig = inputs_sig_digest(tx, gastadas, ht, k, &outputs_mod)?;

    let mut w = PreimageWriter::con_capacidad(96);
    w.digest(&header_digest(tx))
        .digest(&inputs_sig)
        .digest(&outputs_mod);
    Ok(SigHash::from_digest(
        w.finish(DomainTag::raiz(consensus_branch_id)),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// §4.4 · Auth digest
// ─────────────────────────────────────────────────────────────────────────────

/// `auth_digest = H_d("ZZKTxAuthHash___", ⋃ᵢ (CompactSize(len) ‖ witness_bytes))` (C-TX-06).
///
/// Junto con el txid forma el `wtxid` de 64 bytes que identifica la transacción en la red
/// (C-TX-03). El txid solo compromete los datos de efecto; esto compromete la autorización.
#[must_use]
pub fn auth_digest(testigos: &[Vec<u8>]) -> AuthDigest {
    let mut w = PreimageWriter::new();
    for t in testigos {
        w.compact_size(t.len() as u64);
        for b in t {
            w.u8(*b);
        }
    }
    AuthDigest::from_digest(w.finish(TAG_TX_AUTH))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{HashType, auth_digest, sighash, txid};
    use crate::amount::Amount;
    use crate::digest::{Digest, TxId};
    use crate::error::EncodingError;
    use crate::firma::ClavePublica;
    use crate::preimage::PreimageWriter;
    use crate::tx::{ExtensionTx, Lock, OutPoint, SpentOutput, Tx, TxIn, TxOut};

    const CBID: u32 = 0xc478_80ea;

    fn clave(n: u8) -> ClavePublica {
        ClavePublica::desde_bytes([n; 32])
    }

    fn entrada(n: u8, seq: u32) -> TxIn {
        TxIn {
            outpoint: OutPoint {
                prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
                prev_index: u32::from(n),
            },
            sequence: seq,
        }
    }

    fn salida(brek: i64, k: u8) -> TxOut {
        TxOut {
            value: Amount::nuevo(brek).unwrap(),
            lock: Lock::PubKey { pubkey: clave(k) },
        }
    }

    fn gastada(brek: i64, k: u8) -> SpentOutput {
        SpentOutput {
            value: Amount::nuevo(brek).unwrap(),
            lock: Lock::PubKey { pubkey: clave(k) },
        }
    }

    fn tx_ejemplo() -> (Tx, Vec<SpentOutput>) {
        let tx = Tx {
            version: 1,
            inputs: vec![entrada(1, 0xFFFF_FFFF), entrada(2, 0)],
            outputs: vec![salida(50_000, 10), salida(25_000, 11)],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let gastadas = vec![gastada(40_000, 20), gastada(40_000, 21)];
        (tx, gastadas)
    }

    #[test]
    fn el_txid_es_determinista() {
        let (tx, _) = tx_ejemplo();
        assert_eq!(txid(&tx, CBID), txid(&tx, CBID));
    }

    /// C-UPG-04: una transacción de una rama de consenso no se repite en otra.
    #[test]
    fn el_txid_depende_del_branch_id() {
        let (tx, _) = tx_ejemplo();
        assert_ne!(txid(&tx, CBID), txid(&tx, CBID.wrapping_add(1)));
    }

    /// Cualquier cambio en un dato de efecto cambia el txid. Si alguno no lo hiciera, ese campo no
    /// estaría comprometido y sería maleable.
    #[test]
    fn cada_campo_de_efecto_entra_en_el_txid() {
        let (base, _) = tx_ejemplo();
        let original = txid(&base, CBID);

        let mut v = base.clone();
        v.version = 2;
        assert_ne!(txid(&v, CBID), original, "version");

        let mut v = base.clone();
        v.lock_time = 1;
        assert_ne!(txid(&v, CBID), original, "lock_time");

        let mut v = base.clone();
        v.expiry_height = 1;
        assert_ne!(txid(&v, CBID), original, "expiry_height");

        let mut v = base.clone();
        v.inputs.first_mut().unwrap().sequence = 7;
        assert_ne!(txid(&v, CBID), original, "sequence");

        let mut v = base.clone();
        v.inputs.first_mut().unwrap().outpoint.prev_index = 99;
        assert_ne!(txid(&v, CBID), original, "prev_index");

        let mut v = base.clone();
        v.outputs.first_mut().unwrap().value = Amount::nuevo(1).unwrap();
        assert_ne!(txid(&v, CBID), original, "value de salida");

        let mut v = base.clone();
        v.outputs.first_mut().unwrap().lock = Lock::PubKey { pubkey: clave(99) };
        assert_ne!(txid(&v, CBID), original, "lock de salida");

        // El orden importa: reordenar las salidas es otra transacción.
        let mut v = base;
        v.outputs.reverse();
        assert_ne!(txid(&v, CBID), original, "orden de las salidas");
    }

    #[test]
    fn el_sighash_cambia_por_entrada() {
        let (tx, g) = tx_ejemplo();
        let a = sighash(&tx, &g, HashType::All, 0, CBID).unwrap();
        let b = sighash(&tx, &g, HashType::All, 1, CBID).unwrap();
        assert_ne!(a, b, "cada entrada firma su propio digest");
    }

    #[test]
    fn el_sighash_cambia_por_modo() {
        let (tx, g) = tx_ejemplo();
        let modos = [
            HashType::All,
            HashType::None,
            HashType::Single,
            HashType::AllAnyoneCanPay,
            HashType::NoneAnyoneCanPay,
            HashType::SingleAnyoneCanPay,
        ];
        let mut vistos: Vec<_> = Vec::new();
        for m in modos {
            let d = sighash(&tx, &g, m, 0, CBID).unwrap();
            assert!(
                !vistos.contains(&d),
                "dos modos producen el mismo sighash: {m:?}"
            );
            vistos.push(d);
        }
    }

    /// C-SIG-05: el importe de la salida **gastada** entra en el sighash aunque no esté en el txid.
    /// Es lo que permite a un firmante offline comprobar el fee real.
    #[test]
    fn el_importe_gastado_entra_en_el_sighash_pero_no_en_el_txid() {
        let (tx, g) = tx_ejemplo();
        let mut g2 = g.clone();
        g2.first_mut().unwrap().value = Amount::nuevo(999_999).unwrap();

        assert_eq!(
            txid(&tx, CBID),
            txid(&tx, CBID),
            "el txid no ve las gastadas"
        );
        assert_ne!(
            sighash(&tx, &g, HashType::All, 0, CBID).unwrap(),
            sighash(&tx, &g2, HashType::All, 0, CBID).unwrap(),
            "C-SIG-02: el importe gastado MUST estar comprometido"
        );
    }

    /// C-SIG-04. Sin esta regla la entrada usaría de facto `SIGHASH_NONE`, en silencio.
    #[test]
    fn single_sin_salida_correspondiente_falla() {
        let tx = Tx {
            version: 1,
            inputs: vec![entrada(1, 0), entrada(2, 0)],
            outputs: vec![salida(10, 5)], // solo una salida, dos entradas
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let g = vec![gastada(10, 6), gastada(10, 7)];

        assert!(
            sighash(&tx, &g, HashType::Single, 0, CBID).is_ok(),
            "índice 0 sí tiene salida"
        );
        let e = sighash(&tx, &g, HashType::Single, 1, CBID).unwrap_err();
        assert!(
            matches!(
                e,
                EncodingError::SingleSinSalida {
                    indice: 1,
                    salidas: 1
                }
            ),
            "se esperaba SingleSinSalida, salió {e:?}"
        );
    }

    #[test]
    fn un_indice_de_entrada_invalido_falla() {
        let (tx, g) = tx_ejemplo();
        assert!(sighash(&tx, &g, HashType::All, 99, CBID).is_err());
    }

    /// C-SIG-03: conjunto cerrado. Los bits no definidos MUST NOT ignorarse.
    #[test]
    fn el_hash_type_es_un_conjunto_cerrado() {
        for v in [0x01, 0x02, 0x03, 0x81, 0x82, 0x83] {
            let ht = HashType::desde_byte(v).unwrap();
            assert_eq!(ht.byte(), v, "ida y vuelta del byte");
        }
        for v in [0x00, 0x04, 0x05, 0x80, 0x84, 0xFF] {
            assert!(
                HashType::desde_byte(v).is_err(),
                "{v:#04x} debería rechazarse"
            );
        }
    }

    /// Con `ANYONECANPAY`, cambiar **otra** entrada no debe alterar el sighash de la que se firma.
    /// Es precisamente lo que el modo promete.
    #[test]
    fn anyonecanpay_aisla_la_entrada_firmada() {
        let (base, g) = tx_ejemplo();
        let firmado = sighash(&base, &g, HashType::AllAnyoneCanPay, 0, CBID).unwrap();

        let mut otra = base.clone();
        otra.inputs.get_mut(1).unwrap().sequence = 0xDEAD_BEEF;
        let tras_cambio = sighash(&otra, &g, HashType::AllAnyoneCanPay, 0, CBID).unwrap();
        assert_eq!(
            firmado, tras_cambio,
            "ANYONECANPAY no debe ver las otras entradas"
        );

        // Sin ANYONECANPAY, ese mismo cambio sí tiene que verse.
        assert_ne!(
            sighash(&base, &g, HashType::All, 0, CBID).unwrap(),
            sighash(&otra, &g, HashType::All, 0, CBID).unwrap(),
            "SIGHASH_ALL sí compromete todas las entradas"
        );
    }

    /// El auth digest distingue testigos distintos, y el prefijo de longitud impide que dos
    /// reparticiones distintas de los mismos bytes colisionen.
    #[test]
    fn el_auth_digest_delimita_los_testigos() {
        let a = auth_digest(&[vec![1, 2], vec![3]]);
        let b = auth_digest(&[vec![1], vec![2, 3]]);
        assert_ne!(a, b, "C-TX-06: CompactSize(len) es lo que delimita");
        assert_ne!(
            auth_digest(&[]),
            auth_digest(&[vec![]]),
            "cero testigos ≠ un testigo vacío"
        );
    }

    /// La codificación de `Lock` es autodelimitada: dentro de una concatenación, dos secuencias
    /// distintas de locks no pueden producir los mismos bytes. Sin el `CompactSize` de la lista de
    /// `MultiSig` esto no se sostendría.
    #[test]
    fn la_codificacion_de_lock_es_autodelimitada() {
        let mut w1 = PreimageWriter::new();
        w1.lock(&Lock::multisig(1, vec![clave(1), clave(2)]).unwrap());
        let uno = w1.bytes().to_vec();

        let mut w2 = PreimageWriter::new();
        w2.lock(&Lock::multisig(1, vec![clave(1)]).unwrap());
        w2.lock(&Lock::PubKey { pubkey: clave(2) });
        let dos = w2.bytes().to_vec();

        assert_ne!(
            uno, dos,
            "un MultiSig de 2 claves no puede parecerse a MultiSig+PubKey"
        );
    }

    /// Las tres variantes de `Lock` se distinguen por el discriminante, aunque el resto coincida.
    #[test]
    fn las_variantes_de_lock_no_colisionan() {
        let mut vistos: Vec<Vec<u8>> = Vec::new();
        let locks = [
            Lock::PubKey { pubkey: clave(1) },
            Lock::multisig(1, vec![clave(1)]).unwrap(),
            Lock::Htlc {
                hash: [1u8; 32],
                receiver: clave(1),
                sender: clave(1),
                timeout: 0,
            },
        ];
        for l in &locks {
            let mut w = PreimageWriter::new();
            w.lock(l);
            let b = w.bytes().to_vec();
            assert!(!vistos.contains(&b), "colisión de codificación: {l:?}");
            vistos.push(b);
        }
    }
}
