//! SHA3-256 con separación de dominio (SPEC §3).
//!
//! # Por qué casi nada de aquí es público
//!
//! La confusión más cara que se puede cometer en esta base de código es **hashear la serialización
//! de wire (Cap'n Proto) en lugar de la preimagen canónica de §4**. Las dos son secuencias de bytes
//! del mismo objeto; producen digests distintos; y el resultado sería un split de cadena silencioso.
//!
//! La defensa no es una convención ni un comentario: es la **ausencia de una firma invocable**.
//! [`h_d`] es `pub(crate)`, así que ningún crate de fuera puede llamarlo — ni queriendo. Y dentro de
//! `zx-core`, la única forma de alimentarlo es [`crate::preimage`], que se construye campo a campo
//! desde tipos de dominio y no acepta un buffer ya serializado.
//!
//! `zx-core` tampoco depende de `capnp`. No puede ni nombrar un tipo de wire.
//!
//! # Por qué un prefijo basta
//!
//! BLAKE2b tiene un campo de personalización en su *parameter block*; SHA3-256 no. Así que el
//! dominio va como **prefijo explícito de longitud fija** (C-HASH-04):
//!
//! ```text
//! H_d(tag, m) := SHA3-256( tag ‖ m )
//! ```
//!
//! Con **todas** las etiquetas midiendo exactamente 16 bytes, ninguna puede ser prefijo propio de
//! otra, así que la construcción es inyectiva sea cual sea la longitud de `m`. La longitud fija es
//! lo que hace el argumento, no la elección de caracteres.
//!
//! Y SHA-3 **no es vulnerable a extensión de longitud** —a diferencia de SHA-2—, así que el prefijo
//! simple es seguro sin necesidad de una construcción tipo HMAC. FIPS 202 §A.1 lo declara, y la
//! razón estructural es la esponja: la salida se exprime solo del *rate*, y los 512 bits de
//! *capacity* nunca se revelan.

// Todo este módulo lo consume `crate::preimage` (SPEC §4), que llega en la siguiente tanda. Hasta
// entonces solo lo tocan los tests. El `allow` es temporal y debe **retirarse** cuando `preimage`
// exista: si para entonces algo sigue sin usarse, es que sobra.
#![allow(
    dead_code,
    reason = "lo consumirá crate::preimage (§4), aún sin escribir"
)]

use sha3::{Digest as _, Sha3_256};

use crate::digest::Digest;

/// Etiqueta de dominio: exactamente 16 bytes (C-HASH-04).
///
/// No hay constructor que acepte una longitud arbitraria. Las etiquetas se declaran con literales
/// `*b"..."` de tipo `[u8; 16]`, de modo que **una etiqueta de longitud incorrecta no compila**.
/// La regla del SPEC la impone el compilador, no una comprobación en tiempo de ejecución.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct DomainTag([u8; 16]);

impl DomainTag {
    /// Etiqueta fija, íntegramente ASCII.
    pub(crate) const fn fija(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Etiqueta raíz del txid y del sighash: 12 bytes ASCII + `CONSENSUS_BRANCH_ID` en `u32` LE.
    ///
    /// Es la única etiqueta que no es ASCII puro. Lleva el identificador de rama para que una firma
    /// válida en una rama de consenso sea inválida en cualquier otra — la protección de repetición
    /// de C-UPG-04, copiada de ZIP-244.
    ///
    /// El argumento de inyectividad sigue en pie, y se verificó byte a byte: **las demás
    /// etiquetas fijas divergen de `ZZKTxIdHash_` dentro de los primeros 12 bytes**, antes de que
    /// empiece la región del branch ID. Ninguno de los 2³² valores posibles puede provocar una
    /// colisión.
    ///
    /// ⚠️ Invariante que hay que vigilar al añadir etiquetas nuevas (C-HASH-05): **ninguna etiqueta
    /// futura puede empezar por los 12 bytes literales `ZZKTxIdHash_`**. Si alguna lo hiciera,
    /// existiría un branch ID que colisionaría con ella.
    pub(crate) const fn raiz(consensus_branch_id: u32) -> Self {
        let p = *b"ZZKTxIdHash_";
        let c = consensus_branch_id.to_le_bytes();
        Self([
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], c[0], c[1],
            c[2], c[3],
        ])
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Hash con dominio: `SHA3-256(tag ‖ m)` (C-HASH-04).
///
/// `pub(crate)` **a propósito y de forma no negociable** — ver el módulo. Ningún crate externo
/// puede alcanzar esta función, así que no existe ningún camino por el que unos bytes de wire
/// acaben hasheados como si fueran la preimagen canónica.
pub(crate) fn h_d(tag: DomainTag, msg: &[u8]) -> Digest {
    let mut hasher = Sha3_256::new();
    hasher.update(tag.as_bytes());
    hasher.update(msg);
    Digest::from_bytes(hasher.finalize().into())
}

/// SHA3-256 desnudo, sin dominio.
///
/// Solo para lo que la propia especificación define sin etiqueta: la preimagen de un HTLC
/// (C-TX-09) y los prefijos derivados de red (C-NET-01). **No** se usa para nada que entre en un
/// txid, un sighash o un hash de bloque — eso pasa siempre por [`h_d`].
///
/// ⚠️ **Ya no incluye el hash de clave pública de una dirección.** Lo incluía cuando ZEROX usaba
/// P2KH; desde **P-020** la dirección lleva la clave **en claro** y no se hashea nada
/// (C-ENC-07). Se deja escrito porque un comentario obsoleto es peor que ninguno: hace creer que
/// alguien lo comprobó, y una segunda implementación que lo leyera podría reintroducir P2KH.
#[allow(
    dead_code,
    reason = "lo usa la verificación de HTLC (C-TX-09) vía sha3_256_publico"
)]
pub(crate) fn sha3_256(msg: &[u8]) -> Digest {
    Digest::from_bytes(Sha3_256::digest(msg).into())
}

/// SHA3-256 desnudo, expuesto **solo** para lo que el SPEC define sin etiqueta de dominio: la
/// preimagen de un HTLC (C-TX-09) y la derivación de los prefijos mágicos de red (C-NET-01).
///
/// **No** para direcciones: desde P-020 no se hashea la clave pública (C-ENC-07).
///
/// No es una puerta trasera a [`h_d`]: no acepta etiqueta, así que no puede producir un digest con
/// dominio. Un digest de consenso —txid, sighash, hash de bloque— **MUST** salir de
/// [`crate::preimage`], nunca de aquí.
#[must_use]
pub fn sha3_256_publico(msg: &[u8]) -> Digest {
    sha3_256(msg)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tabla de etiquetas de dominio — SPEC §4.5, C-HASH-06.
//
// Son TODAS las de ZEROX v1.0. Añadir una es un cambio de consenso: exige pasar por C-HASH-05,
// y comprobar además la invariante del prefijo documentada en `DomainTag::raiz`.
//
// Cada literal es de tipo [u8; 16]: si alguien escribe una etiqueta de 15 o 17 bytes, no compila.
// ─────────────────────────────────────────────────────────────────────────────

/// §4.2 · cabecera de la transacción.
pub(crate) const TAG_TXID_HEADER: DomainTag = DomainTag::fija(*b"ZZKTxIdHeader___");
/// §4.2 · entradas, y §4.3 entradas-para-firma.
pub(crate) const TAG_TXID_INPUTS: DomainTag = DomainTag::fija(*b"ZZKTxIdInputs___");
/// §4.2 · outpoints consumidos.
pub(crate) const TAG_TXID_PREVOUT: DomainTag = DomainTag::fija(*b"ZZKTxIdPrevout__");
/// §4.2 · campos `sequence`.
pub(crate) const TAG_TXID_SEQUENCE: DomainTag = DomainTag::fija(*b"ZZKTxIdSequence_");
/// §4.2 · salidas creadas.
pub(crate) const TAG_TXID_OUTPUTS: DomainTag = DomainTag::fija(*b"ZZKTxIdOutputs__");
/// §4.3 · importes de las salidas gastadas.
pub(crate) const TAG_TXSIG_AMOUNTS: DomainTag = DomainTag::fija(*b"ZZKTxSigAmounts_");
/// §4.3 · condiciones de bloqueo de las salidas gastadas.
pub(crate) const TAG_TXSIG_LOCKS: DomainTag = DomainTag::fija(*b"ZZKTxSigLocks___");
/// §4.3 · la entrada concreta que se está firmando.
pub(crate) const TAG_TXSIG_THIS_IN: DomainTag = DomainTag::fija(*b"ZZKTxSigThisIn__");
/// §4.4 · auth digest.
pub(crate) const TAG_TX_AUTH: DomainTag = DomainTag::fija(*b"ZZKTxAuthHash___");
/// §6.3 · nodos internos del árbol de Merkle.
pub(crate) const TAG_BLK_MERKLE: DomainTag = DomainTag::fija(*b"ZZKBlkMerkle____");
/// §6.2 · hash de cabecera. Desde el formato DAG identifica la cabecera completa (C-HDR-09); la
/// preimagen del PoW de hash único pertenece a la base lineal retirada.
pub(crate) const TAG_BLK_HEADER: DomainTag = DomainTag::fija(*b"ZZKBlkHeader____");
/// §6.2 · `pre_hash`: el mensaje que firma el sello (C-HDR-03).
pub(crate) const TAG_BLK_PRE_HASH: DomainTag = DomainTag::fija(*b"ZZKBlkPreHash___");
/// §6.1 · compromiso completo del cuerpo, efectos **y** autorización.
pub(crate) const TAG_BLK_BODY_HASH: DomainTag = DomainTag::fija(*b"ZZKBlkBodyHash__");
/// §7.1.4 · identificador de flujo del PoT (`C-FLU-10`). Es la etiqueta de `H_flujo`.
pub(crate) const TAG_FLOW_ID: DomainTag = DomainTag::fija(*b"ZZKFlowId_______");
/// §7.1.3 · etiqueta del génesis del flujo (`C-FLU-06`). Va **dentro del mensaje** de `H_flujo`
/// junto al `block_hash` del génesis; no es la etiqueta de dominio del hash.
pub(crate) const TAG_FLOW_GENESIS: DomainTag = DomainTag::fija(*b"ZZKFlowGenesis__");
/// F-06 · sub-digest de la extensión de v2/v3 (`extension_digest`).
///
/// Añadida en W02 a la tabla cerrada: cambiarla es un cambio de consenso (C-HASH-05).
pub(crate) const TAG_TXID_GARANTIA: DomainTag = DomainTag::fija(*b"ZZKTxIdGarantia_");
/// F-08 · mensaje de la firma de aceptación de v2: `H_d("ZZKTxSigGarant__", txid)`.
pub(crate) const TAG_TXSIG_GARANT: DomainTag = DomainTag::fija(*b"ZZKTxSigGarant__");
/// SL-4a / EV-03 · sub-digest de la extensión de la `EvidenceTx` v4 (`extension_digest`).
///
/// Añadida por SL-4a: cambiar su valor es un cambio de consenso (C-HASH-05). No comparte los 12
/// primeros bytes con `ZZKTxIdHash_`, así que la invariante de `DomainTag::raiz` se conserva.
pub(crate) const TAG_TXID_EVP: DomainTag = DomainTag::fija(*b"ZZKTxIdEvidencia");
/// SL-4a / EV-10 · etiqueta de dominio del `incident_id` (`dom_incidente`).
///
/// El contrato la fija en `TAGS_FIJAS`. La implementación la usa desde
/// [`crate::preimage::tx::incident_id_evidencia`].
pub(crate) const TAG_EVP_INCIDENTE: DomainTag = DomainTag::fija(*b"ZZKEvpIncidente_");
/// SR-1 · sub-digest de la extensión de la operación de sector (v5, `ORDEN-SR1-2` §1).
///
/// `H_d("ZZKTxIdSector__", bytes_canonicos(OperacionSector))`: la txid compromete la operación
/// entera, campo a campo. Añadida por SR-1-2: cambiarla es un cambio de consenso (C-HASH-05). No
/// comparte los 12 primeros bytes con `ZZKTxIdHash_`.
pub(crate) const TAG_TXID_SECTOR: DomainTag = DomainTag::fija(*b"ZZKTxIdSector___");
/// SR-1 · mensaje de la firma de la operación de sector (v5): `H_d("ZZKTxSigSector__", txid)`.
///
/// La firma Ed25519 de `operacion.clave` compromete la operación entera, porque el `txid` incluye
/// su sub-digest. Añadida por SR-1-2 (C-HASH-05).
pub(crate) const TAG_TXSIG_SECTOR: DomainTag = DomainTag::fija(*b"ZZKTxSigSector__");
/// PT-3bc · sub-digest de la extensión de la prueba de almacenamiento (v6).
///
/// `H_d("ZZKTxIdAlmacen__", bytes_canonicos(OperacionAlmacenamiento))`: la txid compromete la
/// operación entera, campo a campo. Añadida por PT-3bc: cambiarla es un cambio de consenso
/// (C-HASH-05). No comparte los 12 primeros bytes con `ZZKTxIdHash_`.
pub(crate) const TAG_TXID_ALMACEN: DomainTag = DomainTag::fija(*b"ZZKTxIdAlmacen__");
/// PT-3bc · mensaje de la firma de la operación de almacenamiento (v6):
/// `H_d("ZZKTxSigAlmacen_", txid)`.
///
/// La firma Ed25519 de `operacion.clave` compromete la operación entera, porque el `txid` incluye
/// su sub-digest. Añadida por PT-3bc (C-HASH-05).
pub(crate) const TAG_TXSIG_ALMACEN: DomainTag = DomainTag::fija(*b"ZZKTxSigAlmacen_");

/// Las veintitrés etiquetas ASCII fijas, para las comprobaciones de invariante.
#[allow(
    dead_code,
    reason = "solo lo usan los tests de invariante de este módulo y la preimagen de evidencia"
)]
pub(crate) const TAGS_FIJAS: [DomainTag; 23] = [
    TAG_TXID_HEADER,
    TAG_TXID_INPUTS,
    TAG_TXID_PREVOUT,
    TAG_TXID_SEQUENCE,
    TAG_TXID_OUTPUTS,
    TAG_TXID_GARANTIA,
    TAG_TXSIG_AMOUNTS,
    TAG_TXSIG_LOCKS,
    TAG_TXSIG_THIS_IN,
    TAG_TXSIG_GARANT,
    TAG_TXID_EVP,
    TAG_EVP_INCIDENTE,
    TAG_TXID_SECTOR,
    TAG_TXSIG_SECTOR,
    TAG_TXID_ALMACEN,
    TAG_TXSIG_ALMACEN,
    TAG_TX_AUTH,
    TAG_BLK_MERKLE,
    TAG_BLK_HEADER,
    TAG_BLK_PRE_HASH,
    TAG_BLK_BODY_HASH,
    TAG_FLOW_ID,
    TAG_FLOW_GENESIS,
];

#[cfg(test)]
mod tests {
    use super::{
        DomainTag, TAG_FLOW_GENESIS, TAG_FLOW_ID, TAG_TXID_GARANTIA, TAG_TXSIG_GARANT, TAGS_FIJAS,
        h_d, sha3_256,
    };

    /// Ancla de cordura: si esto falla, se ha implementado Keccak-256 y no SHA3-256 (H-001).
    #[test]
    fn sha3_256_del_mensaje_vacio() {
        let d = sha3_256(b"");
        assert_eq!(
            format!("{d}"),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            "si sale c5d2460186f7233c... es Keccak-256, no SHA3-256 — ver H-001"
        );
    }

    /// C-HASH-04: todas las etiquetas fijas miden 16 bytes y son distintas entre sí.
    ///
    /// La longitud la garantiza el tipo (`[u8; 16]`); esto verifica la unicidad, que el tipo no
    /// puede garantizar.
    #[test]
    fn las_etiquetas_fijas_son_unicas() {
        let mut vistas: Vec<[u8; 16]> = Vec::new();
        for t in TAGS_FIJAS {
            let b = *t.as_bytes();
            assert!(
                !vistas.contains(&b),
                "etiqueta duplicada: {:?}",
                core::str::from_utf8(&b)
            );
            vistas.push(b);
        }
        assert_eq!(vistas.len(), 23);
    }

    /// Las dos etiquetas del flujo son exactamente las de la tabla C-HASH-06.
    ///
    /// Son **distintas** a propósito: `ZZKFlowId_______` es la etiqueta de dominio de `H_flujo`
    /// (C-FLU-10) y `ZZKFlowGenesis__` va dentro de su mensaje para el génesis (C-FLU-06). Un
    /// cambio aquí es un cambio de consenso (C-HASH-05).
    #[test]
    fn las_etiquetas_de_flujo_son_las_de_la_tabla() {
        assert_eq!(TAG_FLOW_ID.as_bytes(), b"ZZKFlowId_______");
        assert_eq!(TAG_FLOW_GENESIS.as_bytes(), b"ZZKFlowGenesis__");
        assert_ne!(
            TAG_FLOW_ID, TAG_FLOW_GENESIS,
            "no se uniforman: son dos etiquetas distintas"
        );
    }

    /// Las dos etiquetas de W02 son exactamente las de F-06 y F-08.
    ///
    /// `ZZKTxIdGarantia_` es el sub-digest de la extensión de v2/v3 y `ZZKTxSigGarant__` es el
    /// mensaje de la firma de aceptación. Un cambio aquí es un cambio de consenso (C-HASH-05).
    #[test]
    fn las_etiquetas_de_garantia_son_las_de_la_tabla() {
        assert_eq!(TAG_TXID_GARANTIA.as_bytes(), b"ZZKTxIdGarantia_");
        assert_eq!(TAG_TXSIG_GARANT.as_bytes(), b"ZZKTxSigGarant__");
        assert_ne!(
            TAG_TXID_GARANTIA, TAG_TXSIG_GARANT,
            "no se uniforman: son dos etiquetas distintas"
        );
    }

    /// La invariante que hace segura la etiqueta raíz con branch ID variable.
    ///
    /// Ninguna etiqueta fija comparte los 12 primeros bytes con `ZZKTxIdHash_`. Si alguna los
    /// compartiera, existiría un `CONSENSUS_BRANCH_ID` que colisionaría con ella.
    #[test]
    fn ninguna_etiqueta_fija_empieza_por_el_prefijo_de_la_raiz() {
        let prefijo = b"ZZKTxIdHash_";
        for t in TAGS_FIJAS {
            let b = t.as_bytes();
            let coincide = b[..12] == prefijo[..];
            assert!(
                !coincide,
                "la etiqueta {:?} comparte los 12 primeros bytes con la raíz: un branch ID podría \
                 colisionar con ella",
                core::str::from_utf8(b)
            );
        }
    }

    /// La raíz cambia con el branch ID — es lo que da la protección de repetición (C-UPG-04).
    #[test]
    fn la_raiz_depende_del_branch_id() {
        let a = h_d(DomainTag::raiz(0x0000_0000), b"mismo mensaje");
        let b = h_d(DomainTag::raiz(0xc478_80ea), b"mismo mensaje");
        assert_ne!(a, b, "una firma de una rama sería válida en otra");
    }

    /// Cambiar de dominio cambia el digest, aunque el mensaje sea idéntico.
    #[test]
    fn el_dominio_separa() {
        let msg = b"";
        let a = h_d(super::TAG_TXID_HEADER, msg);
        let b = h_d(super::TAG_TXID_INPUTS, msg);
        assert_ne!(a, b);
    }

    /// C-TX-04: el hash con dominio del vacío no es cero, y difiere por etiqueta.
    ///
    /// ZIP-143/243 usaban `uint256(0)` para los campos ausentes, con lo que "campo ausente" y
    /// "campo cuyo hash dio cero" eran indistinguibles y todos los ausentes colisionaban.
    #[test]
    fn el_hash_del_vacio_no_es_cero() {
        for t in TAGS_FIJAS {
            let d = h_d(t, b"");
            assert_ne!(d.as_bytes(), &[0u8; 32]);
        }
    }
}
