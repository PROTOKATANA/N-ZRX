//! Canon de consenso del estado (`P-ZRX/P-004/ORDEN-A1B1.md`, reglas C1–C10; `ORDEN-A1B1-2.md`,
//! reglas K1–K5).
//!
//! Traduce el [`Estado`] de consenso a hojas `(familia, clave_canonica, valor_canonico)` y calcula
//! su raíz con el árbol de [`crate::estado`]. También recorre el [`Undo`] por delta de un bloque y
//! produce los [`Cambio`] que llevan el árbol del estado anterior al posterior (C9).
//!
//! # Familias
//!
//! Una hoja por entrada de `utxo` (`0x01`), `garantias` (`0x02`), `sectores` (`0x04`), `cajas`
//! (`0x05`), `pruebas` (`0x06`), `poreps` (`0x07`), `claves_voto` (`0x08`) y
//! `ultimo_slot_producido` (`0x09`). La familia `0x03` (cuentas) no tiene hojas. Los valores de
//! `utxo`, `garantias`, `sectores` y `cajas` son **byte a byte** los que escribe hoy
//! `crates/zx-node/src/estado_resumen.rs` en sus codificadores (copiados aquí, no importados), más
//! el campo que ese resumen no escribía (A1-B1-2 · `Garantia.incidentes`); los de las otras cuatro
//! siguen el mismo estilo: la clave y después cada campo del tipo en su orden de declaración,
//! enteros en big-endian de su ancho y matrices de bytes tal cual.
//!
//! # Sin campos sin clasificar (K1)
//!
//! Toda función que codifica un `struct` lo desestructura **entero y sin `..`**, y todo `enum` se
//! recorre con un `match` sin brazo comodín. Vale para las claves y los valores de las ocho familias
//! y para todo tipo anidado (`EntradaUtxo`, `Lock`, `Pendiente`, `EnRetirada`, `Incidente`,
//! `Garantia`, `SectorId`, `RegistroSector`, `CajaId`, `Ocupante`, `RegistroCaja`, `PruebaVigente`,
//! `PorepVigente`, `ClaveVoto`, `ClaveVotoAnterior`, `ClaveTablaVoto`). Añadir un campo a cualquiera
//! de ellos rompe la compilación hasta decidir si entra en la raíz.
//!
//! # Escalares y libro
//!
//! `h_escalares` cubre los once escalares más la versión de la codificación y `h_libro`; `h_libro`
//! cubre, campo a campo y en el orden de declaración de `Estado`, todo campo que no sea una de las
//! ocho familias, uno de los once escalares ni `parametros_sector` (C5). `parametros_sector` no
//! entra en nada (C6). Ambas desestructuran `Estado` entero.

use std::collections::BTreeSet;

use zx_consensus::cajas::{CajaId, EtapaCaja, Ocupante, RegistroCaja};
use zx_consensus::sectores::{
    ClaveVoto, ClaveVotoAnterior, Etapa, PorepVigente, PruebaVigente, RegistroSector, SectorId,
};
use zx_consensus::transicion::{
    EnRetirada, EntradaUtxo, Estado, Fase, Garantia, Incidente, Origen, Pendiente, Punto, Undo,
};
use zx_core::{BlockHash, ClavePublica, ClaveTablaVoto, Lock, OutPoint};

use crate::almacen::AlmacenEnMemoria;
use crate::camino::CaminoSha3;
use crate::error::Error;
use crate::estado::Estado as ArbolEstado;
use crate::hash::{Hash32, h_d};
use crate::lote::Cambio;

/// Versión de la codificación canónica (C4). Cualquier cambio del formato la sube: así dos
/// votantes con codificaciones distintas firman raíces distintas **a propósito**.
pub const VERSION_CANON: u8 = 1;

/// Etiqueta de dominio de `h_escalares` (16 B, rellenada con ceros).
const TAG_ESCALARES: [u8; 16] = *b"ZXEstadoEscal1\0\0";
/// Etiqueta de dominio de `h_libro` (16 B, rellenada con ceros).
const TAG_LIBRO: [u8; 16] = *b"ZXEstadoLibro1\0\0";

/// `utxo`.
const FAM_UTXO: u8 = 0x01;
/// `garantias`.
const FAM_GARANTIAS: u8 = 0x02;
/// `sectores`.
const FAM_SECTORES: u8 = 0x04;
/// `cajas`.
const FAM_CAJAS: u8 = 0x05;
/// `pruebas`.
const FAM_PRUEBAS: u8 = 0x06;
/// `poreps`.
const FAM_POREPS: u8 = 0x07;
/// `claves_voto`.
const FAM_CLAVES_VOTO: u8 = 0x08;
/// `ultimo_slot_producido`.
const FAM_ULTIMO_SLOT: u8 = 0x09;

// ---------------------------------------------------------------------------
// Helpers de codificación (los de `estado_resumen.rs`, copiados)
// ---------------------------------------------------------------------------

fn codificar_len(buf: &mut Vec<u8>, n: usize) {
    let n64 = u64::try_from(n).unwrap_or(u64::MAX);
    buf.extend_from_slice(&n64.to_be_bytes());
}

fn codificar_punto(buf: &mut Vec<u8>, p: Punto) {
    match p {
        Punto::Altura(h) => {
            buf.push(0);
            buf.extend_from_slice(&u64::from(h).to_be_bytes());
        }
        Punto::Slot(s) => {
            buf.push(1);
            buf.extend_from_slice(&s.to_be_bytes());
        }
    }
}

fn codificar_lock(buf: &mut Vec<u8>, lock: &Lock) {
    match lock {
        Lock::PubKey { pubkey } => {
            buf.push(0);
            buf.extend_from_slice(pubkey.bytes());
        }
        Lock::MultiSig { k, pubkeys } => {
            buf.push(1);
            buf.push(*k);
            codificar_len(buf, pubkeys.len());
            for pk in pubkeys {
                buf.extend_from_slice(pk.bytes());
            }
        }
        Lock::Htlc {
            hash,
            receiver,
            sender,
            timeout,
        } => {
            buf.push(2);
            buf.extend_from_slice(hash);
            buf.extend_from_slice(receiver.bytes());
            buf.extend_from_slice(sender.bytes());
            buf.extend_from_slice(&u64::from(*timeout).to_be_bytes());
        }
    }
}

fn codificar_outpoint(buf: &mut Vec<u8>, op: &OutPoint) {
    let OutPoint {
        prev_txid,
        prev_index,
    } = op;
    buf.extend_from_slice(prev_txid.as_bytes());
    buf.extend_from_slice(&prev_index.to_be_bytes());
}

fn codificar_entrada_utxo(buf: &mut Vec<u8>, op: &OutPoint, e: &EntradaUtxo) {
    let EntradaUtxo {
        valor,
        lock,
        origen,
        creada,
    } = e;
    codificar_outpoint(buf, op);
    buf.extend_from_slice(&valor.brek().to_be_bytes());
    codificar_lock(buf, lock);
    let codigo: u8 = match origen {
        Origen::CoinbasePow => 0,
        Origen::Tx => 1,
        Origen::Liberacion => 2,
    };
    buf.push(codigo);
    codificar_punto(buf, *creada);
}

fn codificar_pendiente(buf: &mut Vec<u8>, p: &Pendiente) {
    let Pendiente {
        importe,
        madura_en_altura,
        madura_en_slot,
    } = p;
    buf.extend_from_slice(&importe.brek().to_be_bytes());
    match madura_en_altura {
        Some(h) => {
            buf.push(1);
            buf.extend_from_slice(&u64::from(*h).to_be_bytes());
        }
        None => buf.push(0),
    }
    match madura_en_slot {
        Some(s) => {
            buf.push(1);
            buf.extend_from_slice(&s.to_be_bytes());
        }
        None => buf.push(0),
    }
}

fn codificar_en_retirada(buf: &mut Vec<u8>, r: &EnRetirada) {
    let EnRetirada {
        importe,
        inicio_slot,
    } = r;
    buf.extend_from_slice(&importe.brek().to_be_bytes());
    buf.extend_from_slice(&inicio_slot.to_be_bytes());
}

fn codificar_incidente(buf: &mut Vec<u8>, i: &Incidente) {
    let Incidente { id, slot_falta } = i;
    buf.extend_from_slice(id);
    buf.extend_from_slice(&slot_falta.to_be_bytes());
}

fn codificar_garantia(buf: &mut Vec<u8>, pk: &ClavePublica, g: &Garantia) {
    let Garantia {
        activo,
        pendientes,
        en_retirada,
        congelado,
        creditos,
        nonce_siguiente,
        incidentes,
    } = g;
    buf.extend_from_slice(pk.bytes());
    buf.extend_from_slice(&activo.brek().to_be_bytes());
    buf.extend_from_slice(&nonce_siguiente.to_be_bytes());
    codificar_len(buf, pendientes.len());
    for p in pendientes {
        codificar_pendiente(buf, p);
    }
    codificar_len(buf, en_retirada.len());
    for r in en_retirada {
        codificar_en_retirada(buf, r);
    }
    buf.extend_from_slice(&congelado.brek().to_be_bytes());
    codificar_len(buf, creditos.len());
    for c in creditos {
        codificar_pendiente(buf, c);
    }
    // A1-B1-2 · K2 · `incidentes`: longitud y, por cada uno, `id` y `slot_falta` al final.
    codificar_len(buf, incidentes.len());
    for i in incidentes {
        codificar_incidente(buf, i);
    }
}

fn codigo_etapa(e: Etapa) -> u8 {
    match e {
        Etapa::Precomprometido => 0,
        Etapa::Activo => 1,
        Etapa::EnRetirada => 2,
        Etapa::Retirado => 3,
        Etapa::Caducado => 4,
    }
}

fn codigo_etapa_caja(e: EtapaCaja) -> u8 {
    match e {
        EtapaCaja::Abierta => 0,
        EtapaCaja::Cerrada => 1,
        EtapaCaja::EnRetirada => 2,
        EtapaCaja::Retirada => 3,
    }
}

fn codificar_sector(buf: &mut Vec<u8>, r: &RegistroSector) {
    // K1/K2 · se liga `id` al campo del registro (no a la clave del mapa): el valor ya lo escribía
    // por invariante `r.id == clave`, así que los bytes no se mueven y el campo queda cubierto.
    let RegistroSector {
        id,
        r2,
        history_size,
        etapa,
        alta_slot,
        renovacion_slot,
        retiro_slot,
        fianza,
        aud_apertura,
        aud_contestada,
    } = r;
    buf.extend_from_slice(id.clave.bytes());
    buf.extend_from_slice(&id.sector_index.to_be_bytes());
    buf.extend_from_slice(&id.version.to_be_bytes());
    for w in r2 {
        buf.extend_from_slice(&w.to_be_bytes());
    }
    buf.extend_from_slice(&history_size.to_be_bytes());
    buf.push(codigo_etapa(*etapa));
    buf.extend_from_slice(&alta_slot.to_be_bytes());
    buf.extend_from_slice(&renovacion_slot.to_be_bytes());
    buf.extend_from_slice(&retiro_slot.to_be_bytes());
    buf.extend_from_slice(&fianza.to_be_bytes());
    buf.extend_from_slice(&aud_apertura.to_be_bytes());
    buf.extend_from_slice(&aud_contestada.to_be_bytes());
}

fn codificar_ocupante(buf: &mut Vec<u8>, h: &Ocupante) {
    let Ocupante {
        sector_index,
        version,
        ocupado,
    } = h;
    buf.extend_from_slice(&sector_index.to_be_bytes());
    buf.extend_from_slice(&version.to_be_bytes());
    buf.push(u8::from(*ocupado));
}

fn codificar_caja(buf: &mut Vec<u8>, c: &RegistroCaja) {
    let RegistroCaja {
        id,
        raiz,
        n,
        ocupacion,
        estado_hueco,
        history_size,
        etapa,
        alta_slot,
        ultima_alta_slot,
        cierre_slot,
        renovacion_slot,
        retiro_slot,
        fianza,
        huecos,
    } = c;
    let CajaId { clave, seq } = id;
    buf.extend_from_slice(clave.bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    for w in raiz {
        buf.extend_from_slice(&w.to_be_bytes());
    }
    buf.push(*n);
    buf.extend_from_slice(&ocupacion.to_be_bytes());
    buf.extend_from_slice(&estado_hueco.to_be_bytes());
    buf.extend_from_slice(&history_size.to_be_bytes());
    buf.push(codigo_etapa_caja(*etapa));
    buf.extend_from_slice(&alta_slot.to_be_bytes());
    buf.extend_from_slice(&ultima_alta_slot.to_be_bytes());
    buf.extend_from_slice(&cierre_slot.to_be_bytes());
    buf.extend_from_slice(&renovacion_slot.to_be_bytes());
    buf.extend_from_slice(&retiro_slot.to_be_bytes());
    buf.extend_from_slice(&fianza.to_be_bytes());
    for h in huecos {
        codificar_ocupante(buf, h);
    }
}

// ---------------------------------------------------------------------------
// Claves canónicas
// ---------------------------------------------------------------------------

fn clave_outpoint(op: &OutPoint) -> Vec<u8> {
    let mut buf = Vec::with_capacity(36);
    codificar_outpoint(&mut buf, op);
    buf
}

fn clave_sector(id: &SectorId) -> Vec<u8> {
    let SectorId {
        clave,
        sector_index,
        version,
    } = id;
    let mut buf = Vec::with_capacity(38);
    buf.extend_from_slice(clave.bytes());
    buf.extend_from_slice(&sector_index.to_be_bytes());
    buf.extend_from_slice(&version.to_be_bytes());
    buf
}

fn clave_caja(id: &CajaId) -> Vec<u8> {
    let CajaId { clave, seq } = id;
    let mut buf = Vec::with_capacity(36);
    buf.extend_from_slice(clave.bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf
}

fn clave_clave(pk: &ClavePublica) -> Vec<u8> {
    pk.bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Una función por familia: `(clave, valor)` de una entrada (C10)
// ---------------------------------------------------------------------------

/// `(clave_canonica, valor_canonico)` de una entrada de `utxo` (`0x01`).
///
/// El valor son exactamente los bytes de `codificar_entrada_utxo` (clave incluida).
#[must_use]
pub fn hoja_utxo(op: &OutPoint, e: &EntradaUtxo) -> (Vec<u8>, Vec<u8>) {
    let clave = clave_outpoint(op);
    let mut valor = Vec::new();
    codificar_entrada_utxo(&mut valor, op, e);
    (clave, valor)
}

/// `(clave_canonica, valor_canonico)` de una entrada de `garantias` (`0x02`).
#[must_use]
pub fn hoja_garantia(pk: &ClavePublica, g: &Garantia) -> (Vec<u8>, Vec<u8>) {
    let clave = clave_clave(pk);
    let mut valor = Vec::new();
    codificar_garantia(&mut valor, pk, g);
    (clave, valor)
}

/// `(clave_canonica, valor_canonico)` de una entrada de `sectores` (`0x04`).
#[must_use]
pub fn hoja_sector(id: &SectorId, r: &RegistroSector) -> (Vec<u8>, Vec<u8>) {
    let clave = clave_sector(id);
    let mut valor = Vec::new();
    codificar_sector(&mut valor, r);
    (clave, valor)
}

/// `(clave_canonica, valor_canonico)` de una entrada de `cajas` (`0x05`).
#[must_use]
pub fn hoja_caja(id: &CajaId, c: &RegistroCaja) -> (Vec<u8>, Vec<u8>) {
    let clave = clave_caja(id);
    let mut valor = Vec::new();
    codificar_caja(&mut valor, c);
    (clave, valor)
}

/// `(clave_canonica, valor_canonico)` de una entrada de `pruebas` (`0x06`).
#[must_use]
pub fn hoja_prueba(pk: &ClavePublica, p: &PruebaVigente) -> (Vec<u8>, Vec<u8>) {
    let PruebaVigente {
        slot_prueba,
        raiz_conjunto,
        n_sectores,
    } = p;
    let clave = clave_clave(pk);
    let mut valor = Vec::new();
    valor.extend_from_slice(pk.bytes());
    valor.extend_from_slice(&slot_prueba.to_be_bytes());
    for w in raiz_conjunto {
        valor.extend_from_slice(&w.to_be_bytes());
    }
    valor.extend_from_slice(&n_sectores.to_be_bytes());
    (clave, valor)
}

/// `(clave_canonica, valor_canonico)` de una entrada de `poreps` (`0x07`).
#[must_use]
pub fn hoja_porep(pk: &ClavePublica, p: &PorepVigente) -> (Vec<u8>, Vec<u8>) {
    let PorepVigente {
        slot_ventana,
        raiz_lote,
        n_sectores,
    } = p;
    let clave = clave_clave(pk);
    let mut valor = Vec::new();
    valor.extend_from_slice(pk.bytes());
    valor.extend_from_slice(&slot_ventana.to_be_bytes());
    for w in raiz_lote {
        valor.extend_from_slice(&w.to_be_bytes());
    }
    valor.extend_from_slice(&n_sectores.to_be_bytes());
    (clave, valor)
}

/// `(clave_canonica, valor_canonico)` de una entrada de `claves_voto` (`0x08`).
#[must_use]
pub fn hoja_clave_voto(pk: &ClavePublica, c: &ClaveVoto) -> (Vec<u8>, Vec<u8>) {
    let ClaveVoto {
        clave_bls,
        prueba_posesion,
    } = c;
    let clave = clave_clave(pk);
    let mut valor = Vec::new();
    valor.extend_from_slice(pk.bytes());
    valor.extend_from_slice(clave_bls);
    valor.extend_from_slice(prueba_posesion);
    (clave, valor)
}

/// `(clave_canonica, valor_canonico)` de una entrada de `ultimo_slot_producido` (`0x09`).
#[must_use]
pub fn hoja_ultimo_slot(pk: &ClavePublica, slot: u64) -> (Vec<u8>, Vec<u8>) {
    let clave = clave_clave(pk);
    let mut valor = Vec::new();
    valor.extend_from_slice(pk.bytes());
    valor.extend_from_slice(&slot.to_be_bytes());
    (clave, valor)
}

// ---------------------------------------------------------------------------
// Todas las hojas del estado
// ---------------------------------------------------------------------------

/// Todas las hojas del estado como `(familia, clave_canonica, valor_canonico)` (C10).
///
/// Desestructura [`Estado`] **entero y sin `..`** (C7/K1): un campo nuevo rompe la compilación
/// hasta decidir si entra en la raíz.
#[must_use]
pub fn hojas_de_estado(estado: &Estado) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
    let Estado {
        utxo,
        garantias,
        emitido: _,
        quemado: _,
        fase: _,
        terminal: _,
        altura: _,
        trabajo: _,
        slot: _,
        s0: _,
        peso_sufijo: _,
        altura_terminal: _,
        subsidio_acum: _,
        ultimo_slot_producido,
        sectores,
        parametros_sector: _,
        cajas,
        pruebas,
        poreps,
        claves_voto,
        claves_voto_previas: _,
        vencimientos_clave_voto: _,
        finalidad_votos_n: _,
        finalidad_votos: _,
        finalidad_votos_h_t: _,
        raiz_estado: _,
        tablas_voto: _,
        tablas_voto_contenido: _,
        tabla_ventana_voto: _,
        tabla_ciclo_rearranque: _,
        cola_tablas_voto: _,
        ultima_ventana_derivada_sin_base: _,
        votantes_voto: _,
        deuda_ausencia: _,
        liquidacion_voto_hasta: _,
    } = estado;
    let mut hojas = Vec::new();
    for (op, e) in utxo {
        let (k, v) = hoja_utxo(op, e);
        hojas.push((FAM_UTXO, k, v));
    }
    for (pk, g) in garantias {
        let (k, v) = hoja_garantia(pk, g);
        hojas.push((FAM_GARANTIAS, k, v));
    }
    for (id, r) in sectores {
        let (k, v) = hoja_sector(id, r);
        hojas.push((FAM_SECTORES, k, v));
    }
    for (id, c) in cajas {
        let (k, v) = hoja_caja(id, c);
        hojas.push((FAM_CAJAS, k, v));
    }
    for (pk, p) in pruebas {
        let (k, v) = hoja_prueba(pk, p);
        hojas.push((FAM_PRUEBAS, k, v));
    }
    for (pk, p) in poreps {
        let (k, v) = hoja_porep(pk, p);
        hojas.push((FAM_POREPS, k, v));
    }
    for (pk, c) in claves_voto {
        let (k, v) = hoja_clave_voto(pk, c);
        hojas.push((FAM_CLAVES_VOTO, k, v));
    }
    for (pk, slot) in ultimo_slot_producido {
        let (k, v) = hoja_ultimo_slot(pk, *slot);
        hojas.push((FAM_ULTIMO_SLOT, k, v));
    }
    hojas
}

// ---------------------------------------------------------------------------
// Escalares y libro
// ---------------------------------------------------------------------------

fn codigo_fase(fase: Fase) -> u8 {
    match fase {
        Fase::Genesis => 0,
        Fase::PoW => 1,
        Fase::PoST => 2,
    }
}

fn codificar_opcion_hash(buf: &mut Vec<u8>, h: Option<&BlockHash>) {
    match h {
        Some(h) => {
            buf.push(1);
            buf.extend_from_slice(h.as_bytes());
        }
        None => buf.push(0),
    }
}

fn codificar_opcion_bytes32(buf: &mut Vec<u8>, h: Option<&[u8; 32]>) {
    match h {
        Some(h) => {
            buf.push(1);
            buf.extend_from_slice(h);
        }
        None => buf.push(0),
    }
}

fn codificar_opcion_u32(buf: &mut Vec<u8>, v: Option<u32>) {
    match v {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        None => buf.push(0),
    }
}

fn codificar_opcion_u64(buf: &mut Vec<u8>, v: Option<u64>) {
    match v {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        None => buf.push(0),
    }
}

fn codificar_clave_tabla(buf: &mut Vec<u8>, c: &ClaveTablaVoto) {
    let ClaveTablaVoto {
        clave_bls,
        peso,
        activo,
        prueba,
        garantia,
    } = c;
    buf.extend_from_slice(clave_bls);
    buf.extend_from_slice(&peso.to_be_bytes());
    buf.push(u8::from(*activo));
    buf.push(u8::from(*prueba));
    buf.extend_from_slice(&garantia.to_be_bytes());
}

fn codificar_claves_tabla(buf: &mut Vec<u8>, claves: &[ClaveTablaVoto]) {
    codificar_len(buf, claves.len());
    for c in claves {
        codificar_clave_tabla(buf, c);
    }
}

fn codificar_claves_voto_previas(
    buf: &mut Vec<u8>,
    previas: &std::collections::BTreeMap<ClavePublica, ClaveVotoAnterior>,
) {
    codificar_len(buf, previas.len());
    for (clave_ed, prev) in previas {
        let ClaveVotoAnterior {
            clave_bls,
            prueba_posesion,
            vencimiento,
        } = prev;
        buf.extend_from_slice(clave_ed.bytes());
        buf.extend_from_slice(clave_bls);
        buf.extend_from_slice(prueba_posesion);
        buf.extend_from_slice(&vencimiento.to_be_bytes());
    }
}

fn codificar_vencimientos(
    buf: &mut Vec<u8>,
    vencimientos: &std::collections::BTreeMap<u64, BTreeSet<ClavePublica>>,
) {
    codificar_len(buf, vencimientos.len());
    for (vencimiento, claves) in vencimientos {
        buf.extend_from_slice(&vencimiento.to_be_bytes());
        codificar_len(buf, claves.len());
        for clave in claves {
            buf.extend_from_slice(clave.bytes());
        }
    }
}

fn codificar_tablas_voto(
    buf: &mut Vec<u8>,
    tablas: &std::collections::BTreeMap<u64, Vec<ClaveTablaVoto>>,
) {
    codificar_len(buf, tablas.len());
    for (n, claves) in tablas {
        buf.extend_from_slice(&n.to_be_bytes());
        codificar_claves_tabla(buf, claves);
    }
}

fn codificar_tablas_contenido(
    buf: &mut Vec<u8>,
    contenidos: &std::collections::BTreeMap<[u8; 32], Vec<ClaveTablaVoto>>,
) {
    codificar_len(buf, contenidos.len());
    for (h, claves) in contenidos {
        buf.extend_from_slice(h);
        codificar_claves_tabla(buf, claves);
    }
}

fn codificar_mapa_u64_hash(buf: &mut Vec<u8>, mapa: &std::collections::BTreeMap<u64, [u8; 32]>) {
    codificar_len(buf, mapa.len());
    for (n, h) in mapa {
        buf.extend_from_slice(&n.to_be_bytes());
        buf.extend_from_slice(h);
    }
}

fn codificar_cola(buf: &mut Vec<u8>, cola: &[(u64, [u8; 32])]) {
    codificar_len(buf, cola.len());
    for (n, h) in cola {
        buf.extend_from_slice(&n.to_be_bytes());
        buf.extend_from_slice(h);
    }
}

fn codificar_votantes(
    buf: &mut Vec<u8>,
    votantes: &std::collections::BTreeMap<u64, BTreeSet<ClavePublica>>,
) {
    codificar_len(buf, votantes.len());
    for (n, claves) in votantes {
        buf.extend_from_slice(&n.to_be_bytes());
        codificar_len(buf, claves.len());
        for clave in claves {
            buf.extend_from_slice(clave.bytes());
        }
    }
}

fn codificar_deuda(buf: &mut Vec<u8>, deuda: &std::collections::BTreeMap<ClavePublica, i128>) {
    codificar_len(buf, deuda.len());
    for (clave, valor) in deuda {
        buf.extend_from_slice(clave.bytes());
        buf.extend_from_slice(&valor.to_be_bytes());
    }
}

/// `h_libro = h_d("ZXEstadoLibro1", libro)` (C5).
///
/// El libro cubre, campo a campo y en el orden de declaración de `Estado`, todo campo que no sea
/// una de las ocho familias, uno de los once escalares ni `parametros_sector`. Donde
/// `estado_resumen.rs` ya codifica el campo, estos son sus mismos bytes. Desestructura `Estado`
/// entero (K1): un campo nuevo rompe la compilación aunque el libro no lo use.
#[must_use]
pub fn h_libro(estado: &Estado) -> Hash32 {
    let Estado {
        utxo: _,
        garantias: _,
        emitido: _,
        quemado: _,
        fase: _,
        terminal: _,
        altura: _,
        trabajo: _,
        slot: _,
        s0: _,
        peso_sufijo: _,
        altura_terminal: _,
        subsidio_acum: _,
        ultimo_slot_producido: _,
        sectores: _,
        parametros_sector: _,
        cajas: _,
        pruebas: _,
        poreps: _,
        claves_voto: _,
        claves_voto_previas,
        vencimientos_clave_voto,
        finalidad_votos_n,
        finalidad_votos,
        finalidad_votos_h_t,
        raiz_estado,
        tablas_voto,
        tablas_voto_contenido,
        tabla_ventana_voto,
        tabla_ciclo_rearranque,
        cola_tablas_voto,
        ultima_ventana_derivada_sin_base,
        votantes_voto,
        deuda_ausencia,
        liquidacion_voto_hasta,
    } = estado;
    let mut buf = Vec::new();
    codificar_claves_voto_previas(&mut buf, claves_voto_previas);
    codificar_vencimientos(&mut buf, vencimientos_clave_voto);
    buf.extend_from_slice(&finalidad_votos_n.to_be_bytes());
    codificar_opcion_hash(&mut buf, finalidad_votos.as_ref());
    codificar_opcion_bytes32(&mut buf, finalidad_votos_h_t.as_ref());
    codificar_opcion_bytes32(&mut buf, raiz_estado.as_ref());
    codificar_tablas_voto(&mut buf, tablas_voto);
    codificar_tablas_contenido(&mut buf, tablas_voto_contenido);
    codificar_mapa_u64_hash(&mut buf, tabla_ventana_voto);
    codificar_mapa_u64_hash(&mut buf, tabla_ciclo_rearranque);
    codificar_cola(&mut buf, cola_tablas_voto);
    codificar_opcion_u64(&mut buf, *ultima_ventana_derivada_sin_base);
    codificar_votantes(&mut buf, votantes_voto);
    codificar_deuda(&mut buf, deuda_ausencia);
    codificar_opcion_u64(&mut buf, *liquidacion_voto_hasta);
    h_d(TAG_LIBRO, &buf)
}

/// `h_escalares` con la versión de la codificación fijada en [`VERSION_CANON`].
#[must_use]
pub fn h_escalares(estado: &Estado) -> Hash32 {
    h_escalares_con_version(estado, VERSION_CANON)
}

/// `h_escalares` con un byte de versión explícito.
///
/// Es la misma función que usa [`h_escalares`]; se expone para que la prueba
/// `canon_05_la_version_entra` compruebe que el byte de versión entra en la preimagen.
/// Desestructura `Estado` entero (K1).
#[must_use]
pub fn h_escalares_con_version(estado: &Estado, version: u8) -> Hash32 {
    let Estado {
        utxo: _,
        garantias: _,
        emitido,
        quemado,
        fase,
        terminal,
        altura,
        trabajo,
        slot,
        s0,
        peso_sufijo,
        altura_terminal,
        subsidio_acum,
        ultimo_slot_producido: _,
        sectores: _,
        parametros_sector: _,
        cajas: _,
        pruebas: _,
        poreps: _,
        claves_voto: _,
        claves_voto_previas: _,
        vencimientos_clave_voto: _,
        finalidad_votos_n: _,
        finalidad_votos: _,
        finalidad_votos_h_t: _,
        raiz_estado: _,
        tablas_voto: _,
        tablas_voto_contenido: _,
        tabla_ventana_voto: _,
        tabla_ciclo_rearranque: _,
        cola_tablas_voto: _,
        ultima_ventana_derivada_sin_base: _,
        votantes_voto: _,
        deuda_ausencia: _,
        liquidacion_voto_hasta: _,
    } = estado;
    let mut buf = Vec::new();
    buf.push(version);
    buf.extend_from_slice(&emitido.to_be_bytes());
    buf.extend_from_slice(&quemado.to_be_bytes());
    buf.push(codigo_fase(*fase));
    codificar_opcion_hash(&mut buf, terminal.as_ref());
    buf.extend_from_slice(&altura.to_be_bytes());
    buf.extend_from_slice(&trabajo.to_big_endian());
    buf.extend_from_slice(&slot.to_be_bytes());
    buf.extend_from_slice(&s0.to_be_bytes());
    buf.extend_from_slice(&peso_sufijo.to_be_bytes());
    codificar_opcion_u32(&mut buf, *altura_terminal);
    buf.extend_from_slice(&subsidio_acum.to_be_bytes());
    buf.extend_from_slice(&h_libro(estado));
    h_d(TAG_ESCALARES, &buf)
}

// ---------------------------------------------------------------------------
// Raíz y puente (C8, C9)
// ---------------------------------------------------------------------------

/// Raíz de estado de 32 B (C8): construye el árbol en memoria desde cero con las hojas de las ocho
/// familias y llama a la `raiz_estado` del crate con `h_escalares`.
///
/// # Errors
/// Si el árbol en memoria rechaza alguna escritura (no ocurre con [`AlmacenEnMemoria`]).
pub fn raiz_de_estado(estado: &Estado) -> Result<Hash32, Error> {
    let mut arbol = ArbolEstado::nuevo(AlmacenEnMemoria::nuevo(), CaminoSha3);
    let cambios: Vec<Cambio> = hojas_de_estado(estado)
        .into_iter()
        .map(|(familia, clave, valor)| Cambio::poner(familia, clave, valor))
        .collect();
    arbol.aplicar(&cambios, 1)?;
    let escalares = h_escalares(estado);
    arbol.raiz_estado(&escalares)
}

/// Cambios que llevan el árbol del estado anterior al `posterior` a partir del [`Undo`] de un
/// bloque (C9).
///
/// Para cada clave que el `Undo` lista en sus siete familias pone el valor que tiene en `posterior`
/// o la borra si ya no está; para `ultimo_slot_producido`, la diferencia entre el mapa de
/// `undo.escalares` y el de `posterior`.
#[must_use]
pub fn cambios_de_undo(posterior: &Estado, undo: &Undo) -> Vec<Cambio> {
    let mut cambios = Vec::new();
    for (op, _) in &undo.utxo {
        cambios.push(match posterior.utxo.get(op) {
            Some(e) => {
                let (clave, valor) = hoja_utxo(op, e);
                Cambio::poner(FAM_UTXO, clave, valor)
            }
            None => Cambio::borrar(FAM_UTXO, clave_outpoint(op)),
        });
    }
    for (pk, _) in &undo.garantias {
        cambios.push(match posterior.garantias.get(pk) {
            Some(g) => {
                let (clave, valor) = hoja_garantia(pk, g);
                Cambio::poner(FAM_GARANTIAS, clave, valor)
            }
            None => Cambio::borrar(FAM_GARANTIAS, clave_clave(pk)),
        });
    }
    for (id, _) in &undo.sectores {
        cambios.push(match posterior.sectores.get(id) {
            Some(r) => {
                let (clave, valor) = hoja_sector(id, r);
                Cambio::poner(FAM_SECTORES, clave, valor)
            }
            None => Cambio::borrar(FAM_SECTORES, clave_sector(id)),
        });
    }
    for (id, _) in &undo.cajas {
        cambios.push(match posterior.cajas.get(id) {
            Some(c) => {
                let (clave, valor) = hoja_caja(id, c);
                Cambio::poner(FAM_CAJAS, clave, valor)
            }
            None => Cambio::borrar(FAM_CAJAS, clave_caja(id)),
        });
    }
    for (pk, _) in &undo.pruebas {
        cambios.push(match posterior.pruebas.get(pk) {
            Some(p) => {
                let (clave, valor) = hoja_prueba(pk, p);
                Cambio::poner(FAM_PRUEBAS, clave, valor)
            }
            None => Cambio::borrar(FAM_PRUEBAS, clave_clave(pk)),
        });
    }
    for (pk, _) in &undo.poreps {
        cambios.push(match posterior.poreps.get(pk) {
            Some(p) => {
                let (clave, valor) = hoja_porep(pk, p);
                Cambio::poner(FAM_POREPS, clave, valor)
            }
            None => Cambio::borrar(FAM_POREPS, clave_clave(pk)),
        });
    }
    for (pk, _) in &undo.claves_voto {
        cambios.push(match posterior.claves_voto.get(pk) {
            Some(c) => {
                let (clave, valor) = hoja_clave_voto(pk, c);
                Cambio::poner(FAM_CLAVES_VOTO, clave, valor)
            }
            None => Cambio::borrar(FAM_CLAVES_VOTO, clave_clave(pk)),
        });
    }
    let mut claves: BTreeSet<ClavePublica> = undo
        .escalares
        .ultimo_slot_producido
        .keys()
        .copied()
        .collect();
    claves.extend(posterior.ultimo_slot_producido.keys().copied());
    for clave in claves {
        cambios.push(match posterior.ultimo_slot_producido.get(&clave) {
            Some(slot) => {
                let (k, v) = hoja_ultimo_slot(&clave, *slot);
                Cambio::poner(FAM_ULTIMO_SLOT, k, v)
            }
            None => Cambio::borrar(FAM_ULTIMO_SLOT, clave_clave(&clave)),
        });
    }
    cambios
}
