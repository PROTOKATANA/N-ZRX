//! Resumen de estado (decisión 8 de `ORDEN-W06d1`; «Relanzamiento» punto 5).
//!
//! `blake3` de una codificación canónica **propia de `zx-node`** del estado de la punta
//! seleccionada: UTXO, garantía (con nonce) y emisión. Ni `zx-cadena` ni `zx-consensus` ofrecen esta
//! codificación (buscado explícitamente antes de escribirla; ninguna pieza migrada la impedía, así
//! que no hace falta ningún arreglo a otro crate). Objetivo: comparar el estado de dos aperturas del
//! mismo nodo (o, en el futuro, de dos nodos) sin volcar el estado entero.
//!
//! # Formato canónico
//!
//! Big-endian para todo entero de ancho fijo. Las colecciones de `Estado` que son `BTreeMap`
//! (`utxo`, `garantias`, …) ya iteran en orden de clave: no hace falta ordenar nada aparte. Los
//! `Vec<Pendiente>`/`Vec<EnRetirada>` de cada [`Garantia`] se codifican en su orden de aparición: es
//! el orden en que el motor de transición los fue añadiendo, determinista para una misma historia.
//!
//! ```text
//! resumen(Estado) = blake3(
//!     b"zx-node/resumen-estado/v13"
//!     ‖ CompactLenU64(|utxo|) ‖ Σ_{(op,e) en utxo, orden BTreeMap} entrada_utxo(op, e)
//!     ‖ CompactLenU64(|garantias|) ‖ Σ_{(pk,g) en garantias, orden BTreeMap} garantia(pk, g)
//!     ‖ i128_be(emitido)
//!     ‖ CompactLenU64(|sectores|) ‖ Σ_{(id,r)} sector(id, r)          [SR-1-2]
//!     ‖ CompactLenU64(|cajas|)    ‖ Σ_{(id,c)} caja(id, c)            [SR-G2b]
//!     ‖ finalidad_votos_n_be(8) ‖ flag(1) [‖ hash(32)] ‖ flag(1) [‖ h_t(32)]   [FV-4b-N2]
//!     ‖ flag(1) [‖ raiz(32)]                                          [RE-2c]
//!     ‖ CompactLenU64(|tablas_voto|) ‖ Σ ...
//!     ‖ CompactLenU64(|tablas_voto_contenido|) ‖ Σ ...
//!     ‖ CompactLenU64(|tabla_ventana_voto|) ‖ Σ ...
//!     ‖ CompactLenU64(|tabla_ciclo_rearranque|) ‖ Σ ...
//!     ‖ CompactLenU64(|cola_tablas_voto|) ‖ Σ ...
//!     ‖ flag(1) [‖ u64]                                               [TB-1c-2]
//!     ‖ CompactLenU64(|votantes_voto|) ‖ Σ ...
//!     ‖ CompactLenU64(|deuda_ausencia|) ‖ Σ ...
//!     ‖ flag(1) [‖ u64]                                               [AUS-2a]
//!     ‖ CompactLenU64(|claves_voto_previas|) ‖ Σ clave_ed(32) ‖ clave_bls(48)
//!         ‖ prueba_posesion(96) ‖ vencimiento_be(8)                              [RK-2]
//!     ‖ i128_be(quemado) ‖ fase(1) ‖ flag(1) [‖ terminal(32)]
//!     ‖ altura_be(4) ‖ trabajo_be(32) ‖ slot_be(8) ‖ s0_be(8) ‖ peso_sufijo_be(16)
//!     ‖ flag(1) [‖ altura_terminal_be(4)] ‖ i128_be(subsidio_acum)
//!     ‖ CompactLenU64(|ultimo_slot_producido|) ‖ Σ clave_ed(32) ‖ slot_be(8)   [SL-4a]
//!     ‖ CompactLenU64(|pruebas|) ‖ Σ clave_ed(32) ‖ prueba(...)                [PT-3bc]
//!     ‖ CompactLenU64(|poreps|)  ‖ Σ clave_ed(32) ‖ porep(...)                 [PT-3bc]
//!     ‖ CompactLenU64(|claves_voto|) ‖ Σ clave_ed(32) ‖ clave_voto(...)        [PT-3bc]
//!     ‖ CompactLenU64(|vencimientos_clave_voto|) ‖ Σ vencimiento_be(8)
//!         ‖ CompactLenU64(n) ‖ Σ clave_ed(32)                                    [RK-2]
//! )
//! ```
//!
//! con `entrada_utxo(op, e) = txid(32) ‖ index_be(4) ‖ valor_be(8) ‖ lock(...) ‖ origen(1) ‖ punto(9)`
//! y `garantia(pk, g) = pk(32) ‖ activo_be(8) ‖ nonce_siguiente_be(8) ‖ pendientes(...) ‖
//! en_retirada(...) ‖ congelado_be(8) ‖ creditos(...) ‖ incidentes(...)`. `lock` codifica su
//! discriminante (`0` = P2K, `1` = MultiSig) seguido de sus campos; `origen` es el discriminante de
//! tres valores; `punto` es un byte de discriminante (`0` = Altura, `1` = Slot) seguido de 8 bytes
//! big-endian.
//!
//! El resumen cubre **todos** los campos que cubre la raíz de estado de `canon.rs` (pieza A1); la
//! única exclusión es `parametros_sector`, que la raíz tampoco cubre (lo fija el perfil de red). Todo
//! tipo que el resumen codifica se desestructura entero, sin `..` y sin comodines: un campo nuevo no
//! compila hasta decidir si entra.
//!
//! No es un formato de wire ni entra en ningún hash de consenso: es un instrumento de diagnóstico
//! del nodo (`ESCENARIOS-0.0.1.md` §1, «resumen del estado canónico»).

use zx_consensus::cajas::{CajaId, EtapaCaja, Ocupante, RegistroCaja};
use zx_consensus::sectores::{
    ClaveVoto, ClaveVotoAnterior, Etapa, PorepVigente, PruebaVigente, RegistroSector, SectorId,
};
use zx_consensus::transicion::{
    EnRetirada, EntradaUtxo, Estado, Fase, Garantia, Incidente, Origen, Pendiente, Punto,
};
use zx_core::{BlockHash, ClavePublica, ClaveTablaVoto, Lock, OutPoint};

/// Dominio del resumen de estado (no es una etiqueta de consenso). `v3` añade la finalidad por votos
/// (`FV-4b-N2`), `v4` la capa de sorteo verificable (`FV-4b-N3`: tablas por instancia,
/// compromisos, revelaciones, votantes y suspensiones derivadas), `v5` los campos de AUS-2a que
/// AUS-2b hace visibles (`deuda_ausencia` y `liquidacion_voto_hasta`), `v6` los de PD-1b (C2:
/// contenido de tablas por hash; C5: asociación ventana→tabla), `v7` la instantánea de la tabla
/// del ciclo de rearranque de RA-1 (`tabla_ciclo_rearranque`), **`v8` retira del resumen el estado
/// del sorteo** (la `K` de `tablas_voto`, los compromisos, las revelaciones y las suspensiones
/// materializadas), que M9-b2 borró del estado, **`v9` añade las claves de voto anteriores vivas**
/// de RK-2 (`claves_voto_previas`), **`v10` añade la cola de tablas derivadas** de TB-1a
/// (`cola_tablas_voto`), **`v11` añade la última ventana derivada sin base** de TB-1c-2
/// (`ultima_ventana_derivada_sin_base`), **`v12` añade la raíz del último certificado** de RE-2c
/// (`raiz_estado`) y **`v13` añade todo lo que la raíz de estado cubría y el resumen no** (IPA B-80,
/// ORDEN-B80-1): `Garantia.incidentes`, los diez escalares que faltaban, las familias `pruebas`,
/// `poreps`, `claves_voto` y `ultimo_slot_producido`, y `vencimientos_clave_voto`.
const DOMINIO: &[u8] = b"zx-node/resumen-estado/v13";

fn codificar_len(buf: &mut Vec<u8>, n: usize) {
    #[expect(
        clippy::unwrap_used,
        reason = "un estado real nunca tiene más de u64::MAX entradas"
    )]
    let n64 = u64::try_from(n).unwrap();
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

fn codificar_fase(buf: &mut Vec<u8>, fase: Fase) {
    let codigo: u8 = match fase {
        Fase::Genesis => 0,
        Fase::PoW => 1,
        Fase::PoST => 2,
    };
    buf.push(codigo);
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

fn codificar_opcion_u32(buf: &mut Vec<u8>, v: Option<u32>) {
    match v {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        None => buf.push(0),
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
    // ORDEN-B80-1 · R1 · `incidentes`: longitud y, por cada uno, todos sus campos, al final de la
    // garantía (los bytes que ya había no se mueven). La raíz de estado los cubría y el resumen no.
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

/// Clave del mapa de `sectores` (la «clave canónica» de la hoja). La raíz la escribe aparte del
/// valor, y el valor vuelve a llevar `RegistroSector.id`; el resumen reproduce ambos para no perder
/// la sensibilidad a ninguno de los dos (ORDEN-B80-1).
fn codificar_sector_id(buf: &mut Vec<u8>, id: &SectorId) {
    let SectorId {
        clave,
        sector_index,
        version,
    } = id;
    buf.extend_from_slice(clave.bytes());
    buf.extend_from_slice(&sector_index.to_be_bytes());
    buf.extend_from_slice(&version.to_be_bytes());
}

fn codificar_registro_sector(buf: &mut Vec<u8>, r: &RegistroSector) {
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
    codificar_sector_id(buf, id);
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

/// Clave del mapa de `cajas` (la «clave canónica» de la hoja). El valor (`RegistroCaja.id`) se
/// escribe aparte, como en la raíz (ORDEN-B80-1).
fn codificar_caja_id(buf: &mut Vec<u8>, id: &CajaId) {
    let CajaId { clave, seq } = id;
    buf.extend_from_slice(clave.bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
}

fn codificar_registro_caja(buf: &mut Vec<u8>, c: &RegistroCaja) {
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
    codificar_caja_id(buf, id);
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

fn codificar_prueba(buf: &mut Vec<u8>, p: &PruebaVigente) {
    let PruebaVigente {
        slot_prueba,
        raiz_conjunto,
        n_sectores,
    } = p;
    buf.extend_from_slice(&slot_prueba.to_be_bytes());
    for w in raiz_conjunto {
        buf.extend_from_slice(&w.to_be_bytes());
    }
    buf.extend_from_slice(&n_sectores.to_be_bytes());
}

fn codificar_porep(buf: &mut Vec<u8>, p: &PorepVigente) {
    let PorepVigente {
        slot_ventana,
        raiz_lote,
        n_sectores,
    } = p;
    buf.extend_from_slice(&slot_ventana.to_be_bytes());
    for w in raiz_lote {
        buf.extend_from_slice(&w.to_be_bytes());
    }
    buf.extend_from_slice(&n_sectores.to_be_bytes());
}

fn codificar_clave_voto(buf: &mut Vec<u8>, c: &ClaveVoto) {
    let ClaveVoto {
        clave_bls,
        prueba_posesion,
    } = c;
    buf.extend_from_slice(clave_bls);
    buf.extend_from_slice(prueba_posesion);
}

fn codificar_clave_voto_anterior(buf: &mut Vec<u8>, c: &ClaveVotoAnterior) {
    let ClaveVotoAnterior {
        clave_bls,
        prueba_posesion,
        vencimiento,
    } = c;
    buf.extend_from_slice(clave_bls);
    buf.extend_from_slice(prueba_posesion);
    buf.extend_from_slice(&vencimiento.to_be_bytes());
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

/// Codificación canónica del estado, tal como la documenta el módulo.
#[must_use]
pub fn codificar_estado(estado: &Estado) -> Vec<u8> {
    // ORDEN-B80-1 · R2 · `Estado` se desestructura entero y sin `..`: un campo nuevo rompe la
    // compilación hasta decidir si entra en el resumen. `parametros_sector` se descarta a propósito,
    // porque la raíz de estado tampoco lo cubre (lo fija el perfil de la red, no la cadena; A1-B1-2
    // C6/K3).
    let Estado {
        utxo,
        garantias,
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
        ultimo_slot_producido,
        sectores,
        parametros_sector: _,
        cajas,
        pruebas,
        poreps,
        claves_voto,
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
    buf.extend_from_slice(DOMINIO);
    codificar_len(&mut buf, utxo.len());
    for (op, e) in utxo {
        codificar_entrada_utxo(&mut buf, op, e);
    }
    codificar_len(&mut buf, garantias.len());
    for (pk, g) in garantias {
        codificar_garantia(&mut buf, pk, g);
    }
    buf.extend_from_slice(&emitido.to_be_bytes());
    codificar_len(&mut buf, sectores.len());
    for (id, r) in sectores {
        // Clave del mapa y valor (`r.id` incluido): la raíz cubre los dos por separado.
        codificar_sector_id(&mut buf, id);
        codificar_registro_sector(&mut buf, r);
    }
    codificar_len(&mut buf, cajas.len());
    for (id, c) in cajas {
        // Clave del mapa y valor (`c.id` incluido).
        codificar_caja_id(&mut buf, id);
        codificar_registro_caja(&mut buf, c);
    }
    // FV-4b-N2 · punto de finalidad por votos como estado (monótono).
    buf.extend_from_slice(&finalidad_votos_n.to_be_bytes());
    match finalidad_votos {
        Some(h) => {
            buf.push(1);
            buf.extend_from_slice(h.as_bytes());
        }
        None => buf.push(0),
    }
    match finalidad_votos_h_t {
        Some(h) => {
            buf.push(1);
            buf.extend_from_slice(h);
        }
        None => buf.push(0),
    }
    // RE-2c · C6 · raíz del último certificado aplicado (`None` = ninguno). Dos estados idénticos
    // salvo esta raíz dan resúmenes distintos.
    match raiz_estado {
        Some(h) => {
            buf.push(1);
            buf.extend_from_slice(h);
        }
        None => buf.push(0),
    }
    // M9-b2 · tablas por ventana (sin la `K` del sorteo).
    codificar_len(&mut buf, tablas_voto.len());
    for (n, claves) in tablas_voto {
        buf.extend_from_slice(&n.to_be_bytes());
        codificar_len(&mut buf, claves.len());
        for c in claves {
            codificar_clave_tabla(&mut buf, c);
        }
    }
    // PD-1b · C2/C5 · contenido de tablas por hash y asociación ventana→tabla vigente.
    codificar_len(&mut buf, tablas_voto_contenido.len());
    for (h, claves) in tablas_voto_contenido {
        buf.extend_from_slice(h);
        codificar_len(&mut buf, claves.len());
        for c in claves {
            codificar_clave_tabla(&mut buf, c);
        }
    }
    codificar_len(&mut buf, tabla_ventana_voto.len());
    for (n, h) in tabla_ventana_voto {
        buf.extend_from_slice(&n.to_be_bytes());
        buf.extend_from_slice(h);
    }
    // RA-1 · Y1 · instantánea de la tabla del ciclo de rearranque (`ciclo → hash`).
    codificar_len(&mut buf, tabla_ciclo_rearranque.len());
    for (j, h) in tabla_ciclo_rearranque {
        buf.extend_from_slice(&j.to_be_bytes());
        buf.extend_from_slice(h);
    }
    // TB-1a · R1 · cola `Q` de tablas derivadas: pares `(ventana, huella)` en orden de inserción.
    codificar_len(&mut buf, cola_tablas_voto.len());
    for (n, h) in cola_tablas_voto {
        buf.extend_from_slice(&n.to_be_bytes());
        buf.extend_from_slice(h);
    }
    // TB-1c-2 · X1 · última ventana derivada sin base (el gancho de T1′).
    match ultima_ventana_derivada_sin_base {
        Some(k) => {
            buf.push(1);
            buf.extend_from_slice(&k.to_be_bytes());
        }
        None => buf.push(0),
    }
    // M9-b2 · votantes admitidos por ventana (lo único que queda de la capa de sorteo).
    codificar_len(&mut buf, votantes_voto.len());
    for (n, votantes) in votantes_voto {
        buf.extend_from_slice(&n.to_be_bytes());
        codificar_len(&mut buf, votantes.len());
        for clave in votantes {
            buf.extend_from_slice(clave.bytes());
        }
    }
    // AUS-2b · N9 · deuda de ausencia acumulada por clave (AUS-2a) y hasta qué ventana se ha
    // liquidado. Sin ellos, una divergencia en esos dos campos no la vería la comparación de humos.
    codificar_len(&mut buf, deuda_ausencia.len());
    for (clave, deuda) in deuda_ausencia {
        buf.extend_from_slice(clave.bytes());
        buf.extend_from_slice(&deuda.to_be_bytes());
    }
    match liquidacion_voto_hasta {
        Some(n) => {
            buf.push(1);
            buf.extend_from_slice(&n.to_be_bytes());
        }
        None => buf.push(0),
    }
    // RK-2 · V7 · claves de voto anteriores vivas: `clave Ed25519 ‖ clave BLS (48) ‖ prueba de
    // posesión (96) ‖ vencimiento u64 BE`, en orden del BTreeMap.
    codificar_len(&mut buf, claves_voto_previas.len());
    for (clave_ed, prev) in claves_voto_previas {
        buf.extend_from_slice(clave_ed.bytes());
        codificar_clave_voto_anterior(&mut buf, prev);
    }
    // ------------------------------------------------------------------
    // ORDEN-B80-1 · R3 · campos que la raíz cubría y el resumen no. Se añaden al final del tipo
    // `Estado` (los bytes que ya había no se mueven).
    // ------------------------------------------------------------------
    // Escalares que la raíz mete en `h_escalares` y el resumen no escribía.
    buf.extend_from_slice(&quemado.to_be_bytes());
    codificar_fase(&mut buf, *fase);
    codificar_opcion_hash(&mut buf, terminal.as_ref());
    buf.extend_from_slice(&altura.to_be_bytes());
    buf.extend_from_slice(&trabajo.to_big_endian());
    buf.extend_from_slice(&slot.to_be_bytes());
    buf.extend_from_slice(&s0.to_be_bytes());
    buf.extend_from_slice(&peso_sufijo.to_be_bytes());
    codificar_opcion_u32(&mut buf, *altura_terminal);
    buf.extend_from_slice(&subsidio_acum.to_be_bytes());
    // SL-4a · familia `ultimo_slot_producido` (clave del mapa y valor).
    codificar_len(&mut buf, ultimo_slot_producido.len());
    for (pk, s) in ultimo_slot_producido {
        buf.extend_from_slice(pk.bytes());
        buf.extend_from_slice(&s.to_be_bytes());
    }
    // PT-3bc · familia `pruebas` (clave del mapa y valor).
    codificar_len(&mut buf, pruebas.len());
    for (pk, p) in pruebas {
        buf.extend_from_slice(pk.bytes());
        codificar_prueba(&mut buf, p);
    }
    // PT-3bc · familia `poreps` (clave del mapa y valor).
    codificar_len(&mut buf, poreps.len());
    for (pk, p) in poreps {
        buf.extend_from_slice(pk.bytes());
        codificar_porep(&mut buf, p);
    }
    // PT-3bc · familia `claves_voto` (clave del mapa y valor).
    codificar_len(&mut buf, claves_voto.len());
    for (pk, c) in claves_voto {
        buf.extend_from_slice(pk.bytes());
        codificar_clave_voto(&mut buf, c);
    }
    // RK-2 · V6 · índice por vencimiento (`vencimiento → identidades`).
    codificar_len(&mut buf, vencimientos_clave_voto.len());
    for (vencimiento, claves) in vencimientos_clave_voto {
        buf.extend_from_slice(&vencimiento.to_be_bytes());
        codificar_len(&mut buf, claves.len());
        for clave in claves {
            buf.extend_from_slice(clave.bytes());
        }
    }
    buf
}

/// `blake3` del estado, en hexadecimal, para el registro estructurado.
#[must_use]
pub fn resumen_estado(estado: &Estado) -> String {
    let bytes = codificar_estado(estado);
    blake3::hash(&bytes).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "pruebas del resumen: el fallo es un panic por diseño"
    )]

    use super::{DOMINIO, resumen_estado};
    use primitive_types::U256;
    use zx_consensus::cajas::{CajaId, EtapaCaja, Ocupante, RegistroCaja};
    use zx_consensus::sectores::{
        ClaveVoto, ClaveVotoAnterior, Etapa, PorepVigente, PruebaVigente, RegistroSector, SectorId,
    };
    use zx_consensus::transicion::{
        EnRetirada, EntradaUtxo, Estado, Fase, Garantia, Incidente, Origen, Pendiente, Punto,
    };
    use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest, Lock, OutPoint, TxId};

    #[test]
    fn es_determinista_y_sensible_a_cambios() {
        let e1 = Estado::inicial();
        let e2 = Estado::inicial();
        assert_eq!(resumen_estado(&e1), resumen_estado(&e2));

        let mut e3 = Estado::inicial();
        e3.emitido = 1;
        assert_ne!(resumen_estado(&e1), resumen_estado(&e3));
    }

    /// AUS-2b · B9 · dos estados que solo difieren en `deuda_ausencia` (o solo en
    /// `liquidacion_voto_hasta`) dan resúmenes distintos.
    #[test]
    fn deuda_y_liquidacion_cambian_el_resumen() {
        let base = Estado::inicial();

        let mut con_deuda = base.clone();
        con_deuda
            .deuda_ausencia
            .insert(zx_core::ClavePublica::desde_bytes([7u8; 32]), 7);
        assert_ne!(
            resumen_estado(&base),
            resumen_estado(&con_deuda),
            "deuda_ausencia debe verse en el resumen"
        );

        let mut con_liquidacion = base.clone();
        con_liquidacion.liquidacion_voto_hasta = Some(3);
        assert_ne!(
            resumen_estado(&base),
            resumen_estado(&con_liquidacion),
            "liquidacion_voto_hasta debe verse en el resumen"
        );
    }

    /// TB-1a · §4.A · prueba 11 · dos estados que solo difieren en la cola `Q` de tablas derivadas
    /// dan resúmenes distintos.
    #[test]
    fn resumen_sensible_a_la_cola() {
        let base = Estado::inicial();
        let mut con_cola = base.clone();
        con_cola.cola_tablas_voto.push((7, [0x2a; 32]));
        assert_ne!(
            resumen_estado(&base),
            resumen_estado(&con_cola),
            "cola_tablas_voto debe verse en el resumen"
        );
    }

    /// RE-2c · C6 · dos estados idénticos salvo `raiz_estado` dan resúmenes distintos, y el dominio
    /// del resumen ha subido una versión respecto de la base (TB-1c-2 dejó `v11`; RE-2c usó `v12`;
    /// ORDEN-B80-1 usa `v13`).
    #[test]
    fn t_raiz_03_resumen_incluye_la_raiz() {
        assert_eq!(DOMINIO, b"zx-node/resumen-estado/v13");

        let base = Estado::inicial();
        let mut con_raiz = base.clone();
        con_raiz.raiz_estado = Some([0x2a; 32]);
        assert_ne!(
            resumen_estado(&base),
            resumen_estado(&con_raiz),
            "raiz_estado debe verse en el resumen"
        );

        let mut sin_raiz = con_raiz.clone();
        sin_raiz.raiz_estado = None;
        assert_eq!(resumen_estado(&base), resumen_estado(&sin_raiz));
    }

    /// ORDEN-B80-1 · §3.1 · los incidentes de una garantía cambian el resumen: añadir, quitar y
    /// cambiar cada campo de un incidente.
    #[test]
    fn rsm_01_los_incidentes_de_la_garantia_cambian_el_resumen() {
        let base = estado_fijo();
        let antes = resumen_estado(&base);

        let mut anadido = base.clone();
        if let Some(g) = anadido.garantias.values_mut().next() {
            g.incidentes.push(Incidente {
                id: [0x3A; 32],
                slot_falta: 31,
            });
        }
        assert_ne!(
            resumen_estado(&anadido),
            antes,
            "añadir un incidente no cambia el resumen"
        );

        let mut quitado = base.clone();
        if let Some(g) = quitado.garantias.values_mut().next() {
            g.incidentes.pop();
        }
        assert_ne!(
            resumen_estado(&quitado),
            antes,
            "quitar el incidente no cambia el resumen"
        );

        let mut otro_id = base.clone();
        if let Some(i) = otro_id
            .garantias
            .values_mut()
            .next()
            .and_then(|g| g.incidentes.first_mut())
        {
            i.id = [0x4A; 32];
        }
        assert_ne!(
            resumen_estado(&otro_id),
            antes,
            "cambiar el id del incidente no cambia el resumen"
        );

        let mut otro_slot = base.clone();
        if let Some(i) = otro_slot
            .garantias
            .values_mut()
            .next()
            .and_then(|g| g.incidentes.first_mut())
        {
            i.slot_falta = 99;
        }
        assert_ne!(
            resumen_estado(&otro_slot),
            antes,
            "cambiar slot_falta del incidente no cambia el resumen"
        );
    }

    /// ORDEN-B80-1 · §3.2 · un caso por campo de cada tipo que cubre la raíz (`canon.rs`), más cada
    /// elemento de cada colección: mutar un solo campo cambia el resumen.
    #[test]
    fn rsm_02_cada_campo_que_cubre_la_raiz_cambia_el_resumen() {
        let casos = casos();
        let n = casos.len();
        for (nombre, mut e, f) in casos {
            let antes = resumen_estado(&e);
            f(&mut e);
            assert_ne!(
                resumen_estado(&e),
                antes,
                "la mutación «{nombre}» no cambia el resumen"
            );
        }
        assert_eq!(n, 193, "número de mutaciones contadas");
    }

    /// ORDEN-B80-1 · §3.3 · dos estados iguales dan el mismo resumen.
    #[test]
    fn rsm_03_dos_estados_iguales_dan_el_mismo_resumen() {
        let a = estado_fijo();
        let b = estado_fijo();
        assert_eq!(a, b);
        assert_eq!(resumen_estado(&a), resumen_estado(&b));

        let c = Estado::inicial();
        let d = Estado::inicial();
        assert_eq!(resumen_estado(&c), resumen_estado(&d));
    }

    fn clave(n: u8) -> ClavePublica {
        ClavePublica::desde_bytes([n; 32])
    }

    fn hash(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
            prev_index: u32::from(n),
        }
    }

    fn amount(n: i64) -> Amount {
        Amount::nuevo(n).unwrap()
    }
    fn tabla() -> ClaveTablaVoto {
        ClaveTablaVoto {
            clave_bls: [0xF1; 48],
            peso: 60,
            activo: true,
            prueba: true,
            garantia: 61,
        }
    }
    /// Estado fijo con al menos una entrada por familia y todos los escalares y campos del libro
    /// distintos de su valor por defecto.
    fn estado_fijo() -> Estado {
        let mut e = Estado::inicial();

        e.emitido = 11;
        e.quemado = 22;
        e.fase = Fase::PoST;
        e.terminal = Some(hash(0xA1));
        e.altura = 7;
        e.trabajo = U256::from(12_345u64);
        e.slot = 99;
        e.s0 = 88;
        e.peso_sufijo = 777;
        e.altura_terminal = Some(6);
        e.subsidio_acum = 33;

        let op = outpoint(1);
        e.utxo.insert(
            op,
            EntradaUtxo {
                valor: amount(500),
                lock: Lock::PubKey { pubkey: clave(9) },
                origen: Origen::Tx,
                creada: Punto::Altura(3),
            },
        );

        let mut g = Garantia::nueva();
        g.activo = amount(1000);
        g.pendientes = vec![Pendiente {
            importe: amount(7),
            madura_en_altura: Some(4),
            madura_en_slot: Some(5),
        }];
        g.en_retirada = vec![EnRetirada {
            importe: amount(8),
            inicio_slot: 6,
        }];
        g.congelado = amount(9);
        g.creditos = vec![Pendiente {
            importe: amount(10),
            madura_en_altura: None,
            madura_en_slot: Some(11),
        }];
        g.nonce_siguiente = 12;
        g.incidentes = vec![Incidente {
            id: [0x1A; 32],
            slot_falta: 13,
        }];
        e.garantias.insert(clave(2), g);

        let id = SectorId {
            clave: clave(3),
            sector_index: 4,
            version: 5,
        };
        e.sectores.insert(
            id,
            RegistroSector {
                id,
                r2: [1, 2, 3, 4],
                history_size: 16,
                etapa: Etapa::Activo,
                alta_slot: 20,
                renovacion_slot: 21,
                retiro_slot: 22,
                fianza: 23,
                aud_apertura: 24,
                aud_contestada: 25,
            },
        );

        let cid = CajaId {
            clave: clave(6),
            seq: 7,
        };
        let mut caja = RegistroCaja::nueva(cid, 30, 31);
        caja.raiz = [5, 6, 7, 8];
        caja.n = 1;
        caja.ocupacion = 0b1;
        caja.estado_hueco = 0b10;
        caja.etapa = EtapaCaja::Cerrada;
        caja.alta_slot = 32;
        caja.ultima_alta_slot = 33;
        caja.cierre_slot = 34;
        caja.renovacion_slot = 35;
        caja.retiro_slot = 36;
        caja.fianza = 37;
        caja.huecos[0].sector_index = 8;
        caja.huecos[0].version = 9;
        caja.huecos[0].ocupado = true;
        e.cajas.insert(cid, caja);

        e.pruebas.insert(
            clave(10),
            PruebaVigente {
                slot_prueba: 40,
                raiz_conjunto: [9, 10, 11, 12],
                n_sectores: 13,
            },
        );
        e.poreps.insert(
            clave(11),
            PorepVigente {
                slot_ventana: 41,
                raiz_lote: [13, 14, 15, 16],
                n_sectores: 17,
            },
        );
        e.claves_voto.insert(
            clave(12),
            ClaveVoto {
                clave_bls: [0xB1; 48],
                prueba_posesion: [0xB2; 96],
            },
        );
        e.ultimo_slot_producido.insert(clave(13), 42);

        e.claves_voto_previas.insert(
            clave(14),
            ClaveVotoAnterior {
                clave_bls: [0xC1; 48],
                prueba_posesion: [0xC2; 96],
                vencimiento: 50,
            },
        );
        e.vencimientos_clave_voto
            .insert(50, [clave(14)].into_iter().collect());
        e.finalidad_votos_n = 51;
        e.finalidad_votos = Some(hash(0xD1));
        e.finalidad_votos_h_t = Some([0xD2; 32]);
        e.raiz_estado = Some([0xD3; 32]);
        e.tablas_voto.insert(52, vec![tabla()]);
        e.tablas_voto_contenido.insert([0xE1; 32], vec![tabla()]);
        e.tabla_ventana_voto.insert(53, [0xE2; 32]);
        e.tabla_ciclo_rearranque.insert(54, [0xE3; 32]);
        e.cola_tablas_voto.push((55, [0xE4; 32]));
        e.ultima_ventana_derivada_sin_base = Some(56);
        e.votantes_voto
            .insert(57, [clave(15)].into_iter().collect());
        e.deuda_ausencia.insert(clave(16), 58);
        e.liquidacion_voto_hasta = Some(59);
        e
    }
    /// Prepara el estado con un `MultiSig` de dos claves en su única salida.
    fn con_multisig(mut e: Estado) -> Estado {
        if let Some(ent) = e.utxo.values_mut().next() {
            ent.lock = Lock::MultiSig {
                k: 1,
                pubkeys: vec![clave(20), clave(21)],
            };
        }
        e
    }

    /// Prepara el estado con un `Htlc` en su única salida.
    fn con_htlc(mut e: Estado) -> Estado {
        if let Some(ent) = e.utxo.values_mut().next() {
            ent.lock = Lock::Htlc {
                hash: [0x33; 32],
                receiver: clave(22),
                sender: clave(23),
                timeout: 24,
            };
        }
        e
    }

    /// Prepara la garantía con dos elementos en cada colección (para cubrir cada elemento).
    fn con_garantia_llena(mut e: Estado) -> Estado {
        if let Some(g) = e.garantias.values_mut().next() {
            g.pendientes = vec![
                Pendiente {
                    importe: amount(7),
                    madura_en_altura: Some(4),
                    madura_en_slot: Some(5),
                },
                Pendiente {
                    importe: amount(70),
                    madura_en_altura: None,
                    madura_en_slot: Some(50),
                },
            ];
            g.en_retirada = vec![
                EnRetirada {
                    importe: amount(8),
                    inicio_slot: 6,
                },
                EnRetirada {
                    importe: amount(80),
                    inicio_slot: 60,
                },
            ];
            g.creditos = vec![
                Pendiente {
                    importe: amount(10),
                    madura_en_altura: None,
                    madura_en_slot: Some(11),
                },
                Pendiente {
                    importe: amount(100),
                    madura_en_altura: Some(99),
                    madura_en_slot: None,
                },
            ];
            g.incidentes = vec![
                Incidente {
                    id: [0x1A; 32],
                    slot_falta: 13,
                },
                Incidente {
                    id: [0x2A; 32],
                    slot_falta: 23,
                },
            ];
        }
        e
    }

    fn toca_utxo(e: &mut Estado, f: impl FnOnce(&mut EntradaUtxo)) {
        if let Some(ent) = e.utxo.values_mut().next() {
            f(ent);
        }
    }

    fn toca_garantia(e: &mut Estado, f: impl FnOnce(&mut Garantia)) {
        if let Some(g) = e.garantias.values_mut().next() {
            f(g);
        }
    }

    fn toca_pendiente(e: &mut Estado, idx: usize, f: impl FnOnce(&mut Pendiente)) {
        if let Some(p) = e
            .garantias
            .values_mut()
            .next()
            .and_then(|g| g.pendientes.get_mut(idx))
        {
            f(p);
        }
    }

    fn toca_credito(e: &mut Estado, idx: usize, f: impl FnOnce(&mut Pendiente)) {
        if let Some(p) = e
            .garantias
            .values_mut()
            .next()
            .and_then(|g| g.creditos.get_mut(idx))
        {
            f(p);
        }
    }

    fn toca_retirada(e: &mut Estado, idx: usize, f: impl FnOnce(&mut EnRetirada)) {
        if let Some(r) = e
            .garantias
            .values_mut()
            .next()
            .and_then(|g| g.en_retirada.get_mut(idx))
        {
            f(r);
        }
    }

    fn toca_incidente(e: &mut Estado, idx: usize, f: impl FnOnce(&mut Incidente)) {
        if let Some(i) = e
            .garantias
            .values_mut()
            .next()
            .and_then(|g| g.incidentes.get_mut(idx))
        {
            f(i);
        }
    }

    fn toca_sector(e: &mut Estado, f: impl FnOnce(&mut RegistroSector)) {
        if let Some(r) = e.sectores.values_mut().next() {
            f(r);
        }
    }

    fn toca_caja(e: &mut Estado, f: impl FnOnce(&mut RegistroCaja)) {
        if let Some(c) = e.cajas.values_mut().next() {
            f(c);
        }
    }

    fn toca_hueco(e: &mut Estado, idx: usize, f: impl FnOnce(&mut Ocupante)) {
        if let Some(h) = e
            .cajas
            .values_mut()
            .next()
            .and_then(|c| c.huecos.get_mut(idx))
        {
            f(h);
        }
    }

    fn toca_prueba(e: &mut Estado, f: impl FnOnce(&mut PruebaVigente)) {
        if let Some(p) = e.pruebas.values_mut().next() {
            f(p);
        }
    }

    fn toca_porep(e: &mut Estado, f: impl FnOnce(&mut PorepVigente)) {
        if let Some(p) = e.poreps.values_mut().next() {
            f(p);
        }
    }

    fn toca_clave_voto(e: &mut Estado, f: impl FnOnce(&mut ClaveVoto)) {
        if let Some(c) = e.claves_voto.values_mut().next() {
            f(c);
        }
    }
    type Caso = (&'static str, Estado, Box<dyn FnOnce(&mut Estado)>);

    /// Un caso por campo de cada tipo anidado y por cada elemento de cada colección. Cada caso parte
    /// de un estado preparado y muta **un solo** campo; el test exige que la raíz cambie.
    fn casos() -> Vec<Caso> {
        let base = estado_fijo();
        let base_ms = con_multisig(base.clone());
        let base_htlc = con_htlc(base.clone());
        let llena = con_garantia_llena(base.clone());
        let mut v: Vec<Caso> = Vec::new();
        macro_rules! caso {
            ($nombre:expr, $base:expr, $f:expr) => {
                v.push(($nombre, $base, Box::new($f)));
            };
        }

        // ---- utxo · clave OutPoint ----
        caso!("OutPoint.prev_txid", base.clone(), |e: &mut Estado| {
            let op = *e.utxo.keys().next().unwrap();
            let ent = e.utxo.remove(&op).unwrap();
            e.utxo.insert(
                OutPoint {
                    prev_txid: TxId::from_digest(Digest::from_bytes([0x91; 32])),
                    ..op
                },
                ent,
            );
        });
        caso!("OutPoint.prev_index", base.clone(), |e: &mut Estado| {
            let op = *e.utxo.keys().next().unwrap();
            let ent = e.utxo.remove(&op).unwrap();
            e.utxo.insert(
                OutPoint {
                    prev_index: op.prev_index.wrapping_add(1),
                    ..op
                },
                ent,
            );
        });

        // ---- utxo · EntradaUtxo ----
        caso!("EntradaUtxo.valor", base.clone(), |e: &mut Estado| {
            toca_utxo(e, |x| x.valor = amount(501));
        });
        caso!("Lock.PubKey.pubkey", base.clone(), |e: &mut Estado| {
            toca_utxo(e, |x| {
                x.lock = Lock::PubKey {
                    pubkey: clave(0x99),
                }
            });
        });
        caso!("Lock.MultiSig.k", base_ms.clone(), |e: &mut Estado| {
            toca_utxo(e, |x| {
                x.lock = Lock::MultiSig {
                    k: 2,
                    pubkeys: vec![clave(20), clave(21)],
                };
            });
        });
        caso!(
            "Lock.MultiSig.pubkeys[0]",
            base_ms.clone(),
            |e: &mut Estado| {
                toca_utxo(e, |x| {
                    x.lock = Lock::MultiSig {
                        k: 1,
                        pubkeys: vec![clave(0x20), clave(21)],
                    };
                });
            }
        );
        caso!(
            "Lock.MultiSig.pubkeys[1]",
            base_ms.clone(),
            |e: &mut Estado| {
                toca_utxo(e, |x| {
                    x.lock = Lock::MultiSig {
                        k: 1,
                        pubkeys: vec![clave(20), clave(0x21)],
                    };
                });
            }
        );
        caso!(
            "Lock.MultiSig.pubkeys.len",
            base_ms.clone(),
            |e: &mut Estado| {
                toca_utxo(e, |x| {
                    x.lock = Lock::MultiSig {
                        k: 1,
                        pubkeys: vec![clave(20), clave(21), clave(22)],
                    };
                });
            }
        );
        caso!("Lock.Htlc.hash", base_htlc.clone(), |e: &mut Estado| {
            toca_utxo(e, |x| {
                x.lock = Lock::Htlc {
                    hash: [0x44; 32],
                    receiver: clave(22),
                    sender: clave(23),
                    timeout: 24,
                };
            });
        });
        caso!("Lock.Htlc.receiver", base_htlc.clone(), |e: &mut Estado| {
            toca_utxo(e, |x| {
                x.lock = Lock::Htlc {
                    hash: [0x33; 32],
                    receiver: clave(0x22),
                    sender: clave(23),
                    timeout: 24,
                };
            });
        });
        caso!("Lock.Htlc.sender", base_htlc.clone(), |e: &mut Estado| {
            toca_utxo(e, |x| {
                x.lock = Lock::Htlc {
                    hash: [0x33; 32],
                    receiver: clave(22),
                    sender: clave(0x23),
                    timeout: 24,
                };
            });
        });
        caso!("Lock.Htlc.timeout", base_htlc.clone(), |e: &mut Estado| {
            toca_utxo(e, |x| {
                x.lock = Lock::Htlc {
                    hash: [0x33; 32],
                    receiver: clave(22),
                    sender: clave(23),
                    timeout: 25,
                };
            });
        });
        caso!(
            "EntradaUtxo.origen.CoinbasePow",
            base.clone(),
            |e: &mut Estado| {
                toca_utxo(e, |x| x.origen = Origen::CoinbasePow);
            }
        );
        caso!(
            "EntradaUtxo.origen.Liberacion",
            base.clone(),
            |e: &mut Estado| {
                toca_utxo(e, |x| x.origen = Origen::Liberacion);
            }
        );
        caso!("EntradaUtxo.creada.Slot", base.clone(), |e: &mut Estado| {
            toca_utxo(e, |x| x.creada = Punto::Slot(3));
        });
        caso!(
            "EntradaUtxo.creada.Altura",
            base.clone(),
            |e: &mut Estado| {
                toca_utxo(e, |x| x.creada = Punto::Altura(4));
            }
        );

        // ---- garantias · escalares y longitud de colecciones ----
        caso!("Garantia.activo", base.clone(), |e: &mut Estado| {
            toca_garantia(e, |g| g.activo = amount(1001));
        });
        caso!("Garantia.congelado", base.clone(), |e: &mut Estado| {
            toca_garantia(e, |g| g.congelado = amount(91));
        });
        caso!(
            "Garantia.nonce_siguiente",
            base.clone(),
            |e: &mut Estado| {
                toca_garantia(e, |g| g.nonce_siguiente = 13);
            }
        );
        caso!("Garantia.pendientes.len", base.clone(), |e: &mut Estado| {
            toca_garantia(e, |g| {
                g.pendientes.push(Pendiente {
                    importe: amount(70),
                    madura_en_altura: None,
                    madura_en_slot: None,
                });
            });
        });
        caso!(
            "Garantia.en_retirada.len",
            base.clone(),
            |e: &mut Estado| {
                toca_garantia(e, |g| {
                    g.en_retirada.push(EnRetirada {
                        importe: amount(80),
                        inicio_slot: 60,
                    });
                });
            }
        );
        caso!("Garantia.creditos.len", base.clone(), |e: &mut Estado| {
            toca_garantia(e, |g| {
                g.creditos.push(Pendiente {
                    importe: amount(100),
                    madura_en_altura: Some(99),
                    madura_en_slot: None,
                });
            });
        });
        caso!("Garantia.incidentes.len", base.clone(), |e: &mut Estado| {
            toca_garantia(e, |g| {
                g.incidentes.push(Incidente {
                    id: [0x3A; 32],
                    slot_falta: 31,
                });
            });
        });
        caso!("Garantia.clave", base.clone(), |e: &mut Estado| {
            let pk = *e.garantias.keys().next().unwrap();
            let g = e.garantias.remove(&pk).unwrap();
            e.garantias.insert(clave(0x52), g);
        });

        // ---- garantias · Pendiente (pendientes) ----
        caso!(
            "Pendiente.pendientes[0].importe",
            llena.clone(),
            |e: &mut Estado| {
                toca_pendiente(e, 0, |p| p.importe = amount(701));
            }
        );
        caso!(
            "Pendiente.pendientes[1].importe",
            llena.clone(),
            |e: &mut Estado| {
                toca_pendiente(e, 1, |p| p.importe = amount(7001));
            }
        );
        caso!(
            "Pendiente.pendientes[0].madura_en_altura",
            llena.clone(),
            |e: &mut Estado| {
                toca_pendiente(e, 0, |p| p.madura_en_altura = Some(40));
            }
        );
        caso!(
            "Pendiente.pendientes[1].madura_en_altura",
            llena.clone(),
            |e: &mut Estado| {
                toca_pendiente(e, 1, |p| p.madura_en_altura = Some(40));
            }
        );
        caso!(
            "Pendiente.pendientes[0].madura_en_slot",
            llena.clone(),
            |e: &mut Estado| {
                toca_pendiente(e, 0, |p| p.madura_en_slot = Some(50));
            }
        );
        caso!(
            "Pendiente.pendientes[1].madura_en_slot",
            llena.clone(),
            |e: &mut Estado| {
                toca_pendiente(e, 1, |p| p.madura_en_slot = None);
            }
        );
        // ---- garantias · EnRetirada ----
        caso!("EnRetirada[0].importe", llena.clone(), |e: &mut Estado| {
            toca_retirada(e, 0, |r| r.importe = amount(801));
        });
        caso!("EnRetirada[1].importe", llena.clone(), |e: &mut Estado| {
            toca_retirada(e, 1, |r| r.importe = amount(8001));
        });
        caso!(
            "EnRetirada[0].inicio_slot",
            llena.clone(),
            |e: &mut Estado| {
                toca_retirada(e, 0, |r| r.inicio_slot = 61);
            }
        );
        caso!(
            "EnRetirada[1].inicio_slot",
            llena.clone(),
            |e: &mut Estado| {
                toca_retirada(e, 1, |r| r.inicio_slot = 601);
            }
        );
        // ---- garantias · Pendiente (creditos) ----
        caso!(
            "Pendiente.creditos[0].importe",
            llena.clone(),
            |e: &mut Estado| {
                toca_credito(e, 0, |p| p.importe = amount(101));
            }
        );
        caso!(
            "Pendiente.creditos[1].importe",
            llena.clone(),
            |e: &mut Estado| {
                toca_credito(e, 1, |p| p.importe = amount(1001));
            }
        );
        caso!(
            "Pendiente.creditos[0].madura_en_altura",
            llena.clone(),
            |e: &mut Estado| {
                toca_credito(e, 0, |p| p.madura_en_altura = Some(1));
            }
        );
        caso!(
            "Pendiente.creditos[1].madura_en_altura",
            llena.clone(),
            |e: &mut Estado| {
                toca_credito(e, 1, |p| p.madura_en_altura = None);
            }
        );
        caso!(
            "Pendiente.creditos[0].madura_en_slot",
            llena.clone(),
            |e: &mut Estado| {
                toca_credito(e, 0, |p| p.madura_en_slot = None);
            }
        );
        caso!(
            "Pendiente.creditos[1].madura_en_slot",
            llena.clone(),
            |e: &mut Estado| {
                toca_credito(e, 1, |p| p.madura_en_slot = Some(12));
            }
        );
        // ---- garantias · Incidente ----
        caso!("Incidente[0].id", llena.clone(), |e: &mut Estado| {
            toca_incidente(e, 0, |i| i.id = [0x4A; 32]);
        });
        caso!("Incidente[1].id", llena.clone(), |e: &mut Estado| {
            toca_incidente(e, 1, |i| i.id = [0x4B; 32]);
        });
        caso!(
            "Incidente[0].slot_falta",
            llena.clone(),
            |e: &mut Estado| {
                toca_incidente(e, 0, |i| i.slot_falta = 99);
            }
        );
        caso!(
            "Incidente[1].slot_falta",
            llena.clone(),
            |e: &mut Estado| {
                toca_incidente(e, 1, |i| i.slot_falta = 199);
            }
        );

        // ---- sectores · clave SectorId ----
        caso!("SectorId.clave", base.clone(), |e: &mut Estado| {
            let id = *e.sectores.keys().next().unwrap();
            let r = e.sectores.remove(&id).unwrap();
            e.sectores.insert(
                SectorId {
                    clave: clave(0x53),
                    ..id
                },
                r,
            );
        });
        caso!("SectorId.sector_index", base.clone(), |e: &mut Estado| {
            let id = *e.sectores.keys().next().unwrap();
            let r = e.sectores.remove(&id).unwrap();
            e.sectores.insert(
                SectorId {
                    sector_index: id.sector_index.wrapping_add(1),
                    ..id
                },
                r,
            );
        });
        caso!("SectorId.version", base.clone(), |e: &mut Estado| {
            let id = *e.sectores.keys().next().unwrap();
            let r = e.sectores.remove(&id).unwrap();
            e.sectores.insert(
                SectorId {
                    version: id.version.wrapping_add(10),
                    ..id
                },
                r,
            );
        });
        // ---- sectores · RegistroSector ----
        caso!("RegistroSector.id.clave", base.clone(), |e: &mut Estado| {
            toca_sector(e, |r| r.id.clave = clave(0x54));
        });
        caso!(
            "RegistroSector.id.sector_index",
            base.clone(),
            |e: &mut Estado| {
                toca_sector(e, |r| r.id.sector_index = 99);
            }
        );
        caso!(
            "RegistroSector.id.version",
            base.clone(),
            |e: &mut Estado| {
                toca_sector(e, |r| r.id.version = 99);
            }
        );
        for j in 0..4usize {
            caso!(
                "RegistroSector.r2[j]",
                base.clone(),
                move |e: &mut Estado| {
                    toca_sector(e, |r| {
                        if let Some(w) = r.r2.get_mut(j) {
                            *w = w.wrapping_add(100);
                        }
                    });
                }
            );
        }
        caso!(
            "RegistroSector.history_size",
            base.clone(),
            |e: &mut Estado| {
                toca_sector(e, |r| r.history_size = 999);
            }
        );
        caso!("RegistroSector.etapa", base.clone(), |e: &mut Estado| {
            toca_sector(e, |r| r.etapa = Etapa::Caducado);
        });
        caso!(
            "RegistroSector.alta_slot",
            base.clone(),
            |e: &mut Estado| {
                toca_sector(e, |r| r.alta_slot = 999);
            }
        );
        caso!(
            "RegistroSector.renovacion_slot",
            base.clone(),
            |e: &mut Estado| {
                toca_sector(e, |r| r.renovacion_slot = 999);
            }
        );
        caso!(
            "RegistroSector.retiro_slot",
            base.clone(),
            |e: &mut Estado| {
                toca_sector(e, |r| r.retiro_slot = 999);
            }
        );
        caso!("RegistroSector.fianza", base.clone(), |e: &mut Estado| {
            toca_sector(e, |r| r.fianza = 999);
        });
        caso!(
            "RegistroSector.aud_apertura",
            base.clone(),
            |e: &mut Estado| {
                toca_sector(e, |r| r.aud_apertura = 999);
            }
        );
        caso!(
            "RegistroSector.aud_contestada",
            base.clone(),
            |e: &mut Estado| {
                toca_sector(e, |r| r.aud_contestada = 999);
            }
        );

        // ---- cajas · clave CajaId ----
        caso!("CajaId.clave", base.clone(), |e: &mut Estado| {
            let id = *e.cajas.keys().next().unwrap();
            let c = e.cajas.remove(&id).unwrap();
            e.cajas.insert(
                CajaId {
                    clave: clave(0x55),
                    ..id
                },
                c,
            );
        });
        caso!("CajaId.seq", base.clone(), |e: &mut Estado| {
            let id = *e.cajas.keys().next().unwrap();
            let c = e.cajas.remove(&id).unwrap();
            e.cajas.insert(
                CajaId {
                    seq: id.seq.wrapping_add(1),
                    ..id
                },
                c,
            );
        });
        // ---- cajas · RegistroCaja ----
        caso!("RegistroCaja.id.clave", base.clone(), |e: &mut Estado| {
            toca_caja(e, |c| c.id.clave = clave(0x56));
        });
        caso!("RegistroCaja.id.seq", base.clone(), |e: &mut Estado| {
            toca_caja(e, |c| c.id.seq = 99);
        });
        for j in 0..4usize {
            caso!(
                "RegistroCaja.raiz[j]",
                base.clone(),
                move |e: &mut Estado| {
                    toca_caja(e, |c| {
                        if let Some(w) = c.raiz.get_mut(j) {
                            *w = w.wrapping_add(100);
                        }
                    });
                }
            );
        }
        caso!("RegistroCaja.n", base.clone(), |e: &mut Estado| {
            toca_caja(e, |c| c.n = 2);
        });
        caso!("RegistroCaja.ocupacion", base.clone(), |e: &mut Estado| {
            toca_caja(e, |c| c.ocupacion = 0b10);
        });
        caso!(
            "RegistroCaja.estado_hueco",
            base.clone(),
            |e: &mut Estado| {
                toca_caja(e, |c| c.estado_hueco = 0b11);
            }
        );
        caso!(
            "RegistroCaja.history_size",
            base.clone(),
            |e: &mut Estado| {
                toca_caja(e, |c| c.history_size = 999);
            }
        );
        caso!("RegistroCaja.etapa", base.clone(), |e: &mut Estado| {
            toca_caja(e, |c| c.etapa = EtapaCaja::Abierta);
        });
        caso!("RegistroCaja.alta_slot", base.clone(), |e: &mut Estado| {
            toca_caja(e, |c| c.alta_slot = 999);
        });
        caso!(
            "RegistroCaja.ultima_alta_slot",
            base.clone(),
            |e: &mut Estado| {
                toca_caja(e, |c| c.ultima_alta_slot = 999);
            }
        );
        caso!(
            "RegistroCaja.cierre_slot",
            base.clone(),
            |e: &mut Estado| {
                toca_caja(e, |c| c.cierre_slot = 999);
            }
        );
        caso!(
            "RegistroCaja.renovacion_slot",
            base.clone(),
            |e: &mut Estado| {
                toca_caja(e, |c| c.renovacion_slot = 999);
            }
        );
        caso!(
            "RegistroCaja.retiro_slot",
            base.clone(),
            |e: &mut Estado| {
                toca_caja(e, |c| c.retiro_slot = 999);
            }
        );
        caso!("RegistroCaja.fianza", base.clone(), |e: &mut Estado| {
            toca_caja(e, |c| c.fianza = 999);
        });
        for j in 0..16usize {
            caso!(
                "RegistroCaja.huecos[j].sector_index",
                base.clone(),
                move |e: &mut Estado| {
                    toca_hueco(e, j, |h| h.sector_index = h.sector_index.wrapping_add(1));
                }
            );
            caso!(
                "RegistroCaja.huecos[j].version",
                base.clone(),
                move |e: &mut Estado| {
                    toca_hueco(e, j, |h| h.version = h.version.wrapping_add(1));
                }
            );
            caso!(
                "RegistroCaja.huecos[j].ocupado",
                base.clone(),
                move |e: &mut Estado| {
                    toca_hueco(e, j, |h| h.ocupado = !h.ocupado);
                }
            );
        }

        // ---- pruebas ----
        caso!("PruebaVigente.clave", base.clone(), |e: &mut Estado| {
            let pk = *e.pruebas.keys().next().unwrap();
            let p = e.pruebas.remove(&pk).unwrap();
            e.pruebas.insert(clave(0x57), p);
        });
        caso!(
            "PruebaVigente.slot_prueba",
            base.clone(),
            |e: &mut Estado| {
                toca_prueba(e, |p| p.slot_prueba = 999);
            }
        );
        for j in 0..4usize {
            caso!(
                "PruebaVigente.raiz_conjunto[j]",
                base.clone(),
                move |e: &mut Estado| {
                    toca_prueba(e, |p| {
                        if let Some(w) = p.raiz_conjunto.get_mut(j) {
                            *w = w.wrapping_add(100);
                        }
                    });
                }
            );
        }
        caso!(
            "PruebaVigente.n_sectores",
            base.clone(),
            |e: &mut Estado| {
                toca_prueba(e, |p| p.n_sectores = 99);
            }
        );

        // ---- poreps ----
        caso!("PorepVigente.clave", base.clone(), |e: &mut Estado| {
            let pk = *e.poreps.keys().next().unwrap();
            let p = e.poreps.remove(&pk).unwrap();
            e.poreps.insert(clave(0x58), p);
        });
        caso!(
            "PorepVigente.slot_ventana",
            base.clone(),
            |e: &mut Estado| {
                toca_porep(e, |p| p.slot_ventana = 999);
            }
        );
        for j in 0..4usize {
            caso!(
                "PorepVigente.raiz_lote[j]",
                base.clone(),
                move |e: &mut Estado| {
                    toca_porep(e, |p| {
                        if let Some(w) = p.raiz_lote.get_mut(j) {
                            *w = w.wrapping_add(100);
                        }
                    });
                }
            );
        }
        caso!("PorepVigente.n_sectores", base.clone(), |e: &mut Estado| {
            toca_porep(e, |p| p.n_sectores = 99);
        });

        // ---- claves_voto ----
        caso!("ClaveVoto.clave", base.clone(), |e: &mut Estado| {
            let pk = *e.claves_voto.keys().next().unwrap();
            let c = e.claves_voto.remove(&pk).unwrap();
            e.claves_voto.insert(clave(0x59), c);
        });
        caso!("ClaveVoto.clave_bls", base.clone(), |e: &mut Estado| {
            toca_clave_voto(e, |c| c.clave_bls = [0x99; 48]);
        });
        caso!(
            "ClaveVoto.prueba_posesion",
            base.clone(),
            |e: &mut Estado| {
                toca_clave_voto(e, |c| c.prueba_posesion = [0x98; 96]);
            }
        );

        // ---- ultimo_slot_producido ----
        caso!("ultimo_slot.clave", base.clone(), |e: &mut Estado| {
            let pk = *e.ultimo_slot_producido.keys().next().unwrap();
            let s = e.ultimo_slot_producido.remove(&pk).unwrap();
            e.ultimo_slot_producido.insert(clave(0x5A), s);
        });
        caso!("ultimo_slot.slot", base.clone(), |e: &mut Estado| {
            if let Some(s) = e.ultimo_slot_producido.values_mut().next() {
                *s = 999;
            }
        });

        // ---- escalares ----
        caso!("escalar.emitido", base.clone(), |e: &mut Estado| e
            .emitido =
            111);
        caso!("escalar.quemado", base.clone(), |e: &mut Estado| e
            .quemado =
            222);
        caso!("escalar.fase", base.clone(), |e: &mut Estado| e.fase =
            Fase::PoW);
        caso!("escalar.terminal", base.clone(), |e: &mut Estado| {
            e.terminal = Some(hash(0xA2));
        });
        caso!("escalar.altura", base.clone(), |e: &mut Estado| e.altura =
            71);
        caso!("escalar.trabajo", base.clone(), |e: &mut Estado| {
            e.trabajo = U256::from(12_346u64);
        });
        caso!("escalar.slot", base.clone(), |e: &mut Estado| e.slot = 991);
        caso!("escalar.s0", base.clone(), |e: &mut Estado| e.s0 = 881);
        caso!("escalar.peso_sufijo", base.clone(), |e: &mut Estado| e
            .peso_sufijo =
            7771);
        caso!("escalar.altura_terminal", base.clone(), |e: &mut Estado| {
            e.altura_terminal = Some(61);
        });
        caso!("escalar.subsidio_acum", base.clone(), |e: &mut Estado| e
            .subsidio_acum =
            331);

        // ---- libro · claves_voto_previas y ClaveVotoAnterior ----
        caso!(
            "libro.claves_voto_previas.clave",
            base.clone(),
            |e: &mut Estado| {
                let pk = *e.claves_voto_previas.keys().next().unwrap();
                let p = e.claves_voto_previas.remove(&pk).unwrap();
                e.claves_voto_previas.insert(clave(0x5B), p);
            }
        );
        caso!(
            "ClaveVotoAnterior.clave_bls",
            base.clone(),
            |e: &mut Estado| {
                if let Some(p) = e.claves_voto_previas.values_mut().next() {
                    p.clave_bls = [0xC9; 48];
                }
            }
        );
        caso!(
            "ClaveVotoAnterior.prueba_posesion",
            base.clone(),
            |e: &mut Estado| {
                if let Some(p) = e.claves_voto_previas.values_mut().next() {
                    p.prueba_posesion = [0xCA; 96];
                }
            }
        );
        caso!(
            "ClaveVotoAnterior.vencimiento",
            base.clone(),
            |e: &mut Estado| {
                if let Some(p) = e.claves_voto_previas.values_mut().next() {
                    p.vencimiento = 999;
                }
            }
        );
        // ---- libro · vencimientos_clave_voto ----
        caso!(
            "libro.vencimientos.clave",
            base.clone(),
            |e: &mut Estado| {
                let v = *e.vencimientos_clave_voto.keys().next().unwrap();
                let c = e.vencimientos_clave_voto.remove(&v).unwrap();
                e.vencimientos_clave_voto.insert(500, c);
            }
        );
        caso!(
            "libro.vencimientos.elemento",
            base.clone(),
            |e: &mut Estado| {
                let v = *e.vencimientos_clave_voto.keys().next().unwrap();
                if let Some(cs) = e.vencimientos_clave_voto.get_mut(&v) {
                    cs.insert(clave(0x5C));
                }
            }
        );
        // ---- libro · escalares del libro ----
        caso!("libro.finalidad_votos_n", base.clone(), |e: &mut Estado| {
            e.finalidad_votos_n = 511;
        });
        caso!("libro.finalidad_votos", base.clone(), |e: &mut Estado| {
            e.finalidad_votos = Some(hash(0xD4));
        });
        caso!(
            "libro.finalidad_votos_h_t",
            base.clone(),
            |e: &mut Estado| {
                e.finalidad_votos_h_t = Some([0xD5; 32]);
            }
        );
        caso!("libro.raiz_estado", base.clone(), |e: &mut Estado| {
            e.raiz_estado = Some([0xD6; 32]);
        });
        // ---- libro · tablas_voto y ClaveTablaVoto ----
        caso!("libro.tablas_voto.clave", base.clone(), |e: &mut Estado| {
            let n = *e.tablas_voto.keys().next().unwrap();
            let cs = e.tablas_voto.remove(&n).unwrap();
            e.tablas_voto.insert(520, cs);
        });
        caso!(
            "ClaveTablaVoto.tablas_voto.clave_bls",
            base.clone(),
            |e: &mut Estado| {
                if let Some(c) = e
                    .tablas_voto
                    .values_mut()
                    .next()
                    .and_then(|cs| cs.first_mut())
                {
                    c.clave_bls = [0xF9; 48];
                }
            }
        );
        caso!(
            "ClaveTablaVoto.tablas_voto.peso",
            base.clone(),
            |e: &mut Estado| {
                if let Some(c) = e
                    .tablas_voto
                    .values_mut()
                    .next()
                    .and_then(|cs| cs.first_mut())
                {
                    c.peso = 999;
                }
            }
        );
        caso!(
            "ClaveTablaVoto.tablas_voto.activo",
            base.clone(),
            |e: &mut Estado| {
                if let Some(c) = e
                    .tablas_voto
                    .values_mut()
                    .next()
                    .and_then(|cs| cs.first_mut())
                {
                    c.activo = false;
                }
            }
        );
        caso!(
            "ClaveTablaVoto.tablas_voto.prueba",
            base.clone(),
            |e: &mut Estado| {
                if let Some(c) = e
                    .tablas_voto
                    .values_mut()
                    .next()
                    .and_then(|cs| cs.first_mut())
                {
                    c.prueba = false;
                }
            }
        );
        caso!(
            "ClaveTablaVoto.tablas_voto.garantia",
            base.clone(),
            |e: &mut Estado| {
                if let Some(c) = e
                    .tablas_voto
                    .values_mut()
                    .next()
                    .and_then(|cs| cs.first_mut())
                {
                    c.garantia = 999;
                }
            }
        );
        // ---- libro · tablas_voto_contenido y ClaveTablaVoto ----
        caso!(
            "libro.tablas_voto_contenido.clave",
            base.clone(),
            |e: &mut Estado| {
                let h = *e.tablas_voto_contenido.keys().next().unwrap();
                let cs = e.tablas_voto_contenido.remove(&h).unwrap();
                e.tablas_voto_contenido.insert([0xE9; 32], cs);
            }
        );
        caso!(
            "ClaveTablaVoto.contenido.clave_bls",
            base.clone(),
            |e: &mut Estado| {
                if let Some(c) = e
                    .tablas_voto_contenido
                    .values_mut()
                    .next()
                    .and_then(|cs| cs.first_mut())
                {
                    c.clave_bls = [0xFA; 48];
                }
            }
        );
        caso!(
            "ClaveTablaVoto.contenido.peso",
            base.clone(),
            |e: &mut Estado| {
                if let Some(c) = e
                    .tablas_voto_contenido
                    .values_mut()
                    .next()
                    .and_then(|cs| cs.first_mut())
                {
                    c.peso = 999;
                }
            }
        );
        caso!(
            "ClaveTablaVoto.contenido.activo",
            base.clone(),
            |e: &mut Estado| {
                if let Some(c) = e
                    .tablas_voto_contenido
                    .values_mut()
                    .next()
                    .and_then(|cs| cs.first_mut())
                {
                    c.activo = false;
                }
            }
        );
        caso!(
            "ClaveTablaVoto.contenido.prueba",
            base.clone(),
            |e: &mut Estado| {
                if let Some(c) = e
                    .tablas_voto_contenido
                    .values_mut()
                    .next()
                    .and_then(|cs| cs.first_mut())
                {
                    c.prueba = false;
                }
            }
        );
        caso!(
            "ClaveTablaVoto.contenido.garantia",
            base.clone(),
            |e: &mut Estado| {
                if let Some(c) = e
                    .tablas_voto_contenido
                    .values_mut()
                    .next()
                    .and_then(|cs| cs.first_mut())
                {
                    c.garantia = 999;
                }
            }
        );
        // ---- libro · tabla_ventana_voto / tabla_ciclo_rearranque / cola ----
        caso!(
            "libro.tabla_ventana_voto.clave",
            base.clone(),
            |e: &mut Estado| {
                let n = *e.tabla_ventana_voto.keys().next().unwrap();
                let h = e.tabla_ventana_voto.remove(&n).unwrap();
                e.tabla_ventana_voto.insert(530, h);
            }
        );
        caso!(
            "libro.tabla_ventana_voto.valor",
            base.clone(),
            |e: &mut Estado| {
                if let Some(h) = e.tabla_ventana_voto.values_mut().next() {
                    *h = [0xE8; 32];
                }
            }
        );
        caso!(
            "libro.tabla_ciclo_rearranque.clave",
            base.clone(),
            |e: &mut Estado| {
                let n = *e.tabla_ciclo_rearranque.keys().next().unwrap();
                let h = e.tabla_ciclo_rearranque.remove(&n).unwrap();
                e.tabla_ciclo_rearranque.insert(540, h);
            }
        );
        caso!(
            "libro.tabla_ciclo_rearranque.valor",
            base.clone(),
            |e: &mut Estado| {
                if let Some(h) = e.tabla_ciclo_rearranque.values_mut().next() {
                    *h = [0xEA; 32];
                }
            }
        );
        caso!(
            "libro.cola_tablas_voto.ventana",
            base.clone(),
            |e: &mut Estado| {
                if let Some(par) = e.cola_tablas_voto.first_mut() {
                    par.0 = 550;
                }
            }
        );
        caso!(
            "libro.cola_tablas_voto.huella",
            base.clone(),
            |e: &mut Estado| {
                if let Some(par) = e.cola_tablas_voto.first_mut() {
                    par.1 = [0xEB; 32];
                }
            }
        );
        // ---- libro · ultima_ventana / votantes / deuda / liquidacion ----
        caso!(
            "libro.ultima_ventana_derivada_sin_base",
            base.clone(),
            |e: &mut Estado| {
                e.ultima_ventana_derivada_sin_base = Some(561);
            }
        );
        caso!(
            "libro.votantes_voto.clave",
            base.clone(),
            |e: &mut Estado| {
                let n = *e.votantes_voto.keys().next().unwrap();
                let vs = e.votantes_voto.remove(&n).unwrap();
                e.votantes_voto.insert(570, vs);
            }
        );
        caso!(
            "libro.votantes_voto.elemento",
            base.clone(),
            |e: &mut Estado| {
                let n = *e.votantes_voto.keys().next().unwrap();
                if let Some(vs) = e.votantes_voto.get_mut(&n) {
                    vs.insert(clave(0x5D));
                }
            }
        );
        caso!(
            "libro.deuda_ausencia.clave",
            base.clone(),
            |e: &mut Estado| {
                let pk = *e.deuda_ausencia.keys().next().unwrap();
                let d = e.deuda_ausencia.remove(&pk).unwrap();
                e.deuda_ausencia.insert(clave(0x60), d);
            }
        );
        caso!(
            "libro.deuda_ausencia.valor",
            base.clone(),
            |e: &mut Estado| {
                let pk = *e.deuda_ausencia.keys().next().unwrap();
                e.deuda_ausencia.insert(pk, 581);
            }
        );
        caso!(
            "libro.liquidacion_voto_hasta",
            base.clone(),
            |e: &mut Estado| {
                e.liquidacion_voto_hasta = Some(591);
            }
        );

        v
    }
}
