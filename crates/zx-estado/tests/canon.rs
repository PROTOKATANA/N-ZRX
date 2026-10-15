//! Pruebas canónicas de la raíz de estado (`P-ZRX/P-004/ORDEN-A1B1.md` §3,
//! `ORDEN-A1B1-2.md` §3).
//!
//! Las pruebas `canon_01`…`canon_12` fijan la codificación de C2–C5, la raíz de C8 y el puente de
//! C9, y que ningún campo de ningún tipo se queda fuera (K1/K2).
//! `cronometro_sin_medida_limpia` (§4) mide una vez los dos casos grandes y queda marcada como
//! **sin medida limpia**.

#![expect(
    clippy::unwrap_used,
    reason = "pruebas canónicas: el fallo es un panic por diseño"
)]

use primitive_types::U256;
use zx_consensus::cajas::{CajaId, EtapaCaja, Ocupante, RegistroCaja};
use zx_consensus::sectores::{
    ClaveVoto, ClaveVotoAnterior, Etapa, MotivoSector, ParametrosSector, PorepVigente,
    PruebaVigente, RegistroSector, SectorId,
};
use zx_consensus::transicion::{
    BloqueTransicion, EnRetirada, EntradaUtxo, Estado, Fase, Garantia, HechosCabecera, Incidente,
    Origen, ParametrosEvidencia, ParametrosTransicion, Pendiente, Punto, Undo, aplicar_con_undo,
    aplicar_operacion_con_undo, materializar_con_undo,
};
use zx_core::{
    Amount, BlockHash, CBID_RED_DEV, ClavePublica, ClaveTablaVoto, Digest, ExtensionTx, Lock,
    OperacionSector, OutPoint, Tx, TxId, TxOut,
};

use zx_estado::{
    AlmacenEnMemoria, Cambio, CaminoSha3, Estado as ArbolEstado, VERSION_CANON, cambios_de_undo,
    h_escalares, h_escalares_con_version, h_libro, hash_vacio, hoja_caja, hoja_clave_voto,
    hoja_garantia, hoja_porep, hoja_prueba, hoja_sector, hoja_ultimo_slot, hoja_utxo,
    hojas_de_estado, raiz_de_estado,
};

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

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

fn hx(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

fn arbol_de(estado: &Estado) -> ArbolEstado<AlmacenEnMemoria, CaminoSha3> {
    let mut arbol = ArbolEstado::nuevo(AlmacenEnMemoria::nuevo(), CaminoSha3);
    let cambios: Vec<Cambio> = hojas_de_estado(estado)
        .into_iter()
        .map(|(familia, clave, valor)| Cambio::poner(familia, clave, valor))
        .collect();
    arbol.aplicar(&cambios, 1).unwrap();
    arbol
}

/// Propiedad de C9: el árbol anterior con los cambios del puente da las mismas raíces de familia
/// que el árbol reconstruido desde `posterior`.
fn comprobar_puente(anterior: &Estado, posterior: &Estado, undo: &Undo) {
    let mut arbol = arbol_de(anterior);
    let cambios = cambios_de_undo(posterior, undo);
    arbol.aplicar(&cambios, 1).unwrap();
    let referencia = arbol_de(posterior);
    for familia in [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09] {
        assert_eq!(
            arbol.raiz_familia(familia).unwrap(),
            referencia.raiz_familia(familia).unwrap(),
            "la familia {familia:#04x} no coincide tras el puente"
        );
    }
}

fn params_transicion() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 1,
        m_cb: 1,
        m_dep: 0,
        h_corte_min: 1000,
        w_min: U256::one(),
        s_min: Amount::CERO,
        q: Amount::CERO,
        k_min: 0,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 1,
        f_slots: None,
        subsidio_pow,
        subsidio_post,
    }
}

fn subsidio_pow(_h: u32) -> Amount {
    amount(10)
}

fn subsidio_post(_s: u64) -> Amount {
    amount(3)
}

// ---------------------------------------------------------------------------
// canon_01 · vectores fijos
// ---------------------------------------------------------------------------

#[test]
fn canon_01_vectores_fijos() {
    let e = estado_fijo();

    let op = outpoint(1);
    let (k, v) = hoja_utxo(&op, e.utxo.get(&op).unwrap());
    assert_eq!(
        hx(&k),
        "010101010101010101010101010101010101010101010101010101010101010100000001"
    );
    assert_eq!(
        hx(&v),
        "01010101010101010101010101010101010101010101010101010101010101010000000100000000000001f400090909090909090909090909090909090909090909090909090909090909090901000000000000000003"
    );

    let pk = clave(2);
    let (k, v) = hoja_garantia(&pk, e.garantias.get(&pk).unwrap());
    assert_eq!(
        hx(&k),
        "0202020202020202020202020202020202020202020202020202020202020202"
    );
    assert_eq!(
        hx(&v),
        "020202020202020202020202020202020202020202020202020202020202020200000000000003e8000000000000000c0000000000000001000000000000000701000000000000000401000000000000000500000000000000010000000000000008000000000000000600000000000000090000000000000001000000000000000a0001000000000000000b00000000000000011a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a000000000000000d"
    );

    let id = SectorId {
        clave: clave(3),
        sector_index: 4,
        version: 5,
    };
    let (k, v) = hoja_sector(&id, e.sectores.get(&id).unwrap());
    assert_eq!(
        hx(&k),
        "0303030303030303030303030303030303030303030303030303030303030303000400000005"
    );
    assert_eq!(
        hx(&v),
        "03030303030303030303030303030303030303030303030303030303030303030004000000050000000000000001000000000000000200000000000000030000000000000004000000000000001001000000000000001400000000000000150000000000000016000000000000001700000000000000180000000000000019"
    );

    let cid = CajaId {
        clave: clave(6),
        seq: 7,
    };
    let (k, v) = hoja_caja(&cid, e.cajas.get(&cid).unwrap());
    assert_eq!(
        hx(&k),
        "060606060606060606060606060606060606060606060606060606060606060600000007"
    );
    assert_eq!(
        hx(&v),
        "060606060606060606060606060606060606060606060606060606060606060600000007000000000000000500000000000000060000000000000007000000000000000801000100000002000000000000001e0100000000000000200000000000000021000000000000002200000000000000230000000000000024000000000000002500080000000901ffff0000000000ffff0000000000ffff0000000000ffff0000000000ffff0000000000ffff0000000000ffff0000000000ffff0000000000ffff0000000000ffff0000000000ffff0000000000ffff0000000000ffff0000000000ffff0000000000ffff0000000000"
    );

    let pk = clave(10);
    let (k, v) = hoja_prueba(&pk, e.pruebas.get(&pk).unwrap());
    assert_eq!(
        hx(&k),
        "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
    );
    assert_eq!(
        hx(&v),
        "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00000000000000280000000000000009000000000000000a000000000000000b000000000000000c0000000d"
    );

    let pk = clave(11);
    let (k, v) = hoja_porep(&pk, e.poreps.get(&pk).unwrap());
    assert_eq!(
        hx(&k),
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
    );
    assert_eq!(
        hx(&v),
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0000000000000029000000000000000d000000000000000e000000000000000f000000000000001000000011"
    );

    let pk = clave(12);
    let (k, v) = hoja_clave_voto(&pk, e.claves_voto.get(&pk).unwrap());
    assert_eq!(
        hx(&k),
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
    );
    assert_eq!(
        hx(&v),
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0cb1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
    );

    let pk = clave(13);
    let (k, v) = hoja_ultimo_slot(&pk, *e.ultimo_slot_producido.get(&pk).unwrap());
    assert_eq!(
        hx(&k),
        "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"
    );
    assert_eq!(
        hx(&v),
        "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d000000000000002a"
    );

    assert_eq!(
        hx(&h_escalares(&e)),
        "2aecbaef4506972e260386df1df5065758223ec4775d9ccadfd0bdbb92c21380"
    );
    assert_eq!(
        hx(&h_libro(&e)),
        "f7544ff9fb4fbae53f9a9385f8c70e734ccc13404d28c80da582ce26dc082103"
    );
    assert_eq!(
        hx(&raiz_de_estado(&e).unwrap()),
        "10ac502eb1896d2bf388a56d041c629b4d99eb8027a5895738a9d6cf2f63d9db"
    );
}

// ---------------------------------------------------------------------------
// canon_02 · cada campo incluido cambia la raíz
// ---------------------------------------------------------------------------

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

#[test]
fn canon_02_cada_campo_incluido_cambia_la_raiz() {
    let casos = casos();
    let n = casos.len();
    for (nombre, mut e, f) in casos {
        let antes = raiz_de_estado(&e).unwrap();
        f(&mut e);
        assert_ne!(
            raiz_de_estado(&e).unwrap(),
            antes,
            "la mutación «{nombre}» no cambia la raíz"
        );
    }
    assert_eq!(n, 193, "número de mutaciones contadas");
}

// ---------------------------------------------------------------------------
// canon_03 · parametros_sector fuera de la raíz
// ---------------------------------------------------------------------------

#[test]
fn canon_03_parametros_sector_no_cambia_la_raiz() {
    let base = estado_fijo();
    let mut con_otros = base.clone();
    con_otros.parametros_sector.q_sec += 1;
    con_otros.parametros_sector.m_sec += 1;
    con_otros.parametros_sector.capacidad_caja = 1;
    assert_eq!(
        raiz_de_estado(&base).unwrap(),
        raiz_de_estado(&con_otros).unwrap()
    );
}

// ---------------------------------------------------------------------------
// canon_04 · la familia 0x03 está vacía
// ---------------------------------------------------------------------------

#[test]
fn canon_04_cuentas_vacia() {
    let arbol = arbol_de(&estado_fijo());
    assert_eq!(arbol.raiz_familia(0x03).unwrap(), hash_vacio());
    assert_eq!(
        arbol_de(&Estado::inicial()).raiz_familia(0x03).unwrap(),
        hash_vacio()
    );
}

// ---------------------------------------------------------------------------
// canon_05 · la versión entra
// ---------------------------------------------------------------------------

#[test]
fn canon_05_la_version_entra() {
    let e = estado_fijo();
    assert_eq!(h_escalares(&e), h_escalares_con_version(&e, VERSION_CANON));
    assert_ne!(
        h_escalares_con_version(&e, 1),
        h_escalares_con_version(&e, 2)
    );
    assert_ne!(
        h_escalares_con_version(&e, 2),
        h_escalares_con_version(&e, 3)
    );
}

// ---------------------------------------------------------------------------
// canon_06 · estado inicial fijo
// ---------------------------------------------------------------------------

#[test]
fn canon_06_estado_inicial_fijo() {
    assert_eq!(
        hx(&raiz_de_estado(&Estado::inicial()).unwrap()),
        "27cebca9e59dabf378e3daaf6ec0cc06c8d62bf299d53074b4b0ca7adcacc818"
    );
}

// ---------------------------------------------------------------------------
// canon_07 · el puente iguala a reconstruir
// ---------------------------------------------------------------------------

#[test]
fn canon_07_puente_igual_que_reconstruir() {
    let params = ParametrosSector::fixture();

    // Caso A · aplicar_operacion_con_undo (alta de sector).
    let base = estado_fijo();
    let op = OperacionSector::Alta {
        clave: clave(2),
        sector_index: 0,
        version: 0,
        r2: [9u8; 32],
        history_size: 16,
    };
    let (post_a, res_a) = aplicar_operacion_con_undo(&base, &op, 10, &params);
    assert_eq!(res_a.motivo, MotivoSector::Ok);
    comprobar_puente(&base, &post_a, &res_a.undo);

    // Caso B · materializar_con_undo (maduración del sector anterior).
    let (post_b, undo_b) = materializar_con_undo(&post_a, 10 + params.m_sec, &params);
    comprobar_puente(&post_a, &post_b, &undo_b);

    // Caso C · aplicar_con_undo (bloque PoW con coinbase).
    let mut base_pow = Estado::inicial();
    base_pow.fase = Fase::PoW;
    base_pow.parametros_sector = ParametrosSector::dev();
    let coinbase = Tx {
        version: 1,
        inputs: Vec::new(),
        outputs: vec![TxOut {
            value: amount(10),
            lock: Lock::PubKey { pubkey: clave(20) },
        }],
        lock_time: 0,
        expiry_height: 1,
        extension: ExtensionTx::Ninguna,
    };
    let bloque = BloqueTransicion::nuevo(
        HechosCabecera::PoW {
            hash: hash(0x10),
            padre: hash(0x00),
            altura: 1,
            trabajo: U256::one(),
            pow_valido: true,
        },
        vec![(coinbase, Vec::new())],
    );
    let (post_c, undo_c) = aplicar_con_undo(
        &base_pow,
        &bloque,
        &params_transicion(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    assert_eq!(post_c.utxo.len(), 1, "la coinbase debe crear una salida");
    comprobar_puente(&base_pow, &post_c, &undo_c);
}

// ---------------------------------------------------------------------------
// canon_08 · el puente borra
// ---------------------------------------------------------------------------

#[test]
fn canon_08_puente_borra() {
    let params = ParametrosSector::fixture();
    let base = estado_fijo();
    let op = OperacionSector::Alta {
        clave: clave(2),
        sector_index: 0,
        version: 0,
        r2: [9u8; 32],
        history_size: 16,
    };
    let (post, res) = aplicar_operacion_con_undo(&base, &op, 10, &params);
    assert_eq!(res.motivo, MotivoSector::Ok);
    assert!(post.sectores.len() > base.sectores.len());

    // Hacia `base` la clave nueva no existe: el puente emite un borrado.
    let cambios = cambios_de_undo(&base, &res.undo);
    assert!(
        cambios
            .iter()
            .any(|c| c.familia == 0x04 && c.valor.is_none()),
        "el puente debe borrar la hoja del sector que ya no está"
    );

    // Aplicado al árbol de `post`, vuelve a las raíces de `base`.
    let mut arbol = arbol_de(&post);
    arbol.aplicar(&cambios, 1).unwrap();
    let referencia = arbol_de(&base);
    for familia in [0x02u8, 0x04, 0x05] {
        assert_eq!(
            arbol.raiz_familia(familia).unwrap(),
            referencia.raiz_familia(familia).unwrap(),
            "la familia {familia:#04x} no vuelve a la de base"
        );
    }
}

// ---------------------------------------------------------------------------
// canon_09 · un undo vacío no da cambios
// ---------------------------------------------------------------------------

#[test]
fn canon_09_puente_sin_cambios() {
    let base = Estado::inicial();
    let genesis = BloqueTransicion::nuevo(HechosCabecera::Genesis { hash: hash(0) }, Vec::new());
    let (post, undo) = aplicar_con_undo(
        &base,
        &genesis,
        &params_transicion(),
        CBID_RED_DEV,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap();
    assert!(cambios_de_undo(&post, &undo).is_empty());
}

// ---------------------------------------------------------------------------
// canon_10 · el orden de construcción no cambia la raíz
// ---------------------------------------------------------------------------

#[test]
fn canon_10_orden_de_construccion() {
    let e = estado_fijo();
    let hojas = hojas_de_estado(&e);
    let cambios: Vec<Cambio> = hojas
        .iter()
        .map(|(f, k, v)| Cambio::poner(*f, k.clone(), v.clone()))
        .collect();
    let mut al_reves = cambios.clone();
    al_reves.reverse();

    let escalares = h_escalares(&e);
    let mut a1 = ArbolEstado::nuevo(AlmacenEnMemoria::nuevo(), CaminoSha3);
    let mut a2 = ArbolEstado::nuevo(AlmacenEnMemoria::nuevo(), CaminoSha3);
    a1.aplicar(&cambios, 1).unwrap();
    a2.aplicar(&al_reves, 2).unwrap();
    assert_eq!(
        a1.raiz_estado(&escalares).unwrap(),
        a2.raiz_estado(&escalares).unwrap()
    );
}

// ---------------------------------------------------------------------------
// canon_11 · incidentes cambia la raíz
// ---------------------------------------------------------------------------

#[test]
fn canon_11_incidentes_cambia_la_raiz() {
    let base = estado_fijo();
    let raiz = raiz_de_estado(&base).unwrap();
    let pk = clave(2);

    // Añadir.
    let mut anadido = base.clone();
    if let Some(g) = anadido.garantias.get_mut(&pk) {
        g.incidentes.push(Incidente {
            id: [0x3A; 32],
            slot_falta: 31,
        });
    }
    assert_ne!(
        raiz_de_estado(&anadido).unwrap(),
        raiz,
        "añadir un incidente no cambia la raíz"
    );

    // Quitar.
    let mut quitado = base.clone();
    if let Some(g) = quitado.garantias.get_mut(&pk) {
        g.incidentes.pop();
    }
    assert_ne!(
        raiz_de_estado(&quitado).unwrap(),
        raiz,
        "quitar el incidente no cambia la raíz"
    );

    // Cambiar el id.
    let mut otro_id = base.clone();
    if let Some(i) = otro_id
        .garantias
        .get_mut(&pk)
        .and_then(|g| g.incidentes.first_mut())
    {
        i.id = [0x4A; 32];
    }
    assert_ne!(
        raiz_de_estado(&otro_id).unwrap(),
        raiz,
        "cambiar el id del incidente no cambia la raíz"
    );

    // Cambiar el slot_falta.
    let mut otro_slot = base.clone();
    if let Some(i) = otro_slot
        .garantias
        .get_mut(&pk)
        .and_then(|g| g.incidentes.first_mut())
    {
        i.slot_falta = 99;
    }
    assert_ne!(
        raiz_de_estado(&otro_slot).unwrap(),
        raiz,
        "cambiar slot_falta del incidente no cambia la raíz"
    );
}

// ---------------------------------------------------------------------------
// canon_12 · el puente ve los campos nuevos
// ---------------------------------------------------------------------------

#[test]
fn canon_12_el_puente_ve_los_campos_nuevos() {
    // `anterior` y `posterior` difieren SOLO en un incidente de la garantía `clave(2)`. El `Undo`
    // sale de una transición real (Alta de sector) que toca esa garantía; `cambios_de_undo` solo
    // usa del `Undo` las claves tocadas, así que sirve para comprobar que escribe el campo nuevo.
    let anterior = estado_fijo();
    let params = ParametrosSector::fixture();
    let op = OperacionSector::Alta {
        clave: clave(2),
        sector_index: 0,
        version: 0,
        r2: [9u8; 32],
        history_size: 16,
    };
    let (_post, res) = aplicar_operacion_con_undo(&anterior, &op, 10, &params);
    assert_eq!(res.motivo, MotivoSector::Ok);
    let undo = res.undo;
    assert!(
        undo.garantias.iter().any(|(pk, _)| *pk == clave(2)),
        "el undo debe tocar la garantía de clave(2)"
    );

    let mut posterior = anterior.clone();
    if let Some(g) = posterior.garantias.get_mut(&clave(2)) {
        g.incidentes.push(Incidente {
            id: [0x5A; 32],
            slot_falta: 41,
        });
    }

    let cambios = cambios_de_undo(&posterior, &undo);
    assert!(!cambios.is_empty(), "el puente debe emitir un cambio");
    assert!(
        cambios.iter().any(|c| c.familia == 0x02),
        "el puente debe tocar la familia de garantías"
    );

    let mut arbol = arbol_de(&anterior);
    arbol.aplicar(&cambios, 1).unwrap();
    let referencia = arbol_de(&posterior);
    for familia in [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09] {
        assert_eq!(
            arbol.raiz_familia(familia).unwrap(),
            referencia.raiz_familia(familia).unwrap(),
            "la familia {familia:#04x} no coincide tras el puente"
        );
    }
    // El árbol actualizado, con los escalares del posterior, es la raíz reconstruida.
    assert_eq!(
        arbol.raiz_estado(&h_escalares(&posterior)).unwrap(),
        raiz_de_estado(&posterior).unwrap()
    );
}

// ---------------------------------------------------------------------------
// cronómetro (§4) · una ejecución, cifras SIN medida limpia
// ---------------------------------------------------------------------------

fn clave_u32(i: u32) -> ClavePublica {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&i.to_be_bytes());
    ClavePublica::desde_bytes(b)
}

fn bls_u32(i: u32) -> [u8; 48] {
    let mut b = [0u8; 48];
    b[0..4].copy_from_slice(&i.to_be_bytes());
    b
}

fn digest_u32(i: u32) -> Digest {
    let mut b = [0u8; 32];
    b[0..4].copy_from_slice(&i.to_be_bytes());
    Digest::from_bytes(b)
}

#[test]
#[ignore = "cronómetro sin medida limpia (ORDEN-A1B1 §4): se ejecuta una vez a mano"]
fn cronometro_sin_medida_limpia() {
    use std::time::Instant;

    // h_libro con 17 tablas de 65 536 claves cada una.
    let mut libro = Estado::inicial();
    for t in 0..17u64 {
        let claves: Vec<ClaveTablaVoto> = (0..65_536u32)
            .map(|i| ClaveTablaVoto {
                clave_bls: bls_u32(i),
                peso: u64::from(i),
                activo: i % 2 == 0,
                prueba: true,
                garantia: u64::from(i),
            })
            .collect();
        libro.tablas_voto.insert(t, claves);
    }
    let t0 = Instant::now();
    let h = h_libro(&libro);
    println!(
        "cronometro h_libro(17 x 65536) = {:?} hash={}",
        t0.elapsed(),
        hx(&h)
    );

    // raiz_de_estado con 100 000 salidas, 65 536 claves de voto y 65 536 sectores.
    let mut grande = Estado::inicial();
    for i in 0..100_000u32 {
        let op = OutPoint {
            prev_txid: TxId::from_digest(digest_u32(i)),
            prev_index: 0,
        };
        grande.utxo.insert(
            op,
            EntradaUtxo {
                valor: amount(i64::from(i) + 1),
                lock: Lock::PubKey {
                    pubkey: clave_u32(i),
                },
                origen: Origen::Tx,
                creada: Punto::Slot(u64::from(i)),
            },
        );
    }
    for i in 0..65_536u32 {
        grande.claves_voto.insert(
            clave_u32(i),
            ClaveVoto {
                clave_bls: bls_u32(i),
                prueba_posesion: [0u8; 96],
            },
        );
    }
    for i in 0..65_536u32 {
        let id = SectorId {
            clave: clave_u32(i),
            sector_index: (i & 0xFFFF) as u16,
            version: i,
        };
        grande.sectores.insert(
            id,
            RegistroSector {
                id,
                r2: [u64::from(i), 1, 2, 3],
                history_size: u64::from(i) + 1,
                etapa: Etapa::Activo,
                alta_slot: i64::from(i),
                renovacion_slot: i64::from(i),
                retiro_slot: -1,
                fianza: 1,
                aud_apertura: -1,
                aud_contestada: -1,
            },
        );
    }
    let t0 = Instant::now();
    let r = raiz_de_estado(&grande).unwrap();
    println!(
        "cronometro raiz_de_estado(100000 utxo + 65536 claves_voto + 65536 sectores) = {:?} raiz={}",
        t0.elapsed(),
        hx(&r)
    );
}
