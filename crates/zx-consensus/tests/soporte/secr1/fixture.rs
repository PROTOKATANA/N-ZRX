#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "fixtures deterministas compartidos entre pruebas de consenso"
)]
use super::consensus;
use consensus::cajas::{CajaId, EtapaCaja, Ocupante, RegistroCaja};
use consensus::sectores::{ClaveVoto, Etapa, RegistroSector, SectorId};
use consensus::transicion::{
    BloqueTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion,
};
use zx_core::{Amount, BlockHash, ClavePublica, ClaveTablaVoto, Digest};
pub const DEN: i128 = 1_401_600_000;
pub const N: u64 = 3;
pub fn clave(i: u32) -> ClavePublica {
    let mut bytes = [0x42; 32];
    bytes[28..].copy_from_slice(&i.to_be_bytes());
    ClavePublica::desde_bytes(bytes)
}
pub fn hash(i: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([i; 32]))
}
pub fn bls(i: u32) -> zx_votos::ClaveSecreta {
    let mut ikm = [0x53; 32];
    ikm[..4].copy_from_slice(&i.to_le_bytes());
    zx_votos::ClaveSecreta::generar(&ikm).unwrap()
}
pub fn params() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 0,
        m_cb: 1,
        m_dep: 1,
        h_corte_min: 1_000,
        w_min: primitive_types::U256::zero(),
        s_min: Amount::CERO,
        q: Amount::CERO,
        k_min: 0,
        max_tx_bytes: 100_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 600,
        f_slots: Some(600),
        subsidio_pow: |_| Amount::CERO,
        subsidio_post: |_| Amount::CERO,
    }
}
pub fn registro(
    clave: ClavePublica,
    indice: u16,
    version: u32,
    etapa: Etapa,
    fianza: i64,
) -> RegistroSector {
    RegistroSector {
        id: SectorId {
            clave,
            sector_index: indice,
            version,
        },
        r2: [u64::from(indice), u64::from(version), 17, 23],
        history_size: 1,
        etapa,
        alta_slot: 0,
        renovacion_slot: 0,
        retiro_slot: -1,
        fianza,
        aud_apertura: -1,
        aud_contestada: -1,
    }
}
pub fn caja_para(est: &mut Estado, reg: RegistroSector, seq: u32, etapa: EtapaCaja) {
    let id = CajaId {
        clave: reg.id.clave,
        seq,
    };
    let mut caja = RegistroCaja::nueva(id, reg.history_size, 0);
    caja.etapa = etapa;
    caja.n = 1;
    caja.ocupacion = 1;
    caja.fianza = reg.fianza;
    caja.renovacion_slot = 0;
    caja.huecos[0] = Ocupante {
        sector_index: reg.id.sector_index,
        version: reg.id.version,
        ocupado: true,
    };
    caja.raiz = consensus::transicion::raiz_de_caja(est, &caja);
    est.cajas.insert(id, caja);
}
pub fn poner_tabla(est: &mut Estado, mut tabla: Vec<ClaveTablaVoto>) {
    tabla.sort_by_key(|c| c.clave_bls);
    let h = zx_votos::hash_tabla(&zx_votos::Tabla {
        n: 0,
        claves: tabla
            .iter()
            .map(|c| zx_votos::Clave {
                clave: c.clave_bls.to_vec(),
                peso: c.peso,
                activo: c.activo,
                prueba: c.prueba,
                garantia: c.garantia,
            })
            .collect(),
    });
    est.tablas_voto_contenido.insert(h, tabla);
    est.tabla_ventana_voto.insert(N, h);
    est.liquidacion_voto_hasta = Some(N - 1);
}
pub fn estado_ausencia(miembros: u32, sectores: usize, bordes: bool) -> Estado {
    let mut est = Estado::inicial();
    est.fase = Fase::PoST;
    est.parametros_sector.t_cad = 1_000_000_000;
    let mut tabla = Vec::new();
    for i in 0..miembros {
        let ed = clave(i);
        let pk = bls(i).clave_publica().bytes();
        est.claves_voto.insert(
            ed,
            ClaveVoto {
                clave_bls: pk,
                prueba_posesion: [0; 96],
            },
        );
        tabla.push(ClaveTablaVoto {
            clave_bls: pk,
            peso: 1,
            activo: !bordes || i % 8 != 0,
            prueba: false,
            garantia: 1,
        });
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo(if !bordes || i.is_multiple_of(2) {
            DEN as i64
        } else {
            0
        })
        .unwrap();
        est.garantias.insert(ed, g);
        if bordes && i % 4 == 0 {
            est.votantes_voto.entry(N).or_default().insert(ed);
        }
    }
    for j in 0..sectores {
        let i = (j % miembros as usize) as u32;
        let k = j / miembros as usize;
        let (indice, version, etapa, fianza) = if bordes {
            match k % 6 {
                0 => (0, 0, Etapa::Activo, 100),
                1 => (0, u32::MAX, Etapa::EnRetirada, 200),
                2 => (1, 0, Etapa::Precomprometido, 0),
                3 => (u16::MAX, 0, Etapa::Retirado, 0),
                4 => (u16::MAX, u32::MAX - 1, Etapa::Caducado, 0),
                _ => (
                    u16::MAX,
                    u32::MAX,
                    Etapa::Activo,
                    if i.is_multiple_of(2) { DEN as i64 } else { 1 },
                ),
            }
        } else {
            (k as u16, 0, Etapa::Activo, 140)
        };
        let r = registro(clave(i), indice, version, etapa, fianza);
        est.sectores.insert(r.id, r);
    }
    est.emitido = est
        .garantias
        .values()
        .map(consensus::transicion::total_garantia)
        .sum::<i128>()
        + est
            .sectores
            .values()
            .filter(|r| !r.es_terminal())
            .map(|r| i128::from(r.fianza))
            .sum::<i128>();
    poner_tabla(&mut est, tabla);
    est
}
pub fn bloque_liquidacion() -> BloqueTransicion {
    let slot = consensus::transicion::votos::cierre_ventana(N)
        + consensus::transicion::votos::W_REVEAL_SLOTS_VOTOS
        + 1;
    BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: hash(1),
            padre: hash(2),
            slot,
            productor: clave(999_999),
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        Vec::new(),
    )
}
pub fn liquidar(est: &Estado) -> (Estado, consensus::transicion::Undo) {
    consensus::transicion::aplicar_con_undo(
        est,
        &bloque_liquidacion(),
        &params(),
        0,
        &ParametrosEvidencia::inactiva(),
    )
    .unwrap()
}
pub fn huella(est: &Estado) -> String {
    format!(
        "{}",
        zx_core::sha3_256_publico(format!("{est:?}").as_bytes())
    )
}

/// Generador exacto xorshift64, semilla fija mezclada con el número de caso; sin azar del sistema.
pub fn estado_generado(caso: u64) -> Estado {
    let mut est = Estado::inicial();
    est.parametros_sector.exigir_prueba_almacenamiento = caso.is_multiple_of(2);
    let mut rng = 0x5a5a_1040_0000_0001u64 ^ caso;
    let mut siguiente = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    if caso.is_multiple_of(31) {
        return est;
    }
    for i in 0..5 {
        let ed = clave(i);
        let mut g = Garantia::nueva();
        g.activo = Amount::nuevo((siguiente() % 501) as i64).unwrap();
        g.pendientes.push(consensus::transicion::Pendiente {
            importe: Amount::nuevo(7).unwrap(),
            madura_en_altura: None,
            madura_en_slot: Some(1_000),
        });
        g.en_retirada.push(consensus::transicion::EnRetirada {
            importe: Amount::nuevo(11).unwrap(),
            inicio_slot: 0,
        });
        g.creditos.push(consensus::transicion::Pendiente {
            importe: Amount::nuevo(13).unwrap(),
            madura_en_altura: None,
            madura_en_slot: Some(1_000),
        });
        est.garantias.insert(ed, g);
        if siguiente() % 2 == 0 {
            est.pruebas.insert(
                ed,
                consensus::sectores::PruebaVigente {
                    slot_prueba: 10,
                    raiz_conjunto: [0; 4],
                    n_sectores: 8,
                },
            );
        }
        for (j, (indice, version)) in [
            (0, 0),
            (0, 1),
            (0, u32::MAX),
            (1, 0),
            (u16::MAX, 0),
            (u16::MAX, 1),
            (u16::MAX, u32::MAX - 1),
            (u16::MAX, u32::MAX),
        ]
        .into_iter()
        .enumerate()
        {
            let etapa = match siguiente() % 5 {
                0 => Etapa::Precomprometido,
                1 => Etapa::Activo,
                2 => Etapa::EnRetirada,
                3 => Etapa::Retirado,
                _ => Etapa::Caducado,
            };
            let fianza = match siguiente() % 5 {
                0 => 0,
                1 => 1,
                2 => 140,
                3 => 1_000,
                _ => 1_401_600_000,
            };
            let mut r = registro(ed, indice, version, etapa, fianza);
            r.alta_slot = (siguiente() % 31) as i64;
            r.renovacion_slot = (siguiente() % 101) as i64;
            if siguiente() % 2 == 0 {
                r.aud_apertura = 1;
            }
            est.sectores.insert(r.id, r);
            let etapa_caja = match siguiente() % 4 {
                0 => EtapaCaja::Abierta,
                1 => EtapaCaja::Cerrada,
                2 => EtapaCaja::EnRetirada,
                _ => EtapaCaja::Retirada,
            };
            let seq = if j == 7 { u32::MAX } else { j as u32 };
            caja_para(&mut est, r, seq, etapa_caja);
        }
    }
    est
}
