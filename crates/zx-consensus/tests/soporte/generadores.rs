//! Generadores y validador de los 168 vectores de SR-0 (puerto a Rust).
//!
//! Reproduce `SR0/src/generadores.jl`, `SR0/src/escenarios.jl` y `SR0/src/validacion.jl`. Los
//! generadores son deterministas: la semilla **no** interviene en la forma de la traza (igual que
//! en el oráculo Julia), solo etiqueta el vector. Por eso las 12 semillas de un tipo dan el mismo
//! resultado y la verificación es 12 veces el mismo caso por tipo.
//!
//! `validar_caso` devuelve los agregados que fijan `vectores/s03-144.jsonl`
//! (`n_bloques`, `n_sectores`, `n_ops`, `n_descartes`, `ok`) y las propiedades por tipo.

use std::collections::BTreeMap;

use zx_core::ClavePublica;

use super::{
    BloqueSector, CadenaSector, DagSector, EstadoEfectivo, EstadoSector, Etapa, MotivoSector,
    Operacion, ParametrosSector, R2, Solucion, TipoOp, avanzar, clave_de, deshacer,
    estado_efectivo, fianza_comprometida, fold_referencia, fuente_peso_de, invariante_requisito,
    invariante_valor, prueba_sucinta, requisito, sector_vivo, sectores_activos,
};

/// Claves del oráculo `Clave(1)`, `Clave(2)` y `Clave(3)`.
#[must_use]
pub fn k1() -> ClavePublica {
    clave_de(1)
}
/// `Clave(2)`.
#[must_use]
pub fn k2() -> ClavePublica {
    clave_de(2)
}
/// `Clave(3)`.
#[must_use]
pub fn k3() -> ClavePublica {
    clave_de(3)
}

fn r2_de(clave: &ClavePublica, si: u16, version: u32, h: u64) -> R2 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&clave.bytes()[..8]);
    [u64::from_le_bytes(b), u64::from(si), u64::from(version), h]
}

/// Constructor de operaciones.
#[must_use]
pub fn op_fond(clave: ClavePublica, importe: i64) -> Operacion {
    Operacion {
        tipo: TipoOp::Fondear,
        clave,
        importe,
        ..Operacion::base(TipoOp::Fondear)
    }
}

/// `op_dep`.
#[must_use]
pub fn op_dep(clave: ClavePublica, importe: i64) -> Operacion {
    Operacion {
        tipo: TipoOp::Deposito,
        clave,
        importe,
        ..Operacion::base(TipoOp::Deposito)
    }
}

/// `op_ret`.
#[must_use]
pub fn op_ret(clave: ClavePublica, importe: i64) -> Operacion {
    Operacion {
        tipo: TipoOp::Retiro,
        clave,
        importe,
        ..Operacion::base(TipoOp::Retiro)
    }
}

/// `op_lib`.
#[must_use]
pub fn op_lib(clave: ClavePublica, importe: i64) -> Operacion {
    Operacion {
        tipo: TipoOp::Liberacion,
        clave,
        importe,
        ..Operacion::base(TipoOp::Liberacion)
    }
}

/// `op_cbp`.
#[must_use]
pub fn op_cbp(clave: ClavePublica, importe: i64) -> Operacion {
    Operacion {
        tipo: TipoOp::CoinbasePost,
        clave,
        importe,
        ..Operacion::base(TipoOp::CoinbasePost)
    }
}

/// `op_alta`.
#[must_use]
pub fn op_alta(clave: ClavePublica, si: u16, version: u32, importe: i64, h: u64) -> Operacion {
    Operacion {
        tipo: TipoOp::Alta,
        clave,
        sector_index: si,
        version,
        importe,
        r2: r2_de(&clave, si, version, h),
        history_size: h,
        ..Operacion::base(TipoOp::Alta)
    }
}

/// `op_renovar`.
#[must_use]
pub fn op_renovar(clave: ClavePublica, si: u16) -> Operacion {
    Operacion {
        tipo: TipoOp::Renovar,
        clave,
        sector_index: si,
        ..Operacion::base(TipoOp::Renovar)
    }
}

/// `op_abrir`.
#[must_use]
pub fn op_abrir(clave: ClavePublica, si: u16, aud: u64) -> Operacion {
    Operacion {
        tipo: TipoOp::AbrirAud,
        clave,
        sector_index: si,
        auditoria_id: aud,
        ..Operacion::base(TipoOp::AbrirAud)
    }
}

/// `op_contestar`.
#[must_use]
pub fn op_contestar(clave: ClavePublica, si: u16, aud: u64, prueba: bool) -> Operacion {
    Operacion {
        tipo: TipoOp::Contestar,
        clave,
        sector_index: si,
        auditoria_id: aud,
        prueba,
        ..Operacion::base(TipoOp::Contestar)
    }
}

/// `op_retirar`.
#[must_use]
pub fn op_retirar(clave: ClavePublica, si: u16) -> Operacion {
    Operacion {
        tipo: TipoOp::RetirarSector,
        clave,
        sector_index: si,
        ..Operacion::base(TipoOp::RetirarSector)
    }
}

/// `op_evid`.
#[must_use]
pub fn op_evid(clave: ClavePublica, si: u16, aud: u64) -> Operacion {
    Operacion {
        tipo: TipoOp::Evidencia,
        clave,
        sector_index: si,
        auditoria_id: aud,
        h1: [aud, 1, 0, 0],
        h2: [aud, 0, 1, 0],
        ..Operacion::base(TipoOp::Evidencia)
    }
}

/// Constructor de trazas (asigna ids en orden de creación).
#[derive(Clone, Debug)]
pub struct Constr {
    /// DAG en construcción.
    pub dag: DagSector,
    /// Siguiente id.
    pub nid: u64,
    /// Bloques en orden de creación.
    pub bloques: Vec<BloqueSector>,
}

impl Default for Constr {
    fn default() -> Self {
        Self::new()
    }
}

impl Constr {
    /// Constructor vacío.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dag: DagSector::default(),
            nid: 0,
            bloques: Vec::new(),
        }
    }

    /// Bloque de arranque (PoW): `sol = None`.
    pub fn pow(
        &mut self,
        padres: Vec<u64>,
        slot: i64,
        productor: ClavePublica,
        peso: i64,
        ops: Vec<Operacion>,
    ) -> u64 {
        self.nid += 1;
        let b = BloqueSector {
            id: self.nid,
            padres,
            slot,
            productor,
            sol: None,
            peso,
            ops,
        };
        self.dag.agregar(b.clone());
        self.bloques.push(b);
        self.nid
    }

    /// Bloque PoST: exige sector activo de `(productor, si)` con `history_size`.
    #[allow(clippy::too_many_arguments)]
    pub fn post(
        &mut self,
        padres: Vec<u64>,
        slot: i64,
        productor: ClavePublica,
        si: u16,
        h: u64,
        rango: u64,
        peso: i64,
        ops: Vec<Operacion>,
    ) -> u64 {
        self.nid += 1;
        let sol = Solucion {
            clave: productor,
            sector_index: si,
            history_size: h,
            chunk: self.nid,
            rango,
        };
        let b = BloqueSector {
            id: self.nid,
            padres,
            slot,
            productor,
            sol: Some(sol),
            peso,
            ops,
        };
        self.dag.agregar(b.clone());
        self.bloques.push(b);
        self.nid
    }
}

/// Un caso de traza.
#[derive(Clone, Debug)]
pub struct Caso {
    /// Tipo.
    pub tipo: &'static str,
    /// DAG.
    pub dag: DagSector,
    /// Punta principal.
    pub punta: u64,
    /// Datos auxiliares.
    pub extras: Extras,
}

/// Datos auxiliares por tipo.
#[derive(Clone, Debug, Default)]
pub struct Extras {
    /// Bloques en orden de creación (T1).
    pub bloques: Option<Vec<BloqueSector>>,
    /// Punta A (T3/T4).
    pub punta_a: Option<u64>,
    /// Punta B (T3/T4).
    pub punta_b: Option<u64>,
    /// Bloque sin garantía (T7).
    pub bloque_sin_garantia: Option<u64>,
    /// Bloque con garantía (T7).
    pub bloque_con_garantia: Option<u64>,
    /// Clave sin garantía (T7).
    pub clave_sin: Option<ClavePublica>,
    /// Clave con garantía (T7).
    pub clave_con: Option<ClavePublica>,
    /// Clave (T8/T9).
    pub clave: Option<ClavePublica>,
    /// Índice de sector (T8).
    pub sector_index: Option<u16>,
    /// Bloque reciclado (T9).
    pub bloque_reciclado: Option<u64>,
    /// Bloque malo (T10).
    pub bloque_malo: Option<u64>,
    /// Bloque bueno (T10).
    pub bloque_bueno: Option<u64>,
    /// Bloque tardío (T11).
    pub bloque_tardio: Option<u64>,
    /// Bloque de recuperación (T11).
    pub bloque_recuperacion: Option<u64>,
    /// DAG 2 (T12).
    pub dag2: Option<DagSector>,
    /// Punta 2 (T12).
    pub punta2: Option<u64>,
    /// Claves (T6).
    pub claves: Vec<ClavePublica>,
    /// Activos esperados (T6).
    pub n_activos: Vec<i64>,
}

// ── T1…T12 ──────────────────────────────────────────────────────────────────

/// T1 · mismo pasado con distinto orden de llegada.
#[must_use]
pub fn gen_determinismo(p: &ParametrosSector) -> Caso {
    let c = &mut Constr::new();
    let k1 = k1();
    let b1 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 100)]);
    let b2 = c.pow(vec![b1], 1, k1, 1, vec![op_alta(k1, 0, 0, p.q_sec, 1)]);
    let s0 = 1 + p.m_sec;
    let b3 = c.post(vec![b2], s0, k1, 0, 1, 0, 1, vec![]);
    let b4 = c.post(vec![b3], s0 + 1, k1, 0, 1, 0, 1, vec![op_abrir(k1, 0, 7)]);
    let b5 = c.post(
        vec![b4],
        s0 + 2,
        k1,
        0,
        1,
        0,
        1,
        vec![op_contestar(k1, 0, 7, true)],
    );
    let b6 = c.post(vec![b5], s0 + 3, k1, 0, 1, 0, 1, vec![op_renovar(k1, 0)]);
    Caso {
        tipo: "determinismo_orden",
        dag: c.dag.clone(),
        punta: b6,
        extras: Extras {
            bloques: Some(c.bloques.clone()),
            ..Extras::default()
        },
    }
}

/// T2 · alta y auditoría en ramas que se fusionan.
#[must_use]
pub fn gen_fusion(p: &ParametrosSector) -> Caso {
    let c = &mut Constr::new();
    let k1 = k1();
    let b1 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 200)]);
    let b2 = c.pow(
        vec![b1],
        1,
        k1,
        1,
        vec![op_alta(k1, 0, 0, p.q_sec, 1), op_alta(k1, 1, 0, p.q_sec, 1)],
    );
    let s0 = 1 + p.m_sec;
    let b3 = c.post(vec![b2], s0, k1, 0, 1, 0, 1, vec![]);
    let b4 = c.post(vec![b3], s0 + 1, k1, 0, 1, 0, 1, vec![op_abrir(k1, 1, 11)]);
    let b5 = c.post(vec![b3], s0 + 1, k1, 1, 1, 0, 1, vec![op_renovar(k1, 1)]);
    let b6 = c.post(vec![b4, b5], s0 + 2, k1, 0, 1, 0, 1, vec![]);
    Caso {
        tipo: "fusion_ramas",
        dag: c.dag.clone(),
        punta: b6,
        extras: Extras::default(),
    }
}

/// T3 · reorganización antes de la madurez.
#[must_use]
pub fn gen_reorg_antes(p: &ParametrosSector) -> Caso {
    let c = &mut Constr::new();
    let k1 = k1();
    let b1 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 100)]);
    let b2 = c.pow(vec![b1], 1, k1, 1, vec![op_alta(k1, 0, 0, p.q_sec, 1)]);
    let ba = c.pow(vec![b2], 2, k1, 1, vec![]);
    let s0 = 1 + p.m_sec;
    let ba2 = c.post(vec![ba], s0, k1, 0, 1, 0, 1, vec![]);
    let bb = c.pow(vec![b2], 2, k1, 1, vec![]);
    Caso {
        tipo: "reorg_antes",
        dag: c.dag.clone(),
        punta: ba2,
        extras: Extras {
            punta_a: Some(ba2),
            punta_b: Some(bb),
            ..Extras::default()
        },
    }
}

/// T4 · reorganización después de la madurez.
#[must_use]
pub fn gen_reorg_despues(p: &ParametrosSector) -> Caso {
    let c = &mut Constr::new();
    let k1 = k1();
    let b1 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 100)]);
    let b2 = c.pow(vec![b1], 1, k1, 1, vec![op_alta(k1, 0, 0, p.q_sec, 1)]);
    let s0 = 1 + p.m_sec;
    let ba = c.post(vec![b2], s0, k1, 0, 1, 0, 1, vec![]);
    let bb = c.post(vec![b2], s0, k1, 0, 1, 0, 1, vec![]);
    let bb2 = c.post(vec![bb], s0 + 1, k1, 0, 1, 0, 1, vec![op_renovar(k1, 0)]);
    Caso {
        tipo: "reorg_despues",
        dag: c.dag.clone(),
        punta: bb2,
        extras: Extras {
            punta_a: Some(ba),
            punta_b: Some(bb2),
            ..Extras::default()
        },
    }
}

/// T5 · partición honesta que se fusiona después.
#[must_use]
pub fn gen_particion(p: &ParametrosSector) -> Caso {
    let c = &mut Constr::new();
    let (k1, k2) = (k1(), k2());
    let b1 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 200), op_fond(k2, 200)]);
    let b2 = c.pow(
        vec![b1],
        1,
        k1,
        1,
        vec![op_alta(k1, 0, 0, p.q_sec, 1), op_alta(k2, 0, 0, p.q_sec, 1)],
    );
    let s0 = 1 + p.m_sec;
    let ba = c.post(vec![b2], s0, k1, 0, 1, 0, 1, vec![]);
    let bb = c.post(vec![b2], s0, k2, 0, 1, 0, 1, vec![]);
    let bm = c.post(vec![ba, bb], s0 + 1, k1, 0, 1, 0, 1, vec![]);
    Caso {
        tipo: "particion_honesta",
        dag: c.dag.clone(),
        punta: bm,
        extras: Extras::default(),
    }
}

/// T6 · varios sectores por clave (1, 10 y 1 000) y barrera de entrada.
#[must_use]
pub fn gen_varios_sectores(p: &ParametrosSector) -> Caso {
    let c3 = &mut Constr::new();
    let (k1, k2, k3) = (k1(), k2(), k3());
    let b10 = c3.pow(
        vec![],
        0,
        k1,
        1,
        vec![
            op_fond(k1, 100),
            op_fond(k2, 200),
            op_fond(k3, p.q_sec * 1000 + 1000),
        ],
    );
    let mut ops_a = vec![op_alta(k1, 0, 0, p.q_sec, 1)];
    for si in 0..10u16 {
        ops_a.push(op_alta(k2, si, 0, p.q_sec, 1));
    }
    let b20 = c3.pow(vec![b10], 1, k1, 1, ops_a);
    let mut ult = b20;
    let mut vers = 0u32;
    let mut slotc = 1i64;
    while vers < 1000 {
        let n = core::cmp::min(50, 1000 - vers);
        let mut ops = Vec::with_capacity(n as usize);
        for k in 0..n {
            ops.push(op_alta(
                k3,
                u16::try_from(vers + k).unwrap_or(0),
                0,
                p.q_sec,
                1,
            ));
        }
        vers += n;
        slotc += 1;
        ult = c3.pow(vec![ult], slotc, k1, 1, ops);
    }
    let s0 = slotc + p.m_sec;
    let tip = c3.post(vec![ult], s0, k1, 0, 1, 0, 1, vec![]);
    Caso {
        tipo: "varios_sectores",
        dag: c3.dag.clone(),
        punta: tip,
        extras: Extras {
            claves: vec![k1, k2, k3],
            n_activos: vec![1, 10, 1000],
            ..Extras::default()
        },
    }
}

/// T7 · garantía insuficiente.
#[must_use]
pub fn gen_garantia_insuficiente(p: &ParametrosSector) -> Caso {
    let c = &mut Constr::new();
    let (k1, k2) = (k1(), k2());
    let b1 = c.pow(
        vec![],
        0,
        k1,
        1,
        vec![op_fond(k1, p.q_sec - 1), op_fond(k2, p.q_sec)],
    );
    let b2 = c.pow(
        vec![b1],
        1,
        k1,
        1,
        vec![op_alta(k1, 0, 0, p.q_sec, 1), op_alta(k2, 0, 0, p.q_sec, 1)],
    );
    let s0 = 1 + p.m_sec;
    let b3 = c.post(vec![b2], s0, k1, 0, 1, 0, 1, vec![]);
    let b4 = c.post(vec![b2], s0, k2, 0, 1, 0, 1, vec![]);
    Caso {
        tipo: "garantia_insuficiente",
        dag: c.dag.clone(),
        punta: b3,
        extras: Extras {
            bloque_sin_garantia: Some(b3),
            bloque_con_garantia: Some(b4),
            clave_sin: Some(k1),
            clave_con: Some(k2),
            ..Extras::default()
        },
    }
}

/// T8 · retirada con falta pendiente.
#[must_use]
pub fn gen_retirada_con_falta(p: &ParametrosSector) -> Caso {
    let c = &mut Constr::new();
    let (k1, k2) = (k1(), k2());
    let b1 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 200), op_fond(k2, 200)]);
    let b2 = c.pow(
        vec![b1],
        1,
        k1,
        1,
        vec![op_alta(k1, 0, 0, p.q_sec, 1), op_alta(k2, 0, 0, p.q_sec, 1)],
    );
    let s0 = 1 + p.m_sec;
    let b3 = c.post(vec![b2], s0, k1, 0, 1, 0, 1, vec![]);
    let b4 = c.post(vec![b3], s0 + 1, k1, 0, 1, 0, 1, vec![op_retirar(k1, 0)]);
    let b5 = c.post(vec![b4], s0 + 2, k2, 0, 1, 0, 1, vec![op_evid(k1, 0, 3)]);
    let b6 = c.post(vec![b5], s0 + 2 + p.r_sec, k2, 0, 1, 0, 1, vec![]);
    Caso {
        tipo: "retirada_con_falta",
        dag: c.dag.clone(),
        punta: b6,
        extras: Extras {
            clave: Some(k1),
            sector_index: Some(0),
            ..Extras::default()
        },
    }
}

/// T9 · altas duplicadas e índices reciclados con/sin versión.
#[must_use]
pub fn gen_duplicados(p: &ParametrosSector) -> Caso {
    let c = &mut Constr::new();
    let (k1, k2) = (k1(), k2());
    let b1 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 400), op_fond(k2, 400)]);
    let b2 = c.pow(
        vec![b1],
        1,
        k1,
        1,
        vec![
            op_alta(k1, 0, 0, p.q_sec, 1),
            op_alta(k1, 0, 0, p.q_sec, 1),
            op_alta(k1, 0, 1, p.q_sec, 1),
            op_alta(k1, 0, 2, p.q_sec, 1),
            op_alta(k2, 0, 0, p.q_sec, 1),
        ],
    );
    let s0 = 1 + p.m_sec;
    let b3 = c.post(vec![b2], s0, k2, 0, 1, 0, 1, vec![]);
    let b4 = c.post(vec![b3], s0 + 1, k2, 0, 1, 0, 1, vec![op_retirar(k1, 0)]);
    let b5 = c.post(vec![b4], s0 + 1 + p.r_sec, k2, 0, 1, 0, 1, vec![]);
    let b6 = c.post(
        vec![b5],
        s0 + 2 + p.r_sec,
        k2,
        0,
        1,
        0,
        1,
        vec![
            op_alta(k1, 0, 1, p.q_sec, 1),
            op_alta(k1, 0, 0, p.q_sec, 1),
            op_alta(k1, 0, 3, p.q_sec, 1),
        ],
    );
    Caso {
        tipo: "duplicados_reciclados",
        dag: c.dag.clone(),
        punta: b6,
        extras: Extras {
            clave: Some(k1),
            bloque_reciclado: Some(b6),
            ..Extras::default()
        },
    }
}

/// T10 · `history_size` incompatible.
#[must_use]
pub fn gen_history(p: &ParametrosSector) -> Caso {
    let c = &mut Constr::new();
    let (k1, k2) = (k1(), k2());
    let b1 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 200), op_fond(k2, 200)]);
    let b2 = c.pow(
        vec![b1],
        1,
        k1,
        1,
        vec![
            op_alta(k1, 0, 0, p.q_sec, 1),
            op_alta(k2, 0, 0, p.q_sec, 1),
            op_alta(k2, 1, 0, p.q_sec, 0),
            op_alta(k2, 2, 0, p.q_sec, p.h_max + 1),
        ],
    );
    let s0 = 1 + p.m_sec;
    let b3 = c.post(vec![b2], s0, k1, 0, 1, 0, 1, vec![]);
    let b4 = c.post(vec![b3], s0 + 1, k2, 0, 2, 0, 1, vec![]);
    let b5 = c.post(vec![b3], s0 + 1, k2, 0, 1, 0, 1, vec![]);
    Caso {
        tipo: "history_size_incompatible",
        dag: c.dag.clone(),
        punta: b5,
        extras: Extras {
            bloque_malo: Some(b4),
            bloque_bueno: Some(b5),
            ..Extras::default()
        },
    }
}

/// T11 · pruebas fuera de plazo y recuperación.
#[must_use]
pub fn gen_fuera_plazo(p: &ParametrosSector) -> Caso {
    let c = &mut Constr::new();
    let k1 = k1();
    let b1 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 200)]);
    let b2 = c.pow(
        vec![b1],
        1,
        k1,
        1,
        vec![op_alta(k1, 0, 0, p.q_sec, 1), op_alta(k1, 1, 0, p.q_sec, 1)],
    );
    let s0 = 1 + p.m_sec;
    let b3 = c.post(vec![b2], s0, k1, 0, 1, 0, 1, vec![]);
    let b4 = c.post(vec![b3], s0 + 1, k1, 0, 1, 0, 1, vec![op_abrir(k1, 1, 21)]);
    let b5 = c.post(
        vec![b4],
        s0 + 1 + p.p_aud + p.p_rec,
        k1,
        0,
        1,
        0,
        1,
        vec![op_contestar(k1, 1, 21, true)],
    );
    let b6 = c.post(vec![b5], s0 + 2 + p.p_aud + p.p_rec, k1, 0, 1, 0, 1, vec![]);
    let b7 = c.post(
        vec![b4],
        s0 + 1 + p.p_aud,
        k1,
        0,
        1,
        0,
        1,
        vec![op_contestar(k1, 1, 21, true)],
    );
    Caso {
        tipo: "pruebas_fuera_plazo",
        dag: c.dag.clone(),
        punta: b6,
        extras: Extras {
            bloque_tardio: Some(b5),
            bloque_recuperacion: Some(b7),
            ..Extras::default()
        },
    }
}

/// T12 · `blue_work` no cambia al variar el depósito ni el número de sectores.
#[must_use]
pub fn gen_blue_work(p: &ParametrosSector) -> Caso {
    let k1 = k1();
    // DAG A.
    let ca = &mut Constr::new();
    let a1 = ca.pow(
        vec![],
        0,
        k1,
        1,
        vec![op_fond(k1, p.q_sec), op_alta(k1, 0, 0, p.q_sec, 1)],
    );
    let s0 = 1 + p.m_sec;
    let a2 = ca.post(vec![a1], s0, k1, 0, 1, 1_000_000, 7, vec![]);
    // DAG B.
    let cb = &mut Constr::new();
    let mut ops = vec![op_fond(k1, 100 * p.q_sec)];
    for si in 0..10u16 {
        ops.push(op_alta(k1, si, 0, p.q_sec, 1));
    }
    let b1 = cb.pow(vec![], 0, k1, 1, ops);
    let b2 = cb.post(vec![b1], s0, k1, 0, 1, 1_000_000, 7, vec![]);
    Caso {
        tipo: "blue_work_invariante",
        dag: ca.dag.clone(),
        punta: a2,
        extras: Extras {
            dag2: Some(cb.dag.clone()),
            punta2: Some(b2),
            ..Extras::default()
        },
    }
}

/// Despacha el generador por tipo (los 12 de `ORDEN-SR0`).
///
/// # Panics
/// Si el tipo es desconocido.
#[must_use]
#[expect(
    clippy::panic,
    reason = "un tipo de vector desconocido es un error de test, no de producción"
)]
pub fn generar(tipo: &str, p: &ParametrosSector) -> Caso {
    match tipo {
        "determinismo_orden" => gen_determinismo(p),
        "fusion_ramas" => gen_fusion(p),
        "reorg_antes" => gen_reorg_antes(p),
        "reorg_despues" => gen_reorg_despues(p),
        "particion_honesta" => gen_particion(p),
        "varios_sectores" => gen_varios_sectores(p),
        "garantia_insuficiente" => gen_garantia_insuficiente(p),
        "retirada_con_falta" => gen_retirada_con_falta(p),
        "duplicados_reciclados" => gen_duplicados(p),
        "history_size_incompatible" => gen_history(p),
        "pruebas_fuera_plazo" => gen_fuera_plazo(p),
        "blue_work_invariante" => gen_blue_work(p),
        otro => panic!("tipo de traza desconocido: {otro}"),
    }
}

/// Los 12 tipos de traza.
pub const TIPOS: [&str; 12] = [
    "determinismo_orden",
    "fusion_ramas",
    "reorg_antes",
    "reorg_despues",
    "particion_honesta",
    "varios_sectores",
    "garantia_insuficiente",
    "retirada_con_falta",
    "duplicados_reciclados",
    "history_size_incompatible",
    "pruebas_fuera_plazo",
    "blue_work_invariante",
];

// ── validación ──────────────────────────────────────────────────────────────

/// Resultado de validar un caso.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResultadoCaso {
    /// Tipo.
    pub tipo: &'static str,
    /// Propiedades comprobadas (nombre, valor).
    pub propiedades: Vec<(&'static str, bool)>,
    /// ¿Todas las propiedades y comprobaciones pasan?
    pub ok: bool,
    /// Bloques del pasado canónico.
    pub n_bloques: usize,
    /// Registros en el estado final.
    pub n_sectores: usize,
    /// Operaciones del pasado.
    pub n_ops: usize,
    /// Descartes de la punta.
    pub n_descartes: usize,
    /// Máximo de operaciones en un bloque.
    pub max_ops_bloque: usize,
}

fn estado_de_vivo(
    est: &EstadoSector,
    clave: &ClavePublica,
    si: u16,
    slot: i64,
    p: &ParametrosSector,
) -> Option<EstadoEfectivo> {
    sector_vivo(est, clave, si).map(|r| estado_efectivo(&r, slot, p))
}

/// Comprueba que aplicar y deshacer cada bloque vuelve al estado previo bit a bit.
#[must_use]
pub fn undo_exacto(d: &DagSector, id: u64, p: &ParametrosSector) -> bool {
    let mut est = EstadoSector::default();
    for x in d.orden_total(id) {
        let Some(b) = d.bloques.get(&x) else {
            continue;
        };
        let previo = est.clone();
        let r = super::aplicar_bloque(&mut est, b, p);
        deshacer(&mut est, &r.undo);
        if est != previo {
            return false;
        }
        let r2 = super::aplicar_bloque(&mut est, b, p);
        if !r2.valido {
            deshacer(&mut est, &r2.undo);
        }
    }
    true
}

/// Valida un caso y devuelve los agregados de `vectores/s03-144.jsonl`.
#[must_use]
pub fn validar_caso(caso: &Caso, p: &ParametrosSector) -> ResultadoCaso {
    let mut props: Vec<(&'static str, bool)> = Vec::new();
    let (est_ref, desc_ref) = fold_referencia(&caso.dag, caso.punta, p);
    let mut cadena = CadenaSector::default();
    avanzar(&mut cadena, &caso.dag, caso.punta, p);

    props.push(("equivalencia_rapido", cadena.estado == est_ref));
    props.push(("conservacion", invariante_valor(&est_ref)));
    props.push(("requisito", invariante_requisito(&est_ref, p)));
    props.push(("undo_exacto", undo_exacto(&caso.dag, caso.punta, p)));

    let orden = caso.dag.orden_canonico(caso.punta);
    let mut max_ops = 0usize;
    let mut n_ops = 0usize;
    for x in &orden {
        let nb = caso.dag.bloques.get(x).map_or(0, |b| b.ops.len());
        max_ops = max_ops.max(nb);
        n_ops += nb;
    }
    props.push(("cota_ops", max_ops <= p.max_ops_bloque));
    let n_sectores = est_ref.sectores.len();

    if let Some(bloques) = &caso.extras.bloques {
        let mut d2 = DagSector::default();
        for b in bloques.iter().rev() {
            d2.agregar(b.clone());
        }
        let (est2, _) = fold_referencia(&d2, caso.punta, p);
        props.push(("determinismo_llegada", est2 == est_ref));
    }

    let desc_punta = desc_ref.get(&caso.punta).cloned().unwrap_or_default();
    let t = caso.tipo;
    if t == "determinismo_orden" {
        props.push(("t1_sin_descartes", desc_punta.is_empty()));
        let ok = estado_de_vivo(&est_ref, &k1(), 0, est_ref.slot_actual, p)
            == Some(EstadoEfectivo::Activo);
        props.push(("t1_activo", ok));
    } else if t == "fusion_ramas" {
        let r = sector_vivo(&est_ref, &k1(), 1);
        props.push(("t2_fusiona", r.is_some()));
        if let Some(r) = r {
            props.push(("t2_auditoria", r.aud_apertura >= 0));
            props.push(("t2_renovacion", r.renovacion_slot == 1 + p.m_sec + 1));
        }
    } else if t == "reorg_antes" {
        if let (Some(a), Some(b)) = (caso.extras.punta_a, caso.extras.punta_b) {
            let (ea, _) = fold_referencia(&caso.dag, a, p);
            let (eb, _) = fold_referencia(&caso.dag, b, p);
            props.push((
                "t3_a_activo",
                estado_de_vivo(&ea, &k1(), 0, ea.slot_actual, p) == Some(EstadoEfectivo::Activo),
            ));
            props.push((
                "t3_b_precomprometido",
                estado_de_vivo(&eb, &k1(), 0, eb.slot_actual, p)
                    == Some(EstadoEfectivo::Precomprometido),
            ));
        }
    } else if t == "reorg_despues" {
        if let (Some(a), Some(b)) = (caso.extras.punta_a, caso.extras.punta_b) {
            let (ea, _) = fold_referencia(&caso.dag, a, p);
            let (eb, _) = fold_referencia(&caso.dag, b, p);
            props.push((
                "t4_a_activo",
                estado_de_vivo(&ea, &k1(), 0, ea.slot_actual, p) == Some(EstadoEfectivo::Activo),
            ));
            props.push((
                "t4_b_renovado",
                sector_vivo(&eb, &k1(), 0).is_some_and(|r| r.renovacion_slot == 1 + p.m_sec + 1),
            ));
        }
    } else if t == "particion_honesta" {
        for (i, k) in [k1(), k2()].iter().enumerate() {
            let ok = estado_de_vivo(&est_ref, k, 0, est_ref.slot_actual, p)
                == Some(EstadoEfectivo::Activo);
            let nombre: &'static str = if i == 0 { "t5_clave_1" } else { "t5_clave_2" };
            props.push((nombre, ok));
        }
    } else if t == "varios_sectores" {
        for (j, k) in caso.extras.claves.iter().enumerate() {
            let n = sectores_activos(&est_ref, k, est_ref.slot_actual, p);
            let esp = caso.extras.n_activos.get(j).copied().unwrap_or(0);
            let nombre: &'static str = match j {
                0 => "t6_activos_1",
                1 => "t6_activos_2",
                _ => "t6_activos_3",
            };
            props.push((nombre, n == esp));
            props.push((
                match j {
                    0 => "t6_requisito_1",
                    1 => "t6_requisito_2",
                    _ => "t6_requisito_3",
                },
                requisito(&est_ref, k, est_ref.slot_actual, p) == esp * p.q_sec,
            ));
            props.push((
                match j {
                    0 => "t6_fianza_1",
                    1 => "t6_fianza_2",
                    _ => "t6_fianza_3",
                },
                fianza_comprometida(&est_ref, k) == esp * p.q_sec,
            ));
        }
    } else if t == "garantia_insuficiente" {
        if let (Some(ks), Some(kc)) = (caso.extras.clave_sin, caso.extras.clave_con) {
            props.push(("t7_sin_sector", sector_vivo(&est_ref, &ks, 0).is_none()));
            props.push(("t7_con_sector", sector_vivo(&est_ref, &kc, 0).is_some()));
        }
        if let (Some(bm), Some(bb)) = (
            caso.extras.bloque_sin_garantia,
            caso.extras.bloque_con_garantia,
        ) {
            props.push((
                "t7_bloque_malo",
                desc_ref.get(&bm).cloned().unwrap_or_default() == vec![MotivoSector::ErrEstado],
            ));
            let (_, d4) = fold_referencia(&caso.dag, bb, p);
            props.push((
                "t7_bloque_bueno",
                !d4.get(&bb)
                    .cloned()
                    .unwrap_or_default()
                    .contains(&MotivoSector::ErrEstado),
            ));
        }
    } else if t == "retirada_con_falta" {
        if let Some(k) = caso.extras.clave {
            props.push((
                "t8_en_retirada",
                estado_de_vivo(&est_ref, &k, 0, est_ref.slot_actual, p)
                    == Some(EstadoEfectivo::EnRetirada),
            ));
        }
    } else if t == "duplicados_reciclados" {
        if let Some(k) = caso.extras.clave {
            let hay_v1 = est_ref.sectores.values().any(|r| {
                r.id.clave == k && r.id.sector_index == 0 && r.id.version == 1 && !r.es_terminal()
            });
            let hay_v0 = est_ref
                .sectores
                .values()
                .any(|r| r.id.clave == k && r.id.sector_index == 0 && r.id.version == 0);
            props.push(("t9_recilo_con_version", hay_v1));
            props.push(("t9_vieja_terminal", hay_v0));
        }
        if let Some(br) = caso.extras.bloque_reciclado {
            let d = desc_ref.get(&br).cloned().unwrap_or_default();
            props.push((
                "t9_duplicado_rechazado",
                d.contains(&MotivoSector::ErrDobleAlta) || d.contains(&MotivoSector::ErrVersion),
            ));
            props.push(("t9_salto_rechazado", d.contains(&MotivoSector::ErrVersion)));
        }
    } else if t == "history_size_incompatible" {
        if let (Some(bm), Some(bb)) = (caso.extras.bloque_malo, caso.extras.bloque_bueno) {
            let (_, d4) = fold_referencia(&caso.dag, bm, p);
            props.push((
                "t10_malo_invalido",
                d4.get(&bm).cloned().unwrap_or_default() == vec![MotivoSector::ErrEstado],
            ));
            props.push((
                "t10_bueno_valido",
                !desc_ref
                    .get(&bb)
                    .cloned()
                    .unwrap_or_default()
                    .contains(&MotivoSector::ErrEstado),
            ));
        }
    } else if t == "pruebas_fuera_plazo" {
        if let Some(bt) = caso.extras.bloque_tardio {
            props.push((
                "t11_tardia_rechazada",
                desc_ref
                    .get(&bt)
                    .cloned()
                    .unwrap_or_default()
                    .contains(&MotivoSector::ErrPlazo),
            ));
        }
        props.push((
            "t11_suspendido",
            estado_de_vivo(&est_ref, &k1(), 1, est_ref.slot_actual, p)
                == Some(EstadoEfectivo::Suspendido),
        ));
        if let Some(br) = caso.extras.bloque_recuperacion {
            let (e7, _) = fold_referencia(&caso.dag, br, p);
            props.push((
                "t11_recuperacion",
                estado_de_vivo(&e7, &k1(), 1, e7.slot_actual, p) == Some(EstadoEfectivo::Activo),
            ));
        }
    } else if t == "blue_work_invariante"
        && let (Some(d2), Some(p2)) = (&caso.extras.dag2, caso.extras.punta2)
    {
        props.push((
            "t12_blue_work_igual",
            caso.dag.blue_work(caso.punta) == d2.blue_work(p2),
        ));
    }

    let ok = props.iter().all(|(_, b)| *b);
    ResultadoCaso {
        tipo: t,
        propiedades: props,
        ok,
        n_bloques: orden.len(),
        n_sectores,
        n_ops,
        n_descartes: desc_punta.len(),
        max_ops_bloque: max_ops,
    }
}

// ── vectores de rechazo (C-SEC-13) ──────────────────────────────────────────

/// Un vector de rechazo/contrato.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VectorRechazo {
    /// Identificador `R-XX`.
    pub id: &'static str,
    /// Regla(s) `C-SEC-*`.
    pub regla: &'static str,
    /// Nombre del escenario.
    pub escenario: &'static str,
    /// Operación.
    pub operacion: &'static str,
    /// Precondición.
    pub precondicion: &'static str,
    /// Resultado esperado.
    pub esperado: &'static str,
    /// Descripción.
    pub descripcion: &'static str,
}

fn dos_bloques(fondos: &[i64], ops: Vec<Operacion>, slot: i64) -> (Constr, u64) {
    let c = &mut Constr::new();
    let k1 = k1();
    let mut o0 = Vec::with_capacity(fondos.len());
    for f in fondos {
        o0.push(op_fond(k1, *f));
    }
    let b0 = c.pow(vec![], 0, k1, 1, o0);
    let b1 = c.pow(vec![b0], slot, k1, 1, ops);
    (c.clone(), b1)
}

fn base_alta(p: &ParametrosSector, fondos: i64, h: u64) -> (Constr, u64) {
    let c = &mut Constr::new();
    let k1 = k1();
    let b0 = c.pow(
        vec![],
        0,
        k1,
        1,
        vec![op_fond(k1, fondos), op_alta(k1, 0, 0, p.q_sec, h)],
    );
    (c.clone(), b0)
}

/// Construye el escenario de un vector por nombre.
#[must_use]
#[expect(
    clippy::panic,
    reason = "un escenario de vector desconocido es un error de test, no de producción"
)]
pub fn construir_escenario(nombre: &str, p: &ParametrosSector) -> (Constr, u64) {
    let k1 = k1();
    match nombre {
        "alta_sin_firma" => {
            let op = Operacion {
                firma: false,
                ..op_alta(k1, 0, 0, p.q_sec, 1)
            };
            dos_bloques(&[p.q_sec], vec![op], 1)
        }
        "alta_version_salto" => dos_bloques(
            &[4 * p.q_sec],
            vec![op_alta(k1, 0, 0, p.q_sec, 1), op_alta(k1, 0, 2, p.q_sec, 1)],
            1,
        ),
        "alta_doble" => dos_bloques(
            &[4 * p.q_sec],
            vec![op_alta(k1, 0, 0, p.q_sec, 1), op_alta(k1, 0, 0, p.q_sec, 1)],
            1,
        ),
        "alta_history_baja" => dos_bloques(&[p.q_sec], vec![op_alta(k1, 0, 0, p.q_sec, 0)], 1),
        "alta_history_alta" => {
            dos_bloques(&[p.q_sec], vec![op_alta(k1, 0, 0, p.q_sec, p.h_max + 1)], 1)
        }
        "alta_fianza" => dos_bloques(&[p.q_sec - 1], vec![op_alta(k1, 0, 0, p.q_sec, 1)], 1),
        "elegibilidad_prematura" => {
            let (c, b0) = base_alta(p, 2 * p.q_sec, 1);
            let c = &mut c.clone();
            let b1 = c.post(vec![b0], p.m_sec - 1, k1, 0, 1, 0, 1, vec![]);
            (c.clone(), b1)
        }
        "renovar_sin_sector" => dos_bloques(&[p.q_sec], vec![op_renovar(k1, 0)], 1),
        "renovar_prematuro" => dos_bloques(
            &[2 * p.q_sec],
            vec![op_alta(k1, 0, 0, p.q_sec, 1), op_renovar(k1, 0)],
            1,
        ),
        "suspension_auditoria" => {
            let (c, b0) = base_alta(p, 2 * p.q_sec, 1);
            let c = &mut c.clone();
            let s0 = 1 + p.m_sec;
            let b1 = c.post(vec![b0], s0, k1, 0, 1, 0, 1, vec![op_abrir(k1, 0, 7)]);
            let b2 = c.post(vec![b1], s0 + 1 + p.p_aud, k1, 0, 1, 0, 1, vec![]);
            (c.clone(), b2)
        }
        "contestar_sin_aud" => dos_bloques(
            &[2 * p.q_sec],
            vec![op_alta(k1, 0, 0, p.q_sec, 1), op_contestar(k1, 0, 7, true)],
            1,
        ),
        "contestar_tarde" => {
            let (c, b0) = base_alta(p, 2 * p.q_sec, 1);
            let c = &mut c.clone();
            let s0 = 1 + p.m_sec;
            let b1 = c.post(vec![b0], s0, k1, 0, 1, 0, 1, vec![op_abrir(k1, 0, 21)]);
            let b2 = c.pow(
                vec![b1],
                s0 + p.p_aud + p.p_rec,
                k1,
                1,
                vec![op_contestar(k1, 0, 21, true)],
            );
            (c.clone(), b2)
        }
        "contestar_sin_prueba" => {
            let (c, b0) = base_alta(p, 2 * p.q_sec, 1);
            let c = &mut c.clone();
            let s0 = 1 + p.m_sec;
            let b1 = c.post(vec![b0], s0, k1, 0, 1, 0, 1, vec![op_abrir(k1, 0, 21)]);
            let b2 = c.pow(
                vec![b1],
                s0 + p.p_aud,
                k1,
                1,
                vec![op_contestar(k1, 0, 21, false)],
            );
            (c.clone(), b2)
        }
        "renovar_caducado" => {
            let (c, b0) = base_alta(p, 2 * p.q_sec, 1);
            let c = &mut c.clone();
            let b1 = c.pow(
                vec![b0],
                1 + p.m_sec + p.t_cad,
                k1,
                1,
                vec![op_renovar(k1, 0)],
            );
            (c.clone(), b1)
        }
        "retirar_prematuro" => dos_bloques(
            &[2 * p.q_sec],
            vec![op_alta(k1, 0, 0, p.q_sec, 1), op_retirar(k1, 0)],
            1,
        ),
        "valor_retiro_pendiente" => dos_bloques(&[100], vec![op_ret(k1, 50), op_ret(k1, 30)], 1),
        "liberacion_incidente" => {
            let c = &mut Constr::new();
            let b0 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 1000), op_ret(k1, 100)]);
            let b1 = c.pow(vec![b0], 1, k1, 1, vec![op_evid(k1, 0, 9)]);
            let b2 = c.pow(vec![b1], 1 + p.r_slots, k1, 1, vec![op_lib(k1, 100)]);
            (c.clone(), b2)
        }
        "liberacion_antes_plazo" => {
            let c = &mut Constr::new();
            let b0 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 100), op_ret(k1, 50)]);
            let b1 = c.pow(vec![b0], 1, k1, 1, vec![op_lib(k1, 50)]);
            (c.clone(), b1)
        }
        "segunda_auditoria" => {
            let (c, b0) = base_alta(p, 2 * p.q_sec, 1);
            let c = &mut c.clone();
            let s0 = 1 + p.m_sec;
            let b1 = c.post(
                vec![b0],
                s0,
                k1,
                0,
                1,
                0,
                1,
                vec![op_abrir(k1, 0, 7), op_abrir(k1, 0, 8)],
            );
            (c.clone(), b1)
        }
        "elegibilidad_history" => {
            let (c, b0) = base_alta(p, 2 * p.q_sec, 1);
            let c = &mut c.clone();
            let b1 = c.post(vec![b0], 1 + p.m_sec, k1, 0, 2, 0, 1, vec![]);
            (c.clone(), b1)
        }
        "prueba_sucinta_inert" => {
            let (c, b0) = base_alta(p, 2 * p.q_sec, 1);
            let c = &mut c.clone();
            let b1 = c.post(vec![b0], 1 + p.m_sec, k1, 0, 1, 0, 1, vec![]);
            (c.clone(), b1)
        }
        "alta_version_terminal" => {
            let (c, b0) = base_alta(p, 2 * p.q_sec, 1);
            let c = &mut c.clone();
            let s0 = 1 + p.m_sec;
            let b1 = c.pow(vec![b0], s0, k1, 1, vec![op_retirar(k1, 0)]);
            let b2 = c.pow(
                vec![b1],
                s0 + p.r_sec,
                k1,
                1,
                vec![op_alta(k1, 0, 0, p.q_sec, 1)],
            );
            (c.clone(), b2)
        }
        "reorg_deshace_alta" => {
            let c = &mut Constr::new();
            let b0 = c.pow(vec![], 0, k1, 1, vec![op_fond(k1, 100)]);
            let b1 = c.pow(vec![b0], 1, k1, 1, vec![op_alta(k1, 0, 0, p.q_sec, 1)]);
            let bb = c.pow(vec![b0], 2, k1, 1, vec![]);
            let bb2 = c.post(vec![bb], 1 + p.m_sec, k1, 0, 1, 0, 1, vec![]);
            let _ = b1;
            (c.clone(), bb2)
        }
        "entrada_sin_tokens" => dos_bloques(&[0], vec![op_alta(k1, 0, 0, p.q_sec, 1)], 1),
        otro => panic!("escenario de rechazo desconocido: {otro}"),
    }
}

/// Catálogo de los 24 vectores de rechazo.
pub const VECTORES_RECHAZO: [VectorRechazo; 24] = [
    VectorRechazo {
        id: "R-01",
        regla: "C-SEC-02",
        escenario: "alta_sin_firma",
        operacion: "AltaSector",
        precondicion: "firma ausente",
        esperado: "ERR_FIRMA",
        descripcion: "alta sin firma de la clave",
    },
    VectorRechazo {
        id: "R-02",
        regla: "C-SEC-02",
        escenario: "alta_version_salto",
        operacion: "AltaSector v=2 sobre v=0",
        precondicion: "no hay v=1",
        esperado: "ERR_VERSION",
        descripcion: "salto de versión en índice reciclado",
    },
    VectorRechazo {
        id: "R-03",
        regla: "C-SEC-02",
        escenario: "alta_doble",
        operacion: "AltaSector v=0 dos veces",
        precondicion: "v=0 ya viva",
        esperado: "ERR_DOBLE_ALTA",
        descripcion: "doble alta de la misma versión",
    },
    VectorRechazo {
        id: "R-04",
        regla: "C-SEC-02",
        escenario: "alta_history_baja",
        operacion: "AltaSector h=0",
        precondicion: "h < h_min=1",
        esperado: "ERR_HISTORY",
        descripcion: "history_size fuera de ventana (baja)",
    },
    VectorRechazo {
        id: "R-05",
        regla: "C-SEC-02",
        escenario: "alta_history_alta",
        operacion: "AltaSector h=h_max+1",
        precondicion: "h > h_max",
        esperado: "ERR_HISTORY",
        descripcion: "history_size fuera de ventana (alta)",
    },
    VectorRechazo {
        id: "R-06",
        regla: "C-SEC-02/C-SEC-09",
        escenario: "alta_fianza",
        operacion: "AltaSector",
        precondicion: "activo = q_sec-1",
        esperado: "ERR_FIANZA",
        descripcion: "falta garantía para inmovilizar q_sec",
    },
    VectorRechazo {
        id: "R-07",
        regla: "C-SEC-03/C-SEC-12",
        escenario: "elegibilidad_prematura",
        operacion: "Bloque PoST",
        precondicion: "sector precomprometido",
        esperado: "BLOQUE_INVALIDO",
        descripcion: "no elegible antes de M_sec",
    },
    VectorRechazo {
        id: "R-08",
        regla: "C-SEC-04",
        escenario: "renovar_sin_sector",
        operacion: "RenovarSector",
        precondicion: "no hay sector vivo",
        esperado: "ERR_NO_EXISTE",
        descripcion: "renovar sector inexistente",
    },
    VectorRechazo {
        id: "R-09",
        regla: "C-SEC-04",
        escenario: "renovar_prematuro",
        operacion: "RenovarSector",
        precondicion: "sector precomprometido",
        esperado: "ERR_ESTADO",
        descripcion: "renovar antes de madurar",
    },
    VectorRechazo {
        id: "R-10",
        regla: "C-SEC-05/C-SEC-12",
        escenario: "suspension_auditoria",
        operacion: "Bloque PoST",
        precondicion: "auditoría no contestada a plazo",
        esperado: "BLOQUE_INVALIDO",
        descripcion: "suspendido no elegible",
    },
    VectorRechazo {
        id: "R-11",
        regla: "C-SEC-06",
        escenario: "contestar_sin_aud",
        operacion: "ContestarAuditoria",
        precondicion: "sin auditoría abierta",
        esperado: "ERR_AUDITORIA",
        descripcion: "contestar sin auditoría",
    },
    VectorRechazo {
        id: "R-12",
        regla: "C-SEC-06",
        escenario: "contestar_tarde",
        operacion: "ContestarAuditoria",
        precondicion: "slot >= apertura+P_aud+P_rec",
        esperado: "ERR_PLAZO",
        descripcion: "contestar fuera de plazo",
    },
    VectorRechazo {
        id: "R-13",
        regla: "C-SEC-06",
        escenario: "contestar_sin_prueba",
        operacion: "ContestarAuditoria",
        precondicion: "prueba inválida",
        esperado: "ERR_PRUEBA",
        descripcion: "contestación sin prueba válida",
    },
    VectorRechazo {
        id: "R-14",
        regla: "C-SEC-07",
        escenario: "renovar_caducado",
        operacion: "RenovarSector",
        precondicion: "sector con caducidad efectiva vencida",
        esperado: "ERR_ESTADO",
        descripcion: "renovar un sector caducado (madura y caduca en el mismo salto)",
    },
    VectorRechazo {
        id: "R-15",
        regla: "C-SEC-08",
        escenario: "retirar_prematuro",
        operacion: "RetirarSector",
        precondicion: "sector precomprometido",
        esperado: "ERR_ESTADO",
        descripcion: "retirar antes de madurar",
    },
    VectorRechazo {
        id: "R-16",
        regla: "C-SEC-10",
        escenario: "valor_retiro_pendiente",
        operacion: "Retiro (valor)",
        precondicion: "ya hay retiro pendiente",
        esperado: "ERR_RETIRO_PENDIENTE",
        descripcion: "segunda retirada de valor",
    },
    VectorRechazo {
        id: "R-17",
        regla: "C-SEC-10",
        escenario: "liberacion_incidente",
        operacion: "Liberacion",
        precondicion: "incidente C-EVP abierto",
        esperado: "ERR_ESTADO",
        descripcion: "liberar con incidente (EV-24(i))",
    },
    VectorRechazo {
        id: "R-18",
        regla: "C-SEC-10",
        escenario: "liberacion_antes_plazo",
        operacion: "Liberacion",
        precondicion: "slot < retiro+R_slots",
        esperado: "ERR_FIANZA",
        descripcion: "liberar antes de R_slots",
    },
    VectorRechazo {
        id: "R-19",
        regla: "C-SEC-05/C-SEC-13",
        escenario: "segunda_auditoria",
        operacion: "AbrirAuditoria",
        precondicion: "ya hay auditoría abierta",
        esperado: "ERR_LIMITE",
        descripcion: "segunda auditoría abierta (F6)",
    },
    VectorRechazo {
        id: "R-20",
        regla: "C-SEC-12",
        escenario: "elegibilidad_history",
        operacion: "Bloque PoST h=2",
        precondicion: "history_size no casa",
        esperado: "BLOQUE_INVALIDO",
        descripcion: "solución incondicional",
    },
    VectorRechazo {
        id: "R-21",
        regla: "C-SEC-14/C-SEC-15",
        escenario: "prueba_sucinta_inert",
        operacion: "prueba_sucinta; fuente_peso",
        precondicion: "sector activo sin prueba",
        esperado: "SIN_CONSECUENCIAS",
        descripcion: "sin prueba: estado, elegibilidad y FuentePeso no cambian",
    },
    VectorRechazo {
        id: "R-22",
        regla: "C-SEC-11",
        escenario: "reorg_deshace_alta",
        operacion: "Bloque PoST tras reorg",
        precondicion: "la rama nueva no tiene el alta",
        esperado: "BLOQUE_INVALIDO",
        descripcion: "undo en reorganización: sin el alta, la solución no es elegible",
    },
    VectorRechazo {
        id: "R-23",
        regla: "C-SEC-01",
        escenario: "alta_version_terminal",
        operacion: "AltaSector reutiliza v=0 terminal",
        precondicion: "v=0 ya retirada",
        esperado: "ERR_DOBLE_ALTA",
        descripcion: "una versión terminal no se reutiliza; exige v+1",
    },
    VectorRechazo {
        id: "R-24",
        regla: "C-SEC-16",
        escenario: "entrada_sin_tokens",
        operacion: "AltaSector",
        precondicion: "activo = 0",
        esperado: "ERR_FIANZA",
        descripcion: "sin tokens no se inmoviliza q_sec (barrera de entrada)",
    },
];

fn motivo_de(nombre: &str) -> Option<MotivoSector> {
    Some(match nombre {
        "ERR_FIRMA" => MotivoSector::ErrFirma,
        "ERR_DOBLE_ALTA" => MotivoSector::ErrDobleAlta,
        "ERR_VERSION" => MotivoSector::ErrVersion,
        "ERR_HISTORY" => MotivoSector::ErrHistory,
        "ERR_FIANZA" => MotivoSector::ErrFianza,
        "ERR_ESTADO" => MotivoSector::ErrEstado,
        "ERR_PLAZO" => MotivoSector::ErrPlazo,
        "ERR_PRUEBA" => MotivoSector::ErrPrueba,
        "ERR_AUDITORIA" => MotivoSector::ErrAuditoria,
        "ERR_NO_EXISTE" => MotivoSector::ErrNoExiste,
        "ERR_RETIRO_PENDIENTE" => MotivoSector::ErrRetiroPendiente,
        "ERR_LIMITE" => MotivoSector::ErrLimite,
        "ERR_DESBORDAMIENTO" => MotivoSector::ErrDesbordamiento,
        _ => return None,
    })
}

/// Observa el resultado de un vector de rechazo, en el formato de `esperado`.
#[must_use]
pub fn evaluar_vector(v: &VectorRechazo, p: &ParametrosSector) -> String {
    let (c, punta) = construir_escenario(v.escenario, p);
    let (est, desc) = fold_referencia(&c.dag, punta, p);
    if v.esperado == "SIN_CONSECUENCIAS" {
        let Some(r) = sector_vivo(&est, &k1(), 0) else {
            return "NO_ACTIVO".to_string();
        };
        let (res, _) = prueba_sucinta(r.id, r.r2, r.history_size, est.slot_actual, p);
        if res != super::ResultadoPrueba::SinPrueba {
            return "PRUEBA_INESPERADA".to_string();
        }
        if estado_efectivo(&r, est.slot_actual, p) != EstadoEfectivo::Activo {
            return "ESTADO_CAMBIA".to_string();
        }
        if fuente_peso_de(&est, &k1(), est.slot_actual, p) != 1 {
            return "PESO_CAMBIA".to_string();
        }
        return "SIN_CONSECUENCIAS".to_string();
    }
    let d = desc.get(&punta).cloned().unwrap_or_default();
    if v.esperado == "BLOQUE_INVALIDO" {
        return if d == vec![MotivoSector::ErrEstado] {
            "BLOQUE_INVALIDO".to_string()
        } else {
            let nombres: Vec<&str> = d.iter().map(|m| m.nombre()).collect();
            format!("NO_INVALIDO:{}", nombres.join("|"))
        };
    }
    let Some(m) = motivo_de(v.esperado) else {
        return "ESPERADO_DESCONOCIDO".to_string();
    };
    if d.contains(&m) {
        v.esperado.to_string()
    } else {
        let nombres: Vec<&str> = d.iter().map(|mm| mm.nombre()).collect();
        format!("NO_RECHAZO:{}", nombres.join("|"))
    }
}

/// Deja el símbolo `R2` disponible para los tests que lo necesiten.
pub type R2Pub = R2;

/// Deja `Etapa` disponible (usada en chequeos externos).
#[must_use]
pub fn es_terminal_etapa(e: Etapa) -> bool {
    matches!(e, Etapa::Retirado | Etapa::Caducado)
}

/// Cuenta las operaciones descartadas de un bloque en un repliegue concreto.
#[must_use]
pub fn descartes_de(d: &DagSector, id: u64, p: &ParametrosSector) -> Vec<MotivoSector> {
    let (_, desc) = fold_referencia(d, id, p);
    desc.get(&id).cloned().unwrap_or_default()
}

/// Mapa de descartes por bloque de un repliegue (ayuda para informes).
#[must_use]
pub fn descartes_mapa(
    d: &DagSector,
    id: u64,
    p: &ParametrosSector,
) -> BTreeMap<u64, Vec<MotivoSector>> {
    fold_referencia(d, id, p).1
}
