//! AT-1c · C2 · la prueba real del votante honesto frente a la falta entre ventanas.
//!
//! Vive dentro del crate (`crate::nodo::pruebas_at1c`) para poder usar el diario durable y
//! `MotorVotos::votar_tardio`, que son `pub(crate)`. Por cada semilla se monta **una** `Cadena`
//! real con hasta tres ramas, una «mayoría» (> 2/3 del peso) que firma certificados `0x09` reales
//! incluidos en bloques al azar, y **un** `MotorVotos` en modo peso con diario durante todo el
//! mundo. El candidato de cada ventana es el que elegiría el nodo (`Cadena::candidato_por_slot`
//! con el slot de apertura menos `LAG_CANDIDATO_VOTOS`) y el estado, `estado_past(candidato)`.
//!
//! La comprobación: para **cada** par `n₁ < n₂` de votos firmados (normales y tardíos), el hecho
//! que calcula la cadena (`hecho_de_tx_de_prueba`) nunca es `Falta`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    reason = "prueba de escenarios con mundos generados; falla con panic por diseño"
)]

use std::collections::{BTreeMap, HashMap};

use super::*;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::HechoVoto;
use zx_core::{Amount, CBID_RED_DEV, ClavePublica, Digest, OperacionAlmacenamiento};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Tabla};

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Parámetros de la prueba (los mismos del nodo: `T_INST_VOTOS = 2`, `LAG = 4`, `F = 600`).
// ─────────────────────────────────────────────────────────────────────────────────────────────

const T_VOTOS: u64 = 2;
const LAG: u64 = 4;
const PLAZO_EVIDENCIA: u64 = 300;
const F_SLOTS: u64 = 600;
const SEMILLAS: u64 = 12;

/// Claves: 0 = votante bajo prueba (peso 1 de 4, < 1/3); 1, 2 y 3 = mayoría (peso 3 de 4, > 2/3).
const VOTANTE: u8 = 0;
const MAYORIA: [u8; 3] = [1, 2, 3];

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Generador determinista (SplitMix64), sin dependencias nuevas.
// ─────────────────────────────────────────────────────────────────────────────────────────────

struct Azar(u64);

impl Azar {
    fn nuevo(semilla: u64) -> Self {
        Self(semilla.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }

    fn siguiente(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn abajo(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.siguiente() % n }
    }

    fn prob(&mut self, p: f64) -> bool {
        (self.siguiente() as f64) / (u64::MAX as f64) < p
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Claves y estado.
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn ikm(i: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = i;
    k[31] = 0xA5;
    k
}

fn bls(i: u8) -> ClaveSecreta {
    ClaveSecreta::generar(&ikm(i)).expect("clave BLS")
}

fn ed(i: u8) -> ClavePublica {
    let mut b = [0u8; 32];
    b[0] = i;
    b[1] = 0x11;
    ClavePublica::desde_bytes(b)
}

fn hash_de(id: u32) -> BlockHash {
    super::pruebas_eclr2::hash_u32(id)
}

/// Las cuatro claves con un sector activo cada una (peso 1). La tabla canónica queda fija.
fn estado_cuatro_claves() -> EstadoTransicion {
    let p = ParametrosSector::dev();
    let mut est = EstadoTransicion::inicial();
    est.parametros_sector = p;
    est.fase = zx_consensus::transicion::Fase::Genesis;
    for i in 0..4u8 {
        est.claves_voto.insert(
            ed(i),
            ClaveVoto {
                clave_bls: bls(i).clave_publica().bytes(),
                prueba_posesion: [0u8; 96],
            },
        );
        let id = SectorId {
            clave: ed(i),
            sector_index: 0,
            version: 0,
        };
        est.sectores.insert(
            id,
            RegistroSector {
                id,
                r2: [0u64; 4],
                history_size: 1,
                etapa: Etapa::Activo,
                alta_slot: 0,
                renovacion_slot: 1_000_000,
                retiro_slot: -1,
                fianza: p.q_sec,
                aud_apertura: -1,
                aud_contestada: -1,
            },
        );
        let mut g = zx_consensus::transicion::Garantia::nueva();
        g.activo = Amount::nuevo(1_000_000).expect("garantía");
        est.garantias.insert(ed(i), g);
    }
    est
}

fn cadena_con(estado: EstadoTransicion) -> Cadena {
    const K_CADENA: u32 = 1;
    const MAX_PADRES: u8 = 15;
    let mut cadena = Cadena::nueva_con_evidencia_e_inicial(
        super::pruebas_eclr2::params_subsidio(Some(F_SLOTS)),
        K_CADENA,
        CBID_RED_DEV,
        MAX_PADRES,
        zx_consensus::transicion::ParametrosEvidencia::inactiva(),
        estado,
    );
    cadena
        .admitir(super::pruebas_eclr2::genesis())
        .expect("génesis");
    cadena
        .admitir(super::pruebas_eclr2::pow_terminal(1, 1))
        .expect("terminal PoW");
    cadena
}

/// Tabla canónica del estado en `slot`, en **orden canónico** (por bytes de clave BLS), que es el
/// que indexa el mapa de bits del certificado.
fn tabla_canonica_de(estado: &EstadoTransicion, slot: u64) -> Tabla {
    let slot_i = i64::try_from(slot).unwrap_or(i64::MAX);
    let mut claves: Vec<Clave> = zx_consensus::transicion::votos::tabla_canonica(estado, slot_i)
        .iter()
        .map(|c| Clave {
            clave: c.clave_bls.to_vec(),
            peso: c.peso,
            activo: c.activo,
            prueba: c.prueba,
            garantia: c.garantia,
        })
        .collect();
    claves.sort_by(|a, b| a.clave.cmp(&b.clave));
    Tabla { n: 0, claves }
}

/// Certificado `0x09` real firmado por las tres claves de la mayoría (quórum 3 de 4).
fn certificado(
    n: u64,
    candidato: BlockHash,
    h_t: [u8; 32],
    tabla: &Tabla,
) -> zx_votos::CertificadoPeso {
    let cand = *candidato.as_bytes();
    let mensaje = zx_votos::mensaje_voto_peso(n, &cand, &h_t, &[0u8; 32]);
    let mut votos: Vec<(usize, zx_votos::Firma)> = Vec::new();
    for i in MAYORIA {
        let pk = bls(i).clave_publica();
        let pos = tabla
            .claves
            .iter()
            .position(|c| c.clave.as_slice() == pk.bytes().as_slice())
            .expect("clave de la mayoría en la tabla");
        let firma = zx_votos::firmar(&bls(i), DOMINIO_VOTO, &mensaje).expect("firma BLS");
        votos.push((pos + 1, firma));
    }
    zx_votos::construir_certificado(n, cand, h_t, [0u8; 32], tabla, &votos).expect("certificado")
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Votos firmados y evidencia.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct VotoFirmado {
    n: u64,
    candidato: BlockHash,
    h_t: [u8; 32],
    raiz: [u8; 32],
    firma: [u8; 96],
}

fn firmante_sk() -> ed25519_zebra::SigningKey {
    ed25519_zebra::SigningKey::from([7u8; 32])
}

fn firmante_pk() -> ClavePublica {
    ClavePublica::desde_bytes(ed25519_zebra::VerificationKey::from(&firmante_sk()).into())
}

/// Tx v6 `0x0B` de la evidencia con dos votos por peso y su testigo Ed25519.
fn tx_de_dos_votos(v1: &VotoFirmado, v2: &VotoFirmado) -> Tx {
    Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento {
            operacion: OperacionAlmacenamiento::EvidenciaVotosPeso {
                clave: firmante_pk(),
                clave_bls: bls(VOTANTE).clave_publica().bytes(),
                voto1: zx_core::VotoPesoEvidencia {
                    n: v1.n,
                    candidato: *v1.candidato.as_bytes(),
                    h_t_siguiente: v1.h_t,
                    raiz_estado: v1.raiz,
                    firma: v1.firma,
                },
                voto2: zx_core::VotoPesoEvidencia {
                    n: v2.n,
                    candidato: *v2.candidato.as_bytes(),
                    h_t_siguiente: v2.h_t,
                    raiz_estado: v2.raiz,
                    firma: v2.firma,
                },
            },
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// El mundo.
// ─────────────────────────────────────────────────────────────────────────────────────────────

struct Mundo {
    cadena: Cadena,
    terminal: BlockHash,
    x: BlockHash,
    /// Votos honestos por ventana (votante bajo prueba).
    votos: BTreeMap<u64, VotoFirmado>,
    /// Rama de cada bloque: 0 = tronco, 1 = A, 2 = B.
    rama: HashMap<BlockHash, u8>,
    tardios: usize,
    negados_candado: usize,
    negados_v6: usize,
    /// (ventana, candidato) de los sellos de la mayoría.
    sellos: Vec<(u64, BlockHash)>,
    primer_sello: Option<(u64, BlockHash)>,
    rama_a: Vec<BlockHash>,
    ventanas_saltadas: Vec<u64>,
}

/// Si el bloque llevaba certificado `0x09`.
struct BloqueNuevo {
    con_certificado: bool,
}

fn mundo(semilla: u64) -> Mundo {
    let mut rng = Azar::nuevo(semilla ^ 0x0A71_0C00_0000_0000);
    let estado = estado_cuatro_claves();
    let mut cadena = cadena_con(estado.clone());
    let terminal = hash_de(1);
    let (productor, productor_sk) = super::pruebas_eclr2::productor_firmante();
    let tabla = tabla_canonica_de(&estado, 1);
    let h_tabla = zx_votos::hash_tabla(&tabla);

    let dir = tempfile::tempdir().expect("tempdir");
    let diario = crate::votos::DiarioVotos::nueva(dir.path().join("at1c.registro"), CBID_RED_DEV)
        .expect("diario");
    let mut motor = MotorVotos::nuevo(ConfigMotorVotos {
        perfil: crate::perfil::parametros_votos_dev(),
        claves: vec![bls(VOTANTE)],
        emitir_votos: true,
    });
    motor.vincular_diario(diario);

    let mut rama: HashMap<BlockHash, u8> = HashMap::new();
    let mut rama_a: Vec<BlockHash> = Vec::new();
    let mut votos: BTreeMap<u64, VotoFirmado> = BTreeMap::new();
    let mut tardios = 0usize;
    let mut negados_candado = 0usize;
    let mut negados_v6 = 0usize;
    let mut sellos: Vec<(u64, BlockHash)> = Vec::new();
    let mut primer_sello: Option<(u64, BlockHash)> = None;
    let mut ventanas_saltadas: Vec<u64> = Vec::new();

    let mut id: u32 = 100;
    // Tronco común: 2–4 bloques desde el terminal PoW.
    let tronco = 2 + rng.abajo(3);
    let mut padre = terminal;
    let mut s = 2u64;
    for _ in 0..tronco {
        let b = super::pruebas_eclr2::post_con_txs(id, vec![padre], s, 1, productor, Vec::new());
        cadena.admitir(b).expect("tronco");
        let h = hash_de(id);
        rama.insert(h, 0);
        padre = h;
        id += 1;
        s += 1;
    }
    let fork = padre;
    let mut tip_a = fork;
    let mut tip_b = fork;

    // Fases: A crece hasta `s_switch` (el votante vota en A); luego B, y a partir de `s_seal` la
    // mayoría sella en B. El ancla de la cadena cambia la selección a B.
    let s_switch = 24 + rng.abajo(8);
    let s_seal = s_switch + 1 + rng.abajo(3);
    let s_max = 74 + rng.abajo(17);
    let p_salto = 0.20;

    // Certificados pendientes de inclusión: (ventana, candidato, slot_inc, rama).
    let mut pendientes: Vec<(u64, BlockHash, u64, u8)> = Vec::new();
    let mut ultimo_sello_n: u64 = 0;
    let mut ultima_ventana: Option<u64> = None;

    while s <= s_max {
        // 1 · Bloques del slot `s`, con los certificados pendientes que toquen.
        let mut nuevos: Vec<BloqueNuevo> = Vec::new();
        for r in [1u8, 2u8] {
            let extiende = if r == 1 {
                rng.prob(if s < s_switch { 0.9 } else { 0.2 })
            } else {
                rng.prob(if s < s_switch { 0.15 } else { 0.9 })
            };
            if !extiende {
                continue;
            }
            let tip = if r == 1 { tip_a } else { tip_b };
            let mut con_certificado = false;
            let mut txs: Vec<(Tx, Vec<Vec<u8>>)> = Vec::new();
            if let Some(pos) = pendientes
                .iter()
                .position(|(_, _, slot_inc, rama_inc)| *rama_inc == r && *slot_inc <= s)
            {
                let (n_c, cand_c, _, _) = pendientes.remove(pos);
                let cert = certificado(n_c, cand_c, h_tabla, &tabla);
                let (tx, tst) = crate::votos::tx_certificado_peso(
                    &cert,
                    productor,
                    &productor_sk,
                    CBID_RED_DEV,
                );
                txs.push((tx, tst));
                con_certificado = true;
            }
            let b = super::pruebas_eclr2::post_con_txs(id, vec![tip], s, 1, productor, txs);
            cadena.admitir(b).expect("bloque PoST");
            let h = hash_de(id);
            rama.insert(h, r);
            if r == 1 {
                tip_a = h;
                rama_a.push(h);
            } else {
                tip_b = h;
            }
            nuevos.push(BloqueNuevo { con_certificado });
            id += 1;
        }
        // 2 · Lo que hace el nodo al admitir un bloque con `0x09`: si el estado seleccionado tiene
        //      finalidad, anclar la cadena en el bloque sellado.
        for b in &nuevos {
            if !b.con_certificado {
                continue;
            }
            if let Ok(est) = cadena.estado_virtual()
                && let Some(sellado) = est.finalidad_votos
            {
                let _ = cadena.considerar_ancla_de_estado(est.finalidad_votos_n, sellado);
            }
        }
        // 3 · Sellos de la mayoría en ventanas al azar.
        if s.is_multiple_of(T_VOTOS) {
            let n = s / T_VOTOS;
            if s >= s_seal && n > ultimo_sello_n && n >= ultimo_sello_n + 2 && rng.prob(0.7) {
                let candidato = if tip_b != fork {
                    Some(tip_b)
                } else if tip_a != fork {
                    Some(tip_a)
                } else {
                    None
                };
                if let Some(candidato) = candidato {
                    let es_primero = primer_sello.is_none();
                    sellos.push((n, candidato));
                    primer_sello.get_or_insert((n, candidato));
                    ultimo_sello_n = n;
                    // Inclusión con retraso al azar en cualquier rama; el primer sello, en la rama
                    // del candidato, para que la finalidad llegue a sus descendientes.
                    let rama_inc = if es_primero { 2 } else { 1 + rng.abajo(2) };
                    let retraso = 1 + rng.abajo(3);
                    pendientes.push((n, candidato, s + retraso, rama_inc as u8));
                }
            }
        }
        // 4 · El votante, al abrirse la ventana `n = s / T_VOTOS` (con los tardíos antes, como el
        //      nodo).
        if s.is_multiple_of(T_VOTOS) {
            let n = s / T_VOTOS;
            if ultima_ventana.is_none_or(|u| n > u) {
                // Garantía del generador: al menos cuatro ventanas saltadas tempranas, para que
                // cada semilla tenga tardíos suficientes aunque algunas negativas los reduzcan.
                let salta = (3..=6).contains(&n) || rng.prob(p_salto);
                if salta {
                    ventanas_saltadas.push(n);
                } else {
                    // Tardíos de las ventanas saltadas, en orden creciente, antes de abrir `n`.
                    let saltadas = std::mem::take(&mut ventanas_saltadas);
                    for k in saltadas {
                        registrar_tardio(
                            &motor,
                            &cadena,
                            k,
                            &mut votos,
                            &mut tardios,
                            &mut negados_candado,
                            &mut negados_v6,
                        );
                    }
                    abrir_ventana(
                        &mut motor,
                        &cadena,
                        n,
                        s,
                        &mut votos,
                        &mut negados_candado,
                        &mut negados_v6,
                    );
                }
                ultima_ventana = Some(n);
            }
        }
        s += 1;
    }

    // Cierre: bloque de fusión con todas las puntas. Todo candidato queda «aplicado antes» de `x`.
    let x_id = id;
    let mut padres = vec![tip_a, tip_b];
    padres.sort();
    padres.dedup();
    let x = hash_de(x_id);
    let b = super::pruebas_eclr2::post_con_txs(x_id, padres, s, 1, productor, Vec::new());
    cadena.admitir(b).expect("bloque de fusión");

    Mundo {
        cadena,
        terminal,
        x,
        votos,
        rama,
        tardios,
        negados_candado,
        negados_v6,
        sellos,
        primer_sello,
        rama_a,
        ventanas_saltadas,
    }
}

fn registrar_tardio(
    motor: &MotorVotos,
    cadena: &Cadena,
    k: u64,
    votos: &mut BTreeMap<u64, VotoFirmado>,
    tardios: &mut usize,
    negados_candado: &mut usize,
    negados_v6: &mut usize,
) {
    let Some(cand) = cadena.candidato_por_slot(k.saturating_mul(T_VOTOS).saturating_sub(LAG))
    else {
        return;
    };
    let estado = cadena
        .estado_past(&cand)
        .cloned()
        .unwrap_or_else(|| cadena.estado_terminal().clone());
    let paso = motor
        .votar_tardio(k, *cand.as_bytes(), &estado, cadena)
        .expect("voto tardío");
    contar_eventos(&paso.eventos, negados_candado, negados_v6);
    for v in paso.votos {
        votos.insert(
            v.n,
            VotoFirmado {
                n: v.n,
                candidato: BlockHash::from_digest(Digest::from_bytes(v.candidato)),
                h_t: v.h_t_siguiente,
                raiz: v.raiz_estado,
                firma: v.firma.bytes(),
            },
        );
        *tardios += 1;
    }
}

fn abrir_ventana(
    motor: &mut MotorVotos,
    cadena: &Cadena,
    n: u64,
    s: u64,
    votos: &mut BTreeMap<u64, VotoFirmado>,
    negados_candado: &mut usize,
    negados_v6: &mut usize,
) {
    let Some(cand) = cadena.candidato_por_slot(n.saturating_mul(T_VOTOS).saturating_sub(LAG))
    else {
        return;
    };
    let estado = cadena
        .estado_past(&cand)
        .cloned()
        .unwrap_or_else(|| cadena.estado_terminal().clone());
    let paso = motor
        .avanzar_con_vista(
            n,
            cand,
            &estado,
            i64::try_from(s).unwrap_or(i64::MAX),
            cadena,
        )
        .expect("avanzar ventana");
    contar_eventos(&paso.eventos, negados_candado, negados_v6);
    for sobre in &paso.votos {
        let v = crate::votos::deserializar_voto_peso(sobre).expect("voto por peso");
        votos.insert(
            v.n,
            VotoFirmado {
                n: v.n,
                candidato: BlockHash::from_digest(Digest::from_bytes(v.candidato)),
                h_t: v.h_t_siguiente,
                raiz: v.raiz_estado,
                firma: v.firma.bytes(),
            },
        );
    }
}

fn contar_eventos(eventos: &[EventoMotor], candado: &mut usize, v6: &mut usize) {
    for ev in eventos {
        if let EventoMotor::VotoPesoPropio {
            emitido: false,
            motivo,
            ..
        } = ev
        {
            match *motivo {
                "candado" => *candado += 1,
                "no_desciende_del_sello" => *v6 += 1,
                _ => {}
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Comprobación de pares.
// ─────────────────────────────────────────────────────────────────────────────────────────────

struct Recuento {
    pares: usize,
    conflictos: usize,
    sinfalta: usize,
    faltas: usize,
}

fn comprobar_pares(m: &Mundo) -> Recuento {
    let votos: Vec<&VotoFirmado> = m.votos.values().collect();
    let mut r = Recuento {
        pares: 0,
        conflictos: 0,
        sinfalta: 0,
        faltas: 0,
    };
    for i in 0..votos.len() {
        for j in (i + 1)..votos.len() {
            let v1 = votos[i];
            let v2 = votos[j];
            if v1.n >= v2.n {
                continue;
            }
            r.pares += 1;
            let rama1 = m.rama.get(&v1.candidato).copied().unwrap_or(0);
            let rama2 = m.rama.get(&v2.candidato).copied().unwrap_or(0);
            let en_conflicto = rama1 != rama2 && rama1 != 0 && rama2 != 0 && rama1 != rama2;
            if en_conflicto {
                r.conflictos += 1;
            }
            let tx = tx_de_dos_votos(v1, v2);
            match m
                .cadena
                .hecho_de_tx_de_prueba(m.terminal, m.x, &tx, PLAZO_EVIDENCIA)
            {
                Some(HechoVoto::Falta) => r.faltas += 1,
                Some(HechoVoto::SinFalta) if en_conflicto => r.sinfalta += 1,
                _ => {}
            }
        }
    }
    r
}

/// Número de cambios de rama (A↔B) entre votos honestos consecutivos por ventana.
fn cambios_de_rama(m: &Mundo) -> usize {
    let mut cambios = 0usize;
    let mut anterior: Option<u8> = None;
    for v in m.votos.values() {
        let r = m.rama.get(&v.candidato).copied().unwrap_or(0);
        if r == 0 {
            continue;
        }
        if let Some(a) = anterior
            && a != r
        {
            cambios += 1;
        }
        anterior = Some(r);
    }
    cambios
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// La prueba.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn at1c_votante_honesto_nunca_falta() {
    let mut total_faltas = 0usize;
    let mut total_negados_candado = 0usize;
    let mut total_negados_v6 = 0usize;
    let mut total_tardios = 0usize;
    for semilla in 0..SEMILLAS {
        let m = mundo(semilla);
        let r = comprobar_pares(&m);
        let cambios = cambios_de_rama(&m);
        total_faltas += r.faltas;
        total_negados_candado += m.negados_candado;
        total_negados_v6 += m.negados_v6;
        total_tardios += m.tardios;
        println!(
            "semilla {semilla}: votos={} tardios={} cambios={} pares={} conflictos={} sinfalta={} \
             faltas={} negados_candado={} negados_v6={} sellos={} saltadas={}",
            m.votos.len(),
            m.tardios,
            cambios,
            r.pares,
            r.conflictos,
            r.sinfalta,
            r.faltas,
            m.negados_candado,
            m.negados_v6,
            m.sellos.len(),
            m.ventanas_saltadas.len(),
        );
        assert_eq!(
            r.faltas, 0,
            "semilla {semilla}: el votante honesto produjo una falta"
        );
        assert!(
            m.votos.len() >= 20,
            "semilla {semilla}: solo {} votos firmados",
            m.votos.len()
        );
        assert!(
            m.tardios >= 2,
            "semilla {semilla}: solo {} tardíos",
            m.tardios
        );
        assert!(cambios >= 1, "semilla {semilla}: sin cambio de rama");
        assert!(
            r.sinfalta >= 1,
            "semilla {semilla}: sin par en conflicto justificado"
        );
    }
    assert_eq!(total_faltas, 0, "alguna semilla produjo una falta");
    assert!(
        total_negados_candado + total_negados_v6 >= 1,
        "ninguna semilla negó un voto por candado o por no_desciende_del_sello"
    );
    println!(
        "TOTAL: tardíos={total_tardios} negados_candado={total_negados_candado} \
         negados_v6={total_negados_v6}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Mordidas (se ejecutan a mano con `--ignored`; ver INFORME.md).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Primer voto honesto posterior a `n` en la rama `r`.
fn primer_voto_en_rama_desde(m: &Mundo, r: u8, n: u64) -> Option<(u64, BlockHash)> {
    m.votos
        .values()
        .find(|v| v.n > n && m.rama.get(&v.candidato).copied() == Some(r))
        .map(|v| (v.n, v.candidato))
}

/// Firma un voto A3 con la clave del votante para `(n, candidato)`.
fn firmar_voto(n: u64, candidato: BlockHash, h_t: [u8; 32]) -> VotoFirmado {
    let mensaje = zx_votos::mensaje_voto_peso(n, candidato.as_bytes(), &h_t, &[0u8; 32]);
    let firma = zx_votos::firmar(&bls(VOTANTE), DOMINIO_VOTO, &mensaje).expect("firma");
    VotoFirmado {
        n,
        candidato,
        h_t,
        raiz: [0u8; 32],
        firma: firma.bytes(),
    }
}

/// ¿Algún par forma una falta con los votos dados? (Se ordena la pareja por ventana, no por índice.)
fn hay_falta(m: &Mundo, votos: &[VotoFirmado]) -> Option<(u64, u64)> {
    for i in 0..votos.len() {
        for j in (i + 1)..votos.len() {
            let (v1, v2) = if votos[i].n < votos[j].n {
                (&votos[i], &votos[j])
            } else if votos[j].n < votos[i].n {
                (&votos[j], &votos[i])
            } else {
                continue;
            };
            let tx = tx_de_dos_votos(v1, v2);
            if m.cadena
                .hecho_de_tx_de_prueba(m.terminal, m.x, &tx, PLAZO_EVIDENCIA)
                == Some(HechoVoto::Falta)
            {
                return Some((v1.n, v2.n));
            }
        }
    }
    None
}

fn votos_honestos(m: &Mundo) -> Vec<VotoFirmado> {
    m.votos.values().cloned().collect()
}

/// Mordida (i): el votante firmase un candidato que **no desciende del sello** (V6 apagado). Se
/// toma el bloque de la rama conflictiva y se firma para una ventana posterior al sello.
#[test]
#[ignore = "mordida: se ejecuta a mano antes de la suite"]
fn at1c_mordida_desciende_del_sello() {
    let mut visto = false;
    'semillas: for semilla in 0..SEMILLAS {
        let m = mundo(semilla);
        let Some((n_sello, _sello)) = m.primer_sello else {
            continue;
        };
        let Some((n_b, cand_b)) = primer_voto_en_rama_desde(&m, 2, n_sello) else {
            continue;
        };
        let Some(h_t) = m.votos.values().next().map(|v| v.h_t) else {
            continue;
        };
        // El votante con V6 apagado firmaría, en la ventana siguiente, un candidato de la rama A
        // (en conflicto con el sello de B y sin la finalidad del sello en su pasado).
        for cand_a in m.rama_a.iter().rev() {
            let m2 = m
                .cadena
                .estado_past(cand_a)
                .map_or(0, |e| e.finalidad_votos_n);
            if m2 >= n_b {
                continue;
            }
            let _ = (n_b, cand_b);
            let contra = firmar_voto(n_b + 1, *cand_a, h_t);
            let mut votos = votos_honestos(&m);
            votos.push(contra);
            if let Some((n1, n2)) = hay_falta(&m, &votos) {
                println!("mordida V6 (semilla {semilla}): falta entre {n1} y {n2}");
                visto = true;
                break 'semillas;
            }
        }
    }
    assert!(visto, "la mordida de V6 no vio ninguna falta");
}

/// Mordida (ii): se permite firmar tarde una ventana con **atadura de ventana posterior**. Se
/// firma, para una ventana saltada entre el sello y un voto normal posterior, un candidato
/// conflictivo.
#[test]
#[ignore = "mordida: se ejecuta a mano antes de la suite"]
fn at1c_mordida_tardio_con_atadura_posterior() {
    let mut visto = false;
    'semillas: for semilla in 0..SEMILLAS {
        let m = mundo(semilla);
        let Some((n_sello, _)) = m.primer_sello else {
            continue;
        };
        let Some((n_b, cand_b)) = primer_voto_en_rama_desde(&m, 2, n_sello) else {
            continue;
        };
        let Some(h_t) = m.votos.values().next().map(|v| v.h_t) else {
            continue;
        };
        // La finalidad aplicada en el pasado del voto normal es anterior a la ventana tardía `k`:
        // el tardío posterior que la regla prohíbe, si se firma, deja la pareja sin justificar.
        let Some(m2) = m.cadena.estado_past(&cand_b).map(|e| e.finalidad_votos_n) else {
            continue;
        };
        let k = m2.saturating_add(1);
        if k >= n_b {
            continue;
        }
        for cand_a in m.rama_a.iter().rev() {
            let contra = firmar_voto(k, *cand_a, h_t);
            let mut votos = votos_honestos(&m);
            votos.push(contra);
            if let Some((n1, n2)) = hay_falta(&m, &votos) {
                println!("mordida tardío (semilla {semilla}): falta entre {n1} y {n2}");
                visto = true;
                break 'semillas;
            }
        }
    }
    assert!(visto, "la mordida del tardío no vio ninguna falta");
}
