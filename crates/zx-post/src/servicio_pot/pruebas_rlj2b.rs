//! Oráculo causal independiente y propiedades con semillas explícitas.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "fixtures acotadas; la división entera solo formatea ns/iteración"
)]
use super::*;
use zx_core::digest::Digest;

fn h(n: u64) -> BlockHash {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&n.to_le_bytes());
    BlockHash::from_digest(Digest::from_bytes(bytes))
}
type Dag = BTreeMap<BlockHash, (u64, u64, Vec<BlockHash>)>;

fn oraculo(dag: &Dag, padres: &[BlockHash], m: usize) -> Vec<(u64, u64)> {
    let mut vistos = BTreeSet::new();
    let mut pila = padres.to_vec();
    let mut marcas = Vec::new();
    while let Some(hash) = pila.pop() {
        if hash == h(0) || !vistos.insert(hash) {
            continue;
        }
        let (slot, ts, anteriores) = &dag[&hash];
        marcas.push((*slot, hash, *ts));
        pila.extend(anteriores);
    }
    marcas.sort_unstable();
    let mut escogidos = BTreeSet::new();
    if let Some(primero) = marcas.first() {
        escogidos.insert(*primero);
    }
    escogidos.extend(marcas.into_iter().rev().take(m));
    escogidos.into_iter().map(|(s, _, ts)| (s, ts)).collect()
}
fn azar(estado: &mut u64) -> u64 {
    *estado ^= *estado << 13;
    *estado ^= *estado >> 7;
    *estado ^= *estado << 17;
    *estado
}
fn generar(semilla: u64, n: u64) -> Dag {
    let mut rng = semilla;
    let mut dag = Dag::new();
    for i in 1..=n {
        let padre = azar(&mut rng) % i;
        let otro = azar(&mut rng) % i;
        let mut padres = vec![h(padre)];
        if otro != padre {
            padres.push(h(otro));
        }
        let slot = padres
            .iter()
            .filter_map(|p| dag.get(p).map(|b| b.0))
            .max()
            .unwrap_or(0)
            + azar(&mut rng) % 4;
        let ts = 1000 + slot + azar(&mut rng) % 61;
        dag.insert(h(i), (slot, ts, padres));
    }
    dag
}

#[test]
fn propiedad_union_causal_semillas_ordenes_hermanos_y_fusiones() {
    let mut casos = 0;
    for semilla in 1..=32 {
        let dag = generar(semilla, 80);
        for m in [1, 7, 264] {
            for orden in [false, true] {
                let servicio = ServicioPot::nuevo(h(0), 16, 4096).unwrap();
                let mut bloques: Vec<_> = dag.keys().copied().collect();
                if orden {
                    bloques.reverse();
                }
                for hash in bloques {
                    let padres = &dag[&hash].2;
                    let esperado = oraculo(&dag, padres, m);
                    let mut causal = BTreeSet::new();
                    let mut pila = padres.clone();
                    while let Some(p) = pila.pop() {
                        if p == h(0) || !causal.insert(p) {
                            continue;
                        }
                        pila.extend(&dag[&p].2);
                    }
                    for subconjunto in 0..4 {
                        let vista: Dag = dag
                            .iter()
                            .filter(|(p, _)| {
                                causal.contains(p) || (p.as_bytes()[0] % 4 <= subconjunto)
                            })
                            .map(|(p, b)| (*p, b.clone()))
                            .collect();
                        let actual = servicio
                            .ventana_timestamps_causal(padres, m, |p| vista.get(p).cloned())
                            .unwrap();
                        assert_eq!(
                            actual, esperado,
                            "semilla={semilla} m={m} orden={orden} hash={hash} vista={subconjunto}"
                        );
                        casos += 1;
                    }
                }
            }
        }
    }
    println!("semillas=1..32 bloques=80 M=1,7,264 ordenes=2 subconjuntos=4 ventanas={casos}");
}

#[test]
fn contexto_incompleto_no_deja_resumen_parcial_y_se_reintenta() {
    let dag = generar(17, 80);
    let servicio = ServicioPot::nuevo(h(0), 16, 4096).unwrap();
    let padres = [h(80)];
    assert_eq!(
        servicio.ventana_timestamps_causal(&padres, 264, |_| None),
        Err(h(80))
    );
    assert_eq!(
        servicio
            .ventana_timestamps_causal(&padres, 264, |p| dag.get(p).cloned())
            .unwrap(),
        oraculo(&dag, &padres, 264)
    );
}

#[test]
fn fusiones_deduplican_y_conservan_ancla_tras_poda() {
    let mut dag = Dag::new();
    for i in 1..=600 {
        dag.insert(h(i), (i, 1000 + i, vec![h(i - 1)]));
    }
    dag.insert(h(601), (600, 1601, vec![h(599)]));
    let mut servicio = ServicioPot::nuevo(h(0), 16, 16).unwrap();
    let padres = [h(600), h(601)];
    let antes = servicio
        .ventana_timestamps_causal(&padres, 264, |p| dag.get(p).cloned())
        .unwrap();
    assert_eq!(antes, oraculo(&dag, &padres, 264));
    servicio.avanzar_hasta(600).unwrap();
    // Los resúmenes recientes contienen el ancla antigua aunque sus cabeceras se hayan podado.
    let despues = servicio
        .ventana_timestamps_causal(&padres, 264, |_| None)
        .unwrap();
    assert_eq!(antes, despues);
    assert_eq!(despues.first(), Some(&(1, 1001)));
    assert_eq!(despues.len(), 265);
}

#[test]
fn control_rojo_ventana_local_rompe_independencia_de_hermanos() {
    let mut servicio = ServicioPot::nuevo(h(0), 16, 4096).unwrap();
    servicio.avanzar_hasta(1).unwrap();
    let antes = servicio.ventana_timestamps(0, 2);
    servicio
        .registrar_validado_con_timestamp(h(1), 1, 1001)
        .unwrap();
    let despues = servicio.ventana_timestamps(0, 2);
    assert_ne!(antes, despues);
    assert!(
        servicio
            .ventana_timestamps_causal(&[h(0)], 264, |_| None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn discrepancias_mediana_par_y_ancla_sin_descontar_slot() {
    assert_eq!(zx_consensus::pmt(&[1000, 1001], 264).unwrap(), 1001);
    let p = zx_consensus::ParametrosTimestampPost {
        t_ancla: 1000,
        banda_slot: 0,
        ..zx_consensus::PERFIL_TIMESTAMP_POST_DEV
    };
    assert!(zx_consensus::comprobar_banda_ts_slot(1010, 10, &p).is_ok());
    assert!(zx_consensus::comprobar_banda_ts_slot(1007, 10, &p).is_err());
    let contrato = zx_consensus::ParametrosTimestampPost { t_ancla: 997, ..p };
    assert!(zx_consensus::comprobar_banda_ts_slot(1007, 10, &contrato).is_ok());
    println!(
        "par [1000,1001]: código=1001 central inferior=1000; primer slot=3 ts=1000: código ancla=1000, extrapolación slot0=997"
    );
}

#[test]
fn coste_dag_ancho_ramas_fusionadas() {
    use std::cell::Cell;
    let mut dag = Dag::new();
    // 16 ramas de 320 bloques: 5120 antecesores más la fusión.
    for rama in 0..16 {
        for s in 1..=320 {
            let i = 1 + rama * 320 + s - 1;
            let padre = if s == 1 { h(0) } else { h(i - 1) };
            dag.insert(h(i), (s, 1000 + s, vec![padre]));
        }
    }
    let padres: Vec<_> = (1..=16).map(|r| h(r * 320)).collect();
    let servicio = ServicioPot::nuevo(h(0), 16, 4096).unwrap();
    let consultas = Cell::new(0);
    let esperado = oraculo(&dag, &padres, 264);
    let inicio = std::time::Instant::now();
    assert_eq!(
        servicio
            .ventana_timestamps_causal(&padres, 264, |p| {
                consultas.set(consultas.get() + 1);
                dag.get(p).cloned()
            })
            .unwrap(),
        esperado
    );
    let frio = inicio.elapsed();
    assert_eq!(consultas.get(), 5120);
    let inicio = std::time::Instant::now();
    for _ in 0..10000 {
        assert_eq!(
            servicio
                .ventana_timestamps_causal(&padres, 264, |_| {
                    consultas.set(consultas.get() + 1);
                    None
                })
                .unwrap(),
            esperado
        );
    }
    let caliente = inicio.elapsed();
    assert_eq!(
        consultas.get(),
        5120,
        "caliente: cero lecturas de cabeceras"
    );
    println!(
        "dag=5120 padres=16 M=264 consultas_frio=5120 consultas_caliente=0 frio_ns={} caliente_10000_ns={} ns_por_bloque={}",
        frio.as_nanos(),
        caliente.as_nanos(),
        caliente.as_nanos() / 10000
    );
}
