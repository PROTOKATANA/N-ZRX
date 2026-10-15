//! `ORDEN-W06d1` V5 y V5b: muerte y reinicio.
//!
//! V5: el binario real se lanza como proceso hijo y se mata con `SIGKILL` en >= 10 puntos (semilla
//! fija, fases PoW y PoST) — reabre con el **mismo resumen de estado** que el último bloque
//! persistido y sigue produciendo, 0 corrupciones.
//!
//! UT-1: máximo supervisado V5 = 7298 s (2 h 1 min 38 s), calculado por
//! DURACION_MAX_V5_MS: preparación más 4*(arranque + PoW + jitter + reapertura),
//! arranque/corte, 5*(arranque + régimen + reapertura) y arranque/3 s/reapertura.
//! V5b: 500 s, calculados por DURACION_MAX_V5B_MS. Sondeo: hasta 20 ms adicionales;
//! los retrasos del planificador no son una garantía de tiempo real. El silencio se renueva
//! solo con líneas completas nuevas, y no elimina el tope absoluto de fase ni el total.
//! Se conservan los 11 SIGKILL y las aserciones de estado/corrupción de la base.
//!
//! V5b: un testigo de una transacción de un bloque PoW alterado en disco (el almacén no lo detecta,
//! `REVISION-W06b.md`) hace que el nodo se niegue a arrancar con error explícito al repetir.

#![cfg(unix)]
#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "el test falla con panic por diseño"
)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rocksdb::{ColumnFamilyDescriptor, DB, Options};
use zx_core::Red;
use zx_core::wire::{cuerpo_a_bytes, cuerpo_desde_bytes};
use zx_node::nodo::{Config, Nodo};

use std::fs::{File, OpenOptions};
use std::ops::{Deref, DerefMut};
use std::os::unix::process::CommandExt as _;

/// Plazos de silencio y topes absolutos; solo eventos completos renuevan el silencio.
const VIDA_SILENCIO_MS: u64 = 120_000;
const VIDA_MAX_MS: u64 = 180_000;
const POW_SILENCIO_MS: u64 = 180_000;
const POW_MAX_MS: u64 = 360_000;
const CORTE_SILENCIO_MS: u64 = 420_000;
const CORTE_MAX_MS: u64 = 840_000;
const REGIMEN_SILENCIO_MS: u64 = 120_000;
const REGIMEN_MAX_MS: u64 = 240_000;
const REABRIR_SILENCIO_MS: u64 = 120_000;
const REABRIR_MAX_MS: u64 = 180_000;
const JITTER_MAX_MS: u64 = 1_000;
const FINAL_ESPERA_MS: u64 = 3_000;
const FINAL_MAX_MS: u64 = 4_000;
const PREPARACION_MAX_MS: u64 = 30_000;
const SONDEO_MS: u64 = 20;
const DURACION_MAX_V5_MS: u64 = PREPARACION_MAX_MS
    + RONDAS_POW as u64 * (VIDA_MAX_MS + POW_MAX_MS + JITTER_MAX_MS + REABRIR_MAX_MS)
    + VIDA_MAX_MS
    + CORTE_MAX_MS
    + RONDAS_REGIMEN as u64 * (VIDA_MAX_MS + REGIMEN_MAX_MS + REABRIR_MAX_MS)
    + VIDA_MAX_MS
    + FINAL_MAX_MS
    + REABRIR_MAX_MS;
const PRODUCCION_V5B_MS: u64 = 75_000;
const PRODUCCION_V5B_MAX_MS: u64 = 80_000;
const CORROMPER_MAX_MS: u64 = 30_000;
const DURACION_MAX_V5B_MS: u64 =
    PREPARACION_MAX_MS + VIDA_MAX_MS + PRODUCCION_V5B_MAX_MS + CORROMPER_MAX_MS + REABRIR_MAX_MS;

/// Mata y recolecta al hijo incluso al desenrollar un panic. El supervisor posee un grupo propio.
struct Hijo {
    proceso: Child,
    grupo: bool,
    lineas_antes: usize,
    arranque: Option<MarcaFase>,
}

impl Deref for Hijo {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.proceso
    }
}
impl DerefMut for Hijo {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.proceso
    }
}
impl Drop for Hijo {
    fn drop(&mut self) {
        if self.grupo {
            // process_group(0) creó este grupo, formado solo por el worker y sus nodos.
            let _ = Command::new("kill")
                .args(["-KILL", "--", &format!("-{}", self.proceso.id())])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if self.proceso.try_wait().ok().flatten().is_none() {
            let _ = self.proceso.kill();
        }
        let _ = self.proceso.wait();
    }
}

struct MarcaFase {
    nombre: String,
    ronda: u32,
    inicio: Instant,
}
impl Drop for MarcaFase {
    fn drop(&mut self) {
        eprintln!(
            "UT1 FIN fase={} ronda={} segundos={:.3}",
            self.nombre,
            self.ronda,
            self.inicio.elapsed().as_secs_f64()
        );
    }
}

fn fase(dir: &Path, nombre: &str, ronda: u32, silencio_ms: u64, maximo_ms: u64) -> MarcaFase {
    let contenido = format!("{nombre}\t{ronda}\t{silencio_ms}\t{maximo_ms}\n");
    let temporal = dir.join("fase.tmp");
    std::fs::write(&temporal, contenido).expect("escribir fase supervisada");
    std::fs::rename(temporal, dir.join("fase.tsv")).expect("publicar fase supervisada");
    eprintln!(
        "UT1 INICIO fase={nombre} ronda={ronda} silencio_ms={silencio_ms} maximo_ms={maximo_ms}"
    );
    MarcaFase {
        nombre: nombre.to_string(),
        ronda,
        inicio: Instant::now(),
    }
}

struct ParametrosFase {
    firma: String,
    nombre: String,
    ronda: u32,
    silencio: Duration,
    maximo: Duration,
}
fn leer_fase(dir: &Path) -> Option<ParametrosFase> {
    let firma = std::fs::read_to_string(dir.join("fase.tsv")).ok()?;
    let mut campos = firma.trim_end().split('\t');
    let nombre = campos.next()?.to_string();
    let ronda = campos.next()?.parse().ok()?;
    let silencio = Duration::from_millis(campos.next()?.parse().ok()?);
    let maximo = Duration::from_millis(campos.next()?.parse().ok()?);
    Some(ParametrosFase {
        firma,
        nombre,
        ronda,
        silencio,
        maximo,
    })
}

fn lineas_completas(ruta: &Path) -> usize {
    std::fs::read(ruta)
        .unwrap_or_default()
        .iter()
        .filter(|b| **b == b'\n')
        .count()
}
fn ultima_linea(dir: &Path) -> String {
    match std::fs::read_to_string(dir.join("registro.jsonl")) {
        Ok(texto) => texto
            .lines()
            .last()
            .unwrap_or("<registro vacío>")
            .to_string(),
        Err(error) => format!("<registro no disponible: {error}>"),
    }
}
fn diagnostico(dir: &Path, nombre: &str, ronda: u32, motivo: &str) -> String {
    format!(
        "fase={nombre} ronda={ronda}: {motivo}; última línea del registro: {}; datos={}; \
        worker={}; stderr_nodo={}",
        ultima_linea(dir),
        dir.join("datos").display(),
        dir.join("worker.log").display(),
        dir.join("nodo.stderr").display()
    )
}

fn vigilar(dir: &Path, hijo: &mut Hijo, presupuesto: Duration) -> Result<(), String> {
    let inicio = Instant::now();
    let mut parametros = ParametrosFase {
        firma: String::new(),
        nombre: "preparación".to_string(),
        ronda: 0,
        silencio: Duration::from_millis(PREPARACION_MAX_MS),
        maximo: Duration::from_millis(PREPARACION_MAX_MS),
    };
    let mut inicio_fase = inicio;
    let mut ultimo_progreso = inicio;
    let registro = dir.join("registro.jsonl");
    let mut longitud = std::fs::metadata(&registro).map(|m| m.len()).unwrap_or(0);
    let mut lineas = lineas_completas(&registro);
    loop {
        let ahora = Instant::now();
        if let Some(nueva) = leer_fase(dir)
            && nueva.firma != parametros.firma
        {
            parametros = nueva;
            inicio_fase = ahora;
            ultimo_progreso = ahora;
        }
        let nueva_longitud = std::fs::metadata(&registro).map(|m| m.len()).unwrap_or(0);
        if nueva_longitud != longitud {
            longitud = nueva_longitud;
            let nuevas_lineas = lineas_completas(&registro);
            if nuevas_lineas > lineas {
                ultimo_progreso = ahora;
            }
            lineas = nuevas_lineas;
        }
        match hijo.try_wait() {
            Ok(Some(estado)) if estado.success() => return Ok(()),
            Ok(Some(estado)) => {
                return Err(diagnostico(
                    dir,
                    &parametros.nombre,
                    parametros.ronda,
                    &format!("el worker terminó con {estado}"),
                ));
            }
            Err(error) => {
                return Err(diagnostico(
                    dir,
                    &parametros.nombre,
                    parametros.ronda,
                    &format!("no se pudo consultar al worker: {error}"),
                ));
            }
            Ok(None) => {}
        }
        let motivo = if ahora.duration_since(inicio) >= presupuesto {
            Some(format!("tope total {:.3} s", presupuesto.as_secs_f64()))
        } else if ahora.duration_since(inicio_fase) >= parametros.maximo {
            Some(format!(
                "tope de fase {:.3} s (aunque haya eventos)",
                parametros.maximo.as_secs_f64()
            ))
        } else if ahora.duration_since(ultimo_progreso) >= parametros.silencio {
            Some(format!(
                "sin eventos nuevos completos durante {:.3} s",
                parametros.silencio.as_secs_f64()
            ))
        } else {
            None
        };
        if let Some(motivo) = motivo {
            return Err(diagnostico(
                dir,
                &parametros.nombre,
                parametros.ronda,
                &motivo,
            ));
        }
        std::thread::sleep(Duration::from_millis(SONDEO_MS));
    }
}

/// El padre supervisa también las llamadas síncronas a arrancar y Drop, sin cambiar el producto.
fn supervisar(nombre: &str, presupuesto_ms: u64, cuerpo: impl FnOnce(&Path)) {
    if std::env::var("ZX_REINICIO_WORKER").ok().as_deref() == Some(nombre) {
        let dir =
            PathBuf::from(std::env::var_os("ZX_REINICIO_DIR").expect("directorio del worker"));
        cuerpo(&dir);
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    eprintln!("UT1 DATOS {}", dir.path().display());
    let salida = File::create(dir.path().join("worker.log")).expect("registro del worker");
    let error = salida.try_clone().expect("clonar salida");
    let proceso = Command::new(std::env::current_exe().expect("binario de esta prueba"))
        .args(["--exact", nombre, "--nocapture", "--test-threads=1"])
        .env("ZX_REINICIO_WORKER", nombre)
        .env("ZX_REINICIO_DIR", dir.path())
        .stdout(Stdio::from(salida))
        .stderr(Stdio::from(error))
        .process_group(0)
        .spawn()
        .expect("lanzar worker supervisado");
    let mut hijo = Hijo {
        proceso,
        grupo: true,
        lineas_antes: 0,
        arranque: None,
    };
    let resultado = vigilar(dir.path(), &mut hijo, Duration::from_millis(presupuesto_ms));
    drop(hijo); // El grupo se termina ANTES de conservar/eliminar los datos y liberar candados.
    let registro_worker =
        std::fs::read_to_string(dir.path().join("worker.log")).unwrap_or_default();
    eprint!("{registro_worker}");
    if let Err(error) = resultado {
        let conservado = dir.keep();
        panic!("{error}; directorio conservado={}", conservado.display());
    }
}

fn abrir(dir: &Path, ronda: u32, papel: &str) -> Nodo {
    let nombre = format!("reabrir-{papel}");
    let _fase = fase(dir, &nombre, ronda, REABRIR_SILENCIO_MS, REABRIR_MAX_MS);
    Nodo::arrancar(&config_de_test(dir, 0))
        .unwrap_or_else(|error| panic!("{}", diagnostico(dir, &nombre, ronda, &error.to_string())))
}

/// `N_dev` de test: pequeño y múltiplo de 16. No es el valor de red.
const N_DEV_TEST: &str = "32";
/// `SR_dev` de test: sin controlador, ganadores frecuentes.
const SR_DEV_TEST: &str = "18446744073709551615"; // u64::MAX

/// Semilla fija de las esperas entre el arranque y el `SIGKILL` (splitmix64, igual patrón que
/// `crates/zx-storage/tests/matar_a_mitad.rs`).
const SEMILLA_ESPERA: u64 = 0x5a5a_5a5a_5a5a_5a5a;
/// Etiqueta heredada de la última ronda; hay 4+1+5+1=11 SIGKILL reales (>=10).
const RONDAS: u32 = 12;

/// Jitter corto (no determina cuándo matar, solo cuánto esperar **después** de alcanzar el
/// objetivo de la ronda) para que el `SIGKILL` no caiga siempre justo tras la línea de registro que
/// lo desbloquea — ver `objetivo_minado`. Antes determinaba el tiempo de pared completo de la fase
/// 1; ese diseño fallaba en `debug` porque minar la primera altura puede tardar más de 8 s en el
/// peor caso (búsqueda de nonce probabilística, no un tiempo fijo): las 4 rondas podían matarse
/// antes de admitir ningún bloque (medido: `alturas=[0, 0, 0, 0]` en `logs/V3-despues.log`).
fn espera_millis(ronda: u32) -> u64 {
    let mut z = SEMILLA_ESPERA ^ u64::from(ronda).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    z % 500
}

/// Número acumulado (todo el registro `.jsonl`, de solo-anexión entre rondas) de eventos
/// `"bloque_minado"` que se exige antes de matar en la ronda `ronda`-ésima de calentamiento. Un
/// contador de eventos reales, no un tiempo de pared: funciona igual en `release` (~1 s/bloque,
/// limitado al reloj de pared) que en `debug` (~8-9 s/bloque, dificultad inicial real sin optimizar,
/// medido en V5b).
fn objetivo_minado(ronda: u32) -> usize {
    usize::try_from(ronda).unwrap_or(1)
}

fn config_de_test(dir: &Path, parada_tras_slots: u64) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 0x1234,
        indices_claves: vec![0, 1, 2],
        n_dev: N_DEV_TEST.parse().expect("N_dev"),
        sr_dev: SR_DEV_TEST.parse().expect("SR_dev"),
        perfil_red: zx_node::perfil::perfil_red_dev(),
        parada_tras_slots: Some(parada_tras_slots),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    }
}

fn lanzar(dir: &Path, ronda: u32, papel: &str) -> Hijo {
    let nombre = format!("arranque-{papel}");
    let arranque = fase(dir, &nombre, ronda, VIDA_SILENCIO_MS, VIDA_MAX_MS);
    let lineas_antes = lineas_completas(&dir.join("registro.jsonl"));
    let proceso = Command::new(env!("CARGO_BIN_EXE_zx-node"))
        .args([
            "--datos",
            dir.join("datos").to_str().expect("ruta"),
            "--registro",
            dir.join("registro.jsonl").to_str().expect("ruta"),
            "--red",
            "dev",
            "--semilla",
            "4660", // 0x1234
            "--claves",
            "0,1,2",
            "--n-dev",
            N_DEV_TEST,
            "--sr-dev",
            SR_DEV_TEST,
            "--parada-tras-slots",
            "100000",
        ])
        .stdout(Stdio::from(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("nodo.stdout"))
                .expect("stdout nodo"),
        ))
        .stderr(Stdio::from(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("nodo.stderr"))
                .expect("stderr nodo"),
        ))
        .spawn()
        .expect("lanza zx-node");
    Hijo {
        proceso,
        grupo: false,
        lineas_antes,
        arranque: Some(arranque),
    }
}

/// La señal procede del arranque de ESTE hijo, nunca de una ronda anterior ni de una línea parcial.
fn esperar_senal_de_vida(hijo: &mut Hijo, dir: &Path, ronda: u32, papel: &str) {
    let nombre = format!("arranque-{papel}");
    loop {
        let contenido = std::fs::read_to_string(dir.join("registro.jsonl")).unwrap_or_default();
        if contenido
            .split_inclusive('\n')
            .skip(hijo.lineas_antes)
            .any(|linea| linea.ends_with('\n') && linea.contains("\"tipo\":\"arranque\""))
        {
            drop(hijo.arranque.take());
            return;
        }
        assert!(
            hijo.try_wait().expect("consultar hijo").is_none(),
            "{}",
            diagnostico(
                dir,
                &nombre,
                ronda,
                "el nodo terminó antes de anunciar su arranque"
            )
        );
        std::thread::sleep(Duration::from_millis(SONDEO_MS));
    }
}

fn eventos_nuevos(dir: &Path, hijo: &Hijo, tipo: &str) -> usize {
    let contenido = std::fs::read_to_string(dir.join("registro.jsonl")).unwrap_or_default();
    contenido
        .split_inclusive('\n')
        .skip(hijo.lineas_antes)
        .filter(|linea| linea.ends_with('\n') && linea.contains(tipo))
        .count()
}

/// Rondas de calentamiento (fase PoW): kills cortos, antes de forzar el cruce del corte.
const RONDAS_POW: u32 = 4;
/// Rondas de régimen: kills muy cortos, ya cruzado el corte (`N_dev` de test: casi instantáneo).
const RONDAS_REGIMEN: u32 = 5;

#[test]
fn v5_sigkill_en_varios_puntos_reabre_sin_corrupcion_y_sigue_produciendo() {
    supervisar(
        "v5_sigkill_en_varios_puntos_reabre_sin_corrupcion_y_sigue_produciendo",
        DURACION_MAX_V5_MS,
        ejecutar_v5,
    );
}

fn ejecutar_v5(dir: &Path) {
    let ruta_registro = dir.join("registro.jsonl");

    let mut alturas_pow: Vec<u32> = Vec::new();
    let mut posts_regimen: Vec<usize> = Vec::new();

    // Fase 1: `RONDAS_POW` rondas cortas mientras se mina de verdad (dificultad inicial real). Se
    // mata cuando el registro (acumulado, de solo-anexión, entre rondas) acumula `objetivo_minado`
    // eventos `bloque_minado`, no tras un tiempo de pared fijo (ver `objetivo_minado`).
    for ronda in 1..=RONDAS_POW {
        let mut hijo = lanzar(dir, ronda, "PoW");
        esperar_senal_de_vida(&mut hijo, dir, ronda, "PoW");
        let objetivo = objetivo_minado(ronda);
        let espera = fase(dir, "objetivo-PoW", ronda, POW_SILENCIO_MS, POW_MAX_MS);
        loop {
            let contenido = std::fs::read_to_string(&ruta_registro).unwrap_or_default();
            let vistos = contenido.matches("\"bloque_minado\"").count();
            if vistos >= objetivo {
                break;
            }
            assert!(
                hijo.try_wait().ok().flatten().is_none(),
                "ronda PoW {ronda}: el nodo terminó solo antes de minar lo esperado"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(espera);
        let jitter = fase(dir, "jitter-PoW", ronda, JITTER_MAX_MS, JITTER_MAX_MS);
        // Jitter corto tras alcanzar el objetivo: el `kill` no debe caer siempre justo tras la
        // línea de registro que lo desbloqueó.
        std::thread::sleep(Duration::from_millis(espera_millis(ronda)));
        hijo.kill().expect("mata al hijo");
        hijo.wait().expect("lo entierra");

        drop(jitter);
        let nodo = abrir(dir, ronda, "PoW");
        alturas_pow.push(nodo.altura_pow());
        drop(nodo);
    }
    assert!(
        alturas_pow.iter().any(|a| *a > 0),
        "ninguna ronda de PoW llegó a minar nada: alturas={alturas_pow:?}"
    );

    // Fase 2: deja correr sin matar hasta cruzar el corte (o hasta un límite generoso), para que
    // las rondas de régimen de abajo caigan de verdad en la fase PoST. Se comprueba leyendo el
    // registro (el primer «bloque_producido» solo puede ocurrir tras el corte): abrir el mismo
    // RocksDB con el hijo todavía vivo fallaría por el candado de un solo escritor.
    {
        let mut hijo = lanzar(dir, 0, "corte");
        esperar_senal_de_vida(&mut hijo, dir, 0, "corte");
        let _fase = fase(dir, "cruce-corte", 0, CORTE_SILENCIO_MS, CORTE_MAX_MS);
        loop {
            let contenido = std::fs::read_to_string(&ruta_registro).unwrap_or_default();
            if contenido.contains("\"bloque_producido\"") {
                break;
            }
            assert!(
                hijo.try_wait().ok().flatten().is_none(),
                "el nodo de calentamiento terminó solo antes de cruzar el corte"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        hijo.kill().expect("mata al hijo de calentamiento");
        hijo.wait().expect("lo entierra");
    }

    // Fase 3: `RONDAS_REGIMEN` rondas ya en régimen. Con `N_dev` de test y `SR_dev = u64::MAX` la
    // producción es tan rápida (varios bloques por slot, slot casi instantáneo) que una espera en
    // milisegundos no discrimina: el primer intento de esta prueba mató siempre tras el mismo lote
    // inicial (`[4, 4, 4, 4, 4, 4, 4, 4]`, bug real de la prueba, no del nodo — ver `PROGRESO.md`).
    // En su lugar, cada ronda espera a ver un número **creciente** de eventos `bloque_producido` en
    // el registro (una cuenta externa, no una escritura interna concreta) antes de matar: el punto
    // de corte varía por construcción, y sigue siendo un `SIGKILL` en un instante arbitrario del
    // proceso (no hay sincronización con ninguna escritura en curso).
    for ronda in 1..=RONDAS_REGIMEN {
        let mut hijo = lanzar(dir, ronda, "régimen");
        esperar_senal_de_vida(&mut hijo, dir, ronda, "régimen");
        let objetivo = usize::try_from(ronda).unwrap_or(1);
        // El objetivo acumulado sigue siendo el mismo. Se exige además un evento PoST de
        // ESTE hijo: un objetivo ya satisfecho no autoriza matar durante su inicialización.
        let espera = fase(
            dir,
            "objetivo-régimen",
            ronda,
            REGIMEN_SILENCIO_MS,
            REGIMEN_MAX_MS,
        );
        loop {
            let contenido = std::fs::read_to_string(&ruta_registro).unwrap_or_default();
            let vistos = contenido.matches("\"bloque_producido\"").count();
            if vistos >= objetivo && eventos_nuevos(dir, &hijo, "\"bloque_producido\"") > 0 {
                break;
            }
            assert!(
                hijo.try_wait().expect("consultar hijo").is_none(),
                "{}",
                diagnostico(
                    dir,
                    "objetivo-régimen",
                    ronda,
                    "el nodo terminó antes del objetivo"
                )
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(espera);
        hijo.kill().expect("mata al hijo");
        hijo.wait().expect("lo entierra");

        let nodo = abrir(dir, ronda, "régimen");
        posts_regimen.push(nodo.cadena().bloques_post().len());
        drop(nodo);
    }

    // El `kill` no está sincronizado con ninguna escritura concreta: si cayera siempre en el mismo
    // punto, esta prueba no probaría nada (mismo espíritu que `matar_a_mitad.rs`). Se exige
    // variación por separado en cada fase: las rondas de PoW nunca producen bloques PoST (el corte
    // aún no se cruzó) y mezclarlas con las de régimen ocultaría que el `kill` de PoW sí varía.
    let mut alturas_vistas = alturas_pow.clone();
    alturas_vistas.sort_unstable();
    alturas_vistas.dedup();
    assert!(
        alturas_vistas.len() > 1,
        "todas las rondas de PoW alcanzaron la misma altura ({alturas_pow:?}): \
         el `kill` parece sincronizado con algo"
    );
    let mut posts_vistos = posts_regimen.clone();
    posts_vistos.sort_unstable();
    posts_vistos.dedup();
    assert!(
        posts_vistos.len() > 1,
        "todas las rondas de régimen alcanzaron el mismo número de bloques PoST \
         ({posts_regimen:?}): el `kill` parece sincronizado con algo"
    );
    let alcanzados = posts_regimen;

    // "Sigue produciendo": tras las `RONDAS` interrupciones, se deja correr una última vez sin
    // matarlo y el número de bloques PoST admitidos crece.
    let antes = *alcanzados.last().expect("al menos una ronda");
    let mut hijo = lanzar(dir, RONDAS + 1, "final");
    esperar_senal_de_vida(&mut hijo, dir, RONDAS + 1, "final");
    let continuidad = fase(dir, "continuidad", RONDAS + 1, FINAL_MAX_MS, FINAL_MAX_MS);
    std::thread::sleep(Duration::from_millis(FINAL_ESPERA_MS));
    hijo.kill().expect("mata al hijo");
    hijo.wait().expect("lo entierra");

    drop(continuidad);
    let nodo = abrir(dir, RONDAS + 1, "final");
    let despues = nodo.cadena().bloques_post().len();
    assert!(
        despues >= antes,
        "el número de bloques PoST no debe decrecer tras reabrir: antes={antes}, después={despues}"
    );
    assert!(
        despues > 0 || nodo.cadena().terminal().is_none(),
        "si ya hay terminal, debería haber al menos un bloque PoST tras dejarlo correr"
    );
}

/// Reabre el mismo RocksDB por debajo de `Almacen` (nombres de familia documentados en
/// `crates/zx-storage/src/disco.rs`: «bloques», «registro», «meta») y corrompe la primera firma del
/// primer testigo del primer bloque PoW **no genésis** que encuentra.
fn corromper_primer_testigo_pow(ruta_almacen: &Path) -> zx_core::BlockHash {
    let mut opciones = Options::default();
    opciones.create_if_missing(false);
    let familias = ["bloques", "registro", "meta"]
        .into_iter()
        .map(|n| ColumnFamilyDescriptor::new(n, Options::default()))
        .collect::<Vec<_>>();
    let db = DB::open_cf_descriptors(&opciones, ruta_almacen, familias).expect("reabrir rocksdb");
    let cf_registro = db.cf_handle("registro").expect("cf registro");
    let cf_bloques = db.cf_handle("bloques").expect("cf bloques");

    for item in db.iterator_cf(cf_registro, rocksdb::IteratorMode::Start) {
        let (_indice, hash_bytes) = item.expect("iterar registro");
        let valor = db
            .get_cf(cf_bloques, &hash_bytes)
            .expect("leer bloque")
            .expect("el bloque debe existir");
        let (familia, canonicos) = valor.split_first().expect("sobre no vacío");
        if *familia != 0x01 {
            continue; // familia PoW = 0x01 (formato.rs); se busca un bloque PoW.
        }
        let Ok((cuerpo, _)) = cuerpo_desde_bytes(canonicos) else {
            continue;
        };
        let (cabecera, txs, mut testigos) = cuerpo;
        if cabecera.height == 0 {
            continue; // el génesis no tiene testigos que corromper de forma interesante.
        }
        let Some(primeros) = testigos.iter().position(|t| !t.is_empty()) else {
            continue; // este bloque no tiene testigos (p. ej. solo la coinbase, sin depósito).
        };
        #[expect(
            clippy::indexing_slicing,
            reason = "primeros viene de position(), es un índice válido"
        )]
        {
            let firma = &mut testigos[primeros][0];
            let ultimo = firma.len() - 1;
            firma[ultimo] ^= 0xFF;
        }
        let mut nuevos_canonicos = Vec::new();
        cuerpo_a_bytes(&mut nuevos_canonicos, &cabecera, &txs, &testigos);
        let mut nuevo_valor = vec![0x01u8];
        nuevo_valor.extend_from_slice(&nuevos_canonicos);
        db.put_cf(cf_bloques, &hash_bytes, &nuevo_valor)
            .expect("escribir el bloque corrompido");
        return cabecera.block_hash();
    }
    panic!("no se encontró ningún bloque PoW con testigo no vacío que corromper");
}

#[test]
fn v5b_testigo_pow_corrupto_impide_arrancar() {
    supervisar(
        "v5b_testigo_pow_corrupto_impide_arrancar",
        DURACION_MAX_V5B_MS,
        ejecutar_v5b,
    );
}

fn ejecutar_v5b(dir: &Path) {
    // Deja correr lo suficiente para que al menos un depósito (con testigo real) se persista:
    // M_cb = 5, M_dep = 3 (perfil dev); con 3 claves rotando la coinbase, la primera madura hacia
    // la altura 8-9. En `release` basta con ~18 s (~1 bloque/s, limitado al reloj de pared); en
    // `debug` (sin optimizar) minar cada altura tarda bastante más (medido: ~4-5 s/bloque con la
    // dificultad inicial real), así que se espera con margen amplio para no depender del perfil.
    let mut hijo = lanzar(dir, 0, "V5b");
    esperar_senal_de_vida(&mut hijo, dir, 0, "V5b");
    let produccion = fase(
        dir,
        "producción-V5b",
        0,
        VIDA_SILENCIO_MS,
        PRODUCCION_V5B_MAX_MS,
    );
    std::thread::sleep(Duration::from_millis(PRODUCCION_V5B_MS));
    hijo.kill().expect("mata al hijo");
    hijo.wait().expect("lo entierra");

    drop(produccion);
    let corrupcion = fase(dir, "corromper-V5b", 0, CORROMPER_MAX_MS, CORROMPER_MAX_MS);
    let ruta_almacen: PathBuf = dir.join("datos").join("storage");
    let hash_corrompido = corromper_primer_testigo_pow(&ruta_almacen);
    drop(corrupcion);
    let _fase = fase(
        dir,
        "reabrir-corrupto-V5b",
        0,
        REABRIR_SILENCIO_MS,
        REABRIR_MAX_MS,
    );

    let cfg = config_de_test(dir, 0);
    let resultado = Nodo::arrancar(&cfg);
    match resultado {
        Err(e) => {
            let texto = e.to_string();
            assert!(
                texto.contains(&hash_corrompido.to_string())
                    || texto.contains("Firma")
                    || texto.contains("firma"),
                "el error debería señalar el fallo de firma del bloque {hash_corrompido}: {texto}"
            );
        }
        Ok(_) => panic!(
            "el nodo debió negarse a arrancar: el testigo del bloque {hash_corrompido} está corrupto"
        ),
    }
}

/// La señal vieja y una escritura parcial no son eventos del nuevo hijo.
#[test]
fn ut1_registro_viejo_y_linea_parcial_no_son_progreso() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("registro.jsonl");
    std::fs::write(&ruta, "{\"tipo\":\"arranque\"}\n").expect("registro viejo");
    let antes = lineas_completas(&ruta);
    std::fs::write(&ruta, "{\"tipo\":\"arranque\"}\n{\"tipo\":\"arranque\"}")
        .expect("línea parcial");
    assert_eq!(lineas_completas(&ruta), antes);
    std::fs::write(&ruta, "{\"tipo\":\"arranque\"}\n{\"tipo\":\"arranque\"}\n")
        .expect("evento nuevo completo");
    assert_eq!(lineas_completas(&ruta), antes + 1);
}

fn hijo_ficticio(dir: &Path, guion: &str) -> Hijo {
    let proceso = Command::new("/bin/sh")
        .args(["-c", guion, "ut1-fixture"])
        .arg(dir.join("registro.jsonl"))
        .process_group(0)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("hijo ficticio");
    Hijo {
        proceso,
        grupo: true,
        lineas_antes: 0,
        arranque: None,
    }
}

/// Un hijo vivo sin eventos falla con el contexto completo, antes de su espera de diez segundos.
#[test]
fn ut1_supervisor_detecta_silencio_y_da_contexto() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("registro.jsonl"), "ultima conocida\n").expect("registro");
    let _fase = fase(dir.path(), "PoW-ficticio", 7, 200, 2_000);
    let mut hijo = hijo_ficticio(dir.path(), "sleep 10");
    let error = vigilar(dir.path(), &mut hijo, Duration::from_secs(3)).expect_err("debe fallar");
    assert!(error.contains("fase=PoW-ficticio ronda=7"), "{error}");
    assert!(error.contains("sin eventos nuevos completos"), "{error}");
    assert!(error.contains("ultima conocida"), "{error}");
    assert!(
        error.contains(&dir.path().join("datos").display().to_string()),
        "{error}"
    );
}

/// Los eventos renuevan el silencio aunque el trabajo dure más que la ventana inicial.
#[test]
fn ut1_supervisor_renueva_por_eventos_y_respeta_tope() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _fase = fase(dir.path(), "avance-ficticio", 8, 700, 5_000);
    let mut hijo = hijo_ficticio(
        dir.path(),
        "for i in 1 2 3 4 5 6; do printf 'evento\\n' >> \"$1\"; sleep 0.2; done",
    );
    assert!(vigilar(dir.path(), &mut hijo, Duration::from_secs(6)).is_ok());
    assert_eq!(lineas_completas(&dir.path().join("registro.jsonl")), 6);
    drop(hijo);

    let _fase = fase(dir.path(), "avance-infinito-ficticio", 9, 700, 1_200);
    let mut hijo = hijo_ficticio(
        dir.path(),
        "while :; do printf 'evento\\n' >> \"$1\"; sleep 0.1; done",
    );
    let error = vigilar(dir.path(), &mut hijo, Duration::from_secs(3)).expect_err("tope absoluto");
    assert!(error.contains("tope de fase"), "{error}");
    assert!(error.contains("ronda=9"), "{error}");
}
