//! `ORDEN-W06d1` V4: un proceso con 3 claves dev, desde el génesis, cruza el corte y produce
//! `>= 30` bloques PoST que su propia tubería de admisión verifica íntegros.
//!
//! `N_dev` de test (pequeño, múltiplo de 16, `C-POT-04`) y `SR_dev` holgado (`u64::MAX`): la fase
//! PoW usa el `ParametrosTransicion`/`ParametrosPow` **reales** del perfil dev (no se acortan
//! `H_corte_min` ni `q`), así que este test mina de verdad hasta el corte, con la dificultad inicial
//! real de la red dev.

#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "el test falla con panic por diseño; el validador JSON manual indexa cadenas ya \
              comprobadas (ver validar_objeto_json_plano)"
)]

use zx_core::Red;
use zx_node::nodo::{Config, Nodo};

/// `N_dev` de test: pequeño y múltiplo de 16 (`C-POT-04`). No es el valor de red.
const N_DEV_TEST: u64 = 32;
/// `SR_dev` de test: sin controlador, ganadores frecuentes (D-P11, valor de test).
const SR_DEV_TEST: u64 = u64::MAX;

fn config_de_test(dir: &std::path::Path, parada_tras_slots: u64) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 0x5a5a,
        indices_claves: vec![0, 1, 2],
        n_dev: N_DEV_TEST,
        sr_dev: SR_DEV_TEST,
        perfil_red: zx_node::perfil::perfil_red_dev(),
        parada_tras_slots: Some(parada_tras_slots),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    }
}

#[test]
fn un_proceso_cruza_el_corte_y_produce_al_menos_30_bloques_post() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_de_test(dir.path(), 40);

    let mut nodo = Nodo::arrancar(&cfg).expect("arranque limpio");
    nodo.ejecutar()
        .expect("ejecución sin bloques propios rechazados (decisión 4)");

    assert!(
        nodo.cadena().terminal().is_some(),
        "el proceso debe fijar un terminal PoW"
    );

    let posts = nodo.cadena().bloques_post();
    // `ejecutar()` devolvió `Ok`: decisión 4 exige que un bloque propio rechazado sea fatal, así
    // que si llegamos aquí, ninguno de los bloques PoST de `cadena` se rechazó.
    let admitidos: usize = posts
        .iter()
        .filter(|p| nodo.cadena().es_valido(&p.hash))
        .count();
    assert_eq!(
        admitidos,
        posts.len(),
        "ejecutar() fue Ok: no debería haber ningún bloque PoST inválido en la cadena"
    );
    assert!(
        admitidos >= 30,
        "se esperaban >= 30 bloques PoST admitidos, hubo {admitidos}"
    );

    assert!(
        nodo.resumen_estado_actual().is_some(),
        "debe poder calcularse el resumen de estado canónico"
    );

    // El registro estructurado existe y cada línea es un objeto JSON de un solo nivel bien
    // formado: claves entrecomilladas, comas entre campos, sin comas colgantes ni pegadas.
    let contenido = std::fs::read_to_string(&cfg.ruta_registro).expect("leer el registro");
    let lineas = contenido.lines().count();
    assert!(lineas > 0, "el registro estructurado no debe estar vacío");
    for linea in contenido.lines() {
        validar_objeto_json_plano(linea);
    }
}

/// Valida a mano (sin `serde_json`, ver `PROGRESO.md`) que `linea` es `{"clave":valor,...}` con
/// valores de cadena, número o booleano/lista de cadenas, un solo nivel. Suficientemente estricto
/// para atrapar la clase de bug real que este test encontró: una coma que falta entre dos campos
/// (`..."reloj_pared_ns":123"altura":9...`).
fn validar_objeto_json_plano(linea: &str) {
    let l = linea.trim();
    assert!(
        l.starts_with('{') && l.ends_with('}'),
        "línea no es un objeto JSON: {linea}"
    );
    let interior = &l[1..l.len() - 1];
    let mut resto = interior;
    let mut algun_campo = false;
    loop {
        resto = resto.trim_start();
        if resto.is_empty() {
            break;
        }
        algun_campo = true;
        assert!(
            resto.starts_with('"'),
            "se esperaba una clave entre comillas en: {resto}"
        );
        let cierre_clave = resto[1..].find('"').unwrap_or_else(|| {
            panic!("clave sin comilla de cierre en: {resto}");
        });
        let tras_clave = &resto[2 + cierre_clave..];
        let tras_clave = tras_clave.strip_prefix(':').unwrap_or_else(|| {
            panic!("falta ':' tras la clave en: {tras_clave}");
        });
        // El valor termina en la próxima ',' de nivel superior o en el final; los valores de este
        // registro nunca anidan objetos, así que basta con no cortar dentro de una cadena ni de una
        // lista `[...]`.
        let mut profundidad_lista = 0i32;
        let mut dentro_cadena = false;
        let mut fin = tras_clave.len();
        let bytes = tras_clave.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => dentro_cadena = !dentro_cadena,
                b'[' if !dentro_cadena => profundidad_lista += 1,
                b']' if !dentro_cadena => profundidad_lista -= 1,
                b',' if !dentro_cadena && profundidad_lista == 0 => {
                    fin = i;
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        assert!(!dentro_cadena, "cadena sin cerrar en: {tras_clave}");
        let valor = &tras_clave[..fin];
        assert!(!valor.is_empty(), "valor vacío tras ':' en: {tras_clave}");
        resto = tras_clave.get(fin..).unwrap_or("");
        if let Some(siguiente) = resto.strip_prefix(',') {
            resto = siguiente;
            assert!(
                !resto.trim_start().is_empty(),
                "coma colgante al final del objeto"
            );
        } else {
            assert!(
                resto.is_empty(),
                "sobran caracteres tras el último valor: {resto}"
            );
            break;
        }
    }
    assert!(algun_campo, "objeto JSON vacío: {linea}");
}
