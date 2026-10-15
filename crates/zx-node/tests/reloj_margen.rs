//! `RL-2d-2` · **V2/V3**: margen del ajuste del reloj (`A ≥ F + 64`) y guarda de producción.
//!
//! Cubre las decisiones (b) y (c) de `ORDEN-RL2d-2`:
//!
//! - **(c)** un perfil con `A = F + 63` (`663 < 600 + 64`) se **rechaza** al validarlo, y el perfil
//!   `dev-reloj` real usa `A = F + 64 = 664`;
//! - **(b)** si el `N` de la frontera que rige en un slot no está comprometido en el calendario
//!   (la finalidad no alcanzó `f` al llegar `f + A`), `Nodo` **no produce** ese slot y lo registra
//!   con el evento `reloj_n_no_comprometido`, en vez de producir con el `N` viejo y caer con
//!   `Pot(AesFallido)`. Se comprueba tanto con un calendario sintético (perfil real, `A = 664`)
//!   como con el calendario **real** que sale de `calendario_desde_cadena` sobre una lista de
//!   bloques truncada en la finalidad (sin el bloque que cierra la ventana de `f`).

#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "el test falla con panic por diseño; el test indexa un vector ya comprobado no vacío"
)]

use zx_node::nodo::reloj_produccion_permitida;
use zx_node::perfil::{ErrorPerfil, F_SLOTS, PerfilRedConsenso, perfil_red_dev_reloj};
use zx_node::registro::Registro;
use zx_post::reloj_post::{
    MARGEN_RELOJ, PERFIL_RELOJ_DEV, ParametrosRelojPost, calendario_desde_cadena,
};

/// `RL-2d-2` (c): el invariante endurecido `A ≥ F + MARGEN_RELOJ` (`a_epoch ≥ 664`).
#[test]
fn el_perfil_con_a_menor_que_f_mas_margen_se_rechaza() {
    let valido = perfil_red_dev_reloj().expect("el perfil dev-reloj real debe ser válido");
    assert_eq!(
        valido.reloj.a_epoch,
        F_SLOTS + MARGEN_RELOJ,
        "A = F + 64 = 664"
    );
    assert!(valido.validar().is_ok());

    let invalido = PerfilRedConsenso {
        etiqueta: "dev-reloj-invalido",
        reloj_activo: true,
        reloj: ParametrosRelojPost {
            a_epoch: F_SLOTS + MARGEN_RELOJ - 1,
            ..PERFIL_RELOJ_DEV
        },
        timestamp: valido.timestamp,
    };
    let err = invalido.validar();
    assert!(
        matches!(
            err,
            Err(ErrorPerfil::RelojVentanaMenorQueFinalidad { a_epoch, f_slots, margen })
                if a_epoch == F_SLOTS + MARGEN_RELOJ - 1
                    && f_slots == F_SLOTS
                    && margen == MARGEN_RELOJ
        ),
        "un perfil con A = F + 63 debe rechazarse, llegó {err:?}"
    );
}

/// `RL-2d-2` (b), calendario sintético con el perfil real (`A = 664`): a partir de `2A` el nodo
/// exige la entrada del ajuste y, si falta, no produce y lo registra; antes de `2A` no exige nada.
#[test]
fn el_nodo_no_produce_sin_el_ajuste_comprometido() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("registro.jsonl");
    let registro = Registro::abrir(&ruta).expect("registro");
    let perfil = perfil_red_dev_reloj().expect("perfil dev-reloj válido");

    // Sin la entrada `(1328, N)`, el ajuste de la frontera 664 no está comprometido.
    let sin_ajuste: Vec<(u64, u64)> = vec![(0, 1)];
    assert!(
        reloj_produccion_permitida(&perfil, &registro, &sin_ajuste, 1327)
            .expect("guarda ejecutable"),
        "antes de 2A no rige ningún ajuste"
    );
    assert!(
        !reloj_produccion_permitida(&perfil, &registro, &sin_ajuste, 1328)
            .expect("guarda ejecutable"),
        "en 2A el ajuste debe estar comprometido o el nodo no produce"
    );

    // Con el ajuste comprometido, el mismo slot se produce.
    let con_ajuste: Vec<(u64, u64)> = vec![(0, 1), (1328, 2)];
    assert!(
        reloj_produccion_permitida(&perfil, &registro, &con_ajuste, 1328)
            .expect("guarda ejecutable"),
        "con el ajuste comprometido el slot se produce"
    );

    let contenido = std::fs::read_to_string(&ruta).expect("leer el registro");
    let eventos: Vec<&str> = contenido
        .lines()
        .filter(|l| l.contains("\"tipo\":\"reloj_n_no_comprometido\""))
        .collect();
    assert_eq!(
        eventos.len(),
        1,
        "el nodo debe registrar exactamente el slot rechazado: {eventos:?}"
    );
    assert!(
        eventos[0].contains("\"slot\":1328")
            && eventos[0].contains("\"frontera\":664")
            && eventos[0].contains("\"desde_exigido\":1328")
            && eventos[0].contains("\"a_epoch\":664"),
        "evento con los campos del ajuste no comprometido: {}",
        eventos[0]
    );
}

/// `RL-2d-2` (b), calendario **real**: con `A = 4` y una lista finalizada que solo llega al slot 7,
/// la frontera `f = 4` sí se procesa (entrada en `8`) pero la `f = 8` no (sin entrada en `12`); el
/// nodo se niega a producir el slot 12 con el `N` dudoso y lo registra.
#[test]
fn el_calendario_finalizado_truncado_no_compromete_la_frontera() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("registro.jsonl");
    let registro = Registro::abrir(&ruta).expect("registro");
    let base = perfil_red_dev_reloj().expect("perfil dev-reloj válido");
    let perfil = PerfilRedConsenso {
        reloj: ParametrosRelojPost {
            a_epoch: 4,
            ..PERFIL_RELOJ_DEV
        },
        ..base
    };

    // La "parte finalizada" solo alcanza el slot 7: `f = 4` se procesa y añade `(8, N)`; `f = 8`
    // queda fuera y no hay ajuste para el slot `12`.
    let bloques: Vec<(u64, u64)> = (1..=7u64).map(|s| (s, 1_000 + s)).collect();
    let (calendario, _) =
        calendario_desde_cadena(&perfil.reloj, &bloques).expect("calendario exacto");
    assert!(
        calendario.iter().any(|(desde, _)| *desde == 8),
        "la frontera 4 debe haberse procesado: {calendario:?}"
    );
    assert!(
        !calendario.iter().any(|(desde, _)| *desde == 12),
        "la frontera 8 no debe haberse procesado: {calendario:?}"
    );

    assert!(
        reloj_produccion_permitida(&perfil, &registro, &calendario, 11).expect("guarda ejecutable"),
        "el slot 11 rige con el ajuste comprometido en 8"
    );
    assert!(
        !reloj_produccion_permitida(&perfil, &registro, &calendario, 12)
            .expect("guarda ejecutable"),
        "el slot 12 rige con una frontera no comprometida"
    );

    let contenido = std::fs::read_to_string(&ruta).expect("leer el registro");
    let eventos: Vec<&str> = contenido
        .lines()
        .filter(|l| l.contains("\"tipo\":\"reloj_n_no_comprometido\""))
        .collect();
    assert_eq!(eventos.len(), 1, "un único slot rechazado: {eventos:?}");
    assert!(
        eventos[0].contains("\"slot\":12")
            && eventos[0].contains("\"frontera\":8")
            && eventos[0].contains("\"desde_exigido\":12"),
        "evento del slot 12 con la frontera 8: {}",
        eventos[0]
    );
}
