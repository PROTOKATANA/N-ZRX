//! Tests decisivos de la vista estructural del pasado DAG (`VistaPasadoEstructural`).
//!
//! El conjunto esperado de cada caso se escribe **aparte** de la rutina bajo prueba: se declara
//! como `BTreeSet<BlockHash>` a mano y se compara con lo que devuelve la vista. La fuente es un
//! instrumento de test —un `Vec` con búsqueda lineal, para que el orden de inserción sea
//! observable— y **no** acredita ningún bloque: no hay admisión PoST en esta ruta.
//!
//! El `hash_candidato` es siempre un hash hipotético que la fuente puede o no ofrecer. Cuando la
//! fuente lo ofrece como ancestro, o el propio candidato se declara padre, la vista debe
//! rechazarlo con `ErrorVistaCausal::CandidatoEnSuPasado`: ese es el caso adversarial que el
//! fixture original —que omitía al candidato de la fuente— no detectaba.
//!
//! **D-P08:** no hay génesis DAG. La raíz de la vista es el terminal, representado por un registro
//! con `padres` vacíos; el test final fija que un candidato sin padres no tiene pasado.

#![expect(
    clippy::unwrap_used,
    reason = "instrumento de test: construir el fixture y extraer resultados con panic es lo deseado"
)]

use std::collections::BTreeSet;
use std::convert::Infallible;

use zx_core::{BlockHash, Digest, PadresDag};
use zx_dag::dag_causal::{
    ErrorVistaCausal, FuenteRegistrosDag, PresupuestoVista, RegistroEstructural,
    VistaPasadoEstructural,
};

/// Hash hipotético del candidato en los casos donde no se declara padre a sí mismo.
const CANDIDATO: u8 = 0x50;

fn h(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn registro(hash: u8, padres: PadresDag, slot: u64) -> RegistroEstructural {
    RegistroEstructural::nuevo(h(hash), padres, slot)
}

fn padres(seleccionado: u8, extras: &[u8]) -> PadresDag {
    let extras: Vec<BlockHash> = extras.iter().copied().map(h).collect();
    PadresDag::nuevo(h(seleccionado), &extras).unwrap()
}

fn conjunto(vista: &VistaPasadoEstructural) -> BTreeSet<BlockHash> {
    vista
        .ancestros()
        .iter()
        .map(RegistroEstructural::hash)
        .collect()
}

/// Fuente de test respaldada por un `Vec`: el orden interno es el de inserción y `leer` busca
/// linealmente. Sirve para comprobar que la vista no depende de ese orden.
struct FuenteVector {
    registros: Vec<RegistroEstructural>,
}

impl FuenteVector {
    fn new(registros: Vec<RegistroEstructural>) -> Self {
        Self { registros }
    }
}

impl FuenteRegistrosDag for FuenteVector {
    type Error = Infallible;

    fn leer(&self, hash: &BlockHash) -> Result<Option<RegistroEstructural>, Infallible> {
        Ok(self.registros.iter().find(|r| r.hash() == *hash).copied())
    }
}

/// Fuente que devuelve un registro con otro hash para cualquier clave: incoherencia.
struct FuenteClaveAjena;

impl FuenteRegistrosDag for FuenteClaveAjena {
    type Error = Infallible;

    fn leer(&self, _hash: &BlockHash) -> Result<Option<RegistroEstructural>, Infallible> {
        Ok(Some(RegistroEstructural::nuevo(
            h(0xEE),
            PadresDag::genesis(),
            0,
        )))
    }
}

/// Error propio de una fuente que falla, para comprobar que la vista lo propaga sin interpretarlo.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ErrorFuenteTest;

/// Fuente que falla siempre.
struct FuenteRota;

impl FuenteRegistrosDag for FuenteRota {
    type Error = ErrorFuenteTest;

    fn leer(&self, _hash: &BlockHash) -> Result<Option<RegistroEstructural>, ErrorFuenteTest> {
        Err(ErrorFuenteTest)
    }
}

#[test]
fn el_diamante_une_los_padres_y_comparte_el_ancestro_una_vez() {
    // Candidato hipotético P (no está en la fuente) con padres {A, B}.
    // A → C; B → C; C sin padres. El ancestro compartido C entra una sola vez.
    let (a, b, c) = (0x0A, 0x0B, 0x0C);
    let fuente = FuenteVector::new(vec![
        registro(a, padres(c, &[]), 20),
        registro(b, padres(c, &[]), 20),
        registro(c, PadresDag::genesis(), 10),
    ]);
    let candidato = padres(a, &[b]);
    let vista = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(16),
    )
    .unwrap();

    let esperado: BTreeSet<BlockHash> = [h(a), h(b), h(c)].into_iter().collect();
    assert_eq!(conjunto(&vista), esperado);
    assert_eq!(vista.len(), 3);
    assert!(!vista.is_empty());
    assert!(vista.contiene(&h(c)));
    assert!(vista.get(&h(a)).is_some());
    assert!(vista.get(&h(CANDIDATO)).is_none());
}

#[test]
fn dos_padres_del_mismo_slot_se_conservan_sin_indexar_por_slot() {
    // A y B comparten slot, y el ancestro profundo repite ese mismo slot: indexar por slot
    // colapsaría alguno de ellos.
    let (a, b, profundo) = (0x11, 0x22, 0x33);
    let fuente = FuenteVector::new(vec![
        registro(a, padres(profundo, &[]), 7),
        registro(b, PadresDag::genesis(), 7),
        registro(profundo, PadresDag::genesis(), 7),
    ]);
    let candidato = padres(a, &[b]);
    let vista = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(8),
    )
    .unwrap();

    let esperado: BTreeSet<BlockHash> = [h(a), h(b), h(profundo)].into_iter().collect();
    assert_eq!(conjunto(&vista), esperado);
    assert_eq!(vista.len(), 3);
}

#[test]
fn falta_el_padre_seleccionado_da_contexto_incompleto() {
    let fuente = FuenteVector::new(Vec::new());
    let candidato = padres(0x0A, &[]);
    let resultado = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(4),
    );
    assert_eq!(
        resultado,
        Err(ErrorVistaCausal::ContextoIncompleto {
            faltante: h(0x0A),
            referido_por: None,
        })
    );
}

#[test]
fn falta_un_padre_extra_da_contexto_incompleto() {
    let fuente = FuenteVector::new(vec![registro(0x0A, PadresDag::genesis(), 1)]);
    let candidato = padres(0x0A, &[0x0B]);
    let resultado = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(4),
    );
    assert_eq!(
        resultado,
        Err(ErrorVistaCausal::ContextoIncompleto {
            faltante: h(0x0B),
            referido_por: None,
        })
    );
}

#[test]
fn falta_un_ancestro_profundo_da_contexto_incompleto() {
    // A está en la fuente, pero su padre B no: no se construye una vista parcial con A.
    let fuente = FuenteVector::new(vec![registro(0x0A, padres(0x0B, &[]), 2)]);
    let candidato = padres(0x0A, &[]);
    let resultado = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(4),
    );
    assert_eq!(
        resultado,
        Err(ErrorVistaCausal::ContextoIncompleto {
            faltante: h(0x0B),
            referido_por: Some(h(0x0A)),
        })
    );
}

#[test]
fn un_registro_bajo_otra_clave_es_incoherencia() {
    let candidato = padres(0x0A, &[]);
    let resultado = VistaPasadoEstructural::desde_padres(
        &FuenteClaveAjena,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(4),
    );
    assert_eq!(
        resultado,
        Err(ErrorVistaCausal::RegistroIncoherente {
            pedido: h(0x0A),
            devuelto: h(0xEE),
        })
    );
}

#[test]
fn un_ciclo_es_incoherencia_y_no_un_bucle_infinito() {
    // A → B y B → A.
    let fuente = FuenteVector::new(vec![
        registro(0x0A, padres(0x0B, &[]), 2),
        registro(0x0B, padres(0x0A, &[]), 1),
    ]);
    let candidato = padres(0x0A, &[]);
    let resultado = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(4),
    );
    assert_eq!(
        resultado,
        Err(ErrorVistaCausal::CicloDetectado { bloque: h(0x0A) })
    );
}

#[test]
fn el_presupuesto_suficiente_construye_y_el_menor_falla_sin_truncar() {
    // Cadena A → B → C.
    let fuente = FuenteVector::new(vec![
        registro(0x0A, padres(0x0B, &[]), 3),
        registro(0x0B, padres(0x0C, &[]), 2),
        registro(0x0C, PadresDag::genesis(), 1),
    ]);
    let candidato = padres(0x0A, &[]);

    let completa = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(3),
    )
    .unwrap();
    assert_eq!(completa.len(), 3);

    let corta = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(2),
    );
    assert_eq!(
        corta,
        Err(ErrorVistaCausal::PresupuestoAgotado { presupuesto: 2 })
    );
}

#[test]
fn presupuesto_cero_agota_antes_de_leer() {
    let fuente = FuenteVector::new(vec![registro(0x0A, PadresDag::genesis(), 1)]);
    let candidato = padres(0x0A, &[]);
    let resultado = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(0),
    );
    assert_eq!(
        resultado,
        Err(ErrorVistaCausal::PresupuestoAgotado { presupuesto: 0 })
    );
}

#[test]
fn el_orden_interno_de_la_fuente_no_cambia_la_vista() {
    let (a, b, c) = (0x0A, 0x0B, 0x0C);
    let uno = FuenteVector::new(vec![
        registro(c, PadresDag::genesis(), 1),
        registro(a, padres(c, &[]), 3),
        registro(b, padres(c, &[]), 3),
    ]);
    let dos = FuenteVector::new(vec![
        registro(b, padres(c, &[]), 3),
        registro(c, PadresDag::genesis(), 1),
        registro(a, padres(c, &[]), 3),
    ]);
    let candidato = padres(a, &[b]);

    let vista_uno = VistaPasadoEstructural::desde_padres(
        &uno,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(8),
    )
    .unwrap();
    let vista_dos = VistaPasadoEstructural::desde_padres(
        &dos,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(8),
    )
    .unwrap();

    assert_eq!(vista_uno, vista_dos);
    let esperado: BTreeSet<BlockHash> = [h(a), h(b), h(c)].into_iter().collect();
    assert_eq!(conjunto(&vista_uno), esperado);
}

#[test]
fn un_candidato_que_la_fuente_no_ofrece_no_cuenta_como_ancestro() {
    // La fuente ofrece el pasado de A (A → B) pero NO el candidato P, que vive en una estructura
    // separada que la fuente no consulta. P no puede aparecer en la vista.
    let fuente = FuenteVector::new(vec![
        registro(0x0A, padres(0x0B, &[]), 2),
        registro(0x0B, PadresDag::genesis(), 1),
    ]);
    let candidato = RegistroEstructural::nuevo(h(CANDIDATO), padres(0x0A, &[]), 3);

    let vista = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato.padres(),
        candidato.hash(),
        PresupuestoVista::nuevo(8),
    )
    .unwrap();

    assert!(!vista.contiene(&h(CANDIDATO)));
    let esperado: BTreeSet<BlockHash> = [h(0x0A), h(0x0B)].into_iter().collect();
    assert_eq!(conjunto(&vista), esperado);
}

#[test]
fn el_candidato_en_su_propio_pasado_por_la_fuente_es_error_tipado() {
    // P declara como padre a A; la fuente ofrece A → P y P → sin padres (terminal). El grafo de la
    // fuente no tiene un ciclo interno —A y P se cierran sin volver a sí mismos—, pero el candidato
    // P queda en su propio pasado declarado.
    let fuente = FuenteVector::new(vec![
        registro(0x0A, padres(CANDIDATO, &[]), 2),
        registro(CANDIDATO, PadresDag::genesis(), 1),
    ]);
    let candidato = RegistroEstructural::nuevo(h(CANDIDATO), padres(0x0A, &[]), 3);

    // Presupuesto 1: A se lee y al entrar en P el límite ya está agotado. La comprobación del
    // candidato precede al presupuesto: el error es de incoherencia, no de agotamiento.
    let resultado = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato.padres(),
        candidato.hash(),
        PresupuestoVista::nuevo(1),
    );
    assert_eq!(
        resultado,
        Err(ErrorVistaCausal::CandidatoEnSuPasado { hash: h(CANDIDATO) })
    );
    assert!(resultado.is_err(), "un candidato en su pasado no da vista");

    // Con presupuesto de sobra, el mismo error: no es un artefacto del límite.
    let holgado = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato.padres(),
        candidato.hash(),
        PresupuestoVista::nuevo(16),
    );
    assert_eq!(
        holgado,
        Err(ErrorVistaCausal::CandidatoEnSuPasado { hash: h(CANDIDATO) })
    );
}

#[test]
fn un_padre_directo_igual_al_candidato_se_rechaza_antes_del_presupuesto() {
    // El candidato declara P como padre seleccionado. La fuente está vacía: el rechazo no depende
    // de que contenga un registro para P. El presupuesto 0 demuestra que la comprobación precede
    // al límite de recursos y no se disfraza de agotamiento.
    let fuente = FuenteVector::new(Vec::new());
    let candidato = RegistroEstructural::nuevo(h(CANDIDATO), padres(CANDIDATO, &[]), 3);

    let resultado = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato.padres(),
        candidato.hash(),
        PresupuestoVista::nuevo(0),
    );
    assert_eq!(
        resultado,
        Err(ErrorVistaCausal::CandidatoEnSuPasado { hash: h(CANDIDATO) })
    );

    // También como padre adicional, no solo como seleccionado: el seleccionado tiene hash mayor
    // para que el adicional —el candidato— se visite primero.
    let con_extra = RegistroEstructural::nuevo(h(CANDIDATO), padres(0x60, &[CANDIDATO]), 3);
    let resultado = VistaPasadoEstructural::desde_padres(
        &fuente,
        &con_extra.padres(),
        con_extra.hash(),
        PresupuestoVista::nuevo(8),
    );
    assert_eq!(
        resultado,
        Err(ErrorVistaCausal::CandidatoEnSuPasado { hash: h(CANDIDATO) })
    );
}

#[test]
fn los_ancestros_salen_en_orden_ascendente_de_hash() {
    // Se insertan en orden descendente para que el resultado no sea el de entrada.
    let fuente = FuenteVector::new(vec![
        registro(0x0C, PadresDag::genesis(), 1),
        registro(0x0B, PadresDag::genesis(), 1),
        registro(0x0A, PadresDag::genesis(), 1),
    ]);
    let candidato = padres(0x0A, &[0x0B, 0x0C]);
    let vista = VistaPasadoEstructural::desde_padres(
        &fuente,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(8),
    )
    .unwrap();

    let hashes: Vec<BlockHash> = vista
        .ancestros()
        .iter()
        .map(RegistroEstructural::hash)
        .collect();
    assert_eq!(hashes, vec![h(0x0A), h(0x0B), h(0x0C)]);
}

#[test]
fn el_error_de_la_fuente_se_propaga_por_su_variante() {
    let candidato = padres(0x0A, &[]);
    let resultado = VistaPasadoEstructural::desde_padres(
        &FuenteRota,
        &candidato,
        h(CANDIDATO),
        PresupuestoVista::nuevo(4),
    );
    assert_eq!(resultado, Err(ErrorVistaCausal::Fuente(ErrorFuenteTest)));
}

/// **D-P08 · sustituye a `el_genesis_no_tiene_pasado`.** El terminal —registro con `padres`
/// vacíos— es la raíz de la vista y no tiene pasado.
#[test]
fn el_terminal_sin_padres_no_tiene_pasado() {
    let fuente = FuenteVector::new(Vec::new());
    let vista = VistaPasadoEstructural::desde_padres(
        &fuente,
        &PadresDag::genesis(),
        h(CANDIDATO),
        PresupuestoVista::nuevo(1),
    )
    .unwrap();
    assert!(vista.is_empty());
    assert_eq!(vista.len(), 0);
}
