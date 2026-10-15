//! `ORDEN-W07a` V2: test de integración (en proceso) del registro estructurado.
//!
//! Un proceso cruza el corte, produce y persiste bloques PoW y PoST, y luego se reabre (repetición
//! del almacén). Después se comprueba, **línea por línea**, que cada evento es un objeto JSON plano
//! con los campos comunes (`tipo`, `reloj_ns`, `reloj_pared_ns`) y los campos de su tipo en el §1 de
//! `ESQUEMA-REGISTRO-v1.md`, y que el conjunto de tipos observado cubre los que esta ejecución en
//! proceso puede producir. Los tipos que solo aparecen con red (`bloque_recibido`,
//! `bloque_red_admitido`, `bloque_red_rechazado`, `bloque_red_huerfano`, huérfanos, par y límite) se
//! cubren en V3 (tres procesos reales) y así se declara en la tabla de cobertura del `INFORME.md`.
//!
//! `ORDEN-VI6A-FIX1`: se añaden al vocabulario finito los eventos del motor de votos y de la ruta
//! R2b de evidencia de doble voto ya implementados (`votos_arranque`, sorteo/ventanas, evidencia),
//! con los campos que su productor garantiza. Los campos condicionales se documentan pero **no** se
//! exigen. Se añaden controles negativos que usan la misma validación que las líneas reales.
//!
//! No se añade `serde_json`: el parser es manual, como el de `integracion.rs`.

#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "el test falla con panic por diseño; el parser manual indexa cadenas ya comprobadas"
)]

use std::collections::{BTreeMap, BTreeSet};

use zx_core::Red;
use zx_node::nodo::{Config, Nodo};

const N_DEV_TEST: u64 = 32;
const SR_DEV_TEST: u64 = u64::MAX;

fn config_de_test(dir: &std::path::Path) -> Config {
    Config {
        dir_datos: dir.join("datos"),
        ruta_registro: dir.join("registro.jsonl"),
        red: Red::Dev,
        semilla: 0x5a5a,
        indices_claves: vec![0, 1, 2],
        n_dev: N_DEV_TEST,
        sr_dev: SR_DEV_TEST,
        perfil_red: zx_node::perfil::perfil_red_dev(),
        parada_tras_slots: Some(12),
        dejar_de_producir_en_slot: None,
        punto_control: None,
        sin_voto: false,
        sin_revelacion: false,
    }
}

/// Clase de un campo para las comprobaciones acotadas del `ORDEN-VI6A-FIX1` (completadas por
/// `ORDEN-VI6AFIX1-CONT1`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaseCampo {
    /// Cadena JSON real (`"..."`). No se exige no-vacía: el productor emite `""` en `punta`
    /// cuando no hay bloque seleccionado (`cambio_punta`/`reorganizacion_pow`).
    Texto,
    /// Entero sin signo en decimal (`u64`), dentro de rango.
    EnteroU,
    /// Entero con signo en decimal (`i64`), dentro de rango (garantías del R2b).
    EnteroI,
    /// Booleano real: exactamente `true` o `false`.
    Booleano,
    /// Hash de 64 caracteres hexadecimales (32 bytes).
    Hash,
    /// Clave BLS de 96 caracteres hexadecimales (48 bytes).
    HashBls,
    /// Lista JSON (`[...]`), p. ej. `padres_ausentes`.
    Lista,
    /// Campo histórico fuera del inventario de tipos: solo se comprueba presencia y no-vacío
    /// (comportamiento anterior). No se declara validado su tipo.
    SinClasificar,
}

/// Tipos del §1 (salvo los tres de SL-4b2) y campos propios de cada uno. Los campos listados son los
/// que el productor garantiza **siempre**; los condicionales no se exigen (se documentan en
/// `ESQUEMA-REGISTRO-v1.md`).
fn campos_del_tipo(tipo: &str, familia: Option<&str>) -> Option<&'static [&'static str]> {
    match tipo {
        "arranque" => Some(&["version_esquema", "n_dev", "sr_dev", "claves", "modo"]),
        "reinicio_completo" => Some(&[
            "bloques_repetidos",
            "duracion_ns",
            "punta",
            "resumen_estado",
            "n_bloques_dag",
            "compendio_bloques",
        ]),
        "bloque_minado" => Some(&["hash", "altura", "bytes", "n_txs"]),
        "bloque_producido" => Some(&[
            "hash",
            "slot",
            "n_padres",
            "n_txs",
            "bytes",
            "retraso_slot_ns",
            "clave_indice",
            "azules_mergeset",
            "rojos_mergeset",
        ]),
        "bloque_recibido" => Some(&["hash", "familia", "bytes"]),
        "bloque_red_admitido" => match familia {
            Some("pow") => Some(&[
                "hash",
                "familia",
                "altura",
                "bytes",
                "t_cabecera_ns",
                "t_admision_ns",
                "t_persistencia_ns",
                "t_total_ns",
                "n_bloques_dag",
            ]),
            Some("post") => Some(&[
                "hash",
                "familia",
                "slot",
                "n_padres",
                "bytes",
                "t_cabecera_ns",
                "t_admision_ns",
                "t_persistencia_ns",
                "t_total_ns",
                "n_bloques_dag",
                "azules_mergeset",
                "rojos_mergeset",
                "txs_descartadas",
            ]),
            _ => None,
        },
        "bloque_red_rechazado" => {
            Some(&["hash", "familia", "etapa", "motivo", "t_hasta_rechazo_ns"])
        }
        "bloque_red_huerfano" => Some(&["hash", "familia", "padres_ausentes"]),
        "huerfano_resuelto" => Some(&["hash"]),
        "huerfano_desalojado" => Some(&["hash", "motivo"]),
        "cambio_punta" => Some(&["punta", "resumen_estado", "profundidad_reorg"]),
        "reorganizacion_pow" => Some(&["punta_anterior", "punta_nueva", "profundidad"]),
        "par_conectado" | "par_desconectado" => Some(&["par"]),
        "par_penalizado" => Some(&["par", "motivo", "accion"]),
        "limite_alcanzado" => Some(&["limite", "detalle"]),
        "parada" => Some(&[
            "motivo",
            "punta",
            "resumen_estado",
            "n_bloques_dag",
            "compendio_bloques",
            // RA-2 · R6.4 · ancla de votos de la cadena: ventana y bloque.
            "ancla_votos_n",
            "ancla_votos_bloque",
        ]),
        // `ESQUEMA-REGISTRO-v1.md` §1 bis: eventos de diagnóstico restaurados por `ORDEN-W07a-R`
        // (el analizador los ignora sin error; aquí se validan sus campos como los del §1).
        "dejar_de_producir" => Some(&["motivo"]),
        // `ORDEN-W07d` decisión 3: el bloque de transición propio ya no queda sin rastro; tipo
        // propio para no alterar lo que cuenta `reinicio.rs`.
        "bloque_transicion_producido" => Some(&["hash", "slot"]),
        "bloque_red_pendiente" => Some(&["hash", "familia", "motivo", "veredicto"]),
        "bloque_red_ignorado_sin_penalizar" => Some(&["hash", "familia", "motivo"]),
        "bloque_post_gossip_descartado_sincronizando" => Some(&["hash", "padre_ausente"]),
        "bloque_propio_rechazado_legitimo" => Some(&["hash", "motivo"]),
        "bloque_post_de_red_sin_terminal" => Some(&["hash"]),
        // W08c: eventos de diagnóstico del embudo por slot (solo registro). `claves_ganadoras` es
        // una lista que puede quedar vacía, así que no se exige no-vacía; los contadores sí.
        "produccion_auditoria" => Some(&["slot", "n_claves", "n_ganadoras"]),
        // W08e (solo diagnóstico): fases del armado/firma y tiempo total hasta la admisión.
        "produccion_armado" => Some(&["slot", "clave_indice", "t_armado_ns", "t_total_ns"]),
        "produccion_sin_garantia" => Some(&["slot", "clave_indice"]),
        "produccion_descartada" => Some(&["slot", "clave_indice", "motivo"]),
        "produccion_padres" => Some(&[
            "slot_objetivo",
            "n_extras",
            "n_con_garantia",
            "slot_seleccionado",
            // W08d: diagnóstico del embudo B-20 (cuántas `EvidenceTx` eligió el bucle).
            "n_evidencias",
        ]),
        // W08d: diagnóstico del embudo B-20: bloque propio con evidencia rechazado en admisión.
        "bloque_propio_rechazado_con_evidencia" => Some(&[
            "hash",
            "motivo",
            "slot",
            "n_padres",
            "n_txs",
            "n_evidencias",
        ]),
        "productor_avanzar_hasta" => Some(&["desde", "hasta"]),
        // TX-6: muestra periódica de la mempool (bytes, transacciones y rechazos por tope). El
        // evento lo añade `ORDEN-TX6`; la tabla del §1 de `ESQUEMA-REGISTRO-v1.md` queda pendiente
        // de que el orquestador la amplíe (esa ruta no la posee el ejecutor).
        "mempool" => Some(&[
            "txs",
            "bytes",
            "pares",
            "bytes_max_par",
            "huerfanas",
            "bytes_huerfanas",
            "rechazos_limite",
            "rechazos_global",
            "rechazos_par_memoria",
            "rechazos_par_tasa",
            "rechazos_tarifa_minima",
            "rechazos_tarifa_rodante",
            "rechazos_huerfanas",
            "rechazos_cuota_por_clave",
            "rechazos_cuota_por_incidente",
            "rechazos_cuota_por_ventana",
            "rechazos_ventana_voto",
        ]),
        // FV-4b-N1: eventos del motor de finalidad por votos.
        "voto_emitido" => Some(&["n", "clave", "plazas"]),
        "certificado_adoptado" => Some(&["n", "candidato", "plazas", "umbral"]),
        "certificado_en_conflicto" => Some(&["candidato", "motivo"]),
        "punto_control_cargado" => Some(&["punto"]),
        "voto_rechazado" => Some(&["motivo"]),
        // `ORDEN-VI6A-FIX1` §1 quater: carga/reconciliación del motor, sorteo/ventanas, votos de red
        // y evidencia de doble voto `ECL-R2b`. Campos garantizados por el productor (nodo.rs).
        "votos_arranque" => Some(&[
            "origen",
            "diario",
            "observacion",
            "diario_entradas",
            "diario_ruta",
            "motivo",
        ]),
        "votos_espera" => Some(&["clase", "reloj_n", "certificado_n"]),
        "votos_carga_pendiente" => Some(&["reloj_n", "motivo"]),
        "punto_control_conflicto" => Some(&[
            "n",
            "candidato_externo",
            "candidato_aplicado",
            "h_t_externo",
            "h_t_aplicado",
        ]),
        "voto_suprimido" => Some(&["n", "clave", "motivo"]),
        "ventana_abierta" => Some(&["n", "ancla", "h_t_siguiente", "candidato", "slot"]),
        "ventana_cerrada" => Some(&["n", "certificado", "plazas", "umbral", "slot"]),
        // PD-1e · E10 · eventos del flujo por peso (`--votos-peso`).
        "voto_peso_propio" => Some(&["n", "clave", "peso", "emitido", "motivo"]),
        // A1-D2b · W5 · el certificado por peso aplicado lleva su raíz de estado (hex).
        "certificado_peso_aplicado" => Some(&["n", "candidato", "bloque", "raiz"]),
        // A1-D2b · la raíz de estado en el nodo: aviso de discrepancia (A1-D1-2), raíz todavía no
        // lista al votar y cálculo terminado. `certificada` de `raiz_estado_discrepante` y `raiz`
        // de `ventana_cerrada` son condicionales (solo con certificado): se clasifican, no se exigen.
        "raiz_estado_discrepante" => Some(&[
            "n",
            "propia",
            "raiz_mayor",
            "peso_mayor",
            "raiz_segunda",
            "peso_segunda",
            "raices_distintas",
            "sin_quorum_por_division",
        ]),
        "raiz_estado_no_lista" => Some(&["n", "epoca", "punto"]),
        "raiz_estado_calculada" => Some(&["epoca", "punto", "raiz", "ms"]),
        // VS-2 · V5 · acta de presencia `0x0A` (encolada y aplicada).
        "acta_peso_encolada" => Some(&["n", "firmantes"]),
        "acta_peso_aplicada" => Some(&["n"]),
        "evidencia_votos_peso" => {
            Some(&["n", "clave_bls", "h1", "h2", "txid", "punto", "admision"])
        }
        // `n`/`clave`/`plazas`/`candidato` son condicionales: solo si el sobre es interpretable.
        "voto_recibido" => Some(&["aceptado", "motivo"]),
        // AUS-2b · N7 · cola de votos propios (AV-11).
        "voto_propio_pendiente" => Some(&["n", "clave"]),
        "voto_propio_difundido" => Some(&["n", "clave", "slot"]),
        "voto_propio_aplicado" => Some(&["n", "slot"]),
        "voto_propio_descartado" => Some(&["n", "motivo"]),
        // `bls_registrada`/`error_transicion` son condicionales (solo en rechazo `VistaLocal`).
        "evidencia_difundida" => Some(&["txid"]),
        "evidencia_no_publicada" => Some(&["txid", "motivo"]),
        "evidencia_rechazada" => Some(&["txid", "punto", "motivo"]),
        // RN-1 · S5 · rastro de las operaciones de sector o de almacenamiento (admisión, rechazo y
        // descarte) y de las renovaciones propias de sector.
        "tx_admitida" => Some(&["txid", "clase", "origen"]),
        "tx_rechazada" => Some(&["txid", "clase", "origen", "motivo"]),
        "tx_descartada" => Some(&["bloque", "indice", "txid", "clase", "motivo"]),
        "renovacion_enviada" | "renovacion_aplicada" => {
            Some(&["clave", "sector", "renovacion_slot"])
        }
        // A5-c-2b · X8 · un `agregacion_ventana` por ventana cerrada (métricas del motor y
        // contadores de votos de subred y agregados) y un `agregado_publicado` por agregado propio.
        "agregacion_ventana" => Some(&[
            "n",
            "sueltos_antes_de_publicar",
            "sueltos_despues_de_publicar",
            "peso_agregado_propio",
            "subredes",
            "agregados_validos",
            "peso_agregado_elegido",
            "votos_recibidos",
            "votos_reenviados",
            "votos_ignorados",
            "votos_penalizados",
            "agregados_recibidos",
            "agregados_reenviados",
            "agregados_ignorados",
            "agregados_penalizados",
        ]),
        "agregado_publicado" => Some(&["n", "subred", "bytes"]),
        // A5-c-2c · N2 · B-83 · aviso, una sola vez, de que el motor no pudo leer azar del sistema.
        "azar_del_sistema_no_disponible" => Some(&[]),
        _ => None,
    }
}

/// Clase concreta de un campo inventariado, según el productor. Los campos históricos no
/// inventariados quedan en [`ClaseCampo::SinClasificar`] (solo presencia), **no** se les exige
/// cadena: así no se aplica el check de `.str` a numéricos históricos de otros eventos.
fn clase_del_campo(tipo: &str, campo: &str) -> ClaseCampo {
    // Todo campo `hash` del contrato es un hash de 32 bytes (64 hex), como hasta ahora.
    if campo == "hash" {
        return ClaseCampo::Hash;
    }
    match (tipo, campo) {
        // RN-1 · S5 · eventos nuevos: `txid`/`clase`/`origen`/`motivo` texto, el bloque un hash
        // Ed25519 (`clave`, 32 B) o de bloque, y los contadores enteros.
        ("tx_descartada", "bloque") => ClaseCampo::Hash,
        (
            "tx_admitida" | "tx_rechazada" | "tx_descartada",
            "txid" | "clase" | "origen" | "motivo",
        ) => ClaseCampo::Texto,
        ("renovacion_enviada" | "renovacion_aplicada", "clave") => ClaseCampo::Hash,
        ("tx_descartada", "indice") => ClaseCampo::EnteroU,
        ("renovacion_enviada" | "renovacion_aplicada", "sector") => ClaseCampo::EnteroU,
        ("renovacion_enviada" | "renovacion_aplicada", "renovacion_slot") => ClaseCampo::EnteroI,
        // Claves BLS de 48 bytes (96 hex) por productor (`[u8; 48]` + `hex`), **no** 64.
        (
            "voto_emitido" | "falta_voto" | "doble_voto" | "voto_suprimido" | "sorteo_propio"
            | "voto_peso_propio",
            "clave",
        )
        | ("voto_recibido", "clave")
        | (
            "evidencia_doble_voto" | "evidencia_doble_voto_en_bloque_admitido"
            | "evidencia_votos_peso",
            "clave_bls",
        ) => ClaseCampo::HashBls,

        // Hashes de 32 bytes (64 hex) por productor (`hex(&Hash)`, `BlockHash::to_string`,
        // `Digest::to_string`). **Ojo**: `clave_suspendida`/`revelacion_*` usan la clave **Ed25519**
        // (32 bytes) del estado (`claves_suspendidas`, `revelaciones_voto: ClavePublica`), no la BLS.
        ("sorteo_propio" | "ventana_abierta", "ancla" | "h_t_siguiente" | "candidato")
        | (
            "certificado_adoptado" | "certificado_en_conflicto" | "voto_recibido"
            | "certificado_peso_aplicado",
            "candidato",
        )
        | ("evidencia_votos_peso", "h1" | "h2")
        | ("votos_cargados" | "votos_reconciliados" | "certificado_aplicado", "candidato")
        | (
            "punto_control_conflicto",
            "candidato_externo" | "candidato_aplicado" | "h_t_externo" | "h_t_aplicado",
        )
        | ("evidencia_doble_voto", "h_t" | "h1" | "h2" | "incident_id")
        | ("evidencia_doble_voto_en_bloque_admitido", "h1" | "h2" | "incident_id")
        | ("certificado_aplicado", "h_t_siguiente" | "ancla_tabla")
        | (
            "clave_suspendida" | "revelacion_aplicada" | "revelacion_enviada"
            | "voto_propio_pendiente" | "voto_propio_difundido",
            "clave",
        )
        | ("votos_cargados" | "punto_control_cargado", "punto")
        // A1-D2b · raíces de estado y punto de época de los eventos nuevos.
        | ("certificado_peso_aplicado" | "ventana_cerrada", "raiz")
        | ("raiz_estado_discrepante", "propia" | "raiz_mayor" | "raiz_segunda" | "certificada")
        | ("raiz_estado_no_lista" | "raiz_estado_calculada", "punto" | "raiz")
        => ClaseCampo::Hash,

        // Booleanos reales (`true`/`false`).
        ("votos_arranque", "diario" | "observacion")
        | ("sorteo_propio", "emitido")
        | ("voto_peso_propio", "emitido")
        | ("ventana_cerrada", "certificado")
        | ("voto_recibido", "aceptado")
        | ("revelacion_aplicada", "voto_admitido")
        | ("evidencia_doble_voto", "bls_registrada")
        | ("certificado_aplicado", "admitido_en_orden")
        // A1-D2b · la división de raíces dejó sin quórum a todos los grupos.
        | ("raiz_estado_discrepante", "sin_quorum_por_division") => ClaseCampo::Booleano,

        // Garantías del R2b: el productor escribe `.i64` (`brek()`), no `u64`.
        (
            "evidencia_doble_voto_en_bloque_admitido",
            "activo_antes" | "congelado_antes" | "activo_despues" | "congelado_despues"
            | "quemado_delta",
        )
        // AUS-2b · N7 · deuda de ausencia de la clave del nodo y quemado del estado aplicado.
        | ("parada", "deuda_ausencia" | "quemado") => ClaseCampo::EnteroI,

        // RA-2 · R6.4 · ancla de votos de la cadena (ventana).
        | ("parada", "ancla_votos_n") => ClaseCampo::EnteroU,

        // Enteros sin signo en decimal (`u64`), con rango comprobado.
        ("arranque", "version_esquema" | "n_dev" | "sr_dev")
        | ("reinicio_completo", "bloques_repetidos" | "duracion_ns" | "n_bloques_dag")
        | ("bloque_minado", "altura" | "bytes" | "n_txs")
        | (
            "bloque_producido",
            "slot" | "n_padres" | "n_txs" | "bytes" | "retraso_slot_ns" | "clave_indice"
            | "azules_mergeset" | "rojos_mergeset",
        )
        | ("bloque_recibido", "bytes")
        | (
            "bloque_red_admitido",
            "altura" | "slot" | "n_padres" | "bytes" | "t_cabecera_ns" | "t_admision_ns"
            | "t_persistencia_ns" | "t_total_ns" | "n_bloques_dag" | "azules_mergeset"
            | "rojos_mergeset" | "txs_descartadas",
        )
        | ("bloque_red_rechazado" | "bloque_red_ignorado_sin_penalizar", "t_hasta_rechazo_ns")
        | (
            "cambio_punta",
            "profundidad_reorg"
            | "blue_score"
            | "eclipse_n"
            | "eclipse_n_certificado"
            | "eclipse_profundidad",
        )
        | ("reorganizacion_pow", "profundidad")
        | ("bloque_transicion_producido", "slot")
        | (
            "produccion_auditoria",
            "slot"
            | "n_claves"
            | "n_candidatos"
            | "n_ganadoras"
            | "t_pot_ns"
            | "t_conv_ns"
            | "t_auditoria_max_ns"
            | "t_conversion_max_ns",
        )
        | ("produccion_armado", "slot" | "clave_indice" | "t_armado_ns" | "t_total_ns")
        | ("produccion_sin_garantia", "slot" | "clave_indice")
        | ("produccion_descartada", "slot" | "clave_indice")
        | (
            "produccion_padres",
            "slot_objetivo" | "n_extras" | "n_con_garantia" | "slot_seleccionado" | "n_evidencias",
        )
        | (
            "bloque_propio_rechazado_con_evidencia",
            "slot" | "n_padres" | "n_txs" | "n_evidencias",
        )
        | ("productor_avanzar_hasta", "desde" | "hasta")
        | ("votos_arranque", "diario_entradas")
        | ("sorteo_propio", "n" | "plazas" | "slot")
        | ("ventana_abierta", "n" | "slot")
        | ("ventana_cerrada", "n" | "plazas" | "umbral" | "slot")
        | ("voto_emitido", "n" | "plazas")
        | ("voto_peso_propio", "n" | "peso")
        | ("certificado_peso_aplicado" | "evidencia_votos_peso", "n")
        | ("acta_peso_encolada", "n" | "firmantes")
        | ("acta_peso_aplicada", "n")
        | ("certificado_adoptado", "n" | "plazas" | "umbral")
        | ("falta_voto" | "doble_voto", "n")
        | ("voto_suprimido", "n")
        | (
            "voto_recibido" | "revelacion_aplicada" | "revelacion_enviada",
            "n" | "plazas" | "slot",
        )
        | ("voto_propio_pendiente" | "voto_propio_difundido", "n" | "slot")
        | ("voto_propio_aplicado", "n" | "slot")
        | ("voto_propio_descartado", "n")
        | ("votos_espera", "reloj_n" | "certificado_n")
        | ("votos_carga_pendiente", "reloj_n")
        | ("votos_cargados" | "votos_reconciliados" | "certificado_aplicado", "n" | "indice")
        | ("evidencia_doble_voto" | "evidencia_doble_voto_en_bloque_admitido", "n" | "indice")
        | (
            "mempool",
            "txs"
            | "bytes"
            | "pares"
            | "bytes_max_par"
            | "huerfanas"
            | "bytes_huerfanas"
            | "rechazos_limite"
            | "rechazos_global"
            | "rechazos_par_memoria"
            | "rechazos_par_tasa"
            | "rechazos_tarifa_minima"
            | "rechazos_tarifa_rodante"
            | "rechazos_huerfanas"
            | "rechazos_cuota_por_clave"
            | "rechazos_cuota_por_incidente"
            | "rechazos_cuota_por_ventana"
            | "rechazos_ventana_voto",
        )
        // A1-D2b · contadores de los eventos nuevos de raíz de estado.
        | (
            "raiz_estado_discrepante",
            "n" | "peso_mayor" | "peso_segunda" | "raices_distintas",
        )
        | ("raiz_estado_no_lista", "n" | "epoca")
        | ("raiz_estado_calculada", "epoca" | "ms")
        // A5-c-2b · X8 · contadores y campos numéricos de la agregación.
        | (
            "agregacion_ventana",
            "n"
            | "sueltos_antes_de_publicar"
            | "sueltos_despues_de_publicar"
            | "subredes"
            | "agregados_validos"
            | "votos_recibidos"
            | "votos_reenviados"
            | "votos_ignorados"
            | "votos_penalizados"
            | "agregados_recibidos"
            | "agregados_reenviados"
            | "agregados_ignorados"
            | "agregados_penalizados",
        )
        | ("agregado_publicado", "n" | "subred" | "bytes") => ClaseCampo::EnteroU,

        // Listas JSON.
        ("bloque_red_huerfano", "padres_ausentes") => ClaseCampo::Lista,

        // Cadenas reales (el productor puede emitir `""`; no se exige no-vacía).
        ("arranque", "claves" | "modo" | "peer_id" | "red_escuchar")
        | ("reinicio_completo", "punta" | "resumen_estado" | "compendio_bloques")
        | (
            "bloque_recibido"
            | "bloque_red_admitido"
            | "bloque_red_rechazado"
            | "bloque_red_huerfano"
            | "huerfano_desalojado"
            | "bloque_red_pendiente"
            | "bloque_red_ignorado_sin_penalizar"
            | "bloque_post_gossip_descartado_sincronizando",
            "familia" | "par" | "etapa" | "motivo" | "veredicto" | "padre_ausente",
        )
        | ("dejar_de_producir", "motivo")
        | (
            "bloque_propio_rechazado_legitimo" | "bloque_propio_rechazado_con_evidencia",
            "motivo",
        )
        | ("produccion_sin_garantia" | "produccion_descartada", "motivo")
        | ("produccion_auditoria", "claves_ganadoras")
        | ("cambio_punta", "punta" | "resumen_estado" | "modo" | "eclipse_h")
        | ("reorganizacion_pow", "punta_anterior" | "punta_nueva")
        | ("par_conectado" | "par_desconectado", "par")
        | ("par_penalizado", "par" | "motivo" | "accion")
        | ("limite_alcanzado", "par" | "limite" | "detalle")
        | ("parada", "motivo" | "punta" | "resumen_estado" | "compendio_bloques" | "ancla_votos_bloque")
        | ("votos_arranque", "origen" | "diario_ruta" | "motivo")
        | ("votos_cargados", "origen" | "bloque")
        | ("votos_reconciliacion", "resultado" | "motivo")
        | ("votos_reconciliados" | "certificado_aplicado", "bloque")
        | ("votos_espera", "clase")
        | ("votos_carga_pendiente" | "voto_rechazado" | "certificado_en_conflicto", "motivo")
        | ("certificado_aplicado", "origen" | "txid" | "tip" | "terminal")
        | ("voto_suprimido" | "sorteo_propio" | "voto_recibido", "motivo")
        | ("voto_peso_propio", "motivo")
        | ("certificado_peso_aplicado", "bloque")
        | ("evidencia_votos_peso", "txid" | "punto" | "admision")
        | ("voto_propio_descartado", "motivo")
        | ("evidencia_doble_voto", "punto" | "admision" | "error_transicion" | "txid")
        | ("evidencia_doble_voto_en_bloque_admitido", "alcance" | "bloque" | "txid")
        | ("evidencia_difundida" | "evidencia_no_publicada" | "evidencia_rechazada", "txid")
        | ("evidencia_no_publicada" | "evidencia_rechazada", "motivo")
        | ("evidencia_rechazada", "punto")
        // A5-c-2b · X8 · los pesos de la agregación viajan como decimal en texto (`u128` no cabe).
        | ("agregacion_ventana", "peso_agregado_propio" | "peso_agregado_elegido")
            => ClaseCampo::Texto,

        // Resto: histórico fuera del inventario de tipos; solo presencia (comportamiento anterior).
        _ => ClaseCampo::SinClasificar,
    }
}

/// Cadena JSON real: rodeada de comillas. **No** exige contenido no-vacío (el productor emite `""`).
fn es_cadena(v: &str) -> bool {
    v.len() >= 2 && v.starts_with('"') && v.ends_with('"')
}

/// Lista JSON (`[...]`).
fn es_lista(v: &str) -> bool {
    v.len() >= 2 && v.starts_with('[') && v.ends_with(']')
}

/// Entero sin signo decimal dentro del rango de `u64` (ser solo dígitos no basta).
fn es_u64(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) && v.parse::<u64>().is_ok()
}

/// Entero con signo decimal dentro del rango de `i64`.
fn es_i64(v: &str) -> bool {
    let cuerpo = v.strip_prefix('-').unwrap_or(v);
    !cuerpo.is_empty() && cuerpo.bytes().all(|b| b.is_ascii_digit()) && v.parse::<i64>().is_ok()
}

/// Hexadecimal de longitud exacta (sin prefijo).
fn es_hex(v: &str, n: usize) -> bool {
    v.len() == n && v.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Extrae los pares `clave -> valor crudo` de un objeto JSON plano (sin objetos anidados), con
/// soporte de cadenas, números y listas de cadenas.
fn campos_json(linea: &str) -> Vec<(String, String)> {
    let l = linea.trim();
    assert!(l.starts_with('{') && l.ends_with('}'), "no es objeto: {l}");
    let interior = &l[1..l.len() - 1];
    let bytes = interior.as_bytes();
    let mut campos = Vec::new();
    let mut i = 0usize;
    loop {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        assert_eq!(bytes[i], b'"', "clave sin comillas en: {l}");
        let (clave, fin) = extraer_cadena(interior, i);
        i = fin;
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        assert_eq!(bytes[i], b':', "falta ':' en: {l}");
        i += 1;
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        let inicio_valor = i;
        if bytes[i] == b'"' {
            let (_, fin) = extraer_cadena(interior, i);
            i = fin;
        } else if bytes[i] == b'[' {
            let mut prof = 0i32;
            let mut dentro = false;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => dentro = !dentro,
                    b'[' if !dentro => prof += 1,
                    b']' if !dentro => {
                        prof -= 1;
                        if prof == 0 {
                            i += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        } else {
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
        }
        campos.push((clave, interior[inicio_valor..i].trim().to_string()));
    }
    campos
}

/// Devuelve `(cadena_sin_comillas, índice_tras_la_comilla_de_cierre)`.
fn extraer_cadena(s: &str, inicio: usize) -> (String, usize) {
    let bytes = s.as_bytes();
    assert_eq!(bytes[inicio], b'"');
    let mut i = inicio + 1;
    let mut valor = String::new();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                valor.push(bytes[i + 1] as char);
                i += 2;
            }
            b'"' => return (valor, i + 1),
            b => {
                valor.push(b as char);
                i += 1;
            }
        }
    }
    panic!("cadena sin cerrar");
}

/// Vuelve a serializar pares `clave -> valor crudo` como objeto JSON plano (para los controles
/// negativos, que parten de una línea real).
fn serializar_campos(campos: &[(String, String)]) -> String {
    let mut salida = String::from("{");
    for (i, (clave, valor)) in campos.iter().enumerate() {
        if i > 0 {
            salida.push(',');
        }
        salida.push('"');
        salida.push_str(clave);
        salida.push_str("\":");
        salida.push_str(valor);
    }
    salida.push('}');
    salida
}

/// Comprueba el tipo de un campo según su clase; `SinClasificar` solo exige presencia/no-vacío.
fn validar_campo(tipo: &str, k: &str, v: &str) -> Result<(), String> {
    if v.is_empty() {
        return Err(format!("{tipo}.{k} vacío"));
    }
    match clase_del_campo(tipo, k) {
        ClaseCampo::Texto => {
            if !es_cadena(v) {
                return Err(format!("{tipo}.{k} no es cadena: {v}"));
            }
        }
        ClaseCampo::Lista => {
            if !es_lista(v) {
                return Err(format!("{tipo}.{k} no es lista: {v}"));
            }
        }
        ClaseCampo::Hash => {
            if !es_cadena(v) || !es_hex(&extraer_cadena(v, 0).0, 64) {
                return Err(format!("{tipo}.{k} no es hash hex64: {v}"));
            }
        }
        ClaseCampo::HashBls => {
            if !es_cadena(v) || !es_hex(&extraer_cadena(v, 0).0, 96) {
                return Err(format!("{tipo}.{k} no es clave BLS hex96: {v}"));
            }
        }
        ClaseCampo::Booleano => {
            if v != "true" && v != "false" {
                return Err(format!("{tipo}.{k} no booleano: {v}"));
            }
        }
        ClaseCampo::EnteroU => {
            if !es_u64(v) {
                return Err(format!("{tipo}.{k} no es u64 en rango: {v}"));
            }
        }
        ClaseCampo::EnteroI => {
            if !es_i64(v) {
                return Err(format!("{tipo}.{k} no es i64 en rango: {v}"));
            }
        }
        ClaseCampo::SinClasificar => {}
    }
    Ok(())
}

/// MISMA validación que se aplica a cada línea real del registro. Devuelve `Err(motivo)` si la línea
/// no es un evento válido del vocabulario finito o si un campo (obligatorio, o presente y
/// clasificado) tiene mal tipo.
fn validar_linea(linea: &str) -> Result<(), String> {
    let l = linea.trim();
    if !(l.starts_with('{') && l.ends_with('}')) {
        return Err(format!("no es objeto: {l}"));
    }
    let campos = campos_json(linea);
    let get = |k: &str| campos.iter().find(|(c, _)| c == k).map(|(_, v)| v.as_str());
    // Campos comunes, en cualquier posición.
    let tipo_raw = get("tipo").ok_or_else(|| format!("sin tipo: {linea}"))?;
    let tipo = extraer_cadena(tipo_raw, 0).0;
    for comun in ["reloj_ns", "reloj_pared_ns"] {
        let v = get(comun).ok_or_else(|| format!("{tipo} sin {comun}: {linea}"))?;
        if !es_u64(v) {
            return Err(format!("{tipo}.{comun} no es u64: {v}"));
        }
    }
    let familia = match get("familia") {
        Some(v) if es_cadena(v) => Some(extraer_cadena(v, 0).0),
        Some(v) => return Err(format!("familia no es cadena: {v}")),
        None => None,
    };
    let requeridos = campos_del_tipo(&tipo, familia.as_deref())
        .ok_or_else(|| format!("tipo fuera del §1: {tipo}: {linea}"))?;
    // 1) Campos obligatorios: deben estar y tener su tipo.
    for k in requeridos {
        let v = get(k).ok_or_else(|| format!("{tipo} sin el campo obligatorio {k}: {linea}"))?;
        validar_campo(&tipo, k, v)?;
    }
    // 2) Campos presentes no exigidos: si el productor los clasifica, se comprueban igualmente
    //    (p. ej. `evidencia_doble_voto.bls_registrada` en la ruta `VistaLocal`).
    for (k, v) in &campos {
        if requeridos.contains(&k.as_str()) {
            continue;
        }
        if matches!(
            k.as_str(),
            "tipo" | "reloj_ns" | "reloj_pared_ns" | "familia"
        ) {
            continue;
        }
        validar_campo(&tipo, k, v)?;
    }
    Ok(())
}

#[test]
fn los_eventos_cumplen_el_esquema_y_cubren_los_tipos_en_proceso() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config_de_test(dir.path());

    let mut nodo = Nodo::arrancar(&cfg).expect("arranque limpio");
    nodo.ejecutar().expect("ejecución sin rechazos fatales");
    assert!(nodo.cadena().terminal().is_some(), "debe cruzar el corte");
    // Cerrar el almacén antes de reabrirlo (RocksDB no permite dos handles del mismo directorio).
    drop(nodo);

    // Reapertura: emite `reinicio_completo` (repetición del almacén).
    let _reabierto = Nodo::arrancar(&cfg).expect("reabrir y repetir el almacén");

    let contenido = std::fs::read_to_string(&cfg.ruta_registro).expect("leer el registro");
    let mut vistos: BTreeSet<String> = BTreeSet::new();
    let mut n_lineas = 0usize;
    let mut linea_votos_arranque: Option<String> = None;
    let mut linea_ventana_cerrada: Option<String> = None;
    let mut lineas_por_tipo: BTreeMap<String, usize> = BTreeMap::new();
    for linea in contenido.lines() {
        if linea.trim().is_empty() {
            continue;
        }
        n_lineas += 1;
        // Validación real, línea por línea, con el vocabulario finito y sus tipos.
        if let Err(motivo) = validar_linea(linea) {
            panic!("{motivo}");
        }
        let campos = campos_json(linea);
        let get = |k: &str| campos.iter().find(|(c, _)| c == k).map(|(_, v)| v.as_str());
        let tipo_raw = get("tipo").unwrap_or_else(|| panic!("sin tipo: {linea}"));
        let tipo = extraer_cadena(tipo_raw, 0).0;
        if tipo == "votos_arranque" && linea_votos_arranque.is_none() {
            linea_votos_arranque = Some(linea.to_string());
        }
        if tipo == "ventana_cerrada" && linea_ventana_cerrada.is_none() {
            linea_ventana_cerrada = Some(linea.to_string());
        }
        *lineas_por_tipo.entry(tipo.clone()).or_insert(0) += 1;
        vistos.insert(tipo);
    }
    assert!(n_lineas > 0, "el registro no debe estar vacío");

    // Cobertura de lo que una ejecución en proceso puede producir. `votos_arranque` es el evento
    // productivo que el rojo VI6A demostró que faltaba (nodo.rs, al vincular el diario).
    let exigidos = [
        "arranque",
        "reinicio_completo",
        "bloque_minado",
        "bloque_producido",
        "cambio_punta",
        "parada",
        "votos_arranque",
    ];
    for t in exigidos {
        assert!(
            vistos.contains(t),
            "no se observó el evento {t}; vistos={vistos:?}"
        );
    }

    // Controles negativos significativos: parten de una línea REAL (`votos_arranque`) y usan la
    // MISMA validación, no una comprobación paralela.
    let real = linea_votos_arranque.expect("debe existir una línea real de votos_arranque");
    validar_linea(&real).expect("la línea real de votos_arranque debe validar");
    let pares = campos_json(&real);

    let con_tipo = |nuevo: &str| -> String {
        let mut ps = pares.clone();
        for p in &mut ps {
            if p.0 == "tipo" {
                p.1 = format!("\"{nuevo}\"");
            }
        }
        serializar_campos(&ps)
    };
    assert!(
        validar_linea(&con_tipo("evento_jamas_definido")).is_err(),
        "debe rechazar un tipo desconocido"
    );

    let mut sin_motivo = pares.clone();
    sin_motivo.retain(|(k, _)| k != "motivo");
    assert!(
        validar_linea(&serializar_campos(&sin_motivo)).is_err(),
        "debe rechazar un campo obligatorio ausente"
    );

    let mut mal_booleano = pares.clone();
    for p in &mut mal_booleano {
        if p.0 == "diario" {
            p.1 = "1".to_string();
        }
    }
    assert!(
        validar_linea(&serializar_campos(&mal_booleano)).is_err(),
        "debe rechazar un booleano que no sea true/false"
    );

    let real_ventana =
        linea_ventana_cerrada.expect("debe existir una línea real de ventana_cerrada");
    validar_linea(&real_ventana).expect("la línea real de ventana_cerrada debe validar");
    let pares_ventana = campos_json(&real_ventana);

    let mut bool_malo = pares_ventana.clone();
    for p in &mut bool_malo {
        if p.0 == "certificado" {
            p.1 = "1".to_string();
        }
    }
    assert!(
        validar_linea(&serializar_campos(&bool_malo)).is_err(),
        "debe rechazar un certificado que no es booleano"
    );

    let mut ventana_n_negativo = pares_ventana.clone();
    for p in &mut ventana_n_negativo {
        if p.0 == "n" {
            p.1 = "-1".to_string();
        }
    }
    assert!(
        validar_linea(&serializar_campos(&ventana_n_negativo)).is_err(),
        "debe rechazar un entero sin signo negativo"
    );

    eprintln!(
        "V2: {n_lineas} líneas; tipos observados en proceso = {vistos:?}; \
         recuento = {lineas_por_tipo:?}; (los de red, en V3)"
    );
}

/// RN-1 · N6 · los cinco eventos nuevos del registro (S5) cumplen el esquema, validados con la
/// MISMA función que las líneas reales, y un tipo mal puesto se rechaza.
#[test]
fn rn1_cinco_eventos_nuevos_cumplen_esquema() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ruta = dir.path().join("registro.jsonl");
    let registro = zx_node::registro::Registro::abrir(&ruta).expect("registro");
    let h = "a".repeat(64);
    let hb = "b".repeat(64);
    let eventos = [
        registro
            .evento("tx_admitida")
            .str("txid", &h)
            .str("clase", "sector_renovar")
            .str("origen", "propia"),
        registro
            .evento("tx_rechazada")
            .str("txid", &h)
            .str("clase", "sector_alta")
            .str("origen", "red")
            .str("motivo", "VistaLocal(\"vista\")"),
        registro
            .evento("tx_descartada")
            .str("bloque", &hb)
            .u64("indice", 3)
            .str("txid", &h)
            .str("clase", "almacenamiento_certificado_peso")
            .str("motivo", "ErrCertificadoPesoBytes"),
        registro
            .evento("renovacion_enviada")
            .str("clave", &h)
            .u64("sector", 0)
            .i64("renovacion_slot", 12),
        registro
            .evento("renovacion_aplicada")
            .str("clave", &h)
            .u64("sector", 0)
            .i64("renovacion_slot", 314),
    ];
    for e in eventos {
        registro.escribir(e, false).expect("escribir evento");
    }
    let contenido = std::fs::read_to_string(&ruta).expect("leer registro");
    let mut n = 0usize;
    for linea in contenido.lines() {
        validar_linea(linea).expect("los cinco eventos nuevos deben validar");
        n += 1;
    }
    assert_eq!(n, 5, "deben quedar cinco líneas");
    // Control negativo con la MISMA validación: `tx_descartada.indice` no numérico.
    let descartada = contenido.lines().nth(2).expect("línea tx_descartada");
    let mut pares = campos_json(descartada);
    for p in &mut pares {
        if p.0 == "indice" {
            p.1 = "\"tres\"".to_string();
        }
    }
    assert!(
        validar_linea(&serializar_campos(&pares)).is_err(),
        "un indice no numérico debe rechazarse"
    );
}
