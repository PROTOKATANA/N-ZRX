//! Motor de estado de la transición PoW → PoAS + PoT + DAG (`CONTRATO-v0` v0.1, `ORDEN-W03`).
//!
//! Implementa, sobre los tipos **reales** de `zx-core` (transacciones v1/v2/v3, `OutPoint`,
//! `ClavePublica`, `Lock`, firmas), la máquina de estados del contrato con las interfaces por
//! defecto `CUT-HWΦ`, `FC-3` y `SEC-0`:
//!
//! - [`aplicar`] aplica un bloque en modo estricto y devuelve el estado nuevo;
//! - [`aplicar_con_undo`] devuelve además el **undo por delta** (`I-2`);
//! - [`deshacer`] restituye el estado previo;
//! - [`seleccionar`] y [`nodo_en_linea`] implementan `FC-3` y `C-FIN-01`;
//! - [`aplicar_fusion`] es el modo fusión de `CONTRATO-ESTADO-DAG-v0` §3 (primitivas de W03).
//!
//! El alcance y lo que **no** demuestra están en `INFORME.md` de la orden.

pub mod aplicar;
pub mod caja;
pub mod error;
pub mod estado;
pub mod fusion;
pub mod sector;
pub mod seleccion;
pub mod tipos;
pub mod votos;

#[cfg(test)]
mod tests;

pub use aplicar::{aplicar, aplicar_con_undo, es_terminal, es_terminal_condiciones};
pub use caja::{
    caja_abierta, caja_de_sector, consulta_caja, estado_hueco, fianza_caja, invariante_caja,
    raiz_de_caja, sector_del_hueco, siguiente_seq, todos_en_caja,
};
pub use error::ErrorTransicion;
pub use estado::{
    debitar_garantia, deshacer, gastable_en, invariante_i1, invariante_i1b, phi, podar_incidentes,
    suelo_dos_octavos, suma_garantias, suma_utxo, techo_fraccion, total_garantia,
};
pub use fusion::aplicar_fusion;
pub use sector::{
    ResultadoBloqueSector, ResultadoOperacionSector, aplicar_almacenamiento_con_undo,
    aplicar_bloque_sector, aplicar_operacion_con_undo, cubierto_por_porep, elegible_sector,
    fuente_peso_de, materializar_con_undo, prueba_vigente, raiz_conjunto_de, raiz_lote_de,
    sector_vivo, sectores_activos_de,
};
pub use seleccion::{
    ResultadoSeleccion, comparar_terminal, construir_validos, mapa_por_hash, nodo_en_linea,
    seleccionar,
};
pub use tipos::{
    BloqueTransicion, EnRetirada, EntradaUtxo, Escalares, Estado, Fase, Garantia, HechoVoto,
    HechosCabecera, Incidente, Marca, Origen, ParametrosEvidencia, ParametrosTransicion, Pendiente,
    Punto, TxDescartada, Undo,
};
