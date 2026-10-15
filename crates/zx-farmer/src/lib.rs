//! Crate `zx-farmer`: parcela persistente, auditoría por slot y conversión de candidatos a
//! soluciones PoAS verificadas.
//!
//! Dos módulos, portados **sin cambio de lógica** de `crates/zx-node/src/{farmer.rs,
//! productor_poas.rs}` de `9681061`:
//!
//! - [`farmer`]: ploteo de un sector con `CpuRecordsEncoder::<ChiaTable>` por la ruta paralela,
//!   persistencia en un par de archivos con lock y checksums, y auditoría con `audit_plot_sync`
//!   sobre el descriptor verificado. La historia, el KZG, el erasure coding y el
//!   `FarmerProtocolInfo` llegan de [`zx_poas::HistoriaGenesis`]; el reto de auditoría se deriva
//!   con [`zx_poas::reto_desde_salida`] (valor de prueba en W05b1).
//! - [`productor_poas`]: convierte los candidatos de una auditoría en `Solution`, los pasa a
//!   [`zx_core::SolucionPoas`] y los verifica con [`zx_poas::verificar_solucion_poas`]. Un rechazo
//!   de A1 se descarta y se cuenta; `InvalidHistorySize` se propaga como fallo de contexto.
//!
//! # Lo que este crate NO hace
//!
//! No elige padres, no arranca desde génesis, no ensambla cabecera ni sello, no deriva el
//! `pot_output` futuro, no firma, no admite en red y no publica. La procedencia causal del lote
//! (slot, salida, rango y contexto de pieza) no se acredita aquí: la inyecta el llamante.

#![doc = include_str!("../README.md")]

pub mod farmer;
pub mod productor_poas;

pub use farmer::{
    ErrorFarmer, ParcelaDisco, ResumenCandidatos, VERSION_PARCELA, plotear_sector_en_disco,
};
pub use productor_poas::{
    DiagnosticoLocal, ErrorProductorPoas, ResultadoConversionLocal, SolucionComprobadaLocal,
    convertir_candidatos_locales,
};
