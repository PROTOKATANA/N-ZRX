//! Orden DAG de la red dev (D-P07, D-P08, D-P13).
//!
//! Todo lo de aquí es **consensus-critical**: una divergencia de un bit entre dos nodos es un split
//! de cadena. Cada elemento cita la regla `C-XXX` del SPEC que implementa.
//!
//! El crate porta el orden DAG del commit `9681061` con la raíz en el terminal PoW `T` (D-P07), sin
//! génesis DAG (D-P08) y sin depender de `zx-consensus` ni de `zx-storage`. La admisión en el nodo,
//! la persistencia, el flujo PoT y la verificación PoT/PoAS quedan para W05b/W06.

#![doc = include_str!("../README.md")]

mod alcanzabilidad;
mod conjunto_azul;

pub mod bloque_dag;
pub mod dag_causal;
pub mod error;
pub mod ghostdag;
pub mod identidad;

pub use bloque_dag::{
    CandidatoSinRango, ContextoDag, ContextoRangoDag, RangoSolucionValidado,
    comprobar_compromisos_cuerpo_dag, comprobar_padres_contextual, comprobar_rango_contextual,
};
pub use dag_causal::{
    ErrorVistaCausal, FuenteRegistrosDag, PresupuestoVista, RegistroEstructural,
    VistaPasadoEstructural,
};
pub use error::ErrorDag;
pub use ghostdag::{
    Algoritmo, AlmacenGhostdag, BloqueGhostdag, Color, DatosGhostdag, IdentidadGhostdag, Idx,
    ModoMerge, ModoSp, Parametros, Rank, hash_de_id_textual, peso, sumar_blue_work,
};
pub use identidad::{
    DOMINIO_TICKET_VIGENTE, IdentidadTicket, LONGITUD_HUELLA, VERSION_ESQUEMA,
    identidad_de_cabecera,
};
