//! Capa de red de ZEROX sobre libp2p (SPEC §16), para la red dev híbrida de 0.0.1.
//!
//! # Lo que este crate NO hace
//!
//! **No decide nada.** No valida bloques, no elige cadena, no toca el estado. Transporta bytes y
//! los entrega al [`entrante::ManejadorEntrante`] para que decida. Esa frontera es lo que mantiene
//! el consenso testeable sin red y la red testeable sin cadena.
//!
//! # El principio que gobierna todo el crate
//!
//! **Ningún límite de transporte se deja en su valor por defecto** (C-NET-11). La capa de
//! transporte de libp2p no es segura por defecto para una cadena, y sus defaults peligrosos
//! **no fallan al compilar** — se propagan como bloques que nunca llegan o memoria que se agota.
//! Ver [`limites`].
//!
//! # La frontera, y por qué es una regla y no un gusto
//!
//! ```text
//! zx-node ──▶ zx-p2p ──▶ zx-core
//!    │                      ▲
//!    ├──▶ zx-consensus ─────┤
//!    ├──▶ zx-storage ───────┤
//!    └──▶ zx-mempool ───────┘
//! ```
//!
//! **`zx-p2p` NO depende de `zx-consensus`, `zx-storage` ni `zx-mempool`** — solo de `zx-core`,
//! que son tipos puros. La razón no es estética: red y consenso se necesitan **en las dos
//! direcciones**, y si `zx-p2p` pudiera ver `zx-consensus` el ciclo se cerraría poco a poco. El
//! ciclo se rompe en `zx-node`, que es el único que ve las cuatro cosas a la vez, y lo comprueba
//! `ci/frontera-crates.sh` (`zx-p2p → {zx-core}`).
//!
//! # Mensajes de la red dev
//!
//! Los mensajes lineales de `9681061` se sustituyen por los del híbrido: [`mensaje::BloqueRed`] es
//! un enum de dos familias (`Pow`/`Post`), [`mensaje::Estado`] declara la fase y las dos puntas, y
//! [`mensaje::Peticion`]/[`mensaje::Respuesta`] ganan `CabecerasPow`. El códec **exige** la familia
//! declarada (F-04) y no la adivina por longitud. El relé compacto no se porta.

pub mod behaviour;
pub mod codec;
pub mod config;
pub mod desalojo;
pub mod director;
pub mod entrante;
pub mod error;
pub mod gestor;
pub mod limites;
pub mod limites_ip;
pub mod mensaje;
pub mod presupuesto;
pub mod registro;
pub mod servicio;
// ZRX-C (ORDEN-ZC4): la implementación única (marco, topes, diccionario y verificación) vive en
// el crate `zx-compresion`; aquí se reexporta bajo el nombre histórico `zrxc` para que la red la
// consuma sin duplicar el formato.
pub use zx_compresion as zrxc;
