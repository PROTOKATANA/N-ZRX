//! Validación estructural **sin contexto** de transacciones y cabeceras PoST (F-03, F-05, F-07,
//! F-08, F-10).
//!
//! # Qué decide y qué no
//!
//! Esto responde a la pregunta «¿esta transacción *puede* ser válida mirándola sola?». No sustituye
//! a la máquina de estados: son precisamente los controles que **no** necesitan UTXO, cabecera
//! contenedora ni estado.
//!
//! **No** comprueba:
//! - las firmas de entrada (necesitan el UTXO gastado, `C-SIG`);
//! - la posición de la coinbase en el bloque (`C-BLK-07`);
//! - `clave == sol.public_key` de F-09 (necesita la cabecera que contiene la v3);
//! - saldos, peso ni tarifa (W03, `C-WGT-02`).
//!
//! Para v1, una transacción sin entradas solo es válida como coinbase PoW, y eso no se puede saber
//! aquí: se devuelve `Ok` y el llamante consulta [`Tx::es_candidata_coinbase_pow`].

use crate::error::{EncodingError, ErrorFormaTx};
use crate::firma::LONGITUD_FIRMA;
use crate::preimage::dag::DagBlockHeader;
use crate::tx::{ExtensionTx, Lock, TipoGarantia, Tx};

/// Valida la **forma** de una transacción y de sus testigos, sin contexto (F-05, F-07, F-08, F-10).
///
/// Aplica:
/// 1. versión activa (F-05): `1`, `2` o `3`; la `4` es `Err(VersionInactiva)`; el resto,
///    `Err(VersionDesconocida)`;
/// 2. coherencia `version ⇔ extension` (F-05): `1 ⇔ Ninguna`, `2 ⇔ Garantia`,
///    `3 ⇔ CoinbasePost`;
/// 3. `importe > 0` en la extensión de v2/v3 (F-07);
/// 4. recuentos por versión y tipo (F-05, F-07): depósito con `n_in ≥ 1`; retiro y liberación con
///    `n_in = n_out = 0`; v1 con entradas exige `n_out ≥ 1`; v3 exige `n_in = n_out = n_wit = 0`;
/// 5. testigos de v2 (F-08): `n_wit = n_in + 1` y el **último** (aceptación) de 64 B;
/// 6. campos inactivos (F-10): `lock_time = 0`, `expiry_height = 0` y ninguna salida
///    [`Lock::Htlc`]. **Excepción F-16:** las candidatas a coinbase PoW (`version == 1`,
///    `inputs.is_empty()`) pueden llevar `expiry_height ≠ 0`; el motor exige allí
///    `expiry_height == altura`. La **anchura** de la extensión (con `nonce` y `slot`) la fijan el
///    códec y el `txid` (F-15/F-17), no esta función.
///
/// # Errores
/// [`ErrorFormaTx`], con una variante específica por caso. El orden de comprobación está fijado
/// para que un mismo objeto inválido dé siempre el mismo error.
pub fn validar_forma_tx(tx: &Tx, testigos: &[Vec<u8>]) -> Result<(), ErrorFormaTx> {
    // 1 · versión activa y 2 · coherencia versión ↔ extensión.
    match tx.version {
        1 => {
            if !matches!(tx.extension, ExtensionTx::Ninguna) {
                return Err(ErrorFormaTx::ExtensionIncoherente {
                    version: 1,
                    esperada: "Ninguna",
                });
            }
            // Una v1 con entradas es una transferencia y exige al menos una salida. Una v1 sin
            // entradas es candidata a coinbase PoW (o la coinbase del génesis, F-13): el contexto
            // decide, aquí se acepta.
            if !tx.inputs.is_empty() && tx.outputs.is_empty() {
                return Err(ErrorFormaTx::TransferenciaSinSalidas);
            }
        }
        2 => {
            let (tipo, importe) = match &tx.extension {
                ExtensionTx::Garantia { tipo, importe, .. } => (*tipo, *importe),
                _ => {
                    return Err(ErrorFormaTx::ExtensionIncoherente {
                        version: 2,
                        esperada: "Garantia",
                    });
                }
            };

            // 3 · importe > 0 (F-07).
            if importe.brek() == 0 {
                return Err(ErrorFormaTx::ImporteCero);
            }

            // 5 · testigos de v2 (F-08).
            let esperados = tx.inputs.len() + 1;
            if testigos.len() != esperados {
                return Err(ErrorFormaTx::NumeroDeTestigosInvalido {
                    esperados,
                    obtenidos: testigos.len(),
                });
            }
            let aceptacion = testigos.last().map_or(0, Vec::len);
            if aceptacion != LONGITUD_FIRMA {
                return Err(ErrorFormaTx::TestigoAceptacionLongitud {
                    obtenidos: aceptacion,
                });
            }

            // 4 · recuentos por tipo (F-07).
            match tipo {
                TipoGarantia::Deposito => {
                    if tx.inputs.is_empty() {
                        return Err(ErrorFormaTx::DepositoSinEntradas);
                    }
                }
                TipoGarantia::Retiro => {
                    if !tx.inputs.is_empty() {
                        return Err(ErrorFormaTx::RetiroConEntradas {
                            entradas: tx.inputs.len(),
                        });
                    }
                    if !tx.outputs.is_empty() {
                        return Err(ErrorFormaTx::RetiroConSalidas {
                            salidas: tx.outputs.len(),
                        });
                    }
                }
                TipoGarantia::Liberacion => {
                    if !tx.inputs.is_empty() {
                        return Err(ErrorFormaTx::LiberacionConEntradas {
                            entradas: tx.inputs.len(),
                        });
                    }
                    if !tx.outputs.is_empty() {
                        return Err(ErrorFormaTx::LiberacionConSalidas {
                            salidas: tx.outputs.len(),
                        });
                    }
                }
            }
        }
        3 => {
            let importe = match &tx.extension {
                ExtensionTx::CoinbasePost { importe, .. } => *importe,
                _ => {
                    return Err(ErrorFormaTx::ExtensionIncoherente {
                        version: 3,
                        esperada: "CoinbasePost",
                    });
                }
            };

            // 3 · importe > 0 (F-07).
            if importe.brek() == 0 {
                return Err(ErrorFormaTx::ImporteCero);
            }

            // 4 · la coinbase PoST no lleva entradas, salidas ni testigos (F-05, F-08).
            if !tx.inputs.is_empty() {
                return Err(ErrorFormaTx::EntradasEnCoinbasePost {
                    entradas: tx.inputs.len(),
                });
            }
            if !tx.outputs.is_empty() {
                return Err(ErrorFormaTx::SalidasEnCoinbasePost {
                    salidas: tx.outputs.len(),
                });
            }
            if !testigos.is_empty() {
                return Err(ErrorFormaTx::TestigosEnCoinbasePost {
                    testigos: testigos.len(),
                });
            }
        }
        4 => return Err(ErrorFormaTx::VersionInactiva { version: 4 }),
        5 => {
            // SR-1-2 · v5: operación de sector. Sin entradas, sin salidas y un único testigo de
            // 64 B (la firma Ed25519 de `operacion.clave` sobre el `txid`). El tope canónico se
            // comprueba aquí, antes de que la operación entre en el `txid` de consenso.
            let operacion = match &tx.extension {
                ExtensionTx::Sector { operacion } => operacion,
                _ => {
                    return Err(ErrorFormaTx::ExtensionIncoherente {
                        version: 5,
                        esperada: "Sector",
                    });
                }
            };
            operacion.bytes_canonicos().map_err(|e| {
                ErrorFormaTx::Codificacion(EncodingError::OperacionSectorInvalida(e))
            })?;
            if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
                return Err(ErrorFormaTx::SectorConEntradasOSalidas {
                    entradas: tx.inputs.len(),
                    salidas: tx.outputs.len(),
                });
            }
            if testigos.len() != 1 {
                return Err(ErrorFormaTx::NumeroDeTestigosInvalido {
                    esperados: 1,
                    obtenidos: testigos.len(),
                });
            }
            let firma = testigos.first().map_or(0, Vec::len);
            if firma != LONGITUD_FIRMA {
                return Err(ErrorFormaTx::TestigoAceptacionLongitud { obtenidos: firma });
            }
        }
        6 => {
            // PT-3bc · v6: operación de prueba de almacenamiento. Sin entradas, sin salidas y un
            // único testigo de 64 B (la firma Ed25519 de `operacion.clave` sobre el `txid`). El
            // tope de la prueba y los predicados de la clase (prueba no vacía, `n_sectores > 0`) se
            // comprueban aquí, antes de que la operación entre en el `txid` de consenso.
            let operacion = match &tx.extension {
                ExtensionTx::PruebaAlmacenamiento { operacion } => operacion,
                _ => {
                    return Err(ErrorFormaTx::ExtensionIncoherente {
                        version: 6,
                        esperada: "PruebaAlmacenamiento",
                    });
                }
            };
            operacion.bytes_canonicos().map_err(|e| {
                ErrorFormaTx::Codificacion(EncodingError::OperacionAlmacenamientoInvalida(e))
            })?;
            if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
                return Err(ErrorFormaTx::SectorConEntradasOSalidas {
                    entradas: tx.inputs.len(),
                    salidas: tx.outputs.len(),
                });
            }
            if testigos.len() != 1 {
                return Err(ErrorFormaTx::NumeroDeTestigosInvalido {
                    esperados: 1,
                    obtenidos: testigos.len(),
                });
            }
            let firma = testigos.first().map_or(0, Vec::len);
            if firma != LONGITUD_FIRMA {
                return Err(ErrorFormaTx::TestigoAceptacionLongitud { obtenidos: firma });
            }
        }
        v => return Err(ErrorFormaTx::VersionDesconocida { version: v }),
    }

    // 6 · campos dependientes de altura, inactivos en v0 (F-10), válido para toda versión.
    //
    // Excepción F-16: la coinbase PoW **MUST** llevar `expiry_height = altura` (lo comprueba el
    // motor, que sí conoce el bloque). Como la forma no puede saber la altura, exime a las
    // candidatas a coinbase PoW —igual que ya difiere al contexto su **posición**— y deja la
    // igualdad `expiry_height == altura` para `aplicar_coinbase_pow`. En el resto de transacciones
    // (v1 con entradas, v2 y v3) `expiry_height ≠ 0` sigue siendo `ErrCampoInactivo`.
    if tx.lock_time != 0 {
        return Err(ErrorFormaTx::CampoInactivo { campo: "lock_time" });
    }
    if tx.expiry_height != 0 && !tx.es_candidata_coinbase_pow() {
        return Err(ErrorFormaTx::CampoInactivo {
            campo: "expiry_height",
        });
    }
    if tx
        .outputs
        .iter()
        .any(|o| matches!(&o.lock, Lock::Htlc { .. }))
    {
        return Err(ErrorFormaTx::SalidaHtlc);
    }

    Ok(())
}

/// Valida la forma de una cabecera PoST (`PoAS_PoT_DAG`) en v0 (F-03).
///
/// El campo `height` es **reservado** y MUST ser `0` mientras la semántica de altura DAG siga
/// pendiente (`C-HDR-02`, IPA B-10). El parser de cabecera no cambia: esto se comprueba después de
/// decodificar.
///
/// # Errores
/// [`ErrorFormaTx::AlturaPostNoCero`] si `c.height != 0`.
pub fn validar_forma_cabecera_post(c: &DagBlockHeader) -> Result<(), ErrorFormaTx> {
    if c.height != 0 {
        return Err(ErrorFormaTx::AlturaPostNoCero { height: c.height });
    }
    Ok(())
}

/// Valida la **forma** de una `EvidenceTx` v4 (`EV-01`…`EV-04`, `RAT-1`), sin contexto ni activación.
///
/// Comprueba, **en este orden**:
/// 1. lo meramente estructural: coherencia `version = 4 ⇔ Evidencia`, `lock_time = 0`,
///    `expiry_height = 0`, sin entradas, salidas ni testigos de transacción (`EV-01`, `EV-02`,
///    `EV-04`), y cada cabecera con forma válida de `PoAS_PoT_DAG` (F-03);
/// 2. `RAT-1`: las **dos** cabeceras llevan el `consensus_branch_id` de la red local
///    (`cbid_local`, que el llamante pasa sin valor por defecto);
/// 3. `EV-01`/`EV-04`: orden canónico estricto por `pre_hash`, `pre_hash(H1) <_lex pre_hash(H2)`
///    (incluye rechazar `H1 = H2`).
///
/// El llamante (el motor) pasa como `cbid_local` el `consensus_branch_id` de la red local del
/// perfil (`ParametrosEvidencia::cbid`), **no** el `cbid` semántico de `txid`/sighash. El
/// `cbid` de cada cabecera es un dato de forma sin contexto: no depende del estado ni del orden
/// de fusión.
///
/// **No** comprueba la identidad, los sellos, la puerta RAT-3 ni la ventana: esas comprobaciones
/// son semánticas y viven en `zx_consensus::transicion`.
///
/// # Errores
/// [`ErrorFormaTx`]; ver las variantes usadas.
pub fn validar_forma_tx_v4(
    tx: &Tx,
    testigos: &[Vec<u8>],
    cbid_local: u32,
) -> Result<(), ErrorFormaTx> {
    if tx.version != 4 {
        return Err(ErrorFormaTx::VersionDesconocida {
            version: tx.version,
        });
    }
    let (h1, h2) = match &tx.extension {
        ExtensionTx::Evidencia { h1, h2 } => (h1, h2),
        _ => {
            return Err(ErrorFormaTx::ExtensionIncoherente {
                version: 4,
                esperada: "Evidencia",
            });
        }
    };
    if !tx.inputs.is_empty() || !tx.outputs.is_empty() || !testigos.is_empty() {
        return Err(ErrorFormaTx::EvidenciaConEntradasOSalidas);
    }
    if tx.lock_time != 0 {
        return Err(ErrorFormaTx::CampoInactivo { campo: "lock_time" });
    }
    if tx.expiry_height != 0 {
        return Err(ErrorFormaTx::CampoInactivo {
            campo: "expiry_height",
        });
    }
    validar_forma_cabecera_post(h1)?;
    validar_forma_cabecera_post(h2)?;
    // RAT-1: ambas cabeceras, de la red local.
    if h1.consensus_branch_id != cbid_local || h2.consensus_branch_id != cbid_local {
        return Err(ErrorFormaTx::EvidenciaCbidAjeno);
    }
    // EV-01/EV-04: orden canónico estricto (incluye `H1 = H2`).
    if h1.pre_hash().as_bytes() >= h2.pre_hash().as_bytes() {
        return Err(ErrorFormaTx::OrdenCanonicoInvalido);
    }
    Ok(())
}
