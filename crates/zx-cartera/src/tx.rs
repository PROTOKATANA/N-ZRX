//! Construcción y firma de transacciones de la cartera (TX-4).
//!
//! # Qué reutiliza y qué no reimplementa
//!
//! - El **sighash**, el **txid**, el **mensaje de aceptación** y la **verificación** vienen de
//!   `zx-core` (`preimage::tx`, `firma`). Aquí no se recalcula ninguna preimagen ni se reimplementa
//!   un formato.
//! - La **serialización** (`tx_a_bytes`/`tx_desde_bytes`) es la de `zx-core::wire`.
//! - La **forma** se comprueba con `zx_core::validar_forma_tx`, la misma que usa el nodo.
//!
//! # Salidas que se firman
//!
//! Las entradas guardan también el `SpentOutput` (importe y `Lock`) que consumen, porque el sighash
//! de C-SIG-02 los compromete y el firmante debe conocerlos. La cartera es offline: esos datos los
//! aporta quien la invoca (archivo o argumentos), nunca un RPC.

use ed25519_zebra::Signature as FirmaZebra;
use zx_core::amount::Amount;
use zx_core::firma::Firma;
use zx_core::tx::{ExtensionTx, Lock, OutPoint, SpentOutput, TipoGarantia, Tx, TxIn, TxOut};
use zx_core::wire::{tx_a_bytes, tx_desde_bytes};
use zx_core::{CBID_RED_DEV, HashType, TxId, mensaje_aceptacion, sighash, txid, verificar};

use crate::claves::ClaveCartera;
use crate::error::ErrorCartera;

/// Una entrada que la cartera puede firmar: el `OutPoint` que gasta, el importe y `Lock` de la
/// salida gastada, y la clave que la controla.
#[derive(Clone)]
pub struct Entrada {
    /// Salida que se consume.
    pub outpoint: OutPoint,
    /// Importe de la salida gastada, en brek.
    pub valor: Amount,
    /// Condición de gasto de la salida gastada.
    pub lock: Lock,
    /// Clave con la que se firma esta entrada.
    pub firmante: ClaveCartera,
}

impl Entrada {
    /// Construye una entrada `PubKey` (P2K): el `Lock` es la clave del firmante.
    #[must_use]
    pub fn p2k(outpoint: OutPoint, valor: Amount, firmante: ClaveCartera) -> Self {
        let lock = Lock::PubKey {
            pubkey: firmante.pk,
        };
        Self {
            outpoint,
            valor,
            lock,
            firmante,
        }
    }

    /// La salida gastada que el sighash compromete.
    #[must_use]
    pub fn gastada(&self) -> SpentOutput {
        SpentOutput {
            value: self.valor,
            lock: self.lock.clone(),
        }
    }
}

impl core::fmt::Debug for Entrada {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entrada")
            .field("outpoint", &self.outpoint)
            .field("valor", &self.valor)
            .finish_non_exhaustive()
    }
}

/// Una transacción de la cartera con sus testigos: lo que se serializa y se difunde.
#[derive(Clone, Debug)]
pub struct TxFirmada {
    /// Datos de efecto.
    pub tx: Tx,
    /// Testigos (firmas), en el orden de F-08.
    pub testigos: Vec<Vec<u8>>,
}

impl TxFirmada {
    /// Los bytes canónicos `tx_a_bytes(tx, testigos)`.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut salida = Vec::new();
        tx_a_bytes(&mut salida, &self.tx, &self.testigos);
        salida
    }

    /// El hexadecimal de [`Self::a_bytes`].
    #[must_use]
    pub fn a_hex(&self) -> String {
        hex::encode(self.a_bytes())
    }

    /// El `txid` en la rama dev (`CBID_RED_DEV`).
    #[must_use]
    pub fn txid(&self) -> TxId {
        txid(&self.tx, CBID_RED_DEV)
    }

    /// Decodifica una transacción estricta (exige que no sobre ningún byte).
    ///
    /// # Errores
    /// [`ErrorCartera::Codificacion`] si el wire está truncado o mal formado, y
    /// [`ErrorCartera::Bytes`] si tras la transacción quedan bytes.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, ErrorCartera> {
        let ((tx, testigos), resto) = tx_desde_bytes(bytes)?;
        if !resto.is_empty() {
            return Err(ErrorCartera::Bytes(format!(
                "sobran {} bytes tras la transacción",
                resto.len()
            )));
        }
        Ok(Self { tx, testigos })
    }

    /// Decodifica el hexadecimal de [`Self::a_hex`].
    ///
    /// # Errores
    /// [`ErrorCartera::Parseo`] si el texto no es hexadecimal, o las de [`Self::desde_bytes`].
    pub fn desde_hex(texto: &str) -> Result<Self, ErrorCartera> {
        let bytes =
            hex::decode(texto.trim()).map_err(|e| ErrorCartera::Parseo(format!("hex: {e}")))?;
        Self::desde_bytes(&bytes)
    }

    /// Comprueba la forma y, si es v2, la firma de aceptación (F-08): es todo lo verificable sin
    /// conocer las salidas gastadas.
    ///
    /// # Errores
    /// [`ErrorCartera::Forma`] si la forma no cuadra, o [`ErrorCartera::Codificacion`] con
    /// `FirmaInvalida` si la aceptación no verifica.
    pub fn verificar(&self) -> Result<(), ErrorCartera> {
        zx_core::validar_forma_tx(&self.tx, &self.testigos)?;
        if self.tx.version == 2 {
            let aceptacion = self
                .testigos
                .last()
                .ok_or(ErrorCartera::FirmaNoVerifica { indice: 0 })?;
            zx_core::verificar_aceptacion(&self.tx, aceptacion, CBID_RED_DEV)?;
        }
        Ok(())
    }

    /// Comprueba la forma y **todas** las firmas contra las salidas gastadas que se le pasan: las de
    /// entrada en el orden de `entradas`, y la de aceptación si es v2.
    ///
    /// # Errores
    /// [`ErrorCartera::LockNoSoportado`] si una salida no es `PubKey`, [`ErrorCartera::Forma`] si la
    /// forma no cuadra, y [`ErrorCartera::FirmaNoVerifica`] si alguna firma no valida.
    pub fn verificar_entradas(&self, entradas: &[Entrada]) -> Result<(), ErrorCartera> {
        self.verificar()?;
        let gastadas: Vec<SpentOutput> = entradas.iter().map(Entrada::gastada).collect();
        for (i, entrada) in entradas.iter().enumerate() {
            let Lock::PubKey { pubkey } = &entrada.lock else {
                return Err(ErrorCartera::LockNoSoportado);
            };
            let digest = sighash(&self.tx, &gastadas, HashType::All, i, CBID_RED_DEV)?;
            let testigo = self
                .testigos
                .get(i)
                .ok_or(ErrorCartera::FirmaNoVerifica { indice: i })?;
            let bytes: [u8; 64] = testigo
                .as_slice()
                .try_into()
                .map_err(|_| ErrorCartera::FirmaNoVerifica { indice: i })?;
            verificar(pubkey, &Firma::desde_bytes(bytes), digest.as_bytes())
                .map_err(|_| ErrorCartera::FirmaNoVerifica { indice: i })?;
        }
        Ok(())
    }
}

/// Suma las entradas y comprueba que cubren `salidas + importe`.
fn comprobar_saldo(
    entradas: &[Entrada],
    salidas: &[TxOut],
    importe: i64,
) -> Result<i128, ErrorCartera> {
    let total_entradas: i128 = entradas.iter().map(|e| i128::from(e.valor.brek())).sum();
    let total_salidas: i128 = salidas.iter().map(|s| i128::from(s.value.brek())).sum();
    if total_entradas < total_salidas + i128::from(importe) {
        return Err(ErrorCartera::SaldoInsuficiente {
            entradas: i64::try_from(total_entradas).unwrap_or(i64::MAX),
            salidas: i64::try_from(total_salidas).unwrap_or(i64::MAX),
            importe,
        });
    }
    Ok(total_entradas - total_salidas - i128::from(importe))
}

/// Firma todas las entradas de una transacción v1/v2 en el orden de `entradas`.
fn firmar_entradas(tx: &Tx, entradas: &[Entrada]) -> Result<Vec<Vec<u8>>, ErrorCartera> {
    let gastadas: Vec<SpentOutput> = entradas.iter().map(Entrada::gastada).collect();
    let mut testigos = Vec::with_capacity(entradas.len());
    for (i, e) in entradas.iter().enumerate() {
        let digest = sighash(tx, &gastadas, HashType::All, i, CBID_RED_DEV)?;
        let firma: [u8; 64] = e.firmante.sk.sign(digest.as_bytes()).into();
        testigos.push(firma.to_vec());
    }
    Ok(testigos)
}

/// Traduce las entradas a `TxIn` (sequence 0, como exige la cartera dev).
fn entradas_a_txin(entradas: &[Entrada]) -> Vec<TxIn> {
    entradas
        .iter()
        .map(|e| TxIn {
            outpoint: e.outpoint,
            sequence: 0,
        })
        .collect()
}

/// Construye y firma una **transferencia v1** (`SIGHASH_ALL` por entrada).
///
/// La tarifa es implícita: `Σ entradas − Σ salidas`. La cartera no impone un mínimo (eso es política
/// de mempool, TX-R-11); solo exige que el saldo no sea negativo.
///
/// # Errores
/// [`ErrorCartera::SinEntradas`], [`ErrorCartera::SinSalidas`], [`ErrorCartera::SaldoInsuficiente`],
/// o las de codificación del sighash.
pub fn transferencia_v1(
    entradas: &[Entrada],
    salidas: Vec<TxOut>,
) -> Result<TxFirmada, ErrorCartera> {
    if entradas.is_empty() {
        return Err(ErrorCartera::SinEntradas);
    }
    if salidas.is_empty() {
        return Err(ErrorCartera::SinSalidas);
    }
    comprobar_saldo(entradas, &salidas, 0)?;
    let tx = Tx {
        version: 1,
        inputs: entradas_a_txin(entradas),
        outputs: salidas,
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Ninguna,
    };
    let testigos = firmar_entradas(&tx, entradas)?;
    Ok(TxFirmada { tx, testigos })
}

/// Construye y firma un **depósito v2** (F-07/F-08, `TipoGarantia::Deposito`).
///
/// Testigos: una firma de entrada por cada entrada y, al final, la firma de **aceptación** de la
/// clave destino (la que recibe la garantía). La tarifa es `Σ entradas − Σ salidas − importe ≥ 0`
/// (DEP-FEE, DR-02).
///
/// # Errores
/// [`ErrorCartera::SinEntradas`], [`ErrorCartera::ImporteInvalido`],
/// [`ErrorCartera::SaldoInsuficiente`], o las de codificación.
pub fn deposito_v2(
    entradas: &[Entrada],
    salidas: Vec<TxOut>,
    destino: &ClaveCartera,
    importe: Amount,
    nonce: u64,
) -> Result<TxFirmada, ErrorCartera> {
    if entradas.is_empty() {
        return Err(ErrorCartera::SinEntradas);
    }
    if importe.brek() == 0 {
        return Err(ErrorCartera::ImporteInvalido);
    }
    comprobar_saldo(entradas, &salidas, importe.brek())?;
    let tx = Tx {
        version: 2,
        inputs: entradas_a_txin(entradas),
        outputs: salidas,
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Garantia {
            tipo: TipoGarantia::Deposito,
            clave: destino.pk,
            importe,
            nonce,
        },
    };
    let mut testigos = firmar_entradas(&tx, entradas)?;
    let aceptacion: [u8; 64] = destino
        .sk
        .sign(&mensaje_aceptacion(&tx, CBID_RED_DEV))
        .into();
    testigos.push(aceptacion.to_vec());
    Ok(TxFirmada { tx, testigos })
}

/// Construye y firma una operación de garantía **sin entradas ni salidas** (retiro o liberación).
fn operacion_garantia(
    clave: &ClaveCartera,
    tipo: TipoGarantia,
    importe: Amount,
    nonce: u64,
) -> Result<TxFirmada, ErrorCartera> {
    if importe.brek() == 0 {
        return Err(ErrorCartera::ImporteInvalido);
    }
    let tx = Tx {
        version: 2,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Garantia {
            tipo,
            clave: clave.pk,
            importe,
            nonce,
        },
    };
    let aceptacion: [u8; 64] = clave.sk.sign(&mensaje_aceptacion(&tx, CBID_RED_DEV)).into();
    Ok(TxFirmada {
        tx,
        testigos: vec![aceptacion.to_vec()],
    })
}

/// Construye y firma un **retiro de garantía v2** (`TipoGarantia::Retiro`).
///
/// # Errores
/// [`ErrorCartera::ImporteInvalido`] o las de codificación.
pub fn retiro_v2(
    clave: &ClaveCartera,
    importe: Amount,
    nonce: u64,
) -> Result<TxFirmada, ErrorCartera> {
    operacion_garantia(clave, TipoGarantia::Retiro, importe, nonce)
}

/// Construye y firma una **liberación de garantía v2** (`TipoGarantia::Liberacion`).
///
/// # Errores
/// [`ErrorCartera::ImporteInvalido`] o las de codificación.
pub fn liberacion_v2(
    clave: &ClaveCartera,
    importe: Amount,
    nonce: u64,
) -> Result<TxFirmada, ErrorCartera> {
    operacion_garantia(clave, TipoGarantia::Liberacion, importe, nonce)
}

/// Firma **arbitraria** de un testigo ya construido, para los negativos de V3: firma el digest de la
/// entrada `k` pero no valida nada. Devuelve los bytes de una firma válida criptográficamente para
/// ese digest con la clave dada.
///
/// No es una puerta trasera: solo firma lo que [`sighash`] produce; lo que hace el llamante con ella
/// (corromperla, por ejemplo) es cosa suya.
///
/// # Errores
/// Las de codificación del sighash.
pub fn firma_de_entrada(tx: &Tx, entradas: &[Entrada], k: usize) -> Result<Vec<u8>, ErrorCartera> {
    let gastadas: Vec<SpentOutput> = entradas.iter().map(Entrada::gastada).collect();
    let digest = sighash(tx, &gastadas, HashType::All, k, CBID_RED_DEV)?;
    let Some(e) = entradas.get(k) else {
        return Err(ErrorCartera::FirmaNoVerifica { indice: k });
    };
    let firma: [u8; 64] = e.firmante.sk.sign(digest.as_bytes()).into();
    Ok(firma.to_vec())
}

/// Firma una `tx` v1/v2 con una lista de entradas, para usos de test que necesiten recomponer los
/// testigos. Es la misma operación que hace internamente [`transferencia_v1`].
///
/// # Errores
/// Las de [`sighash`].
pub fn firmar(tx: &Tx, entradas: &[Entrada]) -> Result<Vec<Vec<u8>>, ErrorCartera> {
    firmar_entradas(tx, entradas)
}

/// Envuelve una firma cruda de 64 bytes en el tipo de `zx-core` (para los tests de verificación).
///
/// # Errores
/// [`ErrorCartera::FirmaNoVerifica`] si `bytes` no mide 64.
pub fn firma_desde_bytes(bytes: &[u8]) -> Result<Firma, ErrorCartera> {
    let b: [u8; 64] = bytes
        .try_into()
        .map_err(|_| ErrorCartera::FirmaNoVerifica { indice: 0 })?;
    Ok(Firma::desde_bytes(b))
}

/// Firma con la clave dada sobre bytes arbitrarios (Ed25519 + ZIP-215), para los negativos.
#[must_use]
pub fn firmar_crudo(clave: &ClaveCartera, mensaje: &[u8]) -> [u8; 64] {
    let firma: FirmaZebra = clave.sk.sign(mensaje);
    firma.into()
}
