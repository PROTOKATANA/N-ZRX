//! Claves BLS12-381 en la variante minimal-pubkey-size: la clave pública vive en G1 (48 B
//! comprimidos) y el escalar secreto en 32 B big-endian.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use blst::min_pk::{PublicKey, SecretKey};

use crate::error::{ErrorBLS, motivo_blst};

/// Longitud de una clave pública comprimida (punto de G1).
pub const LONGITUD_CLAVE_PUBLICA: usize = 48;

/// Longitud de una clave secreta serializada (escalar big-endian).
pub const LONGITUD_CLAVE_SECRETA: usize = 32;

/// Tope de la memoria de claves ya validadas (entradas).
///
/// **No es un parámetro de seguridad ni de vivacidad:** solo decide cuánto se acelera. Al llenarse,
/// la memoria se vacía entera y se sigue; ningún resultado depende de este valor.
pub const MEMORIA_CLAVES_MAX: usize = 131_072;

/// Memoria por proceso de claves ya validadas: 48 bytes de entrada → clave validada.
///
/// Solo guarda los **aciertos**; un error se vuelve a validar cada vez. Las lecturas usan un cerrojo
/// compartido (no se bloquean entre sí); un cerrojo envenenado se ignora y se valida sin memoria.
static CLAVES_VALIDADAS: LazyLock<RwLock<HashMap<[u8; LONGITUD_CLAVE_PUBLICA], ClavePublica>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Clave secreta BLS.
///
/// Se envuelve el `SecretKey` de `blst`, que se borra de memoria al caer (`Zeroize`). El `Debug`
/// es propio y **no** imprime el escalar.
pub struct ClaveSecreta(SecretKey);

impl core::fmt::Debug for ClaveSecreta {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ClaveSecreta(<oculta>)")
    }
}

impl ClaveSecreta {
    /// `KeyGen` del borrador (draft-irtf-cfrg-bls-signature) desde material de clave.
    ///
    /// # Errores
    /// [`ErrorBLS::SemillaCorta`] si `ikm` mide menos de 32 bytes.
    pub fn generar(ikm: &[u8]) -> Result<Self, ErrorBLS> {
        if ikm.len() < 32 {
            return Err(ErrorBLS::SemillaCorta(ikm.len()));
        }
        let secreta =
            SecretKey::key_gen(ikm, &[]).map_err(|_| ErrorBLS::SemillaCorta(ikm.len()))?;
        Ok(Self(secreta))
    }

    /// Deserializa un escalar big-endian de 32 bytes.
    ///
    /// # Errores
    /// [`ErrorBLS::ClaveSecretaInvalida`] si la longitud no es 32, si es cero o si supera el orden
    /// del grupo.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, ErrorBLS> {
        if bytes.len() != LONGITUD_CLAVE_SECRETA {
            return Err(ErrorBLS::ClaveSecretaInvalida {
                motivo: "longitud distinta de 32",
            });
        }
        let secreta = SecretKey::from_bytes(bytes).map_err(|e| ErrorBLS::ClaveSecretaInvalida {
            motivo: motivo_blst(e),
        })?;
        Ok(Self(secreta))
    }

    /// El escalar en big-endian de 32 bytes.
    #[must_use]
    pub fn bytes(&self) -> [u8; LONGITUD_CLAVE_SECRETA] {
        self.0.to_bytes()
    }

    /// Deriva la clave pública (`SkToPk`).
    #[must_use]
    pub fn clave_publica(&self) -> ClavePublica {
        ClavePublica(self.0.sk_to_pk())
    }

    /// Vista interna para la capa `crudo`. No sale de este crate.
    pub(crate) fn interna(&self) -> &SecretKey {
        &self.0
    }
}

/// Clave pública BLS: punto de G1 comprimido (48 B).
///
/// **Siempre** se construye con comprobación de subgrupo y rechazo del infinito (decisión 3).
#[derive(Clone, Copy, Debug)]
pub struct ClavePublica(PublicKey);

impl PartialEq for ClavePublica {
    fn eq(&self, otra: &Self) -> bool {
        self.0.to_bytes() == otra.0.to_bytes()
    }
}

impl Eq for ClavePublica {}

impl ClavePublica {
    /// Deserializa 48 bytes comprimidos y **valida** el punto: en la curva, no infinito y en el
    /// subgrupo de orden primo.
    ///
    /// # Errores
    /// [`ErrorBLS::ClaveInvalida`] si la longitud no es 48 o el punto no es válido.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, ErrorBLS> {
        if bytes.len() != LONGITUD_CLAVE_PUBLICA {
            return Err(ErrorBLS::ClaveInvalida {
                motivo: "longitud distinta de 48",
            });
        }
        let publica = PublicKey::key_validate(bytes).map_err(|e| ErrorBLS::ClaveInvalida {
            motivo: motivo_blst(e),
        })?;
        Ok(Self(publica))
    }

    /// Como [`ClavePublica::desde_bytes`], pero recuerda las claves que ya validó.
    ///
    /// Devuelve **exactamente** el mismo resultado que `desde_bytes` para toda entrada: el mismo
    /// `Ok` (mismos `bytes()`) o el mismo `Err` con el mismo motivo. Solo se recuerdan los aciertos;
    /// un error no se guarda y su entrada se vuelve a validar cada vez. La memoria es por proceso.
    ///
    /// Es segura entre hilos y las lecturas no se bloquean entre sí. Si el cerrojo queda envenenado,
    /// se valida sin memoria: esta función **nunca** entra en `panic`.
    ///
    /// # Errores
    /// [`ErrorBLS::ClaveInvalida`] con el mismo motivo que [`ClavePublica::desde_bytes`].
    pub fn desde_bytes_con_memoria(bytes: &[u8]) -> Result<Self, ErrorBLS> {
        Self::desde_bytes_con_memoria_tope(bytes, MEMORIA_CLAVES_MAX)
    }

    /// [`ClavePublica::desde_bytes_con_memoria`] con el tope como argumento.
    ///
    /// Función **interna**: existe para poder probar el tope sin 131 072 claves. No es pública fuera
    /// de este crate.
    pub(crate) fn desde_bytes_con_memoria_tope(
        bytes: &[u8],
        tope: usize,
    ) -> Result<Self, ErrorBLS> {
        if bytes.len() != LONGITUD_CLAVE_PUBLICA {
            return Self::desde_bytes(bytes);
        }
        let mut entrada = [0u8; LONGITUD_CLAVE_PUBLICA];
        entrada.copy_from_slice(bytes);

        let acierto = match CLAVES_VALIDADAS.read() {
            Ok(memoria) => memoria.get(&entrada).copied(),
            Err(_) => None,
        };
        if let Some(validada) = acierto {
            return Ok(validada);
        }

        let validada = Self::desde_bytes(bytes)?;
        if let Ok(mut memoria) = CLAVES_VALIDADAS.write() {
            if memoria.len() >= tope {
                memoria.clear();
            }
            memoria.insert(entrada, validada);
        }
        Ok(validada)
    }

    /// Los 48 bytes comprimidos.
    #[must_use]
    pub fn bytes(&self) -> [u8; LONGITUD_CLAVE_PUBLICA] {
        self.0.to_bytes()
    }

    /// Vista interna para la capa `crudo`. No sale de este crate.
    pub(crate) fn interna(&self) -> &PublicKey {
        &self.0
    }
}

#[cfg(test)]
mod pruebas_memoria {
    use super::{CLAVES_VALIDADAS, ClavePublica, ClaveSecreta, ErrorBLS};

    /// Con tope 8 y 20 claves distintas, los resultados siguen siendo los de `desde_bytes` y la
    /// memoria nunca guarda más de 8 entradas (al llenarse se vacía entera).
    ///
    /// Vive aquí, y no en `tests/`, porque necesita la función interna con el tope y esta no es
    /// pública fuera del crate.
    #[test]
    fn memoria_respeta_el_tope() -> Result<(), ErrorBLS> {
        if let Ok(mut memoria) = CLAVES_VALIDADAS.write() {
            memoria.clear();
        }
        for i in 0..20u32 {
            let mut ikm = [0u8; 32];
            ikm[..4].copy_from_slice(&i.to_le_bytes());
            ikm[31] = 0x5A;
            let secreta = ClaveSecreta::generar(&ikm)?;
            let bytes = secreta.clave_publica().bytes();

            let con_memoria = ClavePublica::desde_bytes_con_memoria_tope(&bytes, 8)?;
            let directa = ClavePublica::desde_bytes(&bytes)?;
            assert_eq!(con_memoria, directa, "la clave {i} difiere de desde_bytes");
            assert_eq!(con_memoria.bytes(), directa.bytes());

            if let Ok(memoria) = CLAVES_VALIDADAS.read() {
                assert!(
                    memoria.len() <= 8,
                    "la memoria tiene {} entradas con tope 8",
                    memoria.len()
                );
            }
        }
        Ok(())
    }
}

/// Tabla inmutable de puntos G1 ya validados, en el orden de sus bytes de entrada.
///
/// No prueba posesión, origen ni elegibilidad de las claves. Es una vista local reconstruible:
/// el llamante conserva la correspondencia con la tabla autenticada que está verificando.
/// No hay constructor desde puntos sin validar ni acceso mutable a su almacenamiento.
///
/// ```compile_fail
/// use zx_bls::ClavesPreparadas;
/// let sin_validar = ClavesPreparadas { claves: Box::new([]) };
/// ```
#[derive(Clone, Debug)]
pub struct ClavesPreparadas {
    claves: Box<[ClavePublica]>,
}

impl ClavesPreparadas {
    /// Descomprime y valida **cada** clave una vez, sin la memoria global de claves.
    ///
    /// Acepta una tabla vacía. Conserva orden y duplicados; no impone reglas de consenso.
    ///
    /// # Errores
    /// El mismo [`ErrorBLS::ClaveInvalida`] que [`ClavePublica::desde_bytes`] para la primera
    /// entrada inválida (longitud, curva, subgrupo o infinito). No devuelve una tabla parcial.
    pub fn desde_bytes<I, B>(bytes: I) -> Result<Self, ErrorBLS>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let claves = bytes
            .into_iter()
            .map(|bytes| ClavePublica::desde_bytes(bytes.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            claves: claves.into_boxed_slice(),
        })
    }

    /// Vista inmutable de las claves, sin descompresión ni revalidación.
    #[must_use]
    pub fn claves(&self) -> &[ClavePublica] {
        &self.claves
    }

    /// Número de entradas de la tabla.
    #[must_use]
    pub fn len(&self) -> usize {
        self.claves.len()
    }

    /// Si la tabla no contiene ninguna clave.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.claves.is_empty()
    }

    /// Bytes del almacenamiento de puntos, sin el descriptor ni metadatos del asignador.
    #[must_use]
    pub fn bytes_puntos(&self) -> usize {
        core::mem::size_of_val(self.claves())
    }
}

#[cfg(test)]
mod pruebas_peso1_subgrupo {
    use super::{ClavePublica, ClaveSecreta, ClavesPreparadas};
    use crate::{ErrorBLS, agregar_firmas, fast_aggregate_verify, firmar};
    use blst::min_pk::{AggregatePublicKey, PublicKey};

    /// Dos puntos fuera de subgrupo cuya torsión se cancela en la suma. Saltarse la validación
    /// individual permite aceptar la firma válida de sus componentes de orden primo.
    #[test]
    fn peso1_control_rojo_torsion_cancelada() -> Result<(), Box<dyn std::error::Error>> {
        let torsion = hex::decode(
            "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )?;
        let q = PublicKey::from_bytes(&torsion).map_err(|e| format!("punto: {e:?}"))?;
        let a = ClaveSecreta::generar(&[0x61; 32])?;
        let b = ClaveSecreta::generar(&[0x62; 32])?;
        let pa = a.clave_publica();
        let pb = b.clave_publica();
        let mas = AggregatePublicKey::aggregate(&[pa.interna(), &q], false)
            .map_err(|e| format!("suma: {e:?}"))?
            .to_public_key();
        let mut menos = AggregatePublicKey::from_public_key(pb.interna());
        menos.sub_aggregate(&AggregatePublicKey::from_public_key(&q));
        let menos = menos.to_public_key();
        let bytes = [mas.to_bytes(), menos.to_bytes()];
        for pk in &bytes {
            assert!(
                matches!(ClavePublica::desde_bytes(pk), Err(ErrorBLS::ClaveInvalida { motivo })
                if motivo.contains("subgrupo"))
            );
        }
        assert!(ClavesPreparadas::desde_bytes(bytes).is_err());
        let dominio = b"ZX-FINALIDAD-VOTO";
        // La única construcción que salta el contrato vive dentro de este test privado.
        let sin_validar = ClavesPreparadas {
            claves: vec![ClavePublica(mas), ClavePublica(menos)].into_boxed_slice(),
        };
        let m = [0x45; 32];
        let fa = firmar(&a, dominio, &m)?;
        let fb = firmar(&b, dominio, &m)?;
        let firma = agregar_firmas(&[&fa, &fb])?;
        let refs = sin_validar.claves().iter().collect::<Vec<_>>();
        fast_aggregate_verify(&refs, &firma, dominio, &m)?;
        // Fixtures públicas para el diferencial de zx-votos; nunca imprime escalares.
        eprintln!(
            "PESO1 torsion_mas={}",
            hex::encode(bytes.first().ok_or("pk")?)
        );
        eprintln!(
            "PESO1 torsion_menos={}",
            hex::encode(bytes.get(1).ok_or("pk")?)
        );
        Ok(())
    }
}
