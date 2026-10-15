//! El **firmante local**: la política de «persistir antes de firmar» (`C-EVP-06`, FIR-01…FIR-15).
//!
//! # Frontera: política local, no consenso
//!
//! Este módulo es **política local del productor**. Ningún verificador DAG puede invocarlo ni
//! rechazar un bloque remoto porque falte registro: la abstención, el registro y el envenenamiento
//! son decisiones del productor honesto, no condiciones de validez. Un bloque remoto con o sin
//! entrada local en el registro se valida con las reglas de consenso, no con esto. La huella de
//! identidad es un marcador local que no entra en el wire ni altera `C-HASH-05` (FIR-15).
//!
//! # La regla, y por qué el orden de las operaciones es el contrato
//!
//! Antes de emitir el sello de un bloque `B`:
//!
//! 1. Calcular su `pre_hash` (`C-HDR-03`).
//! 2. Derivar **internamente** la identidad de oportunidad vigente de `RAT-1`
//!    `(consensus_branch_id, public_key, sector_index, history_size, chunk, slot)` a partir de la
//!    cabecera, nunca declarada por el llamante.
//! 3. Consultar el registro persistente por `(identidad, slot)`.
//! 4. Sin entrada: escribirla y sincronizarla, y **solo entonces** firmar
//!    ([`Resultado::Sellado`]).
//! 5. Con la misma entrada y el mismo `pre_hash`: reemitir ([`Resultado::Reemitido`]).
//! 6. Con la misma entrada y otro `pre_hash`: **no firmar** y descartar el candidato
//!    ([`Resultado::AbstenidoPorConflicto`]).
//!
//! El error por defecto —apuntar el bloque **después** de publicarlo— está cerrado:
//! [`Firmante::firmar`] no tiene ninguna ruta que escriba el sello antes de que el registro
//! devuelva `Ok`.
//!
//! # Qué comprueba antes de reservar
//!
//! [`Firmante::firmar`] exige que la clave del firmador corresponda a `header.sol.public_key`
//! **antes** de tocar el registro (FIR-04). Una clave que no corresponde devuelve
//! [`FirmanteError::ClaveNoCoincide`] sin mutar `header.sello` ni ocupar la oportunidad. Después de
//! firmar, comprueba el sello resultante con
//! [`zx_core::preimage::dag::DagBlockHeader::verificar_sello`] (`C-HDR-04`, FIR-05); si no
//! verificara, el sello de entrada queda intacto.
//!
//! # Qué no expone
//!
//! No hay ninguna variante pública que permita al llamante declarar una identidad no vinculada a la
//! cabecera: la identidad se deriva dentro de [`Firmante::firmar`]. Tampoco se acepta el
//! `s_max_slots` del candidato: entra como parámetro explícito del perfil en [`Registro::abrir`],
//! que es quien lo usa para fijar el horizonte de abstención (FIR-10).
//!
//! # Lo que este tipo no es
//!
//! Es un **filtro de accidentes honestos**, no un mecanismo de seguridad (FIR-13). No cubre dos
//! máquinas con registros distintos, ni a un atacante que borre el registro, ni un `sync_all` que
//! mienta. No cubre clave robada o compartida, ni un registro en red.

pub mod identidad;
pub mod registro;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_zebra::{SigningKey, VerificationKey};
use zx_core::PreHash;
use zx_core::preimage::dag::DagBlockHeader;

use registro::Resolucion;

pub use identidad::{DOMINIO_TICKET_RAT1, IdentidadTicket, LONGITUD_HUELLA, VERSION_ESQUEMA};
pub use registro::{
    MAGIA, OFFSET_ABSTENCION_ACTIVA, OFFSET_ABSTENER_HASTA, OFFSET_COMPROBACION_CABECERA,
    OFFSET_SLOT_PERDIDA, Registro, RegistroError, TAMANO_CABECERA, TAMANO_ENTRADA, VERSION_FORMATO,
};

/// Qué hizo el firmante con un candidato.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Resultado {
    /// No había entrada: se persistió y **después** se selló. Es el camino normal.
    Sellado,
    /// Ya había entrada con el mismo `pre_hash`: es el mismo bloque y se ha vuelto a sellar.
    Reemitido,
    /// El candidato se descartó y **no** se selló. El candidato no llegó a firmarse, así que no
    /// puede producir la evidencia de equivocación.
    AbstenidoPorConflicto {
        /// El `pre_hash` que ya estaba en el registro, con la misma identidad y el mismo slot.
        pre_hash_registrado: PreHash,
    },
    /// El registro perdió el estado y aún está en su ventana de abstención (FIR-10). Es un
    /// **resultado**, distinguible de un error de E/S: no se sella, pero el registro funciona.
    AbstenidoPorPerdida {
        /// Último slot en el que todavía se abstiene.
        hasta: u64,
        /// `s_max_slots` del perfil con el que se abrió el registro.
        s_max_slots: u64,
    },
}

/// Fallos del firmante. Todos significan que **no se emitió sello**.
#[derive(Debug, thiserror::Error)]
pub enum FirmanteError {
    /// El registro falló (E/S, bloqueo, corrupción o envenenamiento). Si dudas, no firmes: es la
    /// decisión segura y es la que toma este tipo. La abstención por pérdida **no** cae aquí: es
    /// [`Resultado::AbstenidoPorPerdida`].
    #[error("firmante: {0}")]
    Registro(#[from] RegistroError),

    /// La clave del firmador no corresponde a `header.sol.public_key`.
    ///
    /// La comprobación ocurre **antes** de reservar la oportunidad y **antes** de tocar el sello:
    /// una clave ajena no ocupa el registro ni muta la cabecera (FIR-04).
    #[error("firmante: la clave del firmador no corresponde a header.sol.public_key")]
    ClaveNoCoincide,

    /// El sello se construyó pero no verifica con las reglas del repositorio (`C-HDR-04`, FIR-05).
    ///
    /// Es un fallo interno: `header.sello` queda intacto y no se publica nada.
    #[error("firmante: el sello construido no verifica bajo header.sol.public_key")]
    SelloInvalido,
}

/// El firmante: un registro compartido.
///
/// Lleva el registro por referencia, así que **varios hilos** pueden llamar a [`Firmante::firmar`]
/// a la vez: la exclusión la impone el `Mutex` del registro. Dos **procesos** sobre el mismo
/// fichero quedan excluidos por el bloqueo de fichero del registro.
///
/// No guarda ninguna copia de `s_max_slots`: el perfil vive en [`Registro::abrir`], que es quien
/// gobierna la abstención. Duplicarlo aquí crearía un valor que no decide nada.
#[derive(Debug)]
pub struct Firmante<'a> {
    registro: &'a Registro,
    /// Inyección solo de test: fuerza que el sello construido no verifique para poder cubrir
    /// [`FirmanteError::SelloInvalido`]. En producción no existe el campo.
    #[cfg(test)]
    forzar_sello_invalido: AtomicBool,
}

impl<'a> Firmante<'a> {
    /// Construye el firmante sobre un registro ya abierto con su perfil.
    #[must_use]
    pub const fn nuevo(registro: &'a Registro) -> Self {
        Self {
            registro,
            #[cfg(test)]
            forzar_sello_invalido: AtomicBool::new(false),
        }
    }

    /// La identidad de oportunidad de `RAT-1` de un candidato.
    ///
    /// Es una consulta de **solo lectura**, para diagnóstico y tests. No firma y no permite pasar
    /// una identidad distinta a [`Firmante::firmar`].
    #[must_use]
    pub fn identidad(header: &DagBlockHeader) -> IdentidadTicket {
        IdentidadTicket::rat1(
            header.consensus_branch_id,
            header.sol.public_key,
            header.sol.sector_index,
            header.sol.history_size,
            header.sol.chunk,
            header.slot,
        )
    }

    /// Inyección solo de test para cubrir [`FirmanteError::SelloInvalido`].
    #[cfg(test)]
    pub(crate) fn forzar_sello_invalido(&self) {
        self.forzar_sello_invalido.store(true, Ordering::Relaxed);
    }

    /// Aplica la regla a un candidato y, **solo si procede**, escribe el sello Ed25519 en
    /// `header.sello`.
    ///
    /// El sello es `Ed25519(sk, pre_hash(B))`: el mensaje es el `pre_hash` (`C-HDR-03`), no la
    /// prefirma ni el `block_hash`.
    ///
    /// `header.sello` se escribe **únicamente** en el camino de éxito. Si hay conflicto o
    /// abstención por pérdida, si el registro falla o si la clave no corresponde, el sello de
    /// entrada queda intacto y no se publica nada; quien llama debe descartar el candidato cuando
    /// el resultado sea [`Resultado::AbstenidoPorConflicto`] o
    /// [`Resultado::AbstenidoPorPerdida`].
    ///
    /// # Errores
    /// [`FirmanteError::ClaveNoCoincide`] si la clave no corresponde a `header.sol.public_key`;
    /// [`FirmanteError::Registro`] si el registro falla de verdad (E/S, envenenamiento, corrupción);
    /// [`FirmanteError::SelloInvalido`] si el sello construido no verifica.
    pub fn firmar(
        &self,
        header: &mut DagBlockHeader,
        sk: &SigningKey,
    ) -> Result<Resultado, FirmanteError> {
        // 1. La clave tiene que ser la de la cabecera ANTES de reservar la oportunidad.
        let clave_del_firmador: [u8; 32] = VerificationKey::from(sk).into();
        if &clave_del_firmador != header.sol.public_key.bytes() {
            return Err(FirmanteError::ClaveNoCoincide);
        }

        // 2. `pre_hash` canónico (C-HDR-03) e identidad de RAT-1, derivada aquí dentro.
        let pre_hash = header.pre_hash();
        let identidad = Self::identidad(header);

        // 3. El registro decide y, si la entrada es nueva, ya la dejó persistida y sincronizada.
        let resultado = match self.registro.resolver(&identidad, pre_hash) {
            Ok(Resolucion::Nueva) => Resultado::Sellado,
            Ok(Resolucion::Conocida) => Resultado::Reemitido,
            Ok(Resolucion::Conflicto {
                pre_hash_registrado,
            }) => {
                return Ok(Resultado::AbstenidoPorConflicto {
                    pre_hash_registrado,
                });
            }
            // FIR-10: la abstención por pérdida es un resultado, no un error de E/S.
            Err(RegistroError::EnAbstinencia {
                hasta, s_max_slots, ..
            }) => {
                return Ok(Resultado::AbstenidoPorPerdida { hasta, s_max_slots });
            }
            Err(fallo) => return Err(FirmanteError::Registro(fallo)),
        };

        // 4. Solo ahora se firma. Se comprueba sobre una copia para no dejar un sello inválido en
        //    la cabecera de entrada si la verificación fallara.
        let firma: [u8; 64] = sk.sign(pre_hash.as_bytes()).into();
        let mut comprobacion = *header;
        comprobacion.sello = firma;
        #[cfg(test)]
        if self.forzar_sello_invalido.load(Ordering::Relaxed)
            && let Some(byte) = comprobacion.sello.first_mut()
        {
            *byte ^= 0x01;
        }
        comprobacion
            .verificar_sello()
            .map_err(|_| FirmanteError::SelloInvalido)?;
        header.sello = firma;
        Ok(resultado)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::{Firmante, FirmanteError, Registro, RegistroError, Resultado};
    use ed25519_zebra::{SigningKey, VerificationKey};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use zx_core::preimage::dag::{DagBlockHeader, PadresDag, SolucionPoas};
    use zx_core::{BlockHash, BodyCommitment, ClavePublica, Digest, MerkleRoot};

    static CONTADOR: AtomicU64 = AtomicU64::new(0);

    struct DirTemporal {
        ruta: PathBuf,
    }

    impl DirTemporal {
        fn nuevo(etiqueta: &str) -> Self {
            let pid = std::process::id();
            let n = CONTADOR.fetch_add(1, Ordering::Relaxed);
            let unico = format!("zx-firmante-mod-{pid}-{n}-{etiqueta}");
            let ruta = std::env::temp_dir().join(unico);
            std::fs::create_dir_all(&ruta).unwrap();
            Self { ruta }
        }

        fn ruta(&self) -> &Path {
            &self.ruta
        }
    }

    impl Drop for DirTemporal {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.ruta);
        }
    }

    fn sk() -> SigningKey {
        SigningKey::from([42u8; 32])
    }

    fn clave_publica() -> ClavePublica {
        ClavePublica::desde_bytes(VerificationKey::from(&sk()).into())
    }

    fn cabecera(padre: u8, chunk: u8, slot: u64) -> DagBlockHeader {
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x22; 32])),
            timestamp: 1_700_000_000,
            height: 10,
            slot,
            pot_output: [0x11; 16],
            rango_solucion: 7,
            sol: SolucionPoas {
                public_key: clave_publica(),
                sector_index: 1,
                history_size: 1 << 20,
                chunk: [chunk; 32],
                ..SolucionPoas::default()
            },
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([0x33; 32])),
            padres: PadresDag::nuevo(BlockHash::from_digest(Digest::from_bytes([padre; 32])), &[])
                .unwrap(),
            sello: [0u8; 64],
        }
    }

    /// Registro sin abstención efectiva para el camino normal de test: `abrir` sobre fichero nuevo
    /// se abstiene hasta el slot 1, y los slots de prueba van muy por encima.
    fn registro_sin_abstencion(ruta: &Path) -> Registro {
        Registro::abrir(ruta, 0, 1).unwrap()
    }

    #[test]
    fn caso_5_con_entrada_previa_y_otro_pre_hash_no_firma() {
        let dir = DirTemporal::nuevo("caso5");
        let mut a = cabecera(1, 5, 100);
        let reg = registro_sin_abstencion(&dir.ruta().join("r.log"));
        let f = Firmante::nuevo(&reg);

        assert_eq!(f.firmar(&mut a, &sk()).unwrap(), Resultado::Sellado);
        let sello_a = a.sello;
        assert_ne!(sello_a, [0u8; 64]);

        let mut b = cabecera(2, 5, 100);
        assert_ne!(a.pre_hash(), b.pre_hash());
        let r = f.firmar(&mut b, &sk()).unwrap();
        assert!(matches!(r, Resultado::AbstenidoPorConflicto { .. }));
        assert_eq!(
            b.sello, [0u8; 64],
            "el candidato descartado NO puede llevar sello"
        );
    }

    #[test]
    fn caso_4_reemitir_el_mismo_bloque_funciona() {
        let dir = DirTemporal::nuevo("caso4");
        let mut a = cabecera(1, 5, 100);
        let reg = registro_sin_abstencion(&dir.ruta().join("r.log"));
        let f = Firmante::nuevo(&reg);
        assert_eq!(f.firmar(&mut a, &sk()).unwrap(), Resultado::Sellado);
        let sello = a.sello;

        let mut otra_vez = cabecera(1, 5, 100);
        assert_eq!(
            f.firmar(&mut otra_vez, &sk()).unwrap(),
            Resultado::Reemitido
        );
        assert_eq!(otra_vez.sello, sello, "el sello es determinista y válido");
        otra_vez.verificar_sello().unwrap();
    }

    #[test]
    fn la_clave_ajena_no_ocupa_la_oportunidad_ni_muta_el_sello() {
        let dir = DirTemporal::nuevo("clave");
        let mut a = cabecera(1, 5, 100);
        let reg = registro_sin_abstencion(&dir.ruta().join("r.log"));
        let f = Firmante::nuevo(&reg);
        let ajena = SigningKey::from([7u8; 32]);

        assert!(matches!(
            f.firmar(&mut a, &ajena).unwrap_err(),
            FirmanteError::ClaveNoCoincide
        ));
        assert_eq!(a.sello, [0u8; 64]);
        assert_eq!(
            reg.entradas(),
            0,
            "la clave ajena no puede reservar la oportunidad"
        );

        // Con la clave correcta, la oportunidad sigue libre.
        assert_eq!(f.firmar(&mut a, &sk()).unwrap(), Resultado::Sellado);
    }

    #[test]
    fn el_sello_verifica_bajo_la_clave_publica() {
        let dir = DirTemporal::nuevo("sello");
        let mut a = cabecera(1, 5, 100);
        let reg = registro_sin_abstencion(&dir.ruta().join("r.log"));
        let f = Firmante::nuevo(&reg);
        assert_eq!(f.firmar(&mut a, &sk()).unwrap(), Resultado::Sellado);
        a.verificar_sello().unwrap();
    }

    #[test]
    fn el_sello_invalido_no_muta_la_cabecera() {
        // Inyección solo de test (DF-5): con la clave correcta, el único modo de que la
        // comprobación de FIR-05 falle es forzarla. La cabecera de entrada queda intacta.
        let dir = DirTemporal::nuevo("sello-invalido");
        let mut a = cabecera(1, 5, 100);
        let reg = registro_sin_abstencion(&dir.ruta().join("r.log"));
        let f = Firmante::nuevo(&reg);
        f.forzar_sello_invalido();
        let e = f.firmar(&mut a, &sk()).unwrap_err();
        assert!(matches!(e, FirmanteError::SelloInvalido), "{e:?}");
        assert_eq!(a.sello, [0u8; 64]);
    }

    #[test]
    fn la_abstencion_usa_el_perfil_de_registro_abrir() {
        // El firmante no guarda `s_max_slots`: el horizonte de abstención sale del perfil que se
        // pasó a `Registro::abrir`. Y la abstención por pérdida es un **resultado**, no un error.
        let dir = DirTemporal::nuevo("perfil-abstencion");
        let ruta = dir.ruta().join("r.log");
        let slot_perdida = 500u64;
        let s_max = 40u64;

        let reg = Registro::abrir(&ruta, slot_perdida, s_max).unwrap();
        assert_eq!(reg.abstener_hasta(), Some(slot_perdida + s_max));
        let f = Firmante::nuevo(&reg);

        let mut bloqueado = cabecera(1, 5, slot_perdida + s_max);
        let r = f.firmar(&mut bloqueado, &sk()).unwrap();
        assert!(
            matches!(
                r,
                Resultado::AbstenidoPorPerdida {
                    hasta,
                    s_max_slots,
                } if hasta == slot_perdida + s_max && s_max_slots == s_max
            ),
            "{r:?}"
        );
        assert_eq!(bloqueado.sello, [0u8; 64]);

        let mut libre = cabecera(1, 5, slot_perdida + s_max + 1);
        assert_eq!(f.firmar(&mut libre, &sk()).unwrap(), Resultado::Sellado);
        assert_ne!(libre.sello, [0u8; 64]);
    }

    #[test]
    fn el_error_de_registro_no_se_confunde_con_la_abstencion() {
        // Un registro envenenado devuelve error, no `AbstenidoPorPerdida`.
        let dir = DirTemporal::nuevo("envenenado-firmante");
        let reg = Registro::nueva(dir.ruta().join("r.log")).unwrap();
        reg.forzar_envenenamiento_para_test();
        let f = Firmante::nuevo(&reg);
        let mut a = cabecera(1, 5, 100);
        assert!(matches!(
            f.firmar(&mut a, &sk()).unwrap_err(),
            FirmanteError::Registro(RegistroError::Envenenado { .. })
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Durabilidad con proceso hijo (V2)
    // ─────────────────────────────────────────────────────────────────────────

    /// Punto de entrada del proceso hijo: persiste la oportunidad por el camino real y **aborta
    /// sin firmar**, justo en el hueco entre la persistencia y la firma.
    ///
    /// Está **guardado**: sin `FIRMANTE_TEST_RUTA` no hace nada y el test pasa. Así,
    /// `--include-ignored` no aborta el arnés.
    #[test]
    #[ignore = "punto de entrada para el proceso hijo; aborta a propósito"]
    fn hijo_persiste_y_aborta() {
        let Some(ruta) = std::env::var_os("FIRMANTE_TEST_RUTA") else {
            return;
        };
        let slot: u64 = std::env::var("FIRMANTE_TEST_SLOT")
            .unwrap()
            .parse()
            .unwrap();
        let chunk: u8 = std::env::var("FIRMANTE_TEST_CHUNK")
            .unwrap()
            .parse()
            .unwrap();

        let header = cabecera(1, chunk, slot);
        // `abrir` sobre fichero nuevo se abstiene hasta 1; el slot de prueba va muy por encima.
        let reg = Registro::abrir(ruta, 0, 1).unwrap();
        let identidad = Firmante::identidad(&header);
        let _ = reg.resolver(&identidad, header.pre_hash());
        std::process::abort();
    }

    #[test]
    fn durabilidad_el_proceso_muere_entre_la_persistencia_y_la_firma_veinte_veces() {
        use std::os::unix::process::ExitStatusExt as _;

        let dir = DirTemporal::nuevo("aborto");
        for i in 0..20u64 {
            let ruta = dir.ruta().join(format!("r-{i}.log"));
            let slot = 100 + i;

            let salida = Command::new(std::env::current_exe().unwrap())
                .arg("--ignored")
                .arg("--exact")
                .arg("firmante::tests::hijo_persiste_y_aborta")
                .arg("--test-threads=1")
                .env("FIRMANTE_TEST_RUTA", &ruta)
                .env("FIRMANTE_TEST_SLOT", slot.to_string())
                .env("FIRMANTE_TEST_CHUNK", "7")
                .output()
                .unwrap();
            assert_eq!(
                salida.status.signal(),
                Some(6),
                "iteración {i}: el hijo debe morir por SIGABRT, no salir limpiamente: {:?}\n{}",
                salida.status,
                String::from_utf8_lossy(&salida.stderr)
            );

            // La entrada persistida sobrevive al SIGABRT y el conflicto se detecta al reiniciar.
            let reg = Registro::abrir(&ruta, slot, 1).unwrap();
            let f = Firmante::nuevo(&reg);
            let mut b = cabecera(1, 7, slot);
            assert_eq!(
                f.firmar(&mut b, &sk()).unwrap(),
                Resultado::Reemitido,
                "iteración {i}"
            );
            let mut c = cabecera(2, 7, slot);
            let r = f.firmar(&mut c, &sk()).unwrap();
            assert!(
                matches!(r, Resultado::AbstenidoPorConflicto { .. }),
                "iteración {i}: el candidato contradictorio no puede sellar tras el reinicio: {r:?}"
            );
            assert_eq!(c.sello, [0u8; 64], "iteración {i}");
        }
    }
}
