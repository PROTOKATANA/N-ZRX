//! Contexto de transición **dev** PoW → PoST (D-P09, D-P10, D-P11; TRN-08).
//!
//! # Qué es
//!
//! [`ContextoTransicion`] es la instancia concreta del marcador **S1** para la red dev: ata el
//! terminal PoW `T` al arranque del PoT de la fase PoST. Implementa a la vez los tres rasgos que la
//! puerta conjunta necesita ([`InstantaneaPot`], [`ContextoDag`] y [`ContextoRangoDag`]) y es la
//! costura que W06 enchufará al nodo.
//!
//! - `f_0 = H_flujo(ETIQUETA_GENESIS ‖ block_hash(T))` ([`zx_core::preimage::flow::flujo_genesis`]).
//! - `semilla(f_0, 0) = blake3(block_hash(T) ‖ ∅)[0..16)` (entropía externa **vacía** en dev,
//!   [`crate::pot::semilla_genesis`]); esa semilla es la **salida confiada del slot 0**.
//! - Un solo flujo, **sin inyecciones**; `D = 0`.
//! - `N(s) = N_dev` constante, recibido por parámetro.
//! - `SR` esperado = `SR_dev` constante, recibido por parámetro.
//! - `es_terminal(h) ⟺ h = block_hash(T)`.
//! - El **pasado validado** lo suministra el llamante: `T` (slot 0) y los bloques PoST que el
//!   llamante declare ya validados. En los tests, `T` y los bloques PoST que el propio test valide.
//!
//! # Marcadores dev y límites
//!
//! Está **etiquetado dev** y su semilla es el marcador S1 (A-07 abierto): no es una derivación de
//! seguridad, ni un valor de mainnet/testnet. `N_dev` y `SR_dev` son parámetros de desarrollo; el
//! valor de red se calibra en W07 (D-P10, D-P11). Este contexto **no** acredita nada por sí mismo:
//! que un bloque PoST ya validado esté en él es una **precondición del llamante**, no una prueba.
//!
//! # Lo que NO hace
//!
//! No elige `sp(B)` con GHOSTDAG (devuelve el declarado si pertenece al contexto), no controla el
//! rango desde el pasado (devuelve la constante dev), no archiva historia, no verifica PoAS y no
//! admite bloques. La selección real de padres y el controlador de rango son de W06.

use std::collections::BTreeMap;

use zx_core::preimage::flow::flujo_genesis;
use zx_core::wire_dag::POT_OUTPUT_BYTES;
use zx_core::{BlockHash, PadresDag};
use zx_dag::ErrorDag;
use zx_dag::bloque_dag::{CandidatoSinRango, ContextoDag, ContextoRangoDag};

use crate::pot::{ErrorContextoPot, proyectar_iteraciones, semilla_genesis};
use crate::pot_rango::{
    BloqueDelPasado, FLUJO_BYTES, InstantaneaPot, InyeccionesPot, MotivoPotPendiente,
};

/// Etiqueta del perfil: valores de **desarrollo**, no de red.
pub const ETIQUETA_PERFIL_DEV: &str = "dev";

/// Marcador de la semilla S1 de D-P09. A-07 sigue **abierto**: no es una derivación de seguridad.
pub const MARCADOR_SEMILLA_S1: &str = "S1";

/// Registro de un bloque PoST que el llamante declara **ya validado**.
///
/// Trae lo justo para el contexto: su `hash`, su `slot`, su `pot_output` de 16 B y sus padres (para
/// la anticadena). No lleva ninguna marca de validez implícita: la validez la aporta el llamante.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistroValidado {
    /// `block_hash` del bloque.
    pub hash: BlockHash,
    /// Su `slot`.
    pub slot: u64,
    /// `salida(f, slot)` del bloque (su `pot_output`).
    pub salida: [u8; POT_OUTPUT_BYTES],
    /// Sus padres, para responder a la anticadena.
    pub padres: PadresDag,
}

impl RegistroValidado {
    /// Construye un registro validado.
    #[must_use]
    pub const fn nuevo(
        hash: BlockHash,
        slot: u64,
        salida: [u8; POT_OUTPUT_BYTES],
        padres: PadresDag,
    ) -> Self {
        Self {
            hash,
            slot,
            salida,
            padres,
        }
    }
}

/// Fallo al construir el contexto de transición dev.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ErrorContextoTransicion {
    /// `N_dev` no cae en el dominio de la primitiva PoT (cero, `> u32::MAX` o no múltiplo de 16).
    #[error("N_dev inválido: {0}")]
    NDevInvalido(ErrorContextoPot),
    /// Un registro validado repite un `block_hash` ya presente.
    #[error("registro validado duplicado: {hash}")]
    RegistroDuplicado {
        /// El hash repetido.
        hash: BlockHash,
    },
    /// Un registro validado usa el `block_hash` del terminal.
    #[error("el terminal {hash} no puede venir como registro PoST validado")]
    RegistroDelTerminal {
        /// El hash del terminal.
        hash: BlockHash,
    },
    /// **H2 de RI-1b:** dos registros validados del **mismo slot** traen `salida` distinta.
    ///
    /// El flujo es único y sin inyecciones (D-P10): `salida(f, s)` es una función determinista del
    /// flujo y del slot. Dos bloques del mismo slot **comparten** salida (hermanos); dos salidas
    /// distintas solo pueden venir de un fallo aguas arriba. Antes el segundo registro se
    /// descartaba en silencio con `or_insert`, ocultándolo.
    #[error(
        "dos registros validados del slot {slot} traen salidas distintas: {primera:?} y {otra:?}"
    )]
    SalidaDeSlotDiscrepa {
        /// Slot repetido.
        slot: u64,
        /// Salida del primer registro que ocupó el slot.
        primera: [u8; POT_OUTPUT_BYTES],
        /// Salida discrepante del registro posterior.
        otra: [u8; POT_OUTPUT_BYTES],
    },
}

/// Entrada interna indexada por `block_hash`.
#[derive(Debug, Clone, Copy)]
struct Entrada {
    slot: u64,
    padres: PadresDag,
}

/// Contexto de transición dev, inmutable tras construirse.
#[derive(Debug, Clone)]
pub struct ContextoTransicion {
    terminal: BlockHash,
    f0: [u8; FLUJO_BYTES],
    s1: [u8; POT_OUTPUT_BYTES],
    n_dev: u64,
    sr_dev: u64,
    entradas: BTreeMap<BlockHash, Entrada>,
    salidas_por_slot: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]>,
    pasado: Vec<BloqueDelPasado>,
}

impl ContextoTransicion {
    /// Construye el contexto dev para el terminal `T` y los registros PoST ya validados.
    ///
    /// Deriva `f_0` y la semilla S1 **solo** de `block_hash(T)` (entropía externa vacía, D-P09) y
    /// exige `N_dev` en el dominio de la primitiva. No deriva nada del candidato ni del orden de
    /// llegada.
    ///
    /// # Errores
    /// [`ErrorContextoTransicion::NDevInvalido`] si `N_dev` no es válido;
    /// [`ErrorContextoTransicion::RegistroDuplicado`] o
    /// [`ErrorContextoTransicion::RegistroDelTerminal`] si los registros validados son incoherentes.
    pub fn nuevo(
        terminal: BlockHash,
        n_dev: u64,
        sr_dev: u64,
        validados: Vec<RegistroValidado>,
    ) -> Result<Self, ErrorContextoTransicion> {
        proyectar_iteraciones(n_dev).map_err(ErrorContextoTransicion::NDevInvalido)?;

        let f0 = flujo_genesis(&terminal);
        let s1 = semilla_genesis(&terminal, &[]);

        let mut entradas: BTreeMap<BlockHash, Entrada> = BTreeMap::new();
        let mut salidas_por_slot: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]> = BTreeMap::new();
        // El terminal ocupa el slot 0 con la salida confiada S1 y sin padres (raíz de la vista).
        entradas.insert(
            terminal,
            Entrada {
                slot: 0,
                padres: PadresDag::genesis(),
            },
        );
        salidas_por_slot.insert(0, s1);

        for registro in validados {
            if registro.hash == terminal {
                return Err(ErrorContextoTransicion::RegistroDelTerminal { hash: terminal });
            }
            if entradas.contains_key(&registro.hash) {
                return Err(ErrorContextoTransicion::RegistroDuplicado {
                    hash: registro.hash,
                });
            }
            entradas.insert(
                registro.hash,
                Entrada {
                    slot: registro.slot,
                    padres: registro.padres,
                },
            );
            // El flujo es único y sin inyecciones: la salida de un slot es una función determinista
            // del flujo y del slot, así que dos bloques del mismo slot comparten salida. **H2 de
            // RI-1b:** si el slot ya está ocupado con otra salida, es un fallo aguas arriba y se
            // devuelve error explícito en vez de descartar el segundo registro en silencio.
            match salidas_por_slot.get(&registro.slot) {
                None => {
                    salidas_por_slot.insert(registro.slot, registro.salida);
                }
                Some(primera) if *primera == registro.salida => {}
                Some(primera) => {
                    return Err(ErrorContextoTransicion::SalidaDeSlotDiscrepa {
                        slot: registro.slot,
                        primera: *primera,
                        otra: registro.salida,
                    });
                }
            }
        }

        let mut pasado: Vec<BloqueDelPasado> = vec![BloqueDelPasado {
            hash: terminal,
            slot: 0,
            timestamp: 0,
            flujo: f0,
        }];
        pasado.extend(entradas.iter().filter(|(hash, _)| **hash != terminal).map(
            |(hash, entrada)| BloqueDelPasado {
                hash: *hash,
                slot: entrada.slot,
                timestamp: 0,
                flujo: f0,
            },
        ));

        Ok(Self {
            terminal,
            f0,
            s1,
            n_dev,
            sr_dev,
            entradas,
            salidas_por_slot,
            pasado,
        })
    }

    /// `block_hash` del terminal `T`.
    #[must_use]
    pub const fn terminal(&self) -> BlockHash {
        self.terminal
    }

    /// `f_0 = H_flujo(ETIQUETA_GENESIS ‖ block_hash(T))` (D-P09).
    #[must_use]
    pub const fn f0(&self) -> [u8; FLUJO_BYTES] {
        self.f0
    }

    /// Semilla S1: `blake3(block_hash(T) ‖ ∅)[0..16)` (D-P09), la salida confiada del slot 0.
    #[must_use]
    pub const fn s1(&self) -> [u8; POT_OUTPUT_BYTES] {
        self.s1
    }

    /// `N_dev` del perfil dev (D-P10).
    #[must_use]
    pub const fn n_dev(&self) -> u64 {
        self.n_dev
    }

    /// `SR_dev` del perfil dev (D-P11).
    #[must_use]
    pub const fn sr_dev(&self) -> u64 {
        self.sr_dev
    }

    /// ¿`h` está en el contexto como terminal o como bloque PoST declarado validado?
    #[must_use]
    fn conocido(&self, h: &BlockHash) -> bool {
        self.entradas.contains_key(h)
    }
}

impl InstantaneaPot for ContextoTransicion {
    /// `f_0` en **todo** slot: un solo flujo y sin inyecciones (D-P10).
    fn flujo_candidato_en(&self, _slot: u64) -> Result<[u8; FLUJO_BYTES], MotivoPotPendiente> {
        Ok(self.f0)
    }

    /// El pasado validado declarado por el llamante, con el terminal en el slot 0.
    fn pasado(&self) -> Result<&[BloqueDelPasado], MotivoPotPendiente> {
        Ok(&self.pasado)
    }

    /// **Ninguna** inyección en dev (D-P10).
    fn inyecciones_en(&self, _slot: u64) -> Result<InyeccionesPot, MotivoPotPendiente> {
        Ok(InyeccionesPot::Ninguna)
    }

    /// `N(s) = N_dev` constante (D-P10).
    fn iteraciones(&self, _slot: u64) -> Result<u64, MotivoPotPendiente> {
        Ok(self.n_dev)
    }

    /// `D = 0` (D-P10).
    fn retardo_autoria(&self) -> Result<u64, MotivoPotPendiente> {
        Ok(0)
    }

    /// Salida **ya validada** de ese slot: la de `T` (S1) o la de un registro PoST declarado.
    fn salida_validada(&self, slot: u64) -> Result<[u8; POT_OUTPUT_BYTES], MotivoPotPendiente> {
        self.salidas_por_slot
            .get(&slot)
            .copied()
            .ok_or(MotivoPotPendiente::ContextoAusente {
                que: "salida ancla de un slot fuera del contexto de transición",
            })
    }
}

impl ContextoDag for ContextoTransicion {
    /// Cierto para el terminal y para todo registro PoST declarado validado por el llamante.
    fn es_bloque_validado(&self, h: &BlockHash) -> bool {
        self.conocido(h)
    }

    /// Ancestría estricta calculada sobre los padres de los registros conocidos.
    ///
    /// # Errores
    /// [`ErrorDag::BloqueDesconocido`] si alguno de los dos no pertenece al contexto.
    fn esta_en_el_pasado_de(
        &self,
        antepasado: &BlockHash,
        descendiente: &BlockHash,
    ) -> Result<bool, ErrorDag> {
        if !self.conocido(antepasado) {
            return Err(ErrorDag::BloqueDesconocido { hash: *antepasado });
        }
        if !self.conocido(descendiente) {
            return Err(ErrorDag::BloqueDesconocido {
                hash: *descendiente,
            });
        }

        // BFS iterativo desde los padres de `descendiente`; ancestría estricta (no reflexiva).
        let mut pila: Vec<BlockHash> = Vec::new();
        if let Some(entrada) = self.entradas.get(descendiente)
            && !entrada.padres.es_genesis()
        {
            pila.push(entrada.padres.seleccionado());
            pila.extend_from_slice(entrada.padres.extras());
        }
        while let Some(actual) = pila.pop() {
            if actual == *antepasado {
                return Ok(true);
            }
            if let Some(entrada) = self.entradas.get(&actual)
                && !entrada.padres.es_genesis()
            {
                pila.push(entrada.padres.seleccionado());
                pila.extend_from_slice(entrada.padres.extras());
            }
        }
        Ok(false)
    }

    /// `slot` del terminal (0) o del registro PoST declarado; clave ajena es error explícito.
    fn slot_de_padre(&self, h: &BlockHash) -> Result<u64, ErrorDag> {
        self.entradas
            .get(h)
            .map(|entrada| entrada.slot)
            .ok_or(ErrorDag::PadreNoValidado { padre: *h })
    }

    /// **Dev**: devuelve el padre seleccionado declarado si pertenece al contexto.
    ///
    /// No calcula GHOSTDAG. Para el bloque de transición el único padre es `T`, comprobado antes por
    /// [`zx_dag::comprobar_padres_contextual`]; W06 sustituirá esta costura por la selección real.
    fn padre_seleccionado(&self, padres: &PadresDag) -> Result<BlockHash, ErrorDag> {
        let seleccionado = padres.seleccionado();
        if self.conocido(&seleccionado) {
            Ok(seleccionado)
        } else {
            Err(ErrorDag::PadreNoValidado {
                padre: seleccionado,
            })
        }
    }

    /// `es_terminal(h) ⟺ h = block_hash(T)` (D-P09, D-P07).
    fn es_terminal(&self, h: &BlockHash) -> bool {
        *h == self.terminal
    }
}

impl ContextoRangoDag for ContextoTransicion {
    /// `SR` esperado = `SR_dev` constante (D-P11); **no** hay controlador derivado del pasado.
    fn rango_esperado(&self, _candidato: &CandidatoSinRango<'_>) -> Result<u64, ErrorDag> {
        Ok(self.sr_dev)
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "los tests fallan por diseño")]
mod tests {
    use zx_core::digest::{BlockHash, BodyCommitment, Digest, MerkleRoot};
    use zx_core::preimage::flow::flujo_genesis;
    use zx_core::{DagBlockHeader, PadresDag, SolucionPoas};
    use zx_dag::ErrorDag;
    use zx_dag::bloque_dag::{ContextoDag, RangoSolucionValidado};

    use super::{ContextoTransicion, ErrorContextoTransicion, RegistroValidado};
    use crate::pot::{semilla_genesis, semilla_siguiente};
    use crate::pot_rango::{InstantaneaPot, InyeccionesPot, MotivoPotPendiente};

    const N: u64 = 16;
    const SR: u64 = 7;

    fn h(marca: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([marca; 32]))
    }

    fn contexto(terminal: BlockHash) -> ContextoTransicion {
        ContextoTransicion::nuevo(terminal, N, SR, Vec::new()).expect("contexto dev válido")
    }

    fn cabecera(rango: u64, padres: PadresDag) -> DagBlockHeader {
        DagBlockHeader {
            vdf_output: [0u8; 16],
            consensus_branch_id: 0xc478_80ea,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([1; 32])),
            timestamp: 1_788_480_000,
            height: 0,
            slot: 1,
            pot_output: [0u8; 16],
            rango_solucion: rango,
            sol: SolucionPoas::default(),
            body_commitment: BodyCommitment::from_digest(Digest::from_bytes([2; 32])),
            padres,
            sello: [0u8; 64],
        }
    }

    #[test]
    fn f0_y_s1_salen_del_terminal_y_no_se_uniforman() {
        let t = h(0x01);
        let ctx = contexto(t);
        assert_eq!(ctx.f0(), flujo_genesis(&t));
        assert_eq!(ctx.s1(), semilla_genesis(&t, &[]));
        assert_eq!(ctx.n_dev(), N);
        assert_eq!(ctx.sr_dev(), SR);
        assert_eq!(ctx.terminal(), t);
        // S1 es la salida confiada del slot 0: sin inyecciones, la semilla del slot 1 es S1.
        assert_eq!(semilla_siguiente(ctx.s1(), None), ctx.s1());
        // Cambiar el terminal cambia f_0 y S1.
        let otro = contexto(h(0x02));
        assert_ne!(ctx.f0(), otro.f0());
        assert_ne!(ctx.s1(), otro.s1());
    }

    #[test]
    fn n_dev_invalido_se_rechaza() {
        assert!(matches!(
            ContextoTransicion::nuevo(h(1), 0, SR, Vec::new()),
            Err(ErrorContextoTransicion::NDevInvalido(
                crate::pot::ErrorContextoPot::IteracionesCero
            ))
        ));
        assert!(matches!(
            ContextoTransicion::nuevo(h(1), 15, SR, Vec::new()),
            Err(ErrorContextoTransicion::NDevInvalido(
                crate::pot::ErrorContextoPot::IteracionesNoMultiploDe16 { valor: 15 }
            ))
        ));
    }

    #[test]
    fn registros_duplicados_o_del_terminal_se_rechazan() {
        let t = h(0x01);
        assert!(matches!(
            ContextoTransicion::nuevo(
                t,
                N,
                SR,
                vec![RegistroValidado::nuevo(
                    t,
                    1,
                    [0u8; 16],
                    PadresDag::genesis()
                )]
            ),
            Err(ErrorContextoTransicion::RegistroDelTerminal { hash }) if hash == t
        ));

        let a =
            RegistroValidado::nuevo(h(0x0A), 1, [0u8; 16], PadresDag::nuevo(t, &[]).expect("p"));
        assert!(matches!(
            ContextoTransicion::nuevo(t, N, SR, vec![a, a]),
            Err(ErrorContextoTransicion::RegistroDuplicado { hash }) if hash == h(0x0A)
        ));
    }

    /// **H2 de RI-1b.** Dos registros validados del mismo slot con salidas distintas ya no se
    /// ocultan con `or_insert`: son un error explícito.
    #[test]
    fn salidas_distintas_del_mismo_slot_se_rechazan() {
        let t = h(0x01);
        let padres = PadresDag::nuevo(t, &[]).expect("p");
        let a = RegistroValidado::nuevo(h(0x0A), 1, [0xAA; 16], padres);
        let b = RegistroValidado::nuevo(h(0x0B), 1, [0xBB; 16], padres);
        assert!(matches!(
            ContextoTransicion::nuevo(t, N, SR, vec![a, b]),
            Err(ErrorContextoTransicion::SalidaDeSlotDiscrepa { slot: 1, primera, otra })
                if primera == [0xAA; 16] && otra == [0xBB; 16]
        ));

        // La discrepancia también alcanza al ancla del terminal (slot 0 con salida ≠ S1).
        let s1 = crate::pot::semilla_genesis(&t, &[]);
        assert_ne!(s1, [0xCC; 16]);
        let intruso = RegistroValidado::nuevo(h(0x0C), 0, [0xCC; 16], padres);
        assert!(matches!(
            ContextoTransicion::nuevo(t, N, SR, vec![intruso]),
            Err(ErrorContextoTransicion::SalidaDeSlotDiscrepa { slot: 0, .. })
        ));

        // Dos hermanos del mismo slot con la **misma** salida siguen siendo válidos.
        let hermano = RegistroValidado::nuevo(h(0x0D), 1, [0xAA; 16], padres);
        let ctx = ContextoTransicion::nuevo(t, N, SR, vec![a, hermano]).expect("hermanos");
        assert_eq!(
            ctx.salida_validada(1).expect("salida del slot 1"),
            [0xAA; 16]
        );
    }

    #[test]
    fn instantanea_pot_del_terminal() {
        let t = h(0x01);
        let ctx = contexto(t);
        let pasado = ctx.pasado().expect("pasado presente");
        assert_eq!(pasado.len(), 1);
        let unico = pasado.first().expect("el terminal está en el pasado");
        assert_eq!(unico.hash, t);
        assert_eq!(unico.slot, 0);
        assert_eq!(unico.flujo, ctx.f0());

        assert_eq!(ctx.flujo_candidato_en(0).expect("flujo"), ctx.f0());
        assert_eq!(ctx.flujo_candidato_en(99).expect("flujo"), ctx.f0());
        assert_eq!(ctx.iteraciones(0).expect("N"), N);
        assert_eq!(ctx.iteraciones(99).expect("N"), N);
        assert_eq!(ctx.retardo_autoria().expect("D"), 0);
        assert_eq!(
            ctx.inyecciones_en(5).expect("sin inyecciones"),
            InyeccionesPot::Ninguna
        );
        assert_eq!(ctx.salida_validada(0).expect("S1"), ctx.s1());
        assert_eq!(
            ctx.salida_validada(5),
            Err(MotivoPotPendiente::ContextoAusente {
                que: "salida ancla de un slot fuera del contexto de transición"
            })
        );
    }

    #[test]
    fn contexto_dag_reconoce_terminal_y_cadena() {
        let t = h(0x01);
        let a = h(0x0A);
        let b = h(0x0B);
        let ctx = ContextoTransicion::nuevo(
            t,
            N,
            SR,
            vec![
                RegistroValidado::nuevo(a, 1, [0xAA; 16], PadresDag::nuevo(t, &[]).expect("p")),
                RegistroValidado::nuevo(b, 2, [0xBB; 16], PadresDag::nuevo(a, &[]).expect("p")),
            ],
        )
        .expect("contexto");

        assert!(ctx.es_terminal(&t));
        assert!(!ctx.es_terminal(&a));
        assert!(ctx.es_bloque_validado(&a));
        assert!(ctx.es_bloque_validado(&b));
        assert!(!ctx.es_bloque_validado(&h(0xEE)));

        assert_eq!(ctx.slot_de_padre(&t).expect("slot"), 0);
        assert_eq!(ctx.slot_de_padre(&a).expect("slot"), 1);
        assert_eq!(
            ctx.slot_de_padre(&h(0xEE)),
            Err(ErrorDag::PadreNoValidado { padre: h(0xEE) })
        );
        assert_eq!(
            ctx.padre_seleccionado(&PadresDag::nuevo(t, &[]).expect("p")),
            Ok(t)
        );
        assert_eq!(
            ctx.padre_seleccionado(&PadresDag::nuevo(h(0xEE), &[]).expect("p")),
            Err(ErrorDag::PadreNoValidado { padre: h(0xEE) })
        );

        assert!(ctx.esta_en_el_pasado_de(&t, &b).expect("ancestría"));
        assert!(ctx.esta_en_el_pasado_de(&a, &b).expect("ancestría"));
        assert!(!ctx.esta_en_el_pasado_de(&b, &a).expect("ancestría"));
        assert!(
            !ctx.esta_en_el_pasado_de(&a, &a)
                .expect("ancestría estricta")
        );
        assert_eq!(
            ctx.esta_en_el_pasado_de(&h(0xEE), &b),
            Err(ErrorDag::BloqueDesconocido { hash: h(0xEE) })
        );
        assert_eq!(ctx.salida_validada(1).expect("salida A"), [0xAA; 16]);
    }

    #[test]
    fn rango_esperado_es_la_constante_dev() {
        let t = h(0x01);
        let ctx = contexto(t);
        let c = cabecera(SR, PadresDag::nuevo(t, &[]).expect("p"));
        let validado = RangoSolucionValidado::validar(&c, &ctx).expect("el contexto coincide");
        assert_eq!(validado.valor(), SR);
        assert_eq!(validado.bloque(), Some(c.block_hash()));

        let malo = cabecera(SR + 1, PadresDag::nuevo(t, &[]).expect("p"));
        assert_eq!(
            RangoSolucionValidado::validar(&malo, &ctx),
            Err(ErrorDag::RangoIncorrecto {
                esperado: SR,
                encontrado: SR + 1
            })
        );
    }
}
