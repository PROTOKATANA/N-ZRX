//! Servicio PoT **local** de la red dev: flujo único, slot a slot, con ventana acotada
//! (D-P09, D-P10; `C-FLU-06`, `C-POT-01`, `C-POT-02`, `C-POT-04`, `C-POT-05`).
//!
//! # Qué es
//!
//! [`ServicioPot`] conserva el estado PoT de **una** historia dev y avanza un slot por llamada:
//!
//! - arranca de la semilla S1 del terminal `T` (`semilla(f_0, 0) = blake3(block_hash(T) ‖ ∅)[0..16)`,
//!   D-P09) como salida del slot 0;
//! - avanza con `N(s)` del **calendario del reloj** por ticks: con [`ServicioPot::nuevo`] el reloj
//!   queda en `T = 1` (equivalente al `N_dev` constante de D-P10, compatible con el nodo actual) y
//!   con [`ServicioPot::nuevo_con_reloj`] arranca en el `(T0, n_iter)` del contrato
//!   (`N(s) = T(s)·n_iter`, `C-RLJ-02`); [`ServicioPot::ajustar_reloj`] aplica un paso de
//!   `C-RLJ-05/03/07` con la medida de ventana **como entrada** (RL-2b la cablea a los timestamps);
//! - calcula `zx_pot::prove(semilla_siguiente(salida_anterior, None), N(s))` con ese `N(s)`;
//! - guarda la salida y el portador de una **ventana acotada y configurable** de slots, con error
//!   explícito fuera de ella;
//! - implementa [`InstantaneaPot`] para que la puerta conjunta verifique **cabeceras ajenas** con
//!   las salidas ya calculadas.
//!
//! Es **lógica pura, sin hilos propios**: no arranca ningún hilo ni temporizador; el nodo (W06) es
//! quien lo avanzará desde su bucle.
//!
//! # El pasado validado no se inventa
//!
//! `InstantaneaPot::pasado()` necesita `(hash, slot, flujo)` de los bloques padre, que **no** se
//! deducen del estado PoT. Por eso el servicio expone [`ServicioPot::registrar_validado`]: el
//! llamante declara los bloques que ya validó y el servicio solo conserva los que caen en la
//! ventana. La validez la aporta el llamante, **no** este objeto; el terminal entra como ancla
//! (slot 0) en la construcción.
//!
//! # Qué NO acredita
//!
//! No admite bloques, no verifica sellos ni PoAS, no elige padres ni rango, no archiva historia y
//! no elige `N_dev` ni `SR_dev` (los fija la red dev; D-P10/D-P11). Su semilla es el marcador S1
//! (A-07 abierto): no es una derivación de seguridad.
//!
//! # Memoria
//!
//! La ventana retiene a lo sumo `ventana` slots de salidas (16 B) y portadores (128 B), más el
//! ancla del terminal (constante extra). Los registros de pasado se podan con el mismo límite. El
//! coste por avance es un `prove` de `N_dev` iteraciones.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use zx_core::BlockHash;
use zx_core::preimage::flow::flujo_genesis;
use zx_core::wire_dag::{MAX_BUNDLES_POT, POT_OUTPUT_BYTES, PotCheckpoints};
use zx_pot::tipos::PotSeed;

use crate::pot::{
    ErrorContextoPot, checkpoints_a_wire, proyectar_iteraciones, semilla_genesis, semilla_siguiente,
};
use crate::pot_rango::{
    BloqueDelPasado, FLUJO_BYTES, InstantaneaPot, InyeccionesPot, MotivoPotPendiente,
};
use crate::reloj::{Ajuste, ErrorReloj, EstadoReloj, Racional, ajustar};

/// Fallo del servicio PoT local.
#[derive(Debug, thiserror::Error)]
pub enum ErrorServicioPot {
    /// La ventana configurada mide cero slots.
    #[error("ventana de {configurada} slots: debe ser >= 1")]
    VentanaInvalida {
        /// Valor configurado.
        configurada: u64,
    },
    /// `N_dev` fuera del dominio de la primitiva PoT.
    #[error("N_dev inválido: {0}")]
    NDevInvalido(#[from] ErrorContextoPot),
    /// El slot pedido no está retenido en la ventana.
    #[error("el slot {slot} no está en la ventana retenida [{desde}, {hasta}]")]
    FueraDeVentana {
        /// Slot pedido.
        slot: u64,
        /// Primer slot retenido.
        desde: u64,
        /// Último slot calculado.
        hasta: u64,
    },
    /// No hay portador retenido para un slot que cae dentro de la ventana (nunca el ancla 0).
    #[error("no hay portador retenido para el slot {slot}")]
    PortadorAusente {
        /// Slot sin portador.
        slot: u64,
    },
    /// El slot ya tenía un portador PoT **distinto** registrado (violaría D-P10: el flujo es único,
    /// así que dos datos verificados del mismo slot deben coincidir siempre).
    #[error("el slot {slot} ya tenía un portador PoT distinto registrado (D-P10)")]
    PortadorDiscrepante {
        /// Slot en conflicto.
        slot: u64,
    },
    /// No se pudieron recompletar los portadores de un rango porque la salida conocida más cercana
    /// está demasiado atrás: recompletar exigiría más de `MAX_BUNDLES_POT` pruebas. No es una
    /// violación de invariante: el llamante **omite** la producción de ese slot (`ORDEN-W06d9`).
    #[error(
        "no se pueden recompletar los portadores de ({sp_slot}, {b_slot}]: la salida conocida más \
         cercana es el slot {base_slot} (distancia {d} > MAX_BUNDLES_POT={max})"
    )]
    RecompletarExcedeMaximo {
        /// Slot inicial del rango.
        sp_slot: u64,
        /// Slot final del rango.
        b_slot: u64,
        /// Slot de la salida conocida desde la que habría que recalcular.
        base_slot: u64,
        /// Pruebas que exigiría el recálculo.
        d: u64,
        /// Cota `MAX_BUNDLES_POT`.
        max: u64,
    },
    /// Se pidió un slot por delante del último calculado.
    #[error("el servicio está en el slot {slot_actual}; se pidió el {slot}")]
    SlotFuturo {
        /// Slot pedido.
        slot: u64,
        /// Último slot calculado.
        slot_actual: u64,
    },
    /// Se pidió retroceder el servicio.
    #[error("el servicio ya avanzó hasta el slot {actual}; se pidió {pedido}")]
    ObjetivoAnterior {
        /// Slot pedido.
        pedido: u64,
        /// Último slot calculado.
        actual: u64,
    },
    /// Aritmética de slots desbordada.
    #[error("aritmética de slots desbordada")]
    AritmeticaDeSlotsDesbordada,
    /// El rango `(sp_slot, b_slot]` es vacío o invertido.
    #[error("rango de slots inválido: sp={sp_slot}, B={b_slot}")]
    RangoInvalido {
        /// Slot del padre seleccionado.
        sp_slot: u64,
        /// Slot del bloque.
        b_slot: u64,
    },
    /// El rango supera la cota de portadores del formato.
    #[error("el rango {d} excede MAX_BUNDLES_POT={max}")]
    RangoExcedeMaximo {
        /// Diferencia pedida.
        d: u64,
        /// Cota del formato.
        max: u64,
    },
    /// Se registró dos veces el mismo `block_hash`.
    #[error("bloque ya registrado en el pasado del servicio: {hash}")]
    BloqueDuplicado {
        /// Hash repetido.
        hash: BlockHash,
    },
    /// La primitiva PoT rechazó el slot.
    #[error("la primitiva PoT rechazó el slot {slot}: {error}")]
    Pot {
        /// Slot que falló.
        slot: u64,
        /// Error de la primitiva.
        #[source]
        error: zx_pot::PotError,
    },
    /// `declarar_salida_pasada` encontró, para el mismo slot, una salida ya registrada distinta
    /// (violaría D-P10: el flujo es único, así que dos declaraciones del mismo slot deben coincidir
    /// siempre; no debería ocurrir con datos de cabeceras ya verificadas).
    #[error("el slot {slot} ya tenía una salida PoT distinta registrada (D-P10)")]
    SalidaPasadaDiscrepante {
        /// Slot en conflicto.
        slot: u64,
    },
    /// El estado del reloj por ticks no cumple el dominio (`n_iter` cero o no múltiplo de 16).
    #[error("reloj por ticks inválido: {0}")]
    Reloj(#[from] ErrorReloj),
}

/// Servicio PoT local de una historia dev, con ventana acotada de slots.
///
/// Se construye con [`ServicioPot::nuevo`] (terminal, `N_dev` y ventana) y se avanza con
/// [`ServicioPot::avanzar`] o [`ServicioPot::avanzar_hasta`]. Es inmutable salvo por esas dos
/// operaciones y [`ServicioPot::registrar_validado`].
#[derive(Debug, Clone)]
pub struct ServicioPot {
    terminal: BlockHash,
    f0: [u8; FLUJO_BYTES],
    s1: [u8; POT_OUTPUT_BYTES],
    n_dev: u64,
    /// Reloj por ticks vigente (`C-RLJ-02`). Con [`ServicioPot::nuevo`] queda en `T = 1`.
    reloj: EstadoReloj,
    /// Calendario `N(s)`: `(slot_desde, N)` en orden creciente. La primera entrada es el slot 0.
    calendario_n: Vec<(u64, u64)>,
    /// Última frontera de epoch cuyo `T` ya se recalculó (`C-RLJ-06`); 0 = ninguna.
    ultima_frontera_ajustada: u64,
    ventana: u64,
    slot_actual: u64,
    salidas: BTreeMap<u64, [u8; POT_OUTPUT_BYTES]>,
    portadores: BTreeMap<u64, PotCheckpoints>,
    pasado: Vec<BloqueDelPasado>,
    /// Resúmenes causales autenticados por el llamante, compartidos entre clones del mismo terminal.
    timestamps_causales: Arc<Mutex<BTreeMap<(usize, BlockHash), ResumenTimestamp>>>,
}

/// El mínimo causal y los M máximos por (slot, hash), sin duplicar fusiones.
#[derive(Debug, Clone)]
struct ResumenTimestamp {
    slot: u64,
    primero: (u64, BlockHash, u64),
    ultimos: Vec<(u64, BlockHash, u64)>,
}

impl ServicioPot {
    /// Arranca el servicio en el terminal `T` (slot 0 = S1) con `N_dev` y una ventana de slots.
    ///
    /// Deriva `f_0` y S1 **solo** de `block_hash(T)` (entropía externa vacía, D-P09) y exige
    /// `N_dev` en el dominio de la primitiva. La ventana debe ser `>= 1`.
    ///
    /// # Errores
    /// [`ErrorServicioPot::NDevInvalido`] si `N_dev` no es válido;
    /// [`ErrorServicioPot::VentanaInvalida`] si `ventana == 0`.
    pub fn nuevo(terminal: BlockHash, n_dev: u64, ventana: u64) -> Result<Self, ErrorServicioPot> {
        proyectar_iteraciones(n_dev)?;
        if ventana == 0 {
            return Err(ErrorServicioPot::VentanaInvalida { configurada: 0 });
        }
        let f0 = flujo_genesis(&terminal);
        let s1 = semilla_genesis(&terminal, &[]);
        let pasado = vec![BloqueDelPasado {
            hash: terminal,
            slot: 0,
            timestamp: 0,
            flujo: f0,
        }];
        Ok(Self {
            terminal,
            f0,
            s1,
            n_dev,
            reloj: EstadoReloj::nuevo(1, n_dev, u64::MAX),
            calendario_n: vec![(0, n_dev)],
            ultima_frontera_ajustada: 0,
            ventana,
            slot_actual: 0,
            salidas: BTreeMap::new(),
            portadores: BTreeMap::new(),
            pasado,
            timestamps_causales: Arc::default(),
        })
    }

    /// Arranca el servicio con el **reloj por ticks** del contrato (`C-RLJ-02`): `N(s) = T·n_iter`.
    ///
    /// A diferencia de [`Self::nuevo`] —que queda en `T = 1` para no cambiar el perfil dev
    /// constante—, aquí se fija `(T0, n_iter)` y se puede bajar `T` o duplicar `n_iter` con
    /// [`Self::ajustar_reloj`]. Exige el dominio de RL1-A10 (`n_iter % 16 == 0`) y que
    /// `T0·n_iter` quepa en la primitiva.
    ///
    /// # Errores
    /// [`ErrorServicioPot::Reloj`] si `n_iter` no cumple RL1-A10;
    /// [`ErrorServicioPot::NDevInvalido`] si `T0·n_iter` está fuera del dominio;
    /// [`ErrorServicioPot::VentanaInvalida`] si `ventana == 0`.
    pub fn nuevo_con_reloj(
        terminal: BlockHash,
        reloj: EstadoReloj,
        ventana: u64,
    ) -> Result<Self, ErrorServicioPot> {
        reloj.valida()?;
        let n_dev = reloj.iteraciones();
        proyectar_iteraciones(n_dev)?;
        if ventana == 0 {
            return Err(ErrorServicioPot::VentanaInvalida { configurada: 0 });
        }
        let f0 = flujo_genesis(&terminal);
        let s1 = semilla_genesis(&terminal, &[]);
        let pasado = vec![BloqueDelPasado {
            hash: terminal,
            slot: 0,
            timestamp: 0,
            flujo: f0,
        }];
        Ok(Self {
            terminal,
            f0,
            s1,
            n_dev,
            reloj,
            calendario_n: vec![(0, n_dev)],
            ultima_frontera_ajustada: 0,
            ventana,
            slot_actual: 0,
            salidas: BTreeMap::new(),
            portadores: BTreeMap::new(),
            pasado,
            timestamps_causales: Arc::default(),
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

    /// S1: `blake3(block_hash(T) ‖ ∅)[0..16)`, la salida confiada del slot 0 (D-P09).
    #[must_use]
    pub const fn s1(&self) -> [u8; POT_OUTPUT_BYTES] {
        self.s1
    }

    /// `N_dev` del perfil dev (D-P10): el `N(s)` **inicial** del servicio.
    #[must_use]
    pub const fn n_dev(&self) -> u64 {
        self.n_dev
    }

    /// Reloj por ticks vigente (`C-RLJ-02`): `(T, n_iter, N_max)`.
    #[must_use]
    pub const fn reloj(&self) -> EstadoReloj {
        self.reloj
    }

    /// Calendario `N(s)` aplicado: pares `(slot_desde, N)` en orden creciente.
    ///
    /// La primera entrada es el slot 0; cada [`Self::ajustar_reloj`] añade una entrada para los
    /// slots siguientes.
    #[must_use]
    pub fn calendario(&self) -> &[(u64, u64)] {
        &self.calendario_n
    }

    /// `N(s)` vigente en `slot` según el calendario del reloj.
    #[must_use]
    pub fn n_vigente(&self, slot: u64) -> u64 {
        let mut vigente = self.n_dev;
        for (desde, n) in &self.calendario_n {
            if *desde <= slot {
                vigente = *n;
            } else {
                break;
            }
        }
        vigente
    }

    /// `N(s)` de `slot` proyectado al dominio de la primitiva (`C-POT-04`).
    fn proyectar_n(&self, slot: u64) -> Result<NonZeroU32, ErrorContextoPot> {
        proyectar_iteraciones(self.n_vigente(slot))
    }

    /// Aplica un paso de ajuste de `T` (`C-RLJ-05`), con la medida de la ventana **como entrada**.
    ///
    /// `tau_est` es la medida (por ejemplo, la de `C-RLJ-04`); `tau_ref` el objetivo y `u` la banda
    /// muerta. El estado nuevo rige a partir del **slot siguiente** (`slot_actual + 1`), de modo que
    /// los slots ya calculados conservan su `N(s)` en el calendario y el flujo PoT no se reescribe.
    /// Aplica también `C-RLJ-03` (duplicación) y `C-RLJ-07` (techo).
    ///
    /// # Errores
    /// [`ErrorServicioPot::NDevInvalido`] si el `N(s)` resultante no cae en el dominio de la
    /// primitiva.
    pub fn ajustar_reloj(
        &mut self,
        tau_est: Racional,
        tau_ref: Racional,
        u: Racional,
    ) -> Result<Ajuste, ErrorServicioPot> {
        let resultado = ajustar(self.reloj, tau_est, tau_ref, u);
        let n_nuevo = resultado.estado.iteraciones();
        proyectar_iteraciones(n_nuevo)?;
        self.reloj = resultado.estado;
        let desde = self.slot_actual.saturating_add(1);
        self.calendario_n.push((desde, n_nuevo));
        Ok(resultado)
    }

    /// Frontera de epoch `f` (múltiplo de `a_epoch`) ya alcanzada por `slot_actual()` y todavía sin
    /// ajustar (`C-RLJ-06`). El nodo la usa para recalcular `T` una sola vez por epoch.
    #[must_use]
    pub fn frontera_pendiente(&self, a_epoch: u64) -> Option<u64> {
        if a_epoch == 0 {
            return None;
        }
        let f = self.slot_actual.div_euclid(a_epoch) * a_epoch;
        (f > 0 && f > self.ultima_frontera_ajustada).then_some(f)
    }

    /// Aplica un estado de reloj ya decidido (`C-RLJ-05`) de forma **determinista**: la medida se
    /// tomó en la frontera `frontera` y el `T` nuevo rige desde `frontera + a_epoch` (`C-RLJ-06`,
    /// «`T` cambia sólo en los slots `s_e + A`»), nunca desde `slot_actual() + 1`. Marca la frontera
    /// como ajustada para no repetirla.
    ///
    /// # Errores
    /// [`ErrorServicioPot::NDevInvalido`] si `T·n_iter` no cae en el dominio de la primitiva.
    pub fn fijar_reloj(
        &mut self,
        frontera: u64,
        a_epoch: u64,
        estado: EstadoReloj,
    ) -> Result<(), ErrorServicioPot> {
        let n_nuevo = estado.iteraciones();
        proyectar_iteraciones(n_nuevo)?;
        self.reloj = estado;
        let desde = frontera.saturating_add(a_epoch.max(1));
        let ultimo_desde = self.calendario_n.last().map(|(d, _)| *d).unwrap_or(0);
        if desde > ultimo_desde {
            self.calendario_n.push((desde, n_nuevo));
        }
        self.ultima_frontera_ajustada = self.ultima_frontera_ajustada.max(frontera);
        Ok(())
    }

    /// `RL-2c` · fija el calendario entero de `T` calculado de forma determinista desde la cadena
    /// seleccionada (`reloj_post::calendario_desde_cadena`), con el estado final del reloj.
    ///
    /// A diferencia de [`Self::fijar_reloj`] —que añade una entrada por frontera—, aquí se
    /// **reemplaza** el calendario completo. Es idempotente y solo es correcto porque el calendario
    /// es función de `past(B)`: recalcularlo tras añadir un bloque no cambia el `N(s)` de ningún
    /// slot `≤ slot(B)` (la frontera que un bloque nuevo puede tocar rige desde `f + A > slot(B)`).
    ///
    /// # Errores
    /// [`ErrorServicioPot::NDevInvalido`] si algún `N` no cae en el dominio de la primitiva.
    pub fn fijar_calendario(
        &mut self,
        calendario: Vec<(u64, u64)>,
        estado: EstadoReloj,
    ) -> Result<(), ErrorServicioPot> {
        if calendario.is_empty() {
            return Ok(());
        }
        for (_, n) in &calendario {
            proyectar_iteraciones(*n)?;
        }
        proyectar_iteraciones(estado.iteraciones())?;
        self.reloj = estado;
        self.calendario_n = calendario;
        Ok(())
    }

    /// Ventana de slots retenida.
    #[must_use]
    pub const fn ventana(&self) -> u64 {
        self.ventana
    }

    /// Último slot calculado (0 si solo está S1).
    #[must_use]
    pub const fn slot_actual(&self) -> u64 {
        self.slot_actual
    }

    /// Primer slot retenido en la ventana.
    #[must_use]
    pub fn primer_slot_retenido(&self) -> u64 {
        self.slot_actual
            .saturating_sub(self.ventana.saturating_sub(1))
    }

    /// `salida(f, slot)` ya calculada. El slot 0 es S1 (ancla del terminal).
    ///
    /// # Errores
    /// [`ErrorServicioPot::FueraDeVentana`] si el slot no está retenido.
    pub fn salida_de(&self, slot: u64) -> Result<[u8; POT_OUTPUT_BYTES], ErrorServicioPot> {
        if slot == 0 {
            return Ok(self.s1);
        }
        self.salidas
            .get(&slot)
            .copied()
            .ok_or(ErrorServicioPot::FueraDeVentana {
                slot,
                desde: self.primer_slot_retenido(),
                hasta: self.slot_actual,
            })
    }

    /// Portador PoT de 128 B del slot, si está retenido. El slot 0 no tiene portador (es S1).
    ///
    /// # Errores
    /// [`ErrorServicioPot::PortadorAusente`] si el slot no tiene portador retenido.
    pub fn portador_de(&self, slot: u64) -> Result<&PotCheckpoints, ErrorServicioPot> {
        self.portadores
            .get(&slot)
            .ok_or(ErrorServicioPot::PortadorAusente { slot })
    }

    /// Avanza **un** slot: calcula la salida y el portador siguientes con `N_dev`.
    ///
    /// # Errores
    /// [`ErrorServicioPot::AritmeticaDeSlotsDesbordada`] si `slot_actual + 1` no cabe;
    /// [`ErrorServicioPot::Pot`] si la primitiva rechaza la terna (no debería con `N_dev` válido).
    pub fn avanzar(&mut self) -> Result<u64, ErrorServicioPot> {
        let slot = self
            .slot_actual
            .checked_add(1)
            .ok_or(ErrorServicioPot::AritmeticaDeSlotsDesbordada)?;
        let anterior = self.salida_de(self.slot_actual)?;
        // Un solo flujo y sin inyecciones: D-P10. La semilla del slot es la salida anterior.
        let semilla = semilla_siguiente(anterior, None);
        let carrier = zx_pot::prove(PotSeed::from(semilla), self.proyectar_n(slot)?)
            .map_err(|error| ErrorServicioPot::Pot { slot, error })?;
        self.salidas.insert(slot, *carrier.output());
        self.portadores.insert(slot, checkpoints_a_wire(&carrier));
        self.slot_actual = slot;
        self.podar();
        Ok(slot)
    }

    /// Avanza hasta `slot` (inclusive). Si ya se pasó, es error explícito.
    ///
    /// # Errores
    /// [`ErrorServicioPot::ObjetivoAnterior`] si `slot < slot_actual`; las de [`Self::avanzar`].
    pub fn avanzar_hasta(&mut self, slot: u64) -> Result<u64, ErrorServicioPot> {
        if slot < self.slot_actual {
            return Err(ErrorServicioPot::ObjetivoAnterior {
                pedido: slot,
                actual: self.slot_actual,
            });
        }
        while self.slot_actual < slot {
            self.avanzar()?;
        }
        Ok(self.slot_actual)
    }

    /// Inserta la salida y el portador de `slot` **ya calculados por el llamante**, sin volver a
    /// correr `zx_pot::prove` (`ORDEN-W06d1`, decisión 7: reconstruir el servicio al reiniciar
    /// «desde las salidas PoT de las cabeceras almacenadas… no recalculando el flujo desde T»,
    /// porque recalcularlo costaría el tiempo real transcurrido).
    ///
    /// A diferencia de [`Self::avanzar`], **no** exige `slot == slot_actual() + 1`: solo que
    /// `slot > slot_actual()`. El flujo es único y global (D-P10): dos bloques de ramas o slots
    /// distintos comparten exactamente la misma `salida(f, slot)`, así que un llamante que reconstruye
    /// varias ramas (o repite el registro de admisión) solo necesita **avanzar**, nunca rellenar un
    /// hueco por el que ya pasó otra rama; los huecos intermedios sin bloque tampoco hace falta
    /// llenarlos, porque nunca son `sp` de nadie (`sp` es siempre el slot de un bloque admitido). No
    /// verifica que `salida`/`portador` sean los que `prove` habría producido: es responsabilidad del
    /// llamante que vengan de una cabecera **ya admitida** (su `pot_output`) y de su justificación,
    /// no de una fuente no verificada.
    ///
    /// # Errores
    /// [`ErrorServicioPot::ObjetivoAnterior`] si `slot <= slot_actual()`.
    pub fn insertar_calculado(
        &mut self,
        slot: u64,
        salida: [u8; POT_OUTPUT_BYTES],
        portador: PotCheckpoints,
    ) -> Result<(), ErrorServicioPot> {
        if slot <= self.slot_actual {
            return Err(ErrorServicioPot::ObjetivoAnterior {
                pedido: slot,
                actual: self.slot_actual,
            });
        }
        self.salidas.insert(slot, salida);
        self.portadores.insert(slot, portador);
        self.slot_actual = slot;
        self.podar();
        Ok(())
    }

    /// Declara la salida y el portador PoT, **ya verificados**, de un slot que quedó **detrás** de
    /// `slot_actual()` (`ORDEN-W06d4` decisión 3, `REVISION-W06d3.md`: causa de
    /// `Pot(PasadoIncompleto)` en un bloque propio de un nodo que se incorpora tarde al régimen).
    ///
    /// `insertar_calculado` permite (a propósito, D-P10) saltar directamente a un slot posterior
    /// sin calcular los intermedios: si ese salto lo hizo un bloque de **otra rama** (el flujo PoT
    /// es único y compartido por todas las ramas, `ORDEN-W06d1`), un slot anterior que otra rama sí
    /// usó de verdad queda como hueco — sin salida ni portador — aunque su bloque sea perfectamente
    /// válido y ya esté admitido en `Cadena`. `salida_de`/`insertar_calculado` no tienen forma de
    /// reconciliar ese slot (el primero exige que ya exista; el segundo exige `slot >
    /// slot_actual()`), así que antes de este método el llamante (`Nodo::actualizar_servicio_
    /// verificacion`) no tenía más opción que rechazar el bloque — quedaba admitido en `Cadena`
    /// pero nunca entraba en `pasado()`, y cualquier hijo que lo declarara padre fallaba después con
    /// `PasadoIncompleto`.
    ///
    /// Rellenar el hueco es siempre seguro: D-P10 garantiza que la salida de un slot es la misma
    /// para cualquier rama, así que un dato ya verificado (viene de `pot_output` de una cabecera
    /// admitida, no de una suposición) nunca puede legítimamente discrepar de uno que ya estuviera
    /// registrado; si discrepa, es una violación real de D-P10, no un hueco, y se rechaza.
    ///
    /// # Errores
    /// [`ErrorServicioPot::SalidaPasadaDiscrepante`] si el slot ya tenía una salida registrada
    /// **distinta**.
    pub fn declarar_salida_pasada(
        &mut self,
        slot: u64,
        salida: [u8; POT_OUTPUT_BYTES],
        portador: PotCheckpoints,
    ) -> Result<(), ErrorServicioPot> {
        if slot == 0 {
            if salida != self.s1 {
                return Err(ErrorServicioPot::SalidaPasadaDiscrepante { slot });
            }
            return Ok(());
        }
        if slot > self.slot_actual {
            // No es un hueco detrás de `slot_actual()`: es exactamente el caso de
            // `insertar_calculado` (aún no llegamos a ese slot por ninguna rama).
            return self.insertar_calculado(slot, salida, portador);
        }
        match self.salidas.get(&slot) {
            Some(existente) if *existente != salida => {
                Err(ErrorServicioPot::SalidaPasadaDiscrepante { slot })
            }
            _ => {
                self.salidas.insert(slot, salida);
                self.portadores.insert(slot, portador);
                self.podar();
                Ok(())
            }
        }
    }

    /// Registra un bloque **ya validado por el llamante** `(hash, slot)` en el pasado del servicio.
    ///
    /// No aporta ninguna prueba: es la declaración explícita que `InstantaneaPot::pasado()` no puede
    /// deducir del estado PoT. El terminal ya está registrado y no se puede repetir.
    ///
    /// # Errores
    /// [`ErrorServicioPot::SlotFuturo`] si el slot va por delante del servicio;
    /// [`ErrorServicioPot::BloqueDuplicado`] si el hash ya está registrado.
    pub fn registrar_validado(
        &mut self,
        hash: BlockHash,
        slot: u64,
    ) -> Result<(), ErrorServicioPot> {
        self.registrar_validado_con_timestamp(hash, slot, 0)
    }

    /// Como [`Self::registrar_validado`], declarando además el `timestamp` de la cabecera (para la
    /// PMT de `C-RLJ-TS-01` y el ajuste del reloj).
    ///
    /// # Errores
    /// Las mismas de [`Self::registrar_validado`].
    pub fn registrar_validado_con_timestamp(
        &mut self,
        hash: BlockHash,
        slot: u64,
        timestamp: u64,
    ) -> Result<(), ErrorServicioPot> {
        if slot > self.slot_actual {
            return Err(ErrorServicioPot::SlotFuturo {
                slot,
                slot_actual: self.slot_actual,
            });
        }
        if hash == self.terminal || self.pasado.iter().any(|b| b.hash == hash) {
            return Err(ErrorServicioPot::BloqueDuplicado { hash });
        }
        self.pasado.push(BloqueDelPasado {
            hash,
            slot,
            timestamp,
            flujo: self.f0,
        });
        self.podar();
        Ok(())
    }

    /// Ventana de timestamps del pasado retenido, ordenada por slot ascendente, con `slot` en
    /// `(desde, hasta]`. La usa el **ajuste del reloj** (`C-RLJ-04`).
    ///
    /// Desde `ORDEN-RLJ3A` **no** es la ventana de la PMT: la PMT usa la cadena seleccionada del
    /// bloque (pieza `reloj_marcas` de `zx-node`); esta ventana local no decide validez de marcas.
    #[must_use]
    pub fn ventana_timestamps(&self, desde: u64, hasta: u64) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self
            .pasado
            .iter()
            .filter(|b| b.slot > desde && b.slot <= hasta)
            .map(|b| (b.slot, b.timestamp))
            .collect();
        v.sort_unstable();
        v
    }

    /// **Retirada de la ruta de producto por `ORDEN-RLJ3A`** (IPA B-105): ya no la llama ningún
    /// camino de admisión ni de producción. Se conserva solo para sus pruebas históricas de la
    /// unión causal; no es un respaldo del que la ventana seleccionada pueda fiarse.
    ///
    /// T1: ancla y últimas `m_ts` marcas de la unión causal de los padres.
    ///
    /// `obtener` solo debe entregar cabeceras ya admitidas del mismo terminal. Un resumen
    /// incluye el propio bloque: truncar cada padre a M preserva los M máximos de la unión.
    /// El mínimo se conserva aparte para no desplazar el ancla al truncar la PMT.
    /// Los empates se resuelven por hash; las fusiones no cuentan un ancestro dos veces.
    ///
    /// # Errores
    /// Hash cuyo contexto falta (también en ciclos o caché envenenada). Nunca devuelve
    /// una ventana parcial. La reconstrucción fría es iterativa y memoiza cada bloque.
    pub fn ventana_timestamps_causal(
        &self,
        padres: &[BlockHash],
        m_ts: usize,
        obtener: impl Fn(&BlockHash) -> Option<(u64, u64, Vec<BlockHash>)>,
    ) -> Result<Vec<(u64, u64)>, BlockHash> {
        if m_ts == 0 {
            return Err(self.terminal);
        }
        let mut cache = self.timestamps_causales.lock().map_err(|_| self.terminal)?;
        let mut activos = BTreeSet::new();
        for padre in padres {
            let mut pila = vec![(*padre, None)];
            while let Some((hash, datos)) = pila.pop() {
                if hash == self.terminal || cache.contains_key(&(m_ts, hash)) {
                    continue;
                }
                if let Some((slot, timestamp, anteriores)) = datos {
                    let marca = (slot, hash, timestamp);
                    let mut marcas = BTreeSet::from([marca]);
                    let mut primero = marca;
                    for h in anteriores {
                        if h == self.terminal {
                            continue;
                        }
                        let resumen = cache.get(&(m_ts, h)).ok_or(h)?;
                        primero = primero.min(resumen.primero);
                        marcas.extend(resumen.ultimos.iter().copied());
                    }
                    let ultimos = marcas.into_iter().rev().take(m_ts).rev().collect();
                    cache.insert(
                        (m_ts, hash),
                        ResumenTimestamp {
                            slot,
                            primero,
                            ultimos,
                        },
                    );
                    activos.remove(&hash);
                } else {
                    if !activos.insert(hash) {
                        return Err(hash);
                    }
                    let datos = obtener(&hash).ok_or(hash)?;
                    let anteriores = datos.2.clone();
                    if anteriores.is_empty() {
                        return Err(hash);
                    }
                    pila.push((hash, Some(datos)));
                    pila.extend(anteriores.into_iter().map(|h| (h, None)));
                }
            }
        }
        let mut marcas = BTreeSet::new();
        let mut primero: Option<(u64, BlockHash, u64)> = None;
        for hash in padres {
            if *hash == self.terminal {
                continue;
            }
            let resumen = cache.get(&(m_ts, *hash)).ok_or(*hash)?;
            primero = Some(primero.map_or(resumen.primero, |p| p.min(resumen.primero)));
            marcas.extend(resumen.ultimos.iter().copied());
        }
        let mut ventana: BTreeSet<_> = marcas.into_iter().rev().take(m_ts).collect();
        ventana.extend(primero);
        Ok(ventana
            .into_iter()
            .map(|(slot, _, ts)| (slot, ts))
            .collect())
    }

    /// `timestamp` de un bloque registrado, si sigue en la ventana.
    #[must_use]
    pub fn timestamp_de(&self, hash: &BlockHash) -> Option<u64> {
        self.pasado
            .iter()
            .find_map(|b| (b.hash == *hash).then_some(b.timestamp))
    }

    /// `slot` declarado de un bloque registrado, si sigue en la ventana.
    #[must_use]
    pub fn slot_de(&self, hash: &BlockHash) -> Option<u64> {
        self.pasado
            .iter()
            .find_map(|b| (b.hash == *hash).then_some(b.slot))
    }

    /// Registra los portadores **ya verificados** de `(sp_slot, b_slot]` (los de la justificación
    /// de un bloque admitido), cada uno en su slot, sin recalcular el PoT.
    ///
    /// `ORDEN-W06d9`, causa de origen: `Nodo::actualizar_servicio_verificacion` solo guardaba el
    /// **último** portador (el del propio bloque) y descartaba los intermedios que la justificación
    /// ya trae verificados; esos huecos quedaban para siempre y [`Self::portadores_para`] los
    /// denunciaba. Registrar el rango entero cierra el hueco en su origen.
    ///
    /// No toca `slot_actual()`: no avanza el reloj. Además de los portadores, **materializa la
    /// salida** de cada slot del rango: el último checkpoint de un portador es exactamente la salida
    /// de ese slot (`C-POT-02`; misma extracción que `zx_post::pot_rango::salida_de`). Esto cierra en
    /// su origen el hueco de `salidas` que dejaba `insertar_calculado` al saltar slots: la ventana
    /// decía retener el slot (el portador estaba) pero `salida_de` no lo encontraba y devolvía
    /// `FueraDeVentana`, que el productor convertía en `fallo_productor` (FIX-05).
    ///
    /// # Errores
    /// [`ErrorServicioPot::RangoInvalido`] si `sp_slot >= b_slot` o si `portadores.len()` no cuadra
    /// con el rango; [`ErrorServicioPot::RangoExcedeMaximo`] si la diferencia supera
    /// `MAX_BUNDLES_POT`; [`ErrorServicioPot::PortadorDiscrepante`] si un slot ya tenía otro
    /// portador distinto (D-P10); [`ErrorServicioPot::SalidaPasadaDiscrepante`] si la salida que
    /// trae un portador contradice una ya registrada para ese slot (violación real de D-P10).
    pub fn registrar_portadores(
        &mut self,
        sp_slot: u64,
        b_slot: u64,
        portadores: &[PotCheckpoints],
    ) -> Result<(), ErrorServicioPot> {
        let Some(d) = b_slot.checked_sub(sp_slot) else {
            return Err(ErrorServicioPot::RangoInvalido { sp_slot, b_slot });
        };
        let n = match u64::try_from(portadores.len()) {
            Ok(n) => n,
            Err(_) => return Err(ErrorServicioPot::AritmeticaDeSlotsDesbordada),
        };
        if d == 0 || d != n {
            return Err(ErrorServicioPot::RangoInvalido { sp_slot, b_slot });
        }
        if d > MAX_BUNDLES_POT as u64 {
            return Err(ErrorServicioPot::RangoExcedeMaximo {
                d,
                max: MAX_BUNDLES_POT as u64,
            });
        }
        for (i, portador) in portadores.iter().enumerate() {
            // `sp_slot < b_slot` y `i < d <= MAX_BUNDLES_POT` garantizan que `sp_slot + 1 + i`
            // no desborda ni sale del rango.
            let slot = sp_slot + 1 + u64::try_from(i).unwrap_or(u64::MAX);
            if let Some(existente) = self.portadores.get(&slot)
                && *existente != *portador
            {
                return Err(ErrorServicioPot::PortadorDiscrepante { slot });
            }
            self.portadores.insert(slot, *portador);
            // El último checkpoint de un portador es la salida del slot (`C-POT-02`). La
            // justificación verificada que trae estos portadores trae, por tanto, las salidas del
            // rango; materializarlas evita el hueco que `insertar_calculado` deja al saltar slots.
            // Si contradicen una salida ya presente, es una violación real de D-P10, no un hueco.
            if let Some(salida) = portador.outputs().into_iter().next_back() {
                if let Some(existente) = self.salidas.get(&slot)
                    && *existente != salida
                {
                    return Err(ErrorServicioPot::SalidaPasadaDiscrepante { slot });
                }
                self.salidas.insert(slot, salida);
            }
        }
        Ok(())
    }

    /// Completa los portadores **ausentes** de `(sp_slot, b_slot]` recalculándolos de forma
    /// determinista desde la salida conocida inmediatamente anterior (D-P10: el PoT es un único
    /// flujo determinista; el cálculo es exactamente el mismo que [`Self::avanzar`]).
    ///
    /// Un hueco (un slot dentro de `slot_actual()` cuya salida/portador no se calcularon porque
    /// [`Self::insertar_calculado`] saltó por encima de él) **no** es una violación de invariante:
    /// es un dato que el servicio aún no había materializado. Esta función lo materializa sin mover
    /// `slot_actual()` y sin publicar nada; solo rellena los mapas locales. Si el rango ya está
    /// completo, no hace nada (camino rápido).
    ///
    /// # Errores
    /// Las mismas cotas de rango que [`Self::portadores_para`], más
    /// [`ErrorServicioPot::RecompletarExcedeMaximo`] si la salida conocida más cercana está tan
    /// atrás que recompletar exigiría más de `MAX_BUNDLES_POT` pruebas (el llamante **omite** la
    /// producción, no falla), y [`ErrorServicioPot::SalidaPasadaDiscrepante`]/
    /// [`ErrorServicioPot::PortadorDiscrepante`] si un dato ya presente contradice el flujo (D-P10).
    pub fn completar_portadores(
        &mut self,
        sp_slot: u64,
        b_slot: u64,
    ) -> Result<(), ErrorServicioPot> {
        let Some(d) = b_slot.checked_sub(sp_slot) else {
            return Err(ErrorServicioPot::RangoInvalido { sp_slot, b_slot });
        };
        if d == 0 {
            return Err(ErrorServicioPot::RangoInvalido { sp_slot, b_slot });
        }
        if d > MAX_BUNDLES_POT as u64 {
            return Err(ErrorServicioPot::RangoExcedeMaximo {
                d,
                max: MAX_BUNDLES_POT as u64,
            });
        }
        if b_slot > self.slot_actual {
            return Err(ErrorServicioPot::SlotFuturo {
                slot: b_slot,
                slot_actual: self.slot_actual,
            });
        }
        // Primer slot del rango sin portador; si no hay ninguno, no hay nada que completar.
        // `sp_slot < b_slot` garantiza que `sp_slot + 1` no desborda.
        let Some(primero) =
            ((sp_slot + 1)..=b_slot).find(|slot| !self.portadores.contains_key(slot))
        else {
            return Ok(());
        };
        // Salida conocida más cercana por debajo del primer hueco. El slot 0 (S1) siempre existe.
        let mut base_slot = primero - 1;
        let base_salida = loop {
            if base_slot == 0 {
                break self.s1;
            }
            if let Some(salida) = self.salidas.get(&base_slot) {
                break *salida;
            }
            base_slot -= 1;
        };
        let trabajo = b_slot - base_slot;
        if trabajo > MAX_BUNDLES_POT as u64 {
            return Err(ErrorServicioPot::RecompletarExcedeMaximo {
                sp_slot,
                b_slot,
                base_slot,
                d: trabajo,
                max: MAX_BUNDLES_POT as u64,
            });
        }
        let mut anterior = base_salida;
        for slot in (base_slot + 1)..=b_slot {
            let semilla = semilla_siguiente(anterior, None);
            let carrier = zx_pot::prove(PotSeed::from(semilla), self.proyectar_n(slot)?)
                .map_err(|error| ErrorServicioPot::Pot { slot, error })?;
            let salida = *carrier.output();
            let portador = checkpoints_a_wire(&carrier);
            if let Some(existente) = self.salidas.get(&slot)
                && *existente != salida
            {
                return Err(ErrorServicioPot::SalidaPasadaDiscrepante { slot });
            }
            if let Some(existente) = self.portadores.get(&slot)
                && *existente != portador
            {
                return Err(ErrorServicioPot::PortadorDiscrepante { slot });
            }
            self.salidas.entry(slot).or_insert(salida);
            self.portadores.entry(slot).or_insert(portador);
            anterior = salida;
        }
        Ok(())
    }

    /// Portadores de `(sp_slot, b_slot]`, en orden, para construir la justificación PoT.
    ///
    /// `ORDEN-W06d9` decisión 2(a): antes de denunciar un hueco, **intenta completarlo**
    /// recalculándolo de forma determinista ([`Self::completar_portadores`], acotado a
    /// `MAX_BUNDLES_POT`). Un hueco no es una violación de invariante del productor: si no se puede
    /// completar, el llamante omite la producción en ese slot (`produccion_omitida`), nunca
    /// `fallo_productor`. Por eso el método toma `&mut self`.
    ///
    /// # Errores
    /// [`ErrorServicioPot::RangoInvalido`] si `sp_slot >= b_slot`;
    /// [`ErrorServicioPot::RangoExcedeMaximo`] si la diferencia supera `MAX_BUNDLES_POT`;
    /// [`ErrorServicioPot::SlotFuturo`] si `b_slot` va por delante del servicio;
    /// [`ErrorServicioPot::RecompletarExcedeMaximo`] si un hueco no se pudo recompletar dentro de
    /// la cota; [`ErrorServicioPot::PortadorAusente`] si tras completar sigue faltando (defensivo).
    pub fn portadores_para(
        &mut self,
        sp_slot: u64,
        b_slot: u64,
    ) -> Result<Vec<PotCheckpoints>, ErrorServicioPot> {
        self.completar_portadores(sp_slot, b_slot)?;
        let mut portadores = Vec::with_capacity((b_slot - sp_slot) as usize);
        // `sp_slot < b_slot` garantiza que `sp_slot + 1` no desborda.
        for slot in (sp_slot + 1)..=b_slot {
            match self.portadores.get(&slot) {
                Some(p) => portadores.push(*p),
                None => return Err(ErrorServicioPot::PortadorAusente { slot }),
            }
        }
        Ok(portadores)
    }

    /// Poda las salidas, portadores y registros que salen de la ventana. El ancla del terminal
    /// (slot 0) es constante y no ocupa entrada en los mapas.
    fn podar(&mut self) {
        let limite = self.primer_slot_retenido();
        self.salidas.retain(|slot, _| *slot >= limite);
        self.portadores.retain(|slot, _| *slot >= limite);
        self.pasado
            .retain(|bloque| bloque.slot == 0 || bloque.slot >= limite);
        if let Ok(mut cache) = self.timestamps_causales.lock() {
            cache.retain(|_, resumen| resumen.slot >= limite);
        }
    }
}

impl InstantaneaPot for ServicioPot {
    /// `f_0` en todo slot: un solo flujo y sin inyecciones (D-P10).
    fn flujo_candidato_en(&self, _slot: u64) -> Result<[u8; FLUJO_BYTES], MotivoPotPendiente> {
        Ok(self.f0)
    }

    /// El pasado registrado por el llamante, con el terminal en el slot 0.
    fn pasado(&self) -> Result<&[BloqueDelPasado], MotivoPotPendiente> {
        Ok(&self.pasado)
    }

    /// Ninguna inyección en dev (D-P10).
    fn inyecciones_en(&self, _slot: u64) -> Result<InyeccionesPot, MotivoPotPendiente> {
        Ok(InyeccionesPot::Ninguna)
    }

    /// `N(s) = T(s)·n_iter` del calendario del reloj (`C-RLJ-02`): con [`ServicioPot::nuevo`],
    /// `N_dev` constante.
    fn iteraciones(&self, slot: u64) -> Result<u64, MotivoPotPendiente> {
        Ok(self.n_vigente(slot))
    }

    /// `D = 0` (D-P10).
    fn retardo_autoria(&self) -> Result<u64, MotivoPotPendiente> {
        Ok(0)
    }

    /// Salida ya calculada por el propio servicio; fuera de ventana es falta de contexto.
    fn salida_validada(&self, slot: u64) -> Result<[u8; POT_OUTPUT_BYTES], MotivoPotPendiente> {
        self.salida_de(slot)
            .map_err(|_| MotivoPotPendiente::ContextoAusente {
                que: "salida del slot fuera de la ventana del ServicioPot",
            })
    }
}

/// Pruebas internas del servicio: la salida de cada slot coincide con calcularla a mano desde S1.
#[cfg(test)]
#[expect(clippy::expect_used, reason = "los tests usan expect por diseño")]
mod pruebas {
    use core::num::NonZeroU32;

    use zx_core::BlockHash;
    use zx_core::digest::Digest;
    use zx_pot::tipos::PotSeed;

    use zx_core::wire_dag::{BUNDLE_BYTES, POT_OUTPUT_BYTES, PotCheckpoints};

    use super::{ErrorServicioPot, ServicioPot};
    use crate::pot::semilla_genesis;
    use crate::pot_rango::{InstantaneaPot, InyeccionesPot, MotivoPotPendiente};
    use crate::reloj::EstadoReloj;

    const N: u64 = 32;

    fn hash(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn servicio(ventana: u64) -> ServicioPot {
        ServicioPot::nuevo(hash(0x01), N, ventana).expect("servicio dev válido")
    }

    fn iteraciones() -> NonZeroU32 {
        NonZeroU32::new(u32::try_from(N).expect("N cabe en u32")).expect("N > 0")
    }

    #[test]
    fn parametros_invalidos_se_rechazan() {
        assert!(matches!(
            ServicioPot::nuevo(hash(1), 0, 10),
            Err(ErrorServicioPot::NDevInvalido(_))
        ));
        assert!(matches!(
            ServicioPot::nuevo(hash(1), 15, 10),
            Err(ErrorServicioPot::NDevInvalido(_))
        ));
        assert!(matches!(
            ServicioPot::nuevo(hash(1), N, 0),
            Err(ErrorServicioPot::VentanaInvalida { configurada: 0 })
        ));
    }

    /// RL-2b: el reloj arranca en `(T0, n_iter)`, la frontera es exacta y fijar un ajuste cambia el
    /// calendario a partir de `frontera + 1` sin reescribir los slots ya calculados.
    #[test]
    fn el_reloj_se_fija_en_la_frontera_y_cambia_el_calendario() {
        let mut s =
            ServicioPot::nuevo_con_reloj(hash(0x31), EstadoReloj::nuevo(50, 16, 1_000_000), 8)
                .expect("servicio con reloj válido");
        assert_eq!(s.reloj().t(), 50);
        assert_eq!(s.n_vigente(1), 50 * 16);
        s.avanzar_hasta(8).expect("avance");
        assert_eq!(s.frontera_pendiente(8), Some(8));
        s.fijar_reloj(8, 8, EstadoReloj::nuevo(51, 16, 1_000_000))
            .expect("fijar reloj");
        assert_eq!(s.frontera_pendiente(8), None, "no se ajusta dos veces");
        assert_eq!(
            s.n_vigente(8),
            50 * 16,
            "los slots ya calculados no cambian"
        );
        assert_eq!(s.n_vigente(15), 50 * 16, "rige desde la frontera + A");
        assert_eq!(
            s.n_vigente(16),
            51 * 16,
            "el calendario nuevo rige desde 16"
        );
        assert_eq!(s.reloj().t(), 51);
    }

    #[test]
    fn la_cadena_coincide_con_calcularla_a_mano() {
        let mut s = servicio(8);
        let mut salida = s.s1();
        for slot in 1..=6u64 {
            let carrier = zx_pot::prove(PotSeed::from(salida), iteraciones()).expect("N válido");
            salida = *carrier.output();
            let calculado = s.avanzar().expect("avance");
            assert_eq!(calculado, slot);
            assert_eq!(s.salida_de(slot).expect("salida"), salida);
            assert_eq!(
                s.portador_de(slot).expect("portador"),
                &crate::pot::checkpoints_a_wire(&carrier)
            );
        }
        assert_eq!(s.slot_actual(), 6);
    }

    #[test]
    fn fuera_de_ventana_es_error_explicito() {
        let mut s = servicio(3);
        s.avanzar_hasta(6).expect("avance");
        assert_eq!(s.primer_slot_retenido(), 4);
        assert_eq!(s.salida_de(0).expect("ancla del terminal"), s.s1());
        assert!(matches!(
            s.salida_de(3),
            Err(ErrorServicioPot::FueraDeVentana {
                slot: 3,
                desde: 4,
                hasta: 6
            })
        ));
        assert!(matches!(
            s.portador_de(3),
            Err(ErrorServicioPot::PortadorAusente { slot: 3 })
        ));
    }

    #[test]
    fn portadores_para_cuenta_y_cotas() {
        let mut s = servicio(8);
        s.avanzar_hasta(5).expect("avance");
        assert_eq!(s.portadores_para(1, 5).expect("rango").len(), 4);
        assert!(matches!(
            s.portadores_para(3, 3),
            Err(ErrorServicioPot::RangoInvalido {
                sp_slot: 3,
                b_slot: 3
            })
        ));
        assert!(matches!(
            s.portadores_para(5, 1),
            Err(ErrorServicioPot::RangoInvalido { .. })
        ));
        assert!(matches!(
            s.portadores_para(1, 6),
            Err(ErrorServicioPot::SlotFuturo { slot: 6, .. })
        ));
    }

    #[test]
    fn registrar_validado_controla_duplicados_y_futuro() {
        let mut s = servicio(8);
        s.avanzar_hasta(3).expect("avance");
        s.registrar_validado(hash(0x0A), 2).expect("registro");
        assert_eq!(s.slot_de(&hash(0x0A)), Some(2));
        assert_eq!(s.slot_de(&s.terminal()), Some(0));
        assert!(matches!(
            s.registrar_validado(hash(0x0A), 2),
            Err(ErrorServicioPot::BloqueDuplicado { .. })
        ));
        assert!(matches!(
            s.registrar_validado(s.terminal(), 0),
            Err(ErrorServicioPot::BloqueDuplicado { .. })
        ));
        assert!(matches!(
            s.registrar_validado(hash(0x0B), 9),
            Err(ErrorServicioPot::SlotFuturo { slot: 9, .. })
        ));
    }

    #[test]
    fn instantanea_pot_respond() {
        let mut s = servicio(8);
        s.avanzar_hasta(2).expect("avance");
        assert_eq!(s.flujo_candidato_en(99).expect("flujo"), s.f0());
        assert_eq!(
            s.inyecciones_en(1).expect("inyecciones"),
            InyeccionesPot::Ninguna
        );
        assert_eq!(s.iteraciones(1).expect("N"), N);
        assert_eq!(s.retardo_autoria().expect("D"), 0);
        assert_eq!(s.salida_validada(0).expect("S1"), s.s1());
        assert_eq!(
            s.salida_validada(2).expect("slot 2"),
            s.salida_de(2).expect("mapa")
        );
        assert_eq!(
            s.salida_validada(50),
            Err(MotivoPotPendiente::ContextoAusente {
                que: "salida del slot fuera de la ventana del ServicioPot"
            })
        );
        assert_eq!(s.pasado().expect("pasado").len(), 1);
    }

    /// `ORDEN-W06d1`: reconstruir con `insertar_calculado` da el mismo estado que `avanzar`.
    #[test]
    fn insertar_calculado_reproduce_avanzar() {
        let mut avanzado = servicio(8);
        avanzado.avanzar_hasta(4).expect("avance");

        let mut reconstruido = servicio(8);
        for slot in 1..=4u64 {
            let salida = avanzado.salida_de(slot).expect("salida ya calculada");
            let portador = *avanzado.portador_de(slot).expect("portador ya calculado");
            reconstruido
                .insertar_calculado(slot, salida, portador)
                .expect("inserción secuencial válida");
        }
        assert_eq!(reconstruido.slot_actual(), avanzado.slot_actual());
        for slot in 1..=4u64 {
            assert_eq!(
                reconstruido.salida_de(slot).expect("salida"),
                avanzado.salida_de(slot).expect("salida")
            );
        }
    }

    #[test]
    fn insertar_calculado_permite_huecos_pero_no_retroceder() {
        let mut s = servicio(8);
        let carrier = zx_pot::prove(PotSeed::from(s.s1()), iteraciones()).expect("N válido");
        let portador = crate::pot::checkpoints_a_wire(&carrier);
        // `slot = 5` cuando `slot_actual() == 0`: salta el hueco 1..=4 (nunca es `sp` de nadie).
        s.insertar_calculado(5, *carrier.output(), portador)
            .expect("avanzar con hueco es válido: D-P10, flujo único");
        assert_eq!(s.slot_actual(), 5);
        // Retroceder (o repetir el mismo slot) sí es un error.
        assert!(matches!(
            s.insertar_calculado(5, *carrier.output(), portador),
            Err(ErrorServicioPot::ObjetivoAnterior {
                pedido: 5,
                actual: 5
            })
        ));
        assert!(matches!(
            s.insertar_calculado(3, *carrier.output(), portador),
            Err(ErrorServicioPot::ObjetivoAnterior {
                pedido: 3,
                actual: 5
            })
        ));
    }

    /// `ORDEN-W06d4` decisión 3: reproduce y corrige la causa confirmada de `Pot(PasadoIncompleto)`
    /// en un bloque propio de un nodo que se incorpora tarde al régimen
    /// (`REVISION-W06d3.md`/`PROGRESO.md`, hallazgo no resuelto).
    ///
    /// El flujo PoT es único y compartido por todas las ramas (D-P10): si una rama más rápida hace
    /// que el `ServicioPot` de verificación salte directamente a un slot posterior
    /// (`insertar_calculado` lo permite a propósito, ver el test de arriba), un slot **anterior** que
    /// otra rama sí usó de verdad queda como hueco — sin salida ni portador calculados — aunque su
    /// bloque sea válido y ya esté admitido en `Cadena`. Antes de esta corrección, el único camino
    /// para reconciliar un slot `<= slot_actual()` era `salida_de`, que exige que el slot **ya
    /// tenga** una salida: con un hueco, fallaba con `FueraDeVentana` aunque el llamante trajera el
    /// `pot_output` real de una cabecera ya admitida y verificada. El bloque se rechazaba sin entrar
    /// nunca en `pasado()`, así que cualquier hijo que lo declarase padre fallaba después con
    /// `PasadoIncompleto` (`zx_post::pot_rango::verificar_rango_pot_fase_previa`) — exactamente el
    /// síntoma observado con tres procesos reales.
    #[test]
    fn declarar_salida_pasada_rellena_un_hueco_dejado_por_otra_rama() {
        let mut s = servicio(16);
        let carrier = zx_pot::prove(PotSeed::from(s.s1()), iteraciones()).expect("N válido");
        let portador = crate::pot::checkpoints_a_wire(&carrier);
        let salida_10 = [10u8; POT_OUTPUT_BYTES];
        let salida_7 = [7u8; POT_OUTPUT_BYTES];

        // Rama B (más rápida): el flujo PoT único ya avanzó hasta el slot 10. El slot 7 queda como
        // hueco, sin calcular.
        s.insertar_calculado(10, salida_10, portador)
            .expect("avanzar con hueco es válido (D-P10)");

        // Llega, por sincronización y en cualquier orden, un bloque de la rama A con slot 7: el nodo
        // ya conoce su `pot_output` real (de una cabecera admitida), no una suposición.
        //
        // Antes del arreglo: el único camino disponible para `slot <= slot_actual()` era
        // `salida_de`, que aquí falla porque el slot 7 es justo un hueco.
        assert!(matches!(
            s.salida_de(7),
            Err(ErrorServicioPot::FueraDeVentana { slot: 7, .. })
        ));

        // La corrección: un slot detrás de `slot_actual()` sin salida calculada todavía es un hueco
        // legítimo (D-P10), no un conflicto; se rellena con el dato ya verificado y el bloque queda
        // disponible para `registrar_validado` (y por tanto para `pasado()`).
        s.declarar_salida_pasada(7, salida_7, portador)
            .expect("un hueco se rellena con un dato ya verificado, sin error");
        assert_eq!(s.salida_de(7).expect("ya rellenado"), salida_7);
        s.registrar_validado(hash(0x07), 7).expect("registro");
        assert_eq!(s.slot_de(&hash(0x07)), Some(7));

        // Repetir la misma salida para un slot ya presente no es un conflicto (dos ramas legítimas
        // pueden compartir el mismo slot, D-P10).
        s.declarar_salida_pasada(7, salida_7, portador)
            .expect("repetir la misma salida para el mismo slot no es un conflicto");

        // D-P10 sigue detectando un conflicto real: una salida **distinta** para un slot ya
        // presente es un error, nunca se sobrescribe en silencio.
        assert!(matches!(
            s.declarar_salida_pasada(7, salida_10, portador),
            Err(ErrorServicioPot::SalidaPasadaDiscrepante { slot: 7 })
        ));
    }

    #[test]
    fn arranca_de_s1_del_terminal() {
        let t = hash(0x02);
        let s = ServicioPot::nuevo(t, N, 4).expect("servicio");
        assert_eq!(s.terminal(), t);
        assert_eq!(s.s1(), semilla_genesis(&t, &[]));
        assert_eq!(s.f0(), zx_core::preimage::flow::flujo_genesis(&t));
        assert_eq!(s.slot_actual(), 0);
    }

    /// `ORDEN-W06d9` V1: reproduce el hueco que tumbó al productor de W07b. Una rama que salta de
    /// slot (el caso que `insertar_calculado` permite a propósito) deja los slots intermedios sin
    /// salida ni portador; antes de esta corrección `portadores_para` devolvía
    /// `PortadorAusente { slot: 6 }` y `regimen.rs` lo convertía en `fallo_productor`. Con la
    /// corrección, `portadores_para` completa el hueco por recálculo determinista (D-P10) y no
    /// falla. Es el test que **falla antes** y **pasa después**.
    #[test]
    fn portadores_para_completa_un_hueco_por_recalculo() {
        let mut referencia = servicio(16);
        referencia.avanzar_hasta(10).expect("referencia densa");

        let mut con_hueco = servicio(16);
        // Salto del 0 al 10: los slots 1..=9 quedan como huecos.
        let salida_10 = referencia.salida_de(10).expect("salida de la referencia");
        let portador_10 = *referencia
            .portador_de(10)
            .expect("portador de la referencia");
        con_hueco
            .insertar_calculado(10, salida_10, portador_10)
            .expect("saltar con hueco es válido (D-P10)");
        assert!(matches!(
            con_hueco.portador_de(6),
            Err(ErrorServicioPot::PortadorAusente { slot: 6 })
        ));

        // Pedir el rango (5, 10] completa por recálculo los portadores 6..=9 y devuelve los cinco.
        let portadores = con_hueco
            .portadores_para(5, 10)
            .expect("un hueco se completa por recálculo determinista");
        assert_eq!(portadores.len(), 5);
        for (i, slot) in (6u64..=10).enumerate() {
            assert_eq!(
                portadores.get(i).copied().expect("posición"),
                referencia.portador_de(slot).copied().expect("referencia"),
                "el portador recalculado del slot {slot} debe coincidir con el de la referencia"
            );
        }
    }

    /// `ORDEN-W06d9` V2: los portadores y salidas recalculados coinciden **byte a byte** con los
    /// calculados por `avanzar` (misma primitiva, mismo flujo único, D-P10).
    #[test]
    fn completar_portadores_coincide_con_avanzar_byte_a_byte() {
        let mut referencia = servicio(16);
        referencia.avanzar_hasta(12).expect("referencia densa");

        let mut con_hueco = servicio(16);
        let salida_12 = referencia.salida_de(12).expect("salida");
        let portador_12 = *referencia.portador_de(12).expect("portador");
        con_hueco
            .insertar_calculado(12, salida_12, portador_12)
            .expect("salto con hueco");

        con_hueco
            .completar_portadores(0, 12)
            .expect("completa todo el rango");

        for slot in 1..=12u64 {
            assert_eq!(
                con_hueco.salida_de(slot).expect("salida"),
                referencia.salida_de(slot).expect("salida"),
                "salida del slot {slot}"
            );
            assert_eq!(
                con_hueco.portador_de(slot).expect("portador"),
                referencia.portador_de(slot).expect("portador"),
                "portador del slot {slot}"
            );
        }
    }

    /// `ORDEN-W06d9` V2: un rango que no se puede recompletar dentro de `MAX_BUNDLES_POT` devuelve
    /// error explícito (el productor lo traduce en `produccion_omitida`, sin pánico ni `fallo`).
    #[test]
    fn rango_no_justificable_es_error_sin_panico() {
        let mut s = servicio(16);
        let carrier = zx_pot::prove(PotSeed::from(s.s1()), iteraciones()).expect("N válido");
        s.insertar_calculado(
            200,
            *carrier.output(),
            crate::pot::checkpoints_a_wire(&carrier),
        )
        .expect("salto");

        // `(100, 200]` tiene 100 portadores (<= 150) pero exigiría recalcular desde el slot 0: 200
        // pruebas, por encima de la cota.
        assert!(matches!(
            s.completar_portadores(100, 200),
            Err(ErrorServicioPot::RecompletarExcedeMaximo {
                base_slot: 0,
                d: 200,
                max: 150,
                ..
            })
        ));
        assert!(matches!(
            s.portadores_para(100, 200),
            Err(ErrorServicioPot::RecompletarExcedeMaximo { .. })
        ));
        // Un rango que de por sí excede el formato ni lo intenta.
        assert!(matches!(
            s.portadores_para(40, 200),
            Err(ErrorServicioPot::RangoExcedeMaximo { d: 160, max: 150 })
        ));
    }

    /// `ORDEN-W06d9` (causa de origen): registrar los portadores **ya verificados** de la
    /// justificación de un bloque deja el rango completo sin recalcular nada, de modo que un bloque
    /// que saltó slots deja de dejar huecos permanentes.
    #[test]
    fn registrar_portadores_rellena_el_rango_sin_recalcular() {
        let mut referencia = servicio(16);
        referencia.avanzar_hasta(10).expect("referencia densa");

        let mut s = servicio(16);
        let salida_10 = referencia.salida_de(10).expect("salida");
        let portador_10 = *referencia.portador_de(10).expect("portador");
        s.insertar_calculado(10, salida_10, portador_10)
            .expect("salto");

        // Justificación de un bloque de slot 10 con `sp = 5`: portadores de `(5, 10]`.
        let justificacion: Vec<PotCheckpoints> = (6..=10)
            .map(|slot| {
                *referencia
                    .portador_de(slot)
                    .expect("portador de la referencia")
            })
            .collect();
        s.registrar_portadores(5, 10, &justificacion)
            .expect("registro de datos verificados");

        // El rango queda completo sin que `completar_portadores` tenga que recalcular: el registro
        // ya trae portadores y salidas verificadas, así que `portadores_para` devuelve exactamente
        // lo registrado.
        assert_eq!(
            s.portadores_para(5, 10).expect("rango completo"),
            justificacion
        );
    }

    /// FIX-05: la justificación verificada de un bloque que **salta** slots (el bloque de transición
    /// es el caso real) trae los portadores del rango y, con ellos, las salidas de esos slots (el
    /// último checkpoint de un portador es la salida del slot, `C-POT-02`). `registrar_portadores`
    /// debe materializarlas, no solo los portadores: antes del arreglo el `ServicioPot` quedaba con
    /// `portadores = {1,2,3,…}` pero `salidas = {3,…}`, y `salida_de(1)` —el padre que GHOSTDAG
    /// elige después— devolvía `FueraDeVentana` con el slot **dentro** de la ventana retenida
    /// `[0, 6]`; `regimen.rs` lo trataba como `fallo_productor` y el nodo moría. Este test falla en
    /// la base y pasa con el arreglo.
    #[test]
    fn registrar_portadores_materializa_las_salidas_del_rango() {
        let mut referencia = servicio(16);
        referencia.avanzar_hasta(6).expect("referencia densa");

        // Estado del `ServicioPot` de verificación justo tras admitir el bloque de transición del
        // slot 3 (`d = 3`): rango `(0, 3]` registrado e inserción calculada del propio bloque.
        let mut s = servicio(16);
        let bundles: Vec<PotCheckpoints> = (1..=3)
            .map(|slot| *referencia.portador_de(slot).expect("portador"))
            .collect();
        s.registrar_portadores(0, 3, &bundles)
            .expect("la justificación verificada se registra");
        s.insertar_calculado(
            3,
            referencia.salida_de(3).expect("salida"),
            *referencia.portador_de(3).expect("portador"),
        )
        .expect("transición al slot 3");

        // El slot 1 (padre elegido en el slot 6) estaba dentro de la ventana pero era un hueco.
        assert_eq!(
            s.salida_de(1)
                .expect("la salida del rango quedó materializada"),
            referencia.salida_de(1).expect("salida de la referencia"),
            "la salida materializada debe ser la del flujo único (D-P10)"
        );
        assert_eq!(
            s.salida_de(2).expect("salida materializada"),
            referencia.salida_de(2).expect("salida de la referencia")
        );

        // El nodo sigue admitiendo slots posteriores y el padre del slot 1 sigue disponible.
        for slot in 4..=6u64 {
            s.insertar_calculado(
                slot,
                referencia.salida_de(slot).expect("salida"),
                *referencia.portador_de(slot).expect("portador"),
            )
            .expect("avance posterior");
        }
        assert_eq!(s.primer_slot_retenido(), 0);
        assert_eq!(s.slot_actual(), 6);
        assert_eq!(
            s.salida_de(1).expect("padre del slot 1 disponible"),
            referencia.salida_de(1).expect("salida")
        );
        assert_eq!(s.portadores_para(1, 6).expect("rango completo").len(), 5);
    }

    /// FIX-05 (D-P10): si la salida que trae un portador contradice una ya registrada para ese slot,
    /// `registrar_portadores` lo denuncia en vez de sobrescribir en silencio.
    #[test]
    fn registrar_portadores_detecta_salida_discrepante() {
        let mut referencia = servicio(16);
        referencia.avanzar_hasta(1).expect("referencia densa");
        let portador = *referencia.portador_de(1).expect("portador");

        let mut s = servicio(16);
        // El slot 1 ya tiene registrada una salida distinta (dato corrupto) con el mismo portador.
        s.declarar_salida_pasada(1, [0xEE; POT_OUTPUT_BYTES], portador)
            .expect("inserción calculada del slot 1");
        assert!(matches!(
            s.registrar_portadores(0, 1, &[portador]),
            Err(ErrorServicioPot::SalidaPasadaDiscrepante { slot: 1 })
        ));
    }

    /// D-P10: registrar un portador **distinto** para un slot ya presente se detecta, nunca se
    /// sobrescribe en silencio.
    #[test]
    fn registrar_portadores_detecta_discrepancia() {
        let mut referencia = servicio(16);
        referencia.avanzar_hasta(10).expect("referencia densa");

        let mut s = servicio(16);
        let salida_10 = referencia.salida_de(10).expect("salida");
        let portador_10 = *referencia.portador_de(10).expect("portador");
        s.insertar_calculado(10, salida_10, portador_10)
            .expect("salto");

        let mut malo: Vec<PotCheckpoints> = (6..=10)
            .map(|slot| *referencia.portador_de(slot).expect("portador"))
            .collect();
        *malo.last_mut().expect("no vacío") = PotCheckpoints::desde_bytes([0xAB; BUNDLE_BYTES]);
        assert!(matches!(
            s.registrar_portadores(5, 10, &malo),
            Err(ErrorServicioPot::PortadorDiscrepante { slot: 10 })
        ));
    }

    /// El calendario del reloj cambia `N(s)` en la frontera: `avanzar` usa el `N(s)` vigente y los
    /// slots ya calculados conservan el suyo.
    #[test]
    fn el_reloj_por_ticks_cambia_n_por_slot() {
        use crate::reloj::{Accion, EstadoReloj, Racional};

        let reloj = EstadoReloj::nuevo(50, 16, u64::MAX);
        let mut s = ServicioPot::nuevo_con_reloj(hash(0x01), reloj, 8).expect("servicio con reloj");
        assert_eq!(s.n_vigente(0), 800);
        // `tau_est` muy por debajo de `tau_ref`: sube `T`; el `N` nuevo rige desde el slot 1.
        let ajuste = s
            .ajustar_reloj(
                Racional::entero(1),
                Racional::entero(1_000),
                Racional::entero(5),
            )
            .expect("ajuste válido");
        assert_eq!(ajuste.accion, Accion::Subir);
        assert_eq!(s.reloj().t(), 51);
        assert_eq!(s.n_vigente(0), 800, "el slot 0 conserva su N");
        assert_eq!(s.n_vigente(1), 816);
        // `avanzar` produce con `N = 816`: coincide con la primitiva calculada a mano.
        assert_eq!(s.avanzar().expect("avance"), 1);
        let esperado = zx_pot::prove(PotSeed::from(s.s1()), NonZeroU32::new(816).expect("N > 0"))
            .expect("N múltiplo de 16");
        assert_eq!(s.salida_de(1).expect("salida"), *esperado.output());
    }

    /// RL1-A10: `n_iter` no múltiplo de 16 se rechaza al construir el reloj.
    #[test]
    fn n_iter_fuera_de_rl1a10_se_rechaza() {
        use crate::reloj::EstadoReloj;

        assert!(matches!(
            ServicioPot::nuevo_con_reloj(hash(1), EstadoReloj::nuevo(50, 15, u64::MAX), 8),
            Err(ErrorServicioPot::Reloj(_))
        ));
    }
}

#[cfg(test)]
#[path = "servicio_pot/pruebas_rlj2b.rs"]
mod pruebas_rlj2b;
