//! VNT-R1 · cursor monotónico del tiempo PoT **verificado en local**.
//!
//! Pieza propia (letras **V** y **T** del plan de MA-1) que no conoce `Nodo` ni el motor de votos:
//! recibe salidas PoT ya verificadas —terminal/identidad del flujo, generación de calendario y
//! slot— y devuelve, en orden, las **fronteras de ventana** (`n = ⌊s_v / T⌋`) que quedan por
//! atender. Es monotónica, ignora las salidas de una generación abandonada o de otro terminal, y
//! trata un salto grande como intervalo: el coste de listar las fronteras pendientes es
//! proporcional al horizonte `H`, no a la distancia entre el slot nuevo y el anterior.
//!
//! Una salida solo entra por [`SalidaVerificada`], que **construye el cableado del nodo**
//! (`Nodo::sincronizar_cursor_votos` tras reconciliar el servicio de verificación del terminal
//! seleccionado, o `Nodo::registrar_frontera_pot` tras contrastar la notificación del hilo con el
//! calendario propio). No hay constructor público desde un `Instant`, un timestamp remoto ni un
//! entero suelto. El cursor no mueve ningún estado de consenso (candidato, cuórum, duración de
//! ventana ni tabla v1.4).

use zx_core::BlockHash;

/// Salida PoT que una ruta de producto ya verificó en local.
///
/// El tipo es la prueba: solo lo construye el cableado de `Nodo` —nunca código ajeno al crate—
/// después de comprobar la salida. `Nodo::sincronizar_cursor_votos` lo hace con el slot ya
/// registrado en el `ServicioPot` de verificación del terminal **seleccionado**;
/// `Nodo::registrar_frontera_pot` con una notificación del hilo cuyo `N` de slot coincide con el
/// calendario que el propio nodo tiene por vigente. No hay constructor desde un `Instant`, desde
/// un timestamp remoto ni desde un entero suelto sin esa verificación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SalidaVerificada {
    terminal: BlockHash,
    generacion: u64,
    slot: u64,
}

impl SalidaVerificada {
    /// Declara una salida ya verificada del flujo `terminal` en la `generacion` de calendario
    /// vigente, observada en `slot`.
    ///
    /// Es `pub(crate)`: solo el cableado de `Nodo` (tras la verificación descrita en el tipo) la
    /// construye; el resto del crate no puede fabricar una salida sin pasar por esa comprobación.
    #[must_use]
    pub(crate) const fn nueva(terminal: BlockHash, generacion: u64, slot: u64) -> Self {
        Self {
            terminal,
            generacion,
            slot,
        }
    }

    /// `block_hash` del terminal que identifica el flujo PoT.
    #[must_use]
    pub const fn terminal(&self) -> BlockHash {
        self.terminal
    }

    /// Generación de calendario a la que pertenece la salida.
    #[must_use]
    pub const fn generacion(&self) -> u64 {
        self.generacion
    }

    /// Slot PoT observado.
    #[must_use]
    pub const fn slot(&self) -> u64 {
        self.slot
    }
}

/// Efecto de registrar una salida en el cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Movimiento {
    /// La salida movió `s_v` hacia delante.
    Avanza {
        /// Valor anterior de `s_v`.
        anterior: u64,
        /// Valor nuevo de `s_v`.
        nuevo: u64,
    },
    /// La salida era de un slot ya cubierto: no mueve `s_v`.
    Repetida,
    /// La salida pertenece a una generación distinta de la vigente: abandonada, no la mueve.
    GeneracionAbandonada,
    /// La salida es de otro terminal: no mueve el cursor.
    TerminalAjeno,
}

/// Cursor monotónico del tiempo PoT verificado en local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorVotos {
    terminal: BlockHash,
    generacion: u64,
    slot_verificado: u64,
    frontera_consumida: Option<u64>,
}

impl CursorVotos {
    /// Cursor nuevo para `terminal` en la `generacion` indicada, con `s_v = slot_inicial`.
    #[must_use]
    pub const fn nuevo(terminal: BlockHash, generacion: u64, slot_inicial: u64) -> Self {
        Self {
            terminal,
            generacion,
            slot_verificado: slot_inicial,
            frontera_consumida: None,
        }
    }

    /// Terminal/identidad del flujo que sigue el cursor.
    #[must_use]
    pub const fn terminal(&self) -> BlockHash {
        self.terminal
    }

    /// Generación de calendario vigente.
    #[must_use]
    pub const fn generacion(&self) -> u64 {
        self.generacion
    }

    /// Último slot PoT verificado (`s_v`).
    #[must_use]
    pub const fn slot_verificado(&self) -> u64 {
        self.slot_verificado
    }

    /// Última frontera ya atendida, si alguna.
    #[must_use]
    pub const fn frontera_consumida(&self) -> Option<u64> {
        self.frontera_consumida
    }

    /// Reconoce el terminal y la generación vigentes **sin rebobinar** `s_v`.
    ///
    /// Se usa al cambiar de terminal (reorganización o servicio nuevo): el tiempo verificado ya
    /// consumido no se reduce nunca. Si cambia la identidad, la generación avanza sola para que
    /// una salida tardía de la generación anterior quede abandonada.
    pub fn reconciliar(&mut self, terminal: BlockHash, generacion: u64) {
        if self.terminal != terminal {
            self.terminal = terminal;
            self.generacion = self.generacion.saturating_add(1).max(generacion);
        } else {
            self.generacion = self.generacion.max(generacion);
        }
    }

    /// Registra una salida verificada. `s_v` solo puede crecer.
    pub fn registrar(&mut self, salida: SalidaVerificada) -> Movimiento {
        if salida.terminal != self.terminal {
            return Movimiento::TerminalAjeno;
        }
        if salida.generacion != self.generacion {
            return Movimiento::GeneracionAbandonada;
        }
        if salida.slot <= self.slot_verificado {
            return Movimiento::Repetida;
        }
        let anterior = self.slot_verificado;
        self.slot_verificado = salida.slot;
        Movimiento::Avanza {
            anterior,
            nuevo: salida.slot,
        }
    }

    /// Fronteras de ventana pendientes, en orden creciente y **sin consumirlas**.
    ///
    /// Solo devuelve las posteriores a la última consumida y no más antiguas que el horizonte `h`
    /// (`H = ⌈W/T⌉ + 1`): un salto enorme se resuelve en `O(h)` sin materializar el rango
    /// intermedio. Con `t_inst == 0` no hay ventanas.
    #[must_use]
    pub fn fronteras_pendientes(&self, t_inst: u64, h: u64) -> Vec<u64> {
        if t_inst == 0 {
            return Vec::new();
        }
        let n_actual = self.slot_verificado.div_euclid(t_inst);
        let desde = self.frontera_consumida.map_or(0, |k| k.saturating_add(1));
        let piso = n_actual.saturating_sub(h);
        let desde = desde.max(piso);
        if desde > n_actual {
            return Vec::new();
        }
        (desde..=n_actual).collect()
    }

    /// ¿Hay alguna frontera pendiente? Coste `O(1)`.
    #[must_use]
    pub fn hay_fronteras(&self, t_inst: u64, h: u64) -> bool {
        if t_inst == 0 {
            return false;
        }
        let n_actual = self.slot_verificado.div_euclid(t_inst);
        let desde = self.frontera_consumida.map_or(0, |k| k.saturating_add(1));
        desde.max(n_actual.saturating_sub(h)) <= n_actual
    }

    /// Marca como consumidas todas las fronteras hasta `n` inclusive.
    pub fn consumir_hasta(&mut self, n: u64) {
        self.frontera_consumida = Some(self.frontera_consumida.map_or(n, |k| k.max(n)));
    }
}

#[cfg(test)]
mod pruebas {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        reason = "fixtures internas que fallan por panic"
    )]

    use super::*;
    use zx_core::digest::Digest;

    fn terminal(byte: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([byte; 32]))
    }

    fn salida(cursor: &CursorVotos, slot: u64) -> SalidaVerificada {
        SalidaVerificada::nueva(cursor.terminal(), cursor.generacion(), slot)
    }

    #[test]
    fn avanzar_es_monotono_y_la_repetida_no_mueve() {
        let mut c = CursorVotos::nuevo(terminal(1), 1, 0);
        assert_eq!(
            c.registrar(salida(&c, 10)),
            Movimiento::Avanza {
                anterior: 0,
                nuevo: 10
            }
        );
        assert_eq!(c.registrar(salida(&c, 10)), Movimiento::Repetida);
        assert_eq!(c.registrar(salida(&c, 7)), Movimiento::Repetida);
        assert_eq!(c.slot_verificado(), 10, "nunca rebobina");
        assert_eq!(
            c.registrar(salida(&c, 12)),
            Movimiento::Avanza {
                anterior: 10,
                nuevo: 12
            }
        );
    }

    #[test]
    fn generacion_abandonada_y_terminal_ajeno_no_mueven() {
        let mut c = CursorVotos::nuevo(terminal(1), 2, 4);
        let abandonada = SalidaVerificada::nueva(terminal(1), 1, 99);
        assert_eq!(c.registrar(abandonada), Movimiento::GeneracionAbandonada);
        assert_eq!(c.slot_verificado(), 4);
        let ajena = SalidaVerificada::nueva(terminal(2), 2, 99);
        assert_eq!(c.registrar(ajena), Movimiento::TerminalAjeno);
        assert_eq!(c.slot_verificado(), 4);
    }

    #[test]
    fn reconciliar_no_rebobina_y_abandona_la_generacion_vieja() {
        let mut c = CursorVotos::nuevo(terminal(1), 1, 100);
        c.reconciliar(terminal(2), 1);
        assert_eq!(c.terminal(), terminal(2));
        assert_eq!(c.slot_verificado(), 100, "la reorg no rebobina");
        assert!(
            c.generacion() >= 2,
            "la generación avanza al cambiar terminal"
        );
        let vieja = SalidaVerificada::nueva(terminal(1), 1, 200);
        assert_eq!(c.registrar(vieja), Movimiento::TerminalAjeno);
        assert_eq!(c.slot_verificado(), 100);
    }

    #[test]
    fn salto_grande_es_intervalo_acotado_al_horizonte() {
        let c = CursorVotos::nuevo(terminal(1), 1, 10_000);
        let pendientes = c.fronteras_pendientes(2, 3);
        // n_actual = 5_000; piso = 4_997; rango [4_997, 5_000].
        assert_eq!(pendientes, vec![4_997, 4_998, 4_999, 5_000]);
        assert!(pendientes.len() <= 4, "coste O(H), no O(n)");
    }

    #[test]
    fn las_fronteras_salen_en_orden_y_el_consumo_es_idempotente() {
        let mut c = CursorVotos::nuevo(terminal(1), 1, 8);
        assert_eq!(c.fronteras_pendientes(2, 100), vec![0, 1, 2, 3, 4]);
        c.consumir_hasta(2);
        assert_eq!(c.fronteras_pendientes(2, 100), vec![3, 4]);
        c.consumir_hasta(2);
        assert_eq!(c.fronteras_pendientes(2, 100), vec![3, 4]);
        c.consumir_hasta(4);
        assert!(c.fronteras_pendientes(2, 100).is_empty());
        assert!(!c.hay_fronteras(2, 100));
    }

    #[test]
    fn una_frontera_no_consumida_se_repite_hasta_consumirse() {
        let c = CursorVotos::nuevo(terminal(1), 1, 4);
        assert_eq!(c.fronteras_pendientes(2, 100), vec![0, 1, 2]);
        assert_eq!(c.fronteras_pendientes(2, 100), vec![0, 1, 2]);
        assert!(c.hay_fronteras(2, 100));
    }

    #[test]
    fn ventana_cero_no_produce_fronteras() {
        let c = CursorVotos::nuevo(terminal(1), 1, 500);
        assert!(c.fronteras_pendientes(0, 10).is_empty());
        assert!(!c.hay_fronteras(0, 10));
    }
}
