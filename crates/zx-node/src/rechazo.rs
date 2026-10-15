//! Clasificación de un rechazo de bloque **propio** (`ORDEN-W06d5` decisión 3).
//!
//! Sustituye la regla general de `ORDEN-W06d1` («bloque propio rechazado ⇒ fallo fatal») por una
//! distinción explícita:
//!
//! - **Legítimo**: el motivo depende de un estado externo/concurrente que pudo cambiar entre el
//!   momento en que el nodo eligió (padres, slot, clave) y el momento en que verificó el bloque ya
//!   construido, y el candidato **ya construido** es permanentemente inválido tal cual (su padre,
//!   su slot o su clave no van a cambiar). Se registra con su motivo, se descarta el bloque y **el
//!   nodo sigue**; para un bloque de red, sigue penalizando al remitente (es un defecto verificable
//!   del candidato, `MotivoCabeceraInvalida`/`MotivoBloque`, no una carrera de contexto local).
//! - **Pendiente**: falta de contexto **local** (típicamente `Pot(PasadoIncompleto)`, un nodo que
//!   sincroniza fuera de orden y cuyo `ServicioPot` de verificación todavía no completó el pasado
//!   PoT de algún ancestro): nunca es prueba de invalidez (contrato propio de
//!   [`MotivoCabeceraPendiente`]). Aviso del director, `ORDEN-W06d5`, tras el hallazgo de V5: para
//!   un bloque **propio**, se descarta igual que `Legitimo` (no hay reintento posible: el nodo no
//!   va a producir el mismo bloque otra vez); para un bloque de **red**, **nunca** penaliza ni se
//!   cachea como inválido (`Ignorar`, no `Rechazar`) y se reintenta cuando el propio pasado avance
//!   (`Nodo::reintentar_post_pendientes`) — es exactamente el riesgo de RI-2a (un hueco local
//!   guardado para siempre como si fuera un defecto del candidato).
//! - **Interno**: una violación de invariante interna — un estado que el propio código garantiza
//!   imposible (forma, firma, cuenta o estructura que el nodo construyó por completo desde su
//!   propio estado). Sigue siendo **fatal** para un bloque propio (decisión 4 de `ORDEN-W06d1`, sin
//!   cambios); para un bloque de red, penaliza igual que `Legitimo`.
//! - **ImposibleSinPenalizar** (`ORDEN-W06d6`, RI-3c H2): `MotivoCabeceraPendiente::PruebaPotIncoherente`
//!   y `MotivoCabeceraPendiente::RangoSinAtadura` documentan, en el propio contrato del tipo
//!   (`zx_post::cabecera_conjunta`), que **no deberían ocurrir por construcción** —a diferencia del
//!   resto de `Pendiente`, que sí es carencia de contexto local genuina (`Pot(PasadoIncompleto)` en
//!   un nodo que sincroniza fuera de orden). Si ocurren de verdad, no tiene sentido reintentar (el
//!   hueco no se va a llenar solo, no es un problema de orden de llegada) pero tampoco hay certeza
//!   de que sea un defecto **del candidato**: puede ser un fallo de este nodo (una implementación
//!   nuestra que rompe la garantía que el propio tipo declara). Fatal si es propio, igual que
//!   `Interno`; si es de red, se rechaza (no se reintenta, no se acepta) pero **sin penalizar** al
//!   remitente — es la diferencia con `Interno`.
//! - **VistaLocal** (`ORDEN-W06d10-B`): la aparente invalidez depende de la **vista local** del nodo,
//!   no de un defecto demostrable del candidato. Las tres familias del hallazgo V1 de W06d10:
//!   (X1) `ErrorPow::TimestampDemasiadoFuturo` (C-TS-03, `ts ≤ reloj_local + ftl`; el propio tipo lo
//!   declara **no permanente** en [`zx_consensus::ErrorPow::es_permanente`]), (X2)
//!   `MotivoBloque::ErrLimiteTerminales` (tope **local** de terminales con DAG, `zx-cadena`) y (X3)
//!   los fallos **locales** de persistencia/servicio (que en el borde de red llegan como
//!   `ErrorNodo` sin `BloquePropioRechazado`). Para un bloque de **red**: `Ignorar` — ni se
//!   desconecta, ni se puntúa, ni se escribe `par_penalizado`, ni se vuelve a marcar como `Rechazar`
//!   por el motivo cacheado. Para uno **propio**: igual que `Interno` en fatalidad (`es_legitimo()`
//!   `== false`), porque `ORDEN-W06d10-B` decisión 2 prohíbe cambiar si un fallo local es fatal
//!   para el nodo.
//!
//! # Motivos legítimos y su justificación (`REVISION-W06d4.md`)
//!
//! - [`MotivoBloque::ErrGarantia`] — la garantía activa de un productor puede variar entre el
//!   momento en que el hilo productor comprobó `Estado(padre_seleccionado)` (decisión 1 de esta
//!   orden) y el momento en que el motor la vuelve a comprobar sobre `Estado(past(B))` completo
//!   (RD-9): un incidente/confiscación (SL-4a, ahora integrada) admitido en una rama concurrente
//!   entre medias puede bajarla. Evidenciado en V5-1.
//! - [`MotivoBloque::ErrMergeDepth`] — cota RD-5 (`F_slots`): dispara con concurrencia/tiempo real
//!   suficiente entre la elección de padres y la admisión, no por un bug. Evidenciado en V6(b).
//! - [`MotivoBloque::ErrMergeset`] — cota R-FIN-12 análoga a `ErrMergeDepth` (demasiados bloques se
//!   fusionaron mientras tanto): misma familia, mismo razonamiento, sin bug.
//! - [`MotivoBloque::ErrU2`] — el billete pudo consumirse de verdad en una rama concurrente entre
//!   la elección y la verificación: la protección U2 funcionando correctamente, no un defecto.
//! - [`MotivoBloque::ErrTransicion`]` (`[`ErrorTransicion::ErrPowTrasCorte`]`)` — el corte (Φ) lo
//!   pudo fijar un bloque de red admitido justo entre que este nodo empezó a minar y a admitir su
//!   propio bloque PoW; es exactamente la misma familia de carrera que las anteriores.
//! - [`MotivoCabeceraInvalida::Padres`]` con `[`ErrorDag::SlotDePadrePosterior`]`,
//!   `[`ErrorDag::PadresNoAnticadena`]` o `[`ErrorDag::PadreSeleccionadoIncorrecto`]` — el GHOSTDAG
//!   cambió (un padre extra o el propio DAG avanzó) entre que el hilo productor pidió los padres y
//!   el bucle verificó el bloque ya construido. `SlotDePadrePosterior` evidenciado en V5-2; los
//!   otros dos comparten idéntico mecanismo (mismo paso de verificación, mismo tipo de carrera).
//! - [`MotivoCabeceraInvalida::Pot`]` con `[`MotivoPotInvalido::SlotDePadrePosterior`]` — la misma
//!   carrera, vista desde la comprobación de rango PoT en vez de la de padres del DAG.
//! - **Toda** variante de [`MotivoCabeceraPendiente`] — por contrato propio del tipo (docstring de
//!   `zx_post::cabecera_conjunta`): "ninguno de estos casos es una prueba de invalidez: no deben
//!   cachearse como rechazo permanente". Es una declaración categórica del propio autor del tipo,
//!   no una inferencia de este módulo.
//!
//! Todo lo demás (forma, sello Ed25519, cuenta de la coinbase, estructura de la transición, PoAS,
//! PoT que no ancla, etc.) es **interno**: el propio nodo construyó ese bloque desde su propio
//! estado sin ninguna dependencia de qué hace otro proceso mientras tanto, así que un rechazo ahí
//! delata un defecto real de construcción, no una carrera — el criterio y el valor por defecto son
//! deliberadamente conservadores (a favor de fatal, no de silenciar un bug).

use zx_cadena::MotivoBloque;
use zx_consensus::ErrorPow;
use zx_consensus::transicion::ErrorTransicion;
use zx_dag::ErrorDag;
use zx_post::cabecera_conjunta::{MotivoCabeceraInvalida, MotivoCabeceraPendiente};
use zx_post::pot_rango::MotivoPotInvalido;

/// Si un rechazo de bloque propio debe tirar el proceso (`Interno`) o solo registrarse y descartar
/// el bloque, dejando que el nodo siga (`Legitimo`). Ver el docstring del módulo para el criterio y
/// la lista completa, con su justificación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClasificacionRechazo {
    /// Rechazo legítimo del protocolo ante un caso de borde real, con el candidato permanentemente
    /// inválido tal cual se construyó: se registra y se descarta (propio); penaliza si es de red.
    Legitimo,
    /// Falta de contexto **local**, nunca prueba de invalidez (contrato de
    /// `MotivoCabeceraPendiente`): se descarta sin penalizar si es propio; si es de red, **no**
    /// penaliza ni se cachea como inválido, y se reintenta más tarde.
    Pendiente,
    /// Violación de invariante interna: fatal si es propio (decisión 4 de `ORDEN-W06d1`, sin
    /// cambios); penaliza igual que `Legitimo` si es de red.
    Interno,
    /// `ORDEN-W06d6`, RI-3c H2: comprobación marcada "imposible por construcción" en su propio
    /// contrato que sin embargo ocurrió (`PruebaPotIncoherente`, `RangoSinAtadura`). Fatal si es
    /// propio, igual que `Interno`; si es de red, se rechaza (`VeredictoFinal::Ignorar`: no se
    /// reintenta, no se acepta) pero **sin penalizar** al remitente, porque no hay certeza de que
    /// sea un defecto suyo y no nuestro.
    ImposibleSinPenalizar,
    /// `ORDEN-W06d10-B`: la aparente invalidez depende de la **vista local** del nodo (reloj local
    /// de C-TS-03, tope local de terminales con DAG, o un fallo local de persistencia/servicio), no
    /// de un defecto demostrable del candidato. Fatal si es propio, igual que `Interno` (decisión 2
    /// de la orden: no cambia la fatalidad de un fallo local); si es de red, `Ignorar` sin
    /// desconectar, sin puntuar y sin `par_penalizado`. Ver el docstring del módulo.
    VistaLocal,
}

impl ClasificacionRechazo {
    /// ¿Es un rechazo no fatal para un bloque **propio** (`Legitimo` o `Pendiente`)?
    #[must_use]
    pub const fn es_legitimo(self) -> bool {
        matches!(self, Self::Legitimo | Self::Pendiente)
    }

    /// ¿Es falta de contexto local, sin penalización ni caché de invalidez para un bloque de
    /// **red** (`Ignorar`, no `Rechazar`)?
    #[must_use]
    pub const fn es_pendiente(self) -> bool {
        matches!(self, Self::Pendiente)
    }

    /// ¿La aparente invalidez depende de la **vista local** del nodo (`ORDEN-W06d10-B`)? Un bloque
    /// de red con esta clasificación es `Ignorar` (ni penaliza ni se marca como inválido de forma
    /// permanente); uno propio conserva la fatalidad de `Interno`.
    #[must_use]
    pub const fn es_vista_local(self) -> bool {
        matches!(self, Self::VistaLocal)
    }

    /// ¿Un bloque de red con esta clasificación debe **penalizar** al remitente si se descarta?
    /// (`ORDEN-W06d6`, RI-3c H2). `Legitimo` e `Interno` sí (defecto verificable, atribuible al
    /// candidato); `ImposibleSinPenalizar` no (podría ser un fallo nuestro); `VistaLocal` no (la
    /// invalidación es de la vista local, no del candidato); `Pendiente` nunca llega a este punto
    /// (se reintenta, no se rechaza).
    #[must_use]
    pub const fn penaliza_en_red(self) -> bool {
        matches!(self, Self::Legitimo | Self::Interno)
    }
}

/// Clasifica un [`MotivoCabeceraInvalida`] (fallo **del candidato**, `verificar_cabecera_conjunta`).
#[must_use]
pub fn clasificar_cabecera_invalida(m: &MotivoCabeceraInvalida) -> ClasificacionRechazo {
    use ClasificacionRechazo::{Interno, Legitimo};
    match m {
        MotivoCabeceraInvalida::Padres(
            ErrorDag::SlotDePadrePosterior { .. }
            | ErrorDag::PadresNoAnticadena { .. }
            | ErrorDag::PadreSeleccionadoIncorrecto { .. },
        ) => Legitimo,
        MotivoCabeceraInvalida::Pot(MotivoPotInvalido::SlotDePadrePosterior { .. }) => Legitimo,
        _ => Interno,
    }
}

/// Casi toda [`MotivoCabeceraPendiente`] es `Pendiente` (nunca prueba de invalidez) por contrato
/// del propio tipo: ver el docstring del módulo. Las dos excepciones (`ORDEN-W06d6`, RI-3c H2) son
/// las que el propio tipo documenta como imposibles por construcción: si ocurren de verdad no son
/// una carencia de contexto que se vaya a resolver reintentando.
#[must_use]
pub const fn clasificar_cabecera_pendiente(m: &MotivoCabeceraPendiente) -> ClasificacionRechazo {
    match m {
        MotivoCabeceraPendiente::PruebaPotIncoherente
        | MotivoCabeceraPendiente::RangoSinAtadura => ClasificacionRechazo::ImposibleSinPenalizar,
        _ => ClasificacionRechazo::Pendiente,
    }
}

/// Clasifica un [`MotivoBloque`] (`Cadena::admitir`).
#[must_use]
pub fn clasificar_motivo_bloque(m: &MotivoBloque) -> ClasificacionRechazo {
    use ClasificacionRechazo::{Interno, Legitimo, VistaLocal};
    match m {
        MotivoBloque::ErrGarantia
        | MotivoBloque::ErrMergeDepth
        | MotivoBloque::ErrMergeset
        | MotivoBloque::ErrU2 => Legitimo,
        MotivoBloque::ErrTransicion(ErrorTransicion::ErrPowTrasCorte) => Legitimo,
        // `ORDEN-W06d10-B` X2: el tope de `MAX_TERMINALES_CON_DAG` es estado **local** (un nodo con
        // otra rama lateral decide distinto). No es un defecto demostrable del candidato.
        MotivoBloque::ErrLimiteTerminales => VistaLocal,
        _ => Interno,
    }
}

/// Clasifica un [`ErrorPow`] de `validar_cabecera_pow` (`ORDEN-W06d10-B` X1). El propio tipo declara
/// con [`ErrorPow::es_permanente`] qué variantes no lo son: hoy solo `TimestampDemasiadoFuturo`
/// (C-TS-03), cuyo contrato exige **diferir y no banear**. Se usa esa declaración, no una lista
/// propia, para que una variante futura no permanente herede la misma política.
#[must_use]
pub const fn clasificar_error_pow(e: &ErrorPow) -> ClasificacionRechazo {
    if e.es_permanente() {
        ClasificacionRechazo::Interno
    } else {
        ClasificacionRechazo::VistaLocal
    }
}

#[cfg(test)]
mod tests {
    use zx_cadena::MotivoBloque;
    use zx_consensus::ErrorPow;
    use zx_consensus::transicion::ErrorTransicion;
    use zx_core::BlockHash;
    use zx_dag::ErrorDag;
    use zx_post::cabecera_conjunta::{MotivoCabeceraInvalida, MotivoCabeceraPendiente};
    use zx_post::pot_rango::{MotivoPotInvalido, MotivoPotPendiente};

    use super::{
        ClasificacionRechazo, clasificar_cabecera_invalida, clasificar_cabecera_pendiente,
        clasificar_error_pow, clasificar_motivo_bloque,
    };

    fn hash_prueba() -> BlockHash {
        BlockHash::from_digest(zx_core::digest::Digest::from_bytes([0x7A; 32]))
    }

    /// `ORDEN-W06d5` decisión 3: los tres motivos evidenciados en V5/V6(b) de
    /// `REVISION-W06d4.md` deben clasificarse como legítimos (no fatales).
    #[test]
    fn motivos_evidenciados_en_w06d4_son_legitimos() {
        assert!(clasificar_motivo_bloque(&MotivoBloque::ErrGarantia).es_legitimo());
        assert!(clasificar_motivo_bloque(&MotivoBloque::ErrMergeDepth).es_legitimo());
        let motivo_padres = MotivoCabeceraInvalida::Padres(ErrorDag::SlotDePadrePosterior {
            padre: hash_prueba(),
            slot_padre: 10,
            slot_b: 9,
        });
        assert!(clasificar_cabecera_invalida(&motivo_padres).es_legitimo());
    }

    /// El resto de la familia de carrera (misma justificación, no evidenciados directamente pero
    /// idéntico mecanismo): también legítimos.
    #[test]
    fn resto_de_la_familia_de_carrera_es_legitima() {
        assert!(clasificar_motivo_bloque(&MotivoBloque::ErrMergeset).es_legitimo());
        assert!(clasificar_motivo_bloque(&MotivoBloque::ErrU2).es_legitimo());
        assert!(
            clasificar_motivo_bloque(&MotivoBloque::ErrTransicion(
                ErrorTransicion::ErrPowTrasCorte
            ))
            .es_legitimo()
        );
        let padres_no_anticadena = MotivoCabeceraInvalida::Padres(ErrorDag::PadresNoAnticadena {
            antepasado: hash_prueba(),
            descendiente: hash_prueba(),
        });
        assert!(clasificar_cabecera_invalida(&padres_no_anticadena).es_legitimo());
        let pot_slot_posterior =
            MotivoCabeceraInvalida::Pot(MotivoPotInvalido::SlotDePadrePosterior {
                padre: hash_prueba(),
                slot_padre: 10,
                slot_bloque: 9,
            });
        assert!(clasificar_cabecera_invalida(&pot_slot_posterior).es_legitimo());
    }

    /// Toda `MotivoCabeceraPendiente` es legítima (no fatal si es propia) y, específicamente,
    /// `Pendiente` (nunca penaliza ni se cachea como inválida si es de red) — aviso del director
    /// tras el hallazgo de V5 (`Pot(PasadoIncompleto)` no es un bloque inválido, es un hueco local).
    #[test]
    fn toda_cabecera_pendiente_es_legitima_y_pendiente() {
        let pasado_incompleto = MotivoCabeceraPendiente::Pot(MotivoPotPendiente::PasadoIncompleto);
        assert!(clasificar_cabecera_pendiente(&pasado_incompleto).es_legitimo());
        assert!(clasificar_cabecera_pendiente(&pasado_incompleto).es_pendiente());
        let contexto_ausente = MotivoCabeceraPendiente::ContextoPiezaAusente;
        assert!(clasificar_cabecera_pendiente(&contexto_ausente).es_legitimo());
        assert!(clasificar_cabecera_pendiente(&contexto_ausente).es_pendiente());
    }

    /// `ORDEN-W06d6`, RI-3c H2: `PruebaPotIncoherente` y `RangoSinAtadura` dejan de ser `Pendiente`
    /// (el propio tipo las documenta como imposibles por construcción, no como carencia de
    /// contexto): fatal si son propias (como `Interno`), y de red se rechazan sin penalizar.
    #[test]
    fn las_dos_imposibles_por_construccion_no_son_pendientes() {
        for m in [
            MotivoCabeceraPendiente::PruebaPotIncoherente,
            MotivoCabeceraPendiente::RangoSinAtadura,
        ] {
            let c = clasificar_cabecera_pendiente(&m);
            assert_eq!(c, ClasificacionRechazo::ImposibleSinPenalizar, "{m:?}");
            assert!(!c.es_pendiente(), "{m:?}: no debe reintentarse");
            assert!(!c.es_legitimo(), "{m:?}: fatal si es propia, como Interno");
            assert!(
                !c.penaliza_en_red(),
                "{m:?}: no debe penalizar al remitente"
            );
        }
    }

    /// `penaliza_en_red`: solo `Legitimo` e `Interno` penalizan; `ImposibleSinPenalizar`, `Pendiente`
    /// y `VistaLocal` no.
    #[test]
    fn solo_legitimo_e_interno_penalizan_en_red() {
        assert!(ClasificacionRechazo::Legitimo.penaliza_en_red());
        assert!(ClasificacionRechazo::Interno.penaliza_en_red());
        assert!(!ClasificacionRechazo::ImposibleSinPenalizar.penaliza_en_red());
        assert!(!ClasificacionRechazo::Pendiente.penaliza_en_red());
        assert!(!ClasificacionRechazo::VistaLocal.penaliza_en_red());
    }

    /// `Legitimo` (defecto verificable del candidato, no falta de contexto) no es `Pendiente`: la
    /// distinción importa para un bloque de red (`Ignorar` sin penalizar frente a `Rechazar` con
    /// penalización) aunque las dos sean no fatales para uno propio.
    #[test]
    fn legitimo_no_es_pendiente() {
        assert!(!ClasificacionRechazo::Legitimo.es_pendiente());
        assert!(ClasificacionRechazo::Legitimo.es_legitimo());
        assert!(!ClasificacionRechazo::Interno.es_pendiente());
        assert!(!ClasificacionRechazo::Interno.es_legitimo());
    }

    /// Un defecto de forma/firma/cuenta que el propio nodo construyó por completo sigue siendo
    /// interno (fatal): el valor por defecto es conservador.
    #[test]
    fn defectos_de_construccion_propia_siguen_siendo_internos() {
        assert!(!clasificar_motivo_bloque(&MotivoBloque::ErrSinPadre).es_legitimo());
        assert!(!clasificar_motivo_bloque(&MotivoBloque::ErrEmision).es_legitimo());
        assert!(!clasificar_motivo_bloque(&MotivoBloque::ErrSaldo).es_legitimo());
        assert!(
            !clasificar_motivo_bloque(&MotivoBloque::ErrTransicion(
                ErrorTransicion::ErrDesbordamiento
            ))
            .es_legitimo()
        );
        let sello_malo = MotivoCabeceraInvalida::Sello(zx_core::EncodingError::PadreDuplicado);
        assert!(!clasificar_cabecera_invalida(&sello_malo).es_legitimo());
        let sin_padres_transicion = MotivoCabeceraInvalida::Padres(ErrorDag::CabeceraPostSinPadres);
        assert!(!clasificar_cabecera_invalida(&sin_padres_transicion).es_legitimo());
    }

    /// `ORDEN-W06d10-B` **X1**: `ErrorPow::TimestampDemasiadoFuturo` (C-TS-03) depende del reloj
    /// local y el propio tipo lo declara no permanente: `VistaLocal`, que en red es `Ignorar` sin
    /// penalizar, y que para un bloque propio conserva la fatalidad (no cambia la decisión 2).
    #[test]
    fn x1_ftl_es_vista_local_y_no_penaliza() {
        let ftl = ErrorPow::TimestampDemasiadoFuturo {
            ts: 1_541,
            limite: 1_540,
        };
        let c = clasificar_error_pow(&ftl);
        assert_eq!(c, ClasificacionRechazo::VistaLocal, "{ftl:?}");
        assert!(c.es_vista_local());
        assert!(!c.penaliza_en_red(), "C-TS-03 exige diferir, no banear");
        assert!(!c.es_legitimo(), "para un bloque propio sigue siendo fatal");
        assert!(
            !c.es_pendiente(),
            "no entra en la cola de reintento de PoST"
        );
        assert!(!ftl.es_permanente());
    }

    /// `ORDEN-W06d10-B` **X1** (contraprueba): un fallo PoW **permanente** (p. ej. `PowInsuficiente`)
    /// sigue siendo un defecto demostrable del candidato: `Interno`, penaliza.
    #[test]
    fn x1_fallo_permanente_sigue_penalizando() {
        for e in [
            ErrorPow::PowInsuficiente,
            ErrorPow::DesbordamientoAritmetico,
        ] {
            let c = clasificar_error_pow(&e);
            assert_eq!(c, ClasificacionRechazo::Interno, "{e:?}");
            assert!(c.penaliza_en_red(), "{e:?}");
            assert!(e.es_permanente(), "{e:?}");
        }
    }

    /// `ORDEN-W06d10-B` **X2**: el tope **local** de terminales con DAG
    /// (`MotivoBloque::ErrLimiteTerminales`) es `VistaLocal`: `Ignorar` sin penalizar, y para un
    /// bloque propio conserva la fatalidad.
    #[test]
    fn x2_limite_terminales_es_vista_local_y_no_penaliza() {
        let c = clasificar_motivo_bloque(&MotivoBloque::ErrLimiteTerminales);
        assert_eq!(c, ClasificacionRechazo::VistaLocal);
        assert!(c.es_vista_local());
        assert!(!c.penaliza_en_red());
        assert!(!c.es_legitimo());
        assert!(!c.es_pendiente());
    }
}
