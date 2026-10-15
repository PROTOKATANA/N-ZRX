//! Errores de la capa de red.
//!
//! # La distinción que gobierna este enum
//!
//! **Un error de un peer NO es un error del nodo** (C-NET-05). La mayoría de lo que sale mal en una
//! red es culpa de un peer concreto —o de nadie— y la respuesta correcta es desconectarlo y seguir,
//! no propagar hacia arriba. Solo los errores de configuración y de arranque suben.

use thiserror::Error;

/// Error de la capa de red.
#[derive(Debug, Error)]
pub enum P2pError {
    /// Configuración inválida. Solo puede ocurrir al construir el nodo, nunca en caliente.
    #[error("configuración de red inválida: {0}")]
    Configuracion(&'static str),

    /// No se pudo levantar el transporte.
    #[error("no se pudo levantar el transporte: {0}")]
    Transporte(&'static str),

    /// `ORDEN-W06d6` decisión 3 (V7): la publicación local por `gossipsub` falló, con el motivo
    /// **real** que devolvió la librería (`gossipsub::PublishError`), no un texto fijo.
    ///
    /// Antes, cualquier fallo de `gossipsub.publish` (sin peers suscritos todavía —normal nada más
    /// conectar—, mensaje demasiado grande, error de firma, colas llenas...) se colapsaba en el
    /// mismo `P2pError::Transporte("gossipsub rechazó la publicación local")`: indistinguible entre
    /// sí y sin valor para diagnosticar `zx-adversario` (`REVISION-W06d5.md`, V7 parcial: «la ráfaga
    /// sigue fallando localmente... con el motivo real oculto»).
    #[error("gossipsub rechazó la publicación local: {0}")]
    Difusion(String),

    /// La dirección de escucha no es válida.
    #[error("dirección de escucha inválida")]
    DireccionInvalida,

    /// C-NET-13: la cadena ha crecido más de lo que este binario puede transportar.
    ///
    /// **No es un fallo de configuración: es un binario que se ha quedado viejo.** El límite de
    /// gossipsub se fija al construir el behaviour y no cambia en caliente, así que seguir
    /// funcionando significaría dejar de ver bloques válidos sin decirlo. Parar y avisar es
    /// estrictamente mejor.
    #[error(
        "C-NET-13: el límite de bloque de la cadena ({limite_bloque}) se ha acercado demasiado a lo \
         que este binario transporta ({limite_transporte}) — actualiza el nodo"
    )]
    MargenDeTransporteInsuficiente {
        /// `LIMITE(H)` vigente.
        limite_bloque: u64,
        /// Lo que este binario puede transportar.
        limite_transporte: usize,
    },
}

/// Por qué se corta con un peer.
///
/// Va **separado** de [`P2pError`] a propósito: son cosas de naturaleza distinta y mezclarlas
/// invita a tratar "este peer va lento" como si fuera "el nodo está roto".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MotivoDesconexion {
    /// No respondió a tiempo, o respondió vacío repetidas veces. **No puntúa** (C-NET-05).
    Lento,
    /// Mandó algo que no se puede ni parsear. **No puntúa**: puede ser una versión distinta.
    Ilegible,
    /// Superó un límite de tamaño de C-NET-11. **No puntúa**, pero se corta de inmediato.
    Excedido,
    /// Violación de consenso **positivamente identificada**. Esto sí puntúa hacia el baneo.
    ViolacionDeConsenso,
    /// ZRX-C (ORDEN-ZC3): el par no anuncia la capacidad de compresión en `identify`. **No
    /// puntúa**: un nodo desactualizado tiene una explicación inocente, y banearlo sería al revés
    /// (el viejo es él, no un atacante). Se corta con un motivo claro y se sigue.
    SinZrxC,
}

impl MotivoDesconexion {
    /// Cuántos puntos suma este motivo hacia el baneo del prefijo de red (C-NET-05, C-NET-20).
    ///
    /// # Los tres niveles, y por qué `Excedido` no es como los demás
    ///
    /// | Motivo | Puntos | Por qué |
    /// |---|---|---|
    /// | `ViolacionDeConsenso` | **100** — baneo de un golpe | Fabricarla cuesta trabajo real: no ocurre por accidente |
    /// | `Excedido` | **20** — cinco avisos | Es atribuible al emisor, pero admite una explicación inocente |
    /// | `Lento`, `Ilegible` | **0** | No son atribuibles a mala fe |
    ///
    /// **Por qué `Excedido` puntúa, si C-NET-05 dice que solo la violación de consenso lo hace.**
    /// Porque la razón de C-NET-05 no cubre este caso. Esa razón es la de Zebra sobre
    /// GHSA-qhr3-cvch-5fh2 —*quien te entrega un bloque no es quien eligió su altura*— y describe
    /// al **mensajero inocente**: un peer que reenvía contenido que él no fabricó.
    ///
    /// Mandar una respuesta de 20 MB cuando el límite pactado son 12,8 **no es reenviar**: es una
    /// acción del emisor. No hay ambigüedad sobre quién la causó.
    ///
    /// # Por qué 20 y no 100
    ///
    /// Porque **sí existe una explicación inocente**: un peer con una versión más nueva, cuyos
    /// límites son mayores porque la cadena creció (C-NET-13). Ahí el desactualizado somos nosotros,
    /// y banearlo sería exactamente al revés.
    ///
    /// Cinco avisos separan los dos casos **solos**, y esa es la parte elegante: como el score va
    /// por **prefijo de red** (C-NET-20), un desajuste de versión aparece como un `Excedido` desde
    /// **muchos prefijos distintos** —toda la red es más nueva que nosotros— mientras que sondear
    /// los límites aparece como muchos **desde el mismo**. La misma señal, leída por prefijo,
    /// distingue las dos causas sin que nadie tenga que decidirlo.
    ///
    /// Y el caso inocente deja además una huella que el operador puede leer: `Excedido` repetido
    /// desde prefijos distintos significa *"tu nodo se ha quedado viejo"*, no *"te están atacando"*.
    #[must_use]
    pub const fn puntos(self) -> u32 {
        match self {
            Self::ViolacionDeConsenso => 100,
            Self::Excedido => 20,
            Self::Lento | Self::Ilegible | Self::SinZrxC => 0,
        }
    }

    /// ¿Este motivo cuenta hacia el baneo?
    #[must_use]
    pub const fn puntua(self) -> bool {
        self.puntos() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::MotivoDesconexion;

    /// **C-NET-05.** Lento e ilegible **nunca** puntúan.
    ///
    /// Si `Lento` puntuara, un peer con mala conexión acabaría baneado — y, peor, un atacante
    /// podría provocar que baneemos a peers honestos ralentizándolos.
    #[test]
    fn lento_e_ilegible_nunca_puntuan() {
        for m in [
            MotivoDesconexion::Lento,
            MotivoDesconexion::Ilegible,
            MotivoDesconexion::SinZrxC,
        ] {
            assert!(!m.puntua(), "{m:?} MUST NOT puntuar");
            assert_eq!(m.puntos(), 0);
        }
    }

    /// **Una violación de consenso banea de un golpe.** Fabricarla cuesta trabajo real.
    #[test]
    fn la_violacion_de_consenso_banea_de_un_golpe() {
        assert_eq!(MotivoDesconexion::ViolacionDeConsenso.puntos(), 100);
    }

    /// **P-026 · `Excedido` puntúa, pero no banea de un golpe.**
    ///
    /// Puntúa porque la razón de C-NET-05 para no hacerlo —el mensajero inocente— **no cubre este
    /// caso**: mandar más bytes de los pactados es una acción del emisor, no un reenvío.
    ///
    /// Pero no de un golpe, porque sí hay una explicación inocente: un peer con versión más nueva
    /// cuyos límites son mayores porque la cadena creció. Cinco avisos separan los dos casos, y el
    /// score por prefijo lo hace solo — un desajuste de versión llega desde **muchos** prefijos, y
    /// sondear los límites desde **uno**.
    #[test]
    fn excedido_puntua_pero_admite_cinco_avisos() {
        let e = MotivoDesconexion::Excedido;
        assert!(e.puntua(), "es atribuible al emisor: MUST puntuar");
        assert_eq!(e.puntos(), 20);

        // Cinco avisos alcanzan el umbral de baneo; cuatro, no.
        assert!(e.puntos() * 4 < 100, "cuatro avisos NO banean");
        assert!(e.puntos() * 5 >= 100, "cinco sí");

        // Y sigue siendo menos grave que una violación de consenso.
        assert!(e.puntos() < MotivoDesconexion::ViolacionDeConsenso.puntos());
    }
}
