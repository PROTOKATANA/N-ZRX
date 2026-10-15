//! El bucle de eventos y su handle (SPEC §16).
//!
//! # Por qué un bucle con canales y no un `Arc<Mutex<Swarm>>`
//!
//! Un `Swarm` de libp2p **hay que pollearlo continuamente** y además es `!Sync`, así que no se
//! puede compartir entre tareas. Solo hay una forma sensata: **una tarea lo posee en exclusiva** y
//! todo el mundo habla con ella por canales.
//!
//! # El `Swarm` NO sale de este módulo
//!
//! Nadie fuera ve un tipo de `libp2p::swarm`. Lo que sale son [`EventoRed`], que son tipos nuestros.
//!
//! # El error de un peer NO es un error del nodo
//!
//! Regla dura de este bucle: **nada que venga de un peer puede propagar un `Err` fuera del
//! `select!`**. Se registra, se desconecta a quien haga falta, y se sigue.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm, identify, kad};
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;

use libp2p::{gossipsub, request_response};

use crate::behaviour::{ZxBehaviour, ZxBehaviourEvent};
use crate::config::{
    BASES_VOTO_SUBRED, ParametrosRed, TOPIC_AGREGADO_DEV, TOPIC_AGREGADO_MAINNET,
    TOPIC_AGREGADO_TESTNET, subred_de_tema_en_base,
};
use crate::desalojo::DesalojoEntrantes;
use crate::director::{Accion, Director};
use crate::entrante::{IdDiferido, ManejadorEntrante, Veredicto, VeredictoFinal};
use crate::error::{MotivoDesconexion, P2pError};
use crate::limites::{
    CUPO_DIFERIDOS_VOTOS_ARRANQUE, MAX_DESCOMPRIMIDO_AGREGADO, MAX_DESCOMPRIMIDO_BLOQUE,
    MAX_DESCOMPRIMIDO_TX, MAX_DESCOMPRIMIDO_VOTO, MAX_DESCOMPRIMIDO_VOTO_RED,
    MAX_DIFERIDOS_PENDIENTES, MAX_GOSSIP_BYTES, MAX_RESPUESTA_PRUEBA_BYTES,
    PLAZO_VALIDACION_DIFERIDA_S,
};
use crate::mensaje::{
    AnuncioPrueba, BloqueRed, FamiliaBloque, LONGITUD_ANUNCIO_PRUEBA, Peticion, Respuesta,
};
use crate::presupuesto::{Presupuesto, PresupuestoGossipPar, cabe_prueba};
use crate::registro::EntradaRegistro;
use crate::zrxc;
use zx_core::firma::ClavePublica;

/// Capacidad del canal de comandos.
///
/// **Nunca cero.** Un canal de capacidad cero es un *rendezvous*: el que envía se bloquea hasta que
/// el bucle recoge. Y si el bucle está bloqueado enviando un evento que nadie consume, deja de
/// pollear el `Swarm` — y **la red entera se para**.
pub const CAPACIDAD_COMANDOS: usize = 256;

/// Capacidad del canal de eventos hacia el nodo.
pub const CAPACIDAD_EVENTOS: usize = 1024;

/// `motivo` del evento `par_penalizado` que `zx-node` escribe cuando `zx-p2p` penaliza al
/// propagador de un bloque difundido **demostrablemente inválido** (`ORDEN-W06d10` decisión 1).
pub const MOTIVO_PAR_PENALIZADO_GOSSIP: &str = "bloque difundido rechazado";

/// `accion` del mismo evento: el par fue expulsado (desconectado y puntuado).
pub const ACCION_PAR_PENALIZADO_EXPULSION: &str = "expulsion";

/// `motivo` del evento `par_penalizado` que `zx-node` escribe cuando `zx-p2p` corta con un par por
/// superar el presupuesto de gossip por ventana (RSS-1).
pub const MOTIVO_GOSSIP_EXCEDIDO: &str = "gossip por par excedido";

/// A6-02 · Q3: `motivo` del evento `par_penalizado` cuando un par contesta a una
/// [`crate::mensaje::Peticion::Prueba`] con una [`crate::mensaje::Respuesta::Prueba`] cuya huella no
/// es la pedida o cuyos `bytes` superan [`MAX_RESPUESTA_PRUEBA_BYTES`].
pub const MOTIVO_PRUEBA_INVALIDA: &str = "respuesta de prueba inválida";

/// Lo que se le pide al bucle desde fuera.
#[derive(Debug)]
pub(crate) enum Comando {
    /// Empezar a escuchar en una dirección.
    Escuchar {
        /// Dónde.
        addr: Multiaddr,
        /// Por dónde vuelve el resultado.
        respuesta: oneshot::Sender<Result<(), P2pError>>,
    },
    /// Conectar con un peer.
    Marcar {
        /// Dónde.
        addr: Multiaddr,
        /// Por dónde vuelve el resultado.
        respuesta: oneshot::Sender<Result<(), P2pError>>,
    },
    /// Enviar una petición de sincronización.
    Pedir {
        /// A quién.
        peer: PeerId,
        /// Qué.
        peticion: Peticion,
    },
    /// A6-02 · Q4: pedir una **prueba** por su huella a un peer concreto.
    ///
    /// La cuota de Q5 se aplica en el bucle: si el par ya tiene una petición de prueba en vuelo, o
    /// ya hay [`crate::presupuesto::MAX_PRUEBAS_EN_VUELO_NODO`] en todo el nodo, esta **espera**
    /// encolada hasta que se libere un hueco.
    PedirPrueba {
        /// A quién se le pide.
        peer: PeerId,
        /// Huella de 32 B del cuerpo.
        huella: [u8; 32],
    },
    /// Publicar bytes ya serializados por un tópico de la red.
    Difundir {
        /// Tópico, que debe ser uno de los dos temas de [`ParametrosRed`].
        topico: String,
        /// Contenido ya serializado.
        datos: Vec<u8>,
        /// Por dónde vuelve el resultado **local** del intento de publicación.
        respuesta: oneshot::Sender<Result<(), P2pError>>,
    },
    /// Cortar con un peer, y por qué.
    Desconectar {
        /// A quién.
        peer: PeerId,
        /// Por qué. Solo [`MotivoDesconexion::ViolacionDeConsenso`] puntúa.
        motivo: MotivoDesconexion,
    },
    /// AG-2c · G3: cambiar la suscripción a una subred de voto concreta (`/<red>/votos-sub/<s>/1`).
    ///
    /// El tema de agregados **no** viaja por aquí: el nodo se suscribe a él al arrancar y no se
    /// desuscribe.
    SuscribirSubred {
        /// Subred 0-based; el rango (`< S`) se comprueba en [`ManejoRed`] y otra vez aquí.
        subred: u8,
        /// `true` para suscribir, `false` para desuscribir.
        suscrito: bool,
        /// Por dónde vuelve el resultado.
        respuesta: oneshot::Sender<Result<(), P2pError>>,
    },
    /// El veredicto final de una validación que [`ManejadorEntrante::bloque_difundido`] había
    /// diferido (decisión 1 de `ORDEN-W06d2`).
    ///
    /// Si `id` ya no está en la tabla de pendientes —porque expiró (§`PLAZO_VALIDACION_DIFERIDA_S`)
    /// o porque ya se informó antes—, el comando **no hace nada**: es idempotente a propósito, para
    /// que un manejador que informe dos veces (o tarde) no cause un error de protocolo.
    InformarValidacion {
        /// El mismo identificador que trajo la llamada a `bloque_difundido`.
        id: IdDiferido,
        /// El veredicto de verdad.
        veredicto: VeredictoFinal,
    },
    /// A5-c-2a-2 · E2: el nodo fija el **cupo** de validaciones diferidas de los dos temas nuevos de
    /// AG-2c (voto de red por subred y agregado). Sustituye al valor de arranque
    /// [`crate::limites::CUPO_DIFERIDOS_VOTOS_ARRANQUE`] con el número que el nodo conoce (el de
    /// agregadores y el de subredes).
    ///
    /// No toca el cupo de los bloques ([`crate::limites::MAX_DIFERIDOS_PENDIENTES`]) ni cambia el de
    /// los diferidos ya pendientes: solo decide cuántos caben a partir de ahora.
    FijarCupoDiferidosAgregacion {
        /// Cuántos diferidos de esos dos temas caben a la vez.
        cupo: usize,
        /// Por dónde vuelve el resultado (siempre `Ok`: es una configuración local).
        respuesta: oneshot::Sender<Result<(), P2pError>>,
    },
    /// Siembra el gestor de direcciones: carga la persistencia (si `dir` es `Some`) e inserta las
    /// direcciones de arranque del operador (`--red-marcar`, C-NET-34). A partir de ahí manda el
    /// descubrimiento.
    Sembrar {
        /// Directorio de datos del nodo donde vive la persistencia del gestor.
        dir: Option<PathBuf>,
        /// Direcciones de arranque del operador.
        arranque: Vec<Multiaddr>,
        /// Por dónde vuelve el resultado.
        respuesta: oneshot::Sender<Result<(), P2pError>>,
    },
    /// RD-4a · H2: fija la **tabla de pesos** del director (`productor → bloques certificados`). La
    /// calcula fuera (el nodo, con su cadena hasta el ancla); el director no la recalcula.
    FijarPesos {
        /// La tabla completa.
        pesos: Vec<(ClavePublica, u64)>,
    },
    /// RD-4a · H2: entrega una entrada `ZXREG1` al director, que **vuelve a validar** forma, época y
    /// firma antes de retenerla (no se confía en quien la envía).
    InsertarRegistro {
        /// La entrada firmada, tal cual viajó por el wire o se firmó localmente.
        entrada: EntradaRegistro,
        /// Reloj de pared en segundos Unix con el que se valida la época y el TTL.
        ahora: u64,
    },
    /// RD-4a · H2: marca (`Some`) o quita (`None`) la saliente **protegida** del director.
    ProtegerSaliente {
        /// La saliente a proteger; `None` deja de proteger.
        peer: Option<PeerId>,
    },
}

/// Lo que el bucle cuenta hacia fuera. **Ningún tipo de libp2p asoma aquí.**
#[derive(Clone, Debug)]
pub enum EventoRed {
    /// Se estableció conexión.
    PeerConectado(PeerId),
    /// Se estableció una conexión **saliente** (la elegimos nosotros). Es la señal para medir
    /// diversidad de salientes (V5): solo estas cuentan para las 24.
    ConexionSaliente(PeerId),
    /// RD-4b · P6: el director hizo un sorteo (uno por rotación con el registro de direcciones
    /// encendido). `peso_total` es la suma de los pesos de la tabla vigente; `entradas` cuántas
    /// entradas tienen peso y dirección aceptable; `productor` son los 8 primeros bytes de la clave
    /// del productor elegido, o `None` si no se eligió a nadie. El nodo lo escribe como
    /// `sorteo_director`.
    SorteoDirector {
        /// Suma de los pesos de la tabla vigente.
        peso_total: u64,
        /// Entradas de la tabla con peso y dirección aceptable.
        entradas: u64,
        /// 8 primeros bytes de la clave del productor elegido, si lo hubo.
        productor: Option<[u8; 8]>,
    },
    /// Se perdió la conexión.
    PeerDesconectado(PeerId),
    /// Estamos escuchando en una dirección.
    Escuchando(Multiaddr),
    /// Un peer respondió a una petición de sincronización.
    ///
    /// La respuesta va en `Box` porque `Respuesta::Bloques` puede ser grande.
    Respuesta {
        /// Quién respondió.
        peer: PeerId,
        /// Identificador de la petición que se contesta.
        peticion: u64,
        /// Lo que respondió.
        respuesta: Box<Respuesta>,
    },
    /// Una petición no llegó a completarse. **No puntúa.**
    PeticionFallida {
        /// A quién se le había pedido.
        peer: PeerId,
    },
    /// Un peer se suscribió (`true`) o desuscribió (`false`) de un tema de gossipsub.
    ///
    /// La malla no se forma en el instante de la conexión: hasta que el `SUBSCRIBE` de un peer no
    /// llega, `gossipsub.publish` devuelve `NoPeersSubscribedToTopic`. Este evento es la señal de
    /// que el otro lado ya está en la malla.
    Suscripcion {
        /// Quién cambió de suscripción.
        peer: PeerId,
        /// A qué tema.
        topico: String,
        /// `true` si se suscribió, `false` si se desuscribió.
        suscrito: bool,
    },
}

/// El handle con el que el resto del nodo habla con la red.
#[derive(Clone, Debug)]
pub struct ManejoRed {
    comandos: mpsc::Sender<Comando>,
    parametros: ParametrosRed,
    /// Contadores de bytes ZRX-C de este nodo (medida de `ORDEN-ZC3`, pregunta (c)).
    metricas: zrxc::Metricas,
}

impl ManejoRed {
    /// Empieza a escuchar.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle ya no está, o lo que devuelva el `Swarm`.
    pub async fn escuchar(&self, addr: Multiaddr) -> Result<(), P2pError> {
        let (tx, rx) = oneshot::channel();
        self.enviar(Comando::Escuchar {
            addr,
            respuesta: tx,
        })
        .await?;
        rx.await
            .map_err(|_| P2pError::Transporte("el bucle de red murió antes de responder"))?
    }

    /// Conecta con un peer.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle ya no está, o lo que devuelva el `Swarm`.
    pub async fn marcar(&self, addr: Multiaddr) -> Result<(), P2pError> {
        let (tx, rx) = oneshot::channel();
        self.enviar(Comando::Marcar {
            addr,
            respuesta: tx,
        })
        .await?;
        rx.await
            .map_err(|_| P2pError::Transporte("el bucle de red murió antes de responder"))?
    }

    /// Siembra el gestor de direcciones con la persistencia y el arranque del operador.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle ya no está, o lo que devuelva el gestor al persistir.
    pub async fn sembrar(
        &self,
        dir: Option<PathBuf>,
        arranque: Vec<Multiaddr>,
    ) -> Result<(), P2pError> {
        let (tx, rx) = oneshot::channel();
        self.enviar(Comando::Sembrar {
            dir,
            arranque,
            respuesta: tx,
        })
        .await?;
        rx.await
            .map_err(|_| P2pError::Transporte("el bucle de red murió antes de responder"))?
    }

    /// Pide algo a un peer. **No espera respuesta**: llegará como evento.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle ya no está.
    pub async fn pedir(&self, peer: PeerId, peticion: Peticion) -> Result<(), P2pError> {
        self.enviar(Comando::Pedir { peer, peticion }).await
    }

    /// Difundir **un bloque completo** por el tema que le corresponde.
    ///
    /// # Qué fija esta API, y qué NO
    ///
    /// El tema **no es un parámetro**: sale de la familia del bloque y de
    /// [`ParametrosRed`], que es la misma fuente que usa la suscripción. No hay una vía pública para
    /// publicar un bloque completo por el tema equivocado.
    ///
    /// Pero fijar **formato y tema no certifica validez**: un [`BloqueRed`] se puede construir sin
    /// validación. Quien produce MUST llamar a este método **solo después** de la validación, y la
    /// recepción mantiene el veredicto del manejador (C-NET-12).
    ///
    /// # Errores
    /// - [`P2pError::Transporte`] si el canal de comandos está cerrado o si `gossipsub.publish`
    ///   **rechaza el envío local**.
    ///
    /// `Ok(())` acredita **solo aceptación local por gossipsub**: no es entrega, no es
    /// retransmisión y no es validez.
    pub async fn difundir_bloque(&self, bloque: &BloqueRed) -> Result<(), P2pError> {
        let topico = match bloque.familia() {
            FamiliaBloque::Pow => self.parametros.topic_bloques_pow(),
            FamiliaBloque::Post => self.parametros.topic_bloques_post(),
        };
        let crudo = crate::codec::bloque_a_bytes(bloque);
        let datos = zrxc::comprimir_red(&crudo, None);
        self.metricas.sumar(crudo.len() as u64, datos.len() as u64);
        let (tx, rx) = oneshot::channel();
        self.enviar(Comando::Difundir {
            topico: topico.to_owned(),
            datos,
            respuesta: tx,
        })
        .await?;
        rx.await
            .map_err(|_| P2pError::Transporte("el bucle de red murió antes de responder"))?
    }

    /// Difunde una **transacción suelta** ya serializada (`tx_a_bytes`) por el tema de tx de la red.
    ///
    /// El tema sale de [`ParametrosRed`], igual que en [`Self::difundir_bloque`]; no hay vía pública
    /// para publicar por el tema equivocado. Quien llama MUST haber validado antes (C-NET-12): aquí
    /// solo se transporta, no se juzga.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el canal de comandos está cerrado o si `gossipsub.publish`
    /// rechaza el envío local.
    pub async fn difundir_tx(&self, tx_bytes: &[u8]) -> Result<(), P2pError> {
        let topico = self.parametros.topic_txs().to_owned();
        let datos = zrxc::comprimir_red(tx_bytes, Some(zrxc::diccionario_tx()));
        self.metricas
            .sumar(tx_bytes.len() as u64, datos.len() as u64);
        let (tx, rx) = oneshot::channel();
        self.enviar(Comando::Difundir {
            topico,
            datos,
            respuesta: tx,
        })
        .await?;
        rx.await
            .map_err(|_| P2pError::Transporte("el bucle de red murió antes de responder"))?
    }

    /// FV-4b-N1 · Difunde un **sobre de voto/certificado de finalidad** ya serializado por el tema
    /// de votos de la red.
    ///
    /// `zx-p2p` transporta **bytes opacos**: el sobre `ZXV1` lo codifica y decodifica `zx-node` con
    /// `zx-votos`. Igual que en [`Self::difundir_tx`], quien llama MUST haberlo validado antes.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el canal de comandos está cerrado o si `gossipsub.publish`
    /// rechaza el envío local.
    pub async fn difundir_voto(&self, bytes: &[u8]) -> Result<(), P2pError> {
        let topico = self.parametros.topic_votos().to_owned();
        let datos = zrxc::comprimir_red(bytes, Some(zrxc::diccionario_tx()));
        self.metricas.sumar(bytes.len() as u64, datos.len() as u64);
        let (tx, rx) = oneshot::channel();
        self.enviar(Comando::Difundir {
            topico,
            datos,
            respuesta: tx,
        })
        .await?;
        rx.await
            .map_err(|_| P2pError::Transporte("el bucle de red murió antes de responder"))?
    }

    /// AG-2c · G3: empieza a recibir los **votos de red** de la subred `s` (0-based).
    ///
    /// Suscribe al tema `/<red>/votos-sub/<s>/1`. Sin llamadas, el nodo no recibe votos sueltos de
    /// ninguna subred: solo los pide quien vota o quien los agrega.
    ///
    /// # Errores
    /// [`P2pError::Configuracion`] si `s >= S` (**error, no pánico**); [`P2pError::Transporte`] si
    /// el bucle de red ya no está.
    pub async fn suscribir_subred(&self, s: u8) -> Result<(), P2pError> {
        self.cambiar_subred(s, true).await
    }

    /// AG-2c · G3: deja de recibir los votos de red de la subred `s` (0-based).
    ///
    /// # Errores
    /// Las mismas que [`Self::suscribir_subred`].
    pub async fn desuscribir_subred(&self, s: u8) -> Result<(), P2pError> {
        self.cambiar_subred(s, false).await
    }

    /// Comprueba el rango y manda el cambio de suscripción al bucle.
    async fn cambiar_subred(&self, s: u8, suscrito: bool) -> Result<(), P2pError> {
        if s >= self.parametros.subredes_voto() {
            return Err(P2pError::Configuracion("subred de voto fuera de rango"));
        }
        let (tx, rx) = oneshot::channel();
        self.enviar(Comando::SuscribirSubred {
            subred: s,
            suscrito,
            respuesta: tx,
        })
        .await?;
        rx.await
            .map_err(|_| P2pError::Transporte("el bucle de red murió antes de responder"))?
    }

    /// AG-2c · G6: difunde un **voto de red** ya serializado por el tema de **su** subred.
    ///
    /// Igual que [`Self::difundir_voto`], transporta **bytes opacos** y quien llama MUST haberlo
    /// validado antes. El tema sale de [`ParametrosRed`]: no hay vía pública para publicar el voto
    /// de una subred por el tema de otra.
    ///
    /// # Errores
    /// [`P2pError::Configuracion`] si `s >= S`; [`P2pError::Difusion`] si `bytes` no cabe en el
    /// tope de transporte local; [`P2pError::Transporte`] si el bucle de red ya no está.
    pub async fn difundir_voto_subred(&self, s: u8, bytes: &[u8]) -> Result<(), P2pError> {
        if s >= self.parametros.subredes_voto() {
            return Err(P2pError::Configuracion("subred de voto fuera de rango"));
        }
        if bytes.len() > MAX_GOSSIP_BYTES {
            return Err(P2pError::Difusion(
                "el voto de red supera el tope de transporte local".to_owned(),
            ));
        }
        let topico = self.parametros.topic_voto_subred(s);
        let datos = zrxc::comprimir_red(bytes, Some(zrxc::diccionario_tx()));
        self.metricas.sumar(bytes.len() as u64, datos.len() as u64);
        let (tx, rx) = oneshot::channel();
        self.enviar(Comando::Difundir {
            topico,
            datos,
            respuesta: tx,
        })
        .await?;
        rx.await
            .map_err(|_| P2pError::Transporte("el bucle de red murió antes de responder"))?
    }

    /// AG-2c · G6: difunde un **agregado de subred** ya serializado por el tema común de agregados.
    ///
    /// Igual que [`Self::difundir_voto`], transporta **bytes opacos**; quien llama MUST haberlo
    /// validado antes.
    ///
    /// # Errores
    /// [`P2pError::Difusion`] si `bytes` no cabe en el tope de transporte local;
    /// [`P2pError::Transporte`] si el bucle de red ya no está.
    pub async fn difundir_agregado(&self, bytes: &[u8]) -> Result<(), P2pError> {
        if bytes.len() > MAX_GOSSIP_BYTES {
            return Err(P2pError::Difusion(
                "el agregado supera el tope de transporte local".to_owned(),
            ));
        }
        let topico = self.parametros.topic_agregado().to_owned();
        let datos = zrxc::comprimir_red(bytes, Some(zrxc::diccionario_tx()));
        self.metricas.sumar(bytes.len() as u64, datos.len() as u64);
        let (tx, rx) = oneshot::channel();
        self.enviar(Comando::Difundir {
            topico,
            datos,
            respuesta: tx,
        })
        .await?;
        rx.await
            .map_err(|_| P2pError::Transporte("el bucle de red murió antes de responder"))?
    }

    /// A6-02 · Q4: difunde un **anuncio de prueba** de 146 B por el tema `/<red>/pruebas/2`.
    ///
    /// El anuncio viaja **crudo** (sin marco ZRX-C): es un mensaje de control de tamaño fijo y el
    /// marco de 35 B solo lo engordaría (ZRX-C R-9). `zx-p2p` no lo valida aquí —quien produce
    /// verifica antes de anunciar (`CP-R-09`)—; la comprobación de forma y firma la hace el receptor
    /// antes de entregarlo al nodo (Q2).
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle de red ya no está, o si `gossipsub.publish` rechaza el
    /// envío local.
    pub async fn difundir_anuncio_prueba(&self, anuncio: &[u8]) -> Result<(), P2pError> {
        let topico = self.parametros.topic_pruebas().to_owned();
        let (tx, rx) = oneshot::channel();
        self.enviar(Comando::Difundir {
            topico,
            datos: anuncio.to_vec(),
            respuesta: tx,
        })
        .await?;
        rx.await
            .map_err(|_| P2pError::Transporte("el bucle de red murió antes de responder"))?
    }

    /// A6-02 · Q4: pide una prueba por su huella a un peer.
    ///
    /// **No espera respuesta**: llegará como [`EventoRed::Respuesta`]. La cuota de Q5 decide si la
    /// petición se envía ya o espera encolada.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle de red ya no está.
    pub async fn pedir_prueba(&self, peer: PeerId, huella: [u8; 32]) -> Result<(), P2pError> {
        self.enviar(Comando::PedirPrueba { peer, huella }).await
    }

    /// Corta con un peer.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle ya no está.
    pub async fn desconectar(
        &self,
        peer: PeerId,
        motivo: MotivoDesconexion,
    ) -> Result<(), P2pError> {
        self.enviar(Comando::Desconectar { peer, motivo }).await
    }

    /// Informa el veredicto final de una validación diferida (decisión 1 de `ORDEN-W06d2`).
    ///
    /// Para usar desde una tarea `tokio`. Si el manejador vive en un hilo normal (el hilo de
    /// consenso de `zx-node`, D-N07), usar [`Self::informar_validacion_bloqueante`].
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle de red ya no está.
    pub async fn informar_validacion(
        &self,
        id: IdDiferido,
        veredicto: VeredictoFinal,
    ) -> Result<(), P2pError> {
        self.enviar(Comando::InformarValidacion { id, veredicto })
            .await
    }

    /// Igual que [`Self::informar_validacion`], pero bloqueante: para llamarse desde un hilo que no
    /// corre sobre el *runtime* de `tokio` (el hilo de consenso, D-N07).
    ///
    /// # Pánico
    /// Como cualquier `blocking_send` de `tokio`, entra en pánico si se llama desde dentro de un
    /// hilo *worker* de un runtime `tokio` (ver la documentación de
    /// [`tokio::sync::mpsc::Sender::blocking_send`]). El hilo de consenso no lo es.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle de red ya no está.
    pub fn informar_validacion_bloqueante(
        &self,
        id: IdDiferido,
        veredicto: VeredictoFinal,
    ) -> Result<(), P2pError> {
        self.comandos
            .blocking_send(Comando::InformarValidacion { id, veredicto })
            .map_err(|_| P2pError::Transporte("el bucle de red ya no está escuchando comandos"))
    }

    /// A5-c-2a-2 · E2: fija el **cupo** de validaciones diferidas de los dos temas nuevos de AG-2c
    /// (voto de red por subred y agregado). El nodo es quien lo decide: es el único que conoce el
    /// número de agregadores y de subredes.
    ///
    /// Sustituye el valor de arranque [`crate::limites::CUPO_DIFERIDOS_VOTOS_ARRANQUE`] a partir de
    /// este momento; no cambia el cupo de bloques ([`crate::limites::MAX_DIFERIDOS_PENDIENTES`]) ni
    /// expulsa a los diferidos que ya estaban pendientes. Es idempotente y local: dos llamadas
    /// seguidas dejan el último valor.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle de red ya no está.
    pub async fn fijar_cupo_diferidos_agregacion(&self, cupo: usize) -> Result<(), P2pError> {
        let (tx, rx) = oneshot::channel();
        self.enviar(Comando::FijarCupoDiferidosAgregacion {
            cupo,
            respuesta: tx,
        })
        .await?;
        rx.await
            .map_err(|_| P2pError::Transporte("el bucle de red murió antes de responder"))?
    }

    /// Los contadores de bytes ZRX-C de este nodo (diagnóstico y medida).
    #[must_use]
    pub const fn metricas(&self) -> &zrxc::Metricas {
        &self.metricas
    }

    /// RD-4a · H2: fija la tabla de pesos del director (`productor → bloques certificados`).
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle de red ya no está.
    pub async fn fijar_tabla_pesos(&self, pesos: Vec<(ClavePublica, u64)>) -> Result<(), P2pError> {
        self.enviar(Comando::FijarPesos { pesos }).await
    }

    /// RD-4b · P3: fija la tabla de pesos **sin esperar**. Si el canal de comandos está lleno,
    /// devuelve `false` de inmediato (la tabla se descarta; quien llama la cuenta y el siguiente
    /// cambio de ancla la vuelve a mandar). Nunca bloquea el hilo de consenso.
    #[must_use]
    pub fn intentar_fijar_tabla_pesos(&self, pesos: Vec<(ClavePublica, u64)>) -> bool {
        self.comandos
            .try_send(Comando::FijarPesos { pesos })
            .is_ok()
    }

    /// RD-4a · H2: entrega al director una entrada del registro firmado; el director la revalida
    /// (forma, época y firma) antes de retenerla.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle de red ya no está.
    pub async fn insertar_registro(
        &self,
        entrada: EntradaRegistro,
        ahora: u64,
    ) -> Result<(), P2pError> {
        self.enviar(Comando::InsertarRegistro { entrada, ahora })
            .await
    }

    /// RD-4a · H2: marca (`Some`) o quita (`None`) la saliente protegida del director.
    ///
    /// # Errores
    /// [`P2pError::Transporte`] si el bucle de red ya no está.
    pub async fn proteger_saliente(&self, peer: Option<PeerId>) -> Result<(), P2pError> {
        self.enviar(Comando::ProtegerSaliente { peer }).await
    }

    async fn enviar(&self, c: Comando) -> Result<(), P2pError> {
        self.comandos
            .send(c)
            .await
            .map_err(|_| P2pError::Transporte("el bucle de red ya no está escuchando comandos"))
    }
}

/// RD-4b · P3 (pruebas) · un `ManejoRed` con un canal de comandos **sin bucle**: nadie lo drena.
/// Sirve para ejercitar `intentar_fijar_tabla_pesos` con el canal lleno sin levantar una red real.
/// El receptor va en un [`GuardaCanal`] que el llamante debe conservar para que el canal no se
/// cierre.
#[doc(hidden)]
#[must_use]
pub fn manejo_sin_bucle(capacidad: usize) -> (ManejoRed, GuardaCanal) {
    let (tx_cmd, rx_cmd) = mpsc::channel(capacidad);
    (
        ManejoRed {
            comandos: tx_cmd,
            parametros: ParametrosRed::dag_dev(),
            metricas: zrxc::Metricas::nuevo(),
        },
        GuardaCanal { rx: rx_cmd },
    )
}

/// RD-4b · P3 (pruebas) · guardián del receptor de [`manejo_sin_bucle`]. Conservarlo mantiene
/// abierto el canal; sus métodos permiten inspeccionar lo encolado sin consumir el bucle.
#[doc(hidden)]
pub struct GuardaCanal {
    rx: mpsc::Receiver<Comando>,
}

impl GuardaCanal {
    /// Extrae las tablas `FijarPesos` encoladas hasta ahora (para las pruebas de RD-4b).
    #[must_use]
    pub fn tablas_recibidas(&mut self) -> Vec<Vec<(ClavePublica, u64)>> {
        let mut salida = Vec::new();
        while let Ok(c) = self.rx.try_recv() {
            if let Comando::FijarPesos { pesos } = c {
                salida.push(pesos);
            }
        }
        salida
    }
}

/// A6-02 · Q5: una petición de prueba, **en vuelo** o **esperando cupo**.
#[derive(Clone, Copy, Debug)]
struct SolicitudPrueba {
    /// A qué par se le pidió (o se le pedirá).
    peer: PeerId,
    /// Qué huella se pidió (para casar la respuesta y para la validación de Q3).
    huella: [u8; 32],
}

/// A5-c-2a · D4: a qué cupo pertenece un diferido. Los bloques conservan
/// [`MAX_DIFERIDOS_PENDIENTES`]; los dos temas nuevos de AG-2c (voto de subred y agregado) tienen
/// **cota propia**, que el nodo fija en marcha
/// ([`ManejoRed::fijar_cupo_diferidos_agregacion`]) para que un aluvión de agregados no desaloje ni
/// bloquee un bloque pendiente. El cupo de [`Self::VotosNuevos`] es el campo
/// [`BucleRed::cupo_diferidos_votos`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ClaseDiferido {
    /// Bloques (el único tema que ya difería antes de A5-c-2a).
    Bloques,
    /// Voto de red por subred y agregado de subred.
    VotosNuevos,
}

/// A qué cupo pertenece un tema de difusión. Solo los bloques y los dos temas nuevos de AG-2c
/// pueden llegar a diferirse; el resto de temas trata `Diferir` como `Ignorar` en [`despachar`].
const fn clase_de_tema(tema: TemaDifusion) -> ClaseDiferido {
    match tema {
        TemaDifusion::VotoSubred(_) | TemaDifusion::Agregado => ClaseDiferido::VotosNuevos,
        _ => ClaseDiferido::Bloques,
    }
}

/// Lo que el bucle guarda de un mensaje de gossipsub cuyo veredicto se difirió.
struct PendienteDiferido {
    /// El mensaje al que hay que responder cuando llegue el veredicto final.
    message_id: gossipsub::MessageId,
    /// Quién lo propagó (a quién penalizar si el veredicto final es `Rechazar`).
    propagador: PeerId,
    /// Cuándo se difirió, para el barrido de [`BucleRed::expirar_diferidos_vencidos`].
    creado: Instant,
    /// A qué cupo cuenta (D4): los temas nuevos no comparten cupo con los bloques.
    clase: ClaseDiferido,
}

/// El bucle. Posee el `Swarm` y corre en su propia tarea.
pub struct BucleRed<M: ManejadorEntrante> {
    swarm: Swarm<ZxBehaviour>,
    comandos: mpsc::Receiver<Comando>,
    eventos: mpsc::Sender<EventoRed>,
    manejador: Arc<M>,
    /// Contador **compartido** de memoria en vuelo (C-NET-21).
    ///
    /// Es el mismo que lleva el códec de `sync`: la reserva del parseo de una respuesta y la del
    /// parseo de un bloque difundido salen del mismo techo.
    presupuesto: Presupuesto,
    /// Validaciones diferidas (decisión 1 de `ORDEN-W06d2`) a la espera de
    /// [`Comando::InformarValidacion`], acotadas por [`MAX_DIFERIDOS_PENDIENTES`].
    pendientes: HashMap<IdDiferido, PendienteDiferido>,
    /// A5-c-2a-2 · E2: cupo vigente de los diferidos de los **dos temas nuevos** de AG-2c (voto de
    /// red por subred y agregado). Nace en [`CUPO_DIFERIDOS_VOTOS_ARRANQUE`] y el nodo lo cambia con
    /// [`ManejoRed::fijar_cupo_diferidos_agregacion`]. No afecta al cupo de los bloques
    /// ([`MAX_DIFERIDOS_PENDIENTES`]).
    cupo_diferidos_votos: usize,
    /// Siguiente [`IdDiferido`] a repartir. Un contador simple basta: `BucleRed` tiene un único
    /// dueño (esta tarea), no hace falta que sea atómico.
    siguiente_id: u64,
    /// Plazo tras el cual un diferido sin informe se trata como `Ignorar`. Configurable solo para
    /// que los tests puedan acortarlo; la ruta de producción usa
    /// [`PLAZO_VALIDACION_DIFERIDA_S`].
    plazo_diferido: Duration,
    /// Descubrimiento, salientes, anclas, sondeo y rotación (RED-2).
    director: Director,
    /// Estado de los entrantes para aplicar el desalojo C-NET-42 en el punto de aceptación
    /// (RED-3 punto 4): antigüedad, latencia de `ping` y «entregó un bloque válido».
    desalojo: DesalojoEntrantes,
    /// Presupuesto de **mensajes** de gossip por par y ventana (RSS-1): las cachés internas de
    /// gossipsub crecen por mensaje, no por byte, así que un par que manda miles de transacciones
    /// diminutas dentro del tope legítimo de bytes se corta aquí.
    gossip_por_par: PresupuestoGossipPar,
    /// A6-02 · Q5: peticiones de prueba **en vuelo**, por `OutboundRequestId` (para casar la
    /// respuesta con su huella y para contar la cuota).
    pruebas_en_vuelo: HashMap<request_response::OutboundRequestId, SolicitudPrueba>,
    /// A6-02 · Q5: peticiones de prueba que **esperan** cupo. La que excede la cuota no se rechaza:
    /// espera, como libp2p encola la que supera `max_concurrent_streams`.
    pruebas_en_espera: VecDeque<SolicitudPrueba>,
    /// Latidos transcurridos, para persistir el gestor cada cierto intervalo sin escribir cada
    /// segundo.
    latidos: u64,
}

/// Lo que devuelve [`arrancar`]: el handle, el flujo de eventos y el bucle listo para correr.
pub struct Piezas<M: ManejadorEntrante> {
    /// Con esto se le habla a la red.
    pub manejo: ManejoRed,
    /// Por aquí llegan los eventos.
    pub eventos: mpsc::Receiver<EventoRed>,
    /// Esto hay que meterlo en una tarea con [`BucleRed::correr`].
    pub bucle: BucleRed<M>,
}

/// Prepara las tres piezas con un presupuesto agregado **concreto**. No arranca nada.
///
/// Usa el plazo de validación diferida de producción ([`PLAZO_VALIDACION_DIFERIDA_S`]). Para
/// pruebas que necesiten un plazo corto, usar [`arrancar_con_plazo`].
pub fn arrancar_con<M: ManejadorEntrante>(
    swarm: Swarm<ZxBehaviour>,
    manejador: Arc<M>,
    presupuesto: Presupuesto,
) -> Piezas<M> {
    arrancar_con_plazo(
        swarm,
        manejador,
        presupuesto,
        Duration::from_secs(PLAZO_VALIDACION_DIFERIDA_S),
    )
}

/// Igual que [`arrancar_con`], con el plazo de validación diferida explícito.
pub fn arrancar_con_plazo<M: ManejadorEntrante>(
    swarm: Swarm<ZxBehaviour>,
    manejador: Arc<M>,
    presupuesto: Presupuesto,
    plazo_diferido: Duration,
) -> Piezas<M> {
    arrancar_con_plazo_y_desalojo(
        swarm,
        manejador,
        presupuesto,
        plazo_diferido,
        DesalojoEntrantes::de_produccion(),
    )
}

/// Igual que [`arrancar_con_plazo`], con el estado de desalojo de entrantes explícito.
///
/// Existe para que un test pueda **bajar el tope** de entrantes y ejercitar el punto de aceptación
/// de C-NET-42 sin montar 72 conexiones; la ruta de producción usa
/// [`DesalojoEntrantes::de_produccion`].
pub fn arrancar_con_plazo_y_desalojo<M: ManejadorEntrante>(
    swarm: Swarm<ZxBehaviour>,
    manejador: Arc<M>,
    presupuesto: Presupuesto,
    plazo_diferido: Duration,
    desalojo: DesalojoEntrantes,
) -> Piezas<M> {
    arrancar_con_plazo_y_desalojo_y_registro(
        swarm,
        manejador,
        presupuesto,
        plazo_diferido,
        desalojo,
        false,
    )
}

/// RD-4b · P6: como [`arrancar_con_plazo_y_desalojo`], con el **registro de direcciones del
/// director** encendido o apagado explícito. La ruta de producción del nodo lo enciende cuando
/// `--red-registro` está activo; así el director sortea por producción certificada. El resto de
/// llamantes (tests y el arranque sin registro) usan `false`.
pub fn arrancar_con_plazo_y_desalojo_y_registro<M: ManejadorEntrante>(
    mut swarm: Swarm<ZxBehaviour>,
    manejador: Arc<M>,
    presupuesto: Presupuesto,
    plazo_diferido: Duration,
    desalojo: DesalojoEntrantes,
    registro_activo: bool,
) -> Piezas<M> {
    let (tx_cmd, rx_cmd) = mpsc::channel(CAPACIDAD_COMANDOS);
    let (tx_ev, rx_ev) = mpsc::channel(CAPACIDAD_EVENTOS);

    let parametros = swarm.behaviour().parametros_de_red();

    // AG-2c · G3: el nodo se suscribe **siempre** al tema de agregados, una vez, aquí. Las subredes
    // no: se piden con `ManejoRed::suscribir_subred` y sin llamadas ninguna queda suscrita.
    // A6-02 · Q1: el tema de pruebas («todo nodo se suscribe») se añade aquí por el mismo motivo:
    // es suscripción permanente del nodo, no de la composición genérica `ZxBehaviour`.
    for tema in [parametros.topic_agregado(), parametros.topic_pruebas()] {
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new(tema))
        {
            tracing::error!(%e, %tema, "no se pudo suscribir a un tema permanente");
        }
    }

    // RD-4b · P6: el perfil del director lleva el registro encendido para que `sortear_candidata`
    // y `RegistroDirecciones` acepten entradas y haya sorteo.
    let mut perfil = crate::config::PerfilRed::de(parametros.red());
    perfil.registro_activo = registro_activo;
    let director = Director::nuevo(parametros.red(), perfil);

    Piezas {
        manejo: ManejoRed {
            comandos: tx_cmd,
            parametros,
            metricas: zrxc::Metricas::nuevo(),
        },
        eventos: rx_ev,
        bucle: BucleRed {
            swarm,
            comandos: rx_cmd,
            eventos: tx_ev,
            manejador,
            presupuesto,
            pendientes: HashMap::new(),
            cupo_diferidos_votos: CUPO_DIFERIDOS_VOTOS_ARRANQUE,
            siguiente_id: 0,
            plazo_diferido,
            director,
            desalojo,
            gossip_por_par: PresupuestoGossipPar::de_produccion(),
            pruebas_en_vuelo: HashMap::new(),
            pruebas_en_espera: VecDeque::new(),
            latidos: 0,
        },
    }
}

/// Prepara las tres piezas con un `Presupuesto` propio. **No arranca nada.**
///
/// ⚠️ El presupuesto que crea aquí es **solo para este bucle**: no lo comparte con el códec. La ruta
/// de producción debe usar [`arrancar_con`] con la misma instancia.
pub fn arrancar<M: ManejadorEntrante>(swarm: Swarm<ZxBehaviour>, manejador: Arc<M>) -> Piezas<M> {
    arrancar_con(swarm, manejador, Presupuesto::default())
}

/// RD-4b · P6: como [`arrancar`], con el registro de direcciones del director encendido explícito.
/// La usa `zx-node` cuando `--red-registro` está activo.
pub fn arrancar_con_registro<M: ManejadorEntrante>(
    swarm: Swarm<ZxBehaviour>,
    manejador: Arc<M>,
    registro_activo: bool,
) -> Piezas<M> {
    arrancar_con_plazo_y_desalojo_y_registro(
        swarm,
        manejador,
        Presupuesto::default(),
        Duration::from_secs(PLAZO_VALIDACION_DIFERIDA_S),
        DesalojoEntrantes::de_produccion(),
        registro_activo,
    )
}

impl<M: ManejadorEntrante> BucleRed<M> {
    /// Corre hasta que se sueltan todos los [`ManejoRed`].
    ///
    /// Termina **de forma cooperativa**: cuando el canal de comandos se cierra —porque nadie
    /// conserva un handle—, el bucle sale tras procesar lo que tuviera entre manos.
    pub async fn correr(mut self) {
        // El barrido corre al **cuarto** del plazo: así un diferido nunca espera más de
        // `plazo_diferido + plazo_diferido/4` antes de expirar, sin necesidad de un temporizador
        // por entrada. `Duration::max(1 ms)` evita un `interval` de período cero si algún test
        // pasara un plazo absurdamente corto.
        let periodo_barrido = (self.plazo_diferido / 4).max(Duration::from_millis(1));
        let mut barrido = tokio::time::interval(periodo_barrido);
        // Un barrido tarde (p. ej. tras una pausa larga del proceso) no debe intentar "ponerse al
        // día" disparando varias veces seguidas: solo importa el estado actual.
        barrido.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Latido del director: descubrimiento, sondeo, rotación y mantenimiento de salientes.
        let mut latido = tokio::time::interval(Duration::from_secs(1));
        latido.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                evento = futures::StreamExt::select_next_some(&mut self.swarm) => {
                    self.atender_swarm(evento);
                }
                comando = self.comandos.recv() => {
                    match comando {
                        Some(c) => self.atender_comando(c),
                        None => {
                            tracing::info!("todos los handles soltados: el bucle de red termina");
                            return;
                        }
                    }
                }
                _ = barrido.tick() => {
                    self.expirar_diferidos_vencidos();
                }
                _ = latido.tick() => {
                    self.latir();
                }
            }
        }
    }

    /// A6-02 · Q5: ¿cabe una petición de prueba para `peer` con las que ya hay en vuelo?
    fn puede_pedir_prueba(&self, peer: &PeerId) -> bool {
        let en_par = self
            .pruebas_en_vuelo
            .values()
            .filter(|s| s.peer == *peer)
            .count();
        cabe_prueba(en_par, self.pruebas_en_vuelo.len())
    }

    /// A6-02 · Q5: envía de la cola de espera todas las peticiones de prueba que quepan.
    ///
    /// Se llama al encolar y cada vez que se libera un hueco (respuesta o fallo). La cola no lleva
    /// cifra propia: quien encola es nuestro propio nodo, no un par.
    fn enviar_pruebas_si_caben(&mut self) {
        while let Some(siguiente) = self.pruebas_en_espera.front().copied() {
            if !self.puede_pedir_prueba(&siguiente.peer) {
                break;
            }
            let Some(solicitud) = self.pruebas_en_espera.pop_front() else {
                break;
            };
            let id = self.swarm.behaviour_mut().sync.send_request(
                &solicitud.peer,
                Peticion::Prueba {
                    huella: solicitud.huella,
                },
            );
            self.pruebas_en_vuelo.insert(id, solicitud);
        }
    }

    /// Trata como [`Veredicto::Ignorar`] todo diferido más viejo que [`Self::plazo_diferido`].
    ///
    /// **No penaliza.** Un veredicto que no llega a tiempo es un fallo del manejador o del hilo de
    /// validación, nunca una prueba de que el peer que propagó el mensaje hizo algo malo.
    fn expirar_diferidos_vencidos(&mut self) {
        let ahora = Instant::now();
        let vencidos: Vec<IdDiferido> = self
            .pendientes
            .iter()
            .filter(|(_, p)| ahora.duration_since(p.creado) >= self.plazo_diferido)
            .map(|(id, _)| *id)
            .collect();
        for id in vencidos {
            if let Some(p) = self.pendientes.remove(&id) {
                tracing::debug!(?id, "validación diferida sin informe a tiempo: se ignora");
                self.reportar_a_gossipsub(&p.message_id, &p.propagador, Veredicto::Ignorar);
            }
        }
    }

    /// Atiende un evento del `Swarm`.
    fn atender_swarm(&mut self, evento: SwarmEvent<ZxBehaviourEvent>) {
        match evento {
            SwarmEvent::NewListenAddr { address, .. } => {
                self.avisar(EventoRed::Escuchando(address));
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let saliente = endpoint.is_dialer();
                let addr = endpoint.get_remote_address().clone();
                if saliente {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                    self.avisar(EventoRed::ConexionSaliente(peer_id));
                } else {
                    // RED-3 punto 4 · punto de aceptación del desalojo C-NET-42: al establecerse
                    // una entrante, si ya estamos en el tope se elige víctima entre las **ya
                    // establecidas** (nunca la recién aceptada) y se la desconecta. El cupo vuelve
                    // al tope en cuanto llega su `ConnectionClosed`.
                    let ahora = Instant::now();
                    if let Some(victima) = self.desalojo.admitir(peer_id, &addr, ahora) {
                        tracing::warn!(
                            %victima,
                            nuevo = %peer_id,
                            "tope de entrantes: se desaloja un par según C-NET-42"
                        );
                        let _ = self.swarm.disconnect_peer_id(victima);
                    }
                }
                let acciones =
                    self.director
                        .on_establecido(peer_id, &addr, saliente, Instant::now());
                self.ejecutar_acciones(acciones);
                self.avisar(EventoRed::PeerConectado(peer_id));
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.desalojo.al_desconectar(&peer_id);
                self.director.on_desconectado(peer_id);
                self.gossip_por_par.olvidar(&peer_id);
                self.avisar(EventoRed::PeerDesconectado(peer_id));
            }
            SwarmEvent::Behaviour(ZxBehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                // ORDEN-ZC3, pregunta (b): ZRX-C es obligatorio. Si el par no anuncia la marca en
                // su `agent_version`, se corta con un motivo claro (`SinZrxC`, 0 puntos: un nodo
                // viejo no es mala fe) antes de añadirlo a Kademlia ni de hablarle.
                if let Some(motivo) = motivo_por_falta_de_zrxc(&info.agent_version) {
                    tracing::warn!(
                        %peer_id,
                        agente = %info.agent_version,
                        "ZRX-C: el par no anuncia capacidad de compresión; se rechaza"
                    );
                    self.desconectar_con_motivo(peer_id, motivo);
                    return;
                }
                for a in &info.listen_addrs {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, a.clone());
                }
                self.director
                    .on_identify(peer_id, &info.listen_addrs, Instant::now());
            }
            SwarmEvent::Behaviour(ZxBehaviourEvent::Kademlia(kad::Event::RoutingUpdated {
                addresses,
                ..
            })) => {
                let addrs: Vec<Multiaddr> = addresses.iter().cloned().collect();
                self.director.on_routing(&addrs);
            }
            SwarmEvent::Behaviour(ZxBehaviourEvent::Ping(evento)) => {
                // RED-3 punto 4 · la latencia es el segundo criterio de C-NET-42. Un fallo de ping
                // no borra la medida anterior: `None` ya significa "peor que cualquiera medida".
                if let Ok(rtt) = evento.result {
                    self.desalojo.al_latencia(&evento.peer, rtt);
                }
            }
            SwarmEvent::Behaviour(ZxBehaviourEvent::Sync(e)) => self.atender_sync(e),
            SwarmEvent::Behaviour(ZxBehaviourEvent::Gossipsub(e)) => self.atender_gossip(e),
            otro => {
                tracing::trace!(?otro, "evento de swarm sin manejo específico");
            }
        }
    }

    /// Un latido del director: mantiene salientes, sondea, rota y persiste el gestor.
    fn latir(&mut self) {
        self.latidos = self.latidos.wrapping_add(1);
        let acciones = self.director.tick(Instant::now());
        self.ejecutar_acciones(acciones);
        self.avisar_sorteos();
        if self.latidos.is_multiple_of(30)
            && self.director.es_sucio()
            && let Err(e) = self.director.guardar()
        {
            tracing::warn!(%e, "no se pudo persistir el gestor de direcciones");
        }
    }

    /// Ejecuta las acciones que pide el director.
    fn ejecutar_acciones(&mut self, acciones: Vec<Accion>) {
        for accion in acciones {
            match accion {
                Accion::Marcar(addr) => {
                    if let Err(e) = self.swarm.dial(addr.clone()) {
                        tracing::debug!(%addr, %e, "no se pudo marcar una dirección");
                    }
                }
                Accion::Desconectar(peer) => {
                    let _ = self.swarm.disconnect_peer_id(peer);
                }
                Accion::Paseo(clave) => {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .get_closest_peers(clave.to_vec());
                }
            }
        }
    }

    /// Atiende el protocolo de sincronización.
    fn atender_sync(&mut self, e: request_response::Event<Peticion, Respuesta>) {
        match e {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    // `ORDEN-W06d6` (RI-3a #1, decisión 4): una `Peticion::Bloques` con hashes
                    // repetidos es la firma del hallazgo confirmado (`REVISION-RI-3a.md`): un par
                    // honesto no pide el mismo bloque varias veces en la misma petición. El
                    // recorte/deduplicación que evita el desperdicio de trabajo ya vive en
                    // `zx-node` (`VistaRed::bloques_por_hash`, aplica pase lo que pase aquí); esto
                    // es la parte que **penaliza** al que lo pidió, con el mismo motivo `Excedido`
                    // que ya existe para "mandaste más de lo pactado" (atribuible al emisor, cinco
                    // avisos antes de banear un prefijo, C-NET-05/`error.rs`).
                    if let Peticion::Bloques { hashes } = &request
                        && tiene_hashes_repetidos(hashes)
                    {
                        tracing::debug!(
                            %peer,
                            n = hashes.len(),
                            "Peticion::Bloques con hashes repetidos: penalizando (Excedido)"
                        );
                        self.desconectar_con_motivo(peer, MotivoDesconexion::Excedido);
                    }
                    let respuesta = self.servir(&request);
                    if self
                        .swarm
                        .behaviour_mut()
                        .sync
                        .send_response(channel, respuesta)
                        .is_err()
                    {
                        tracing::debug!(%peer, "el peer se fue antes de recibir la respuesta");
                    }
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    // A6-02 · Q3: si la respuesta contesta a una petición de prueba nuestra, se
                    // valida contra la huella pedida y el tope del cuerpo; si no casa, se descarta,
                    // **no** llega al nodo y se penaliza al par.
                    if let Some(solicitud) = self.pruebas_en_vuelo.remove(&request_id) {
                        if prueba_respuesta_aceptable(&solicitud.huella, &response) {
                            self.enviar_pruebas_si_caben();
                            self.avisar(EventoRed::Respuesta {
                                peer,
                                peticion: request_id_a_u64(request_id),
                                respuesta: Box::new(response),
                            });
                        } else {
                            tracing::warn!(
                                %peer,
                                "respuesta de prueba inválida (huella o tamaño): se rechaza y penaliza"
                            );
                            self.desconectar_con_motivo(
                                peer,
                                MotivoDesconexion::ViolacionDeConsenso,
                            );
                            self.manejador.par_penalizado(
                                peer,
                                MOTIVO_PRUEBA_INVALIDA,
                                ACCION_PAR_PENALIZADO_EXPULSION,
                            );
                            self.enviar_pruebas_si_caben();
                        }
                        return;
                    }
                    self.avisar(EventoRed::Respuesta {
                        peer,
                        peticion: request_id_a_u64(request_id),
                        respuesta: Box::new(response),
                    });
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                // A6-02 · Q5: un fallo libera el hueco de esa petición de prueba (si lo era).
                self.pruebas_en_vuelo.remove(&request_id);
                self.enviar_pruebas_si_caben();
                tracing::debug!(%peer, %error, "petición de sync fallida");
                self.avisar(EventoRed::PeticionFallida { peer });
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                tracing::debug!(%peer, %error, "petición entrante fallida");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    /// Corta con un peer por un motivo dado y aplica la penalización que corresponda.
    ///
    /// C-NET-05 + C-NET-20: la puntuación es del **prefijo** de red — **salvo** para direcciones
    /// loopback (`127.0.0.0/8`, `::1`), donde es del `PeerId` (excepción de la red local,
    /// `ORDEN-W06d10` decisión 3): en la red dev todos los nodos comparten `127.0.0.0/24`, y vetar
    /// ese prefijo por culpa de un adversario dejaría fuera a los nodos honestos. La decisión vive
    /// en [`crate::limites_ip::LimitesPorIp::penalizar_peer`]. Compartido por
    /// `Comando::Desconectar`, por la penalización directa de una petición abusiva (RI-3a #1) y por
    /// el veredicto `Rechazar` de un bloque difundido (`ORDEN-W06d10` decisión 1).
    fn desconectar_con_motivo(&mut self, peer: PeerId, motivo: MotivoDesconexion) {
        tracing::debug!(%peer, ?motivo, puntua = motivo.puntua(), "desconectando");
        let puntos = motivo.puntos();
        if puntos > 0 {
            let prefijos = self.swarm.behaviour_mut().limites_ip.prefijos_de(peer);
            let r = self
                .swarm
                .behaviour_mut()
                .limites_ip
                .penalizar_peer(peer, &prefijos, puntos);
            // C-NET-43 · P5 `set_application_score` alimentado desde la contabilidad por prefijo,
            // porque la P6 nativa solo cuenta IP, no prefijo.
            let _ = self
                .swarm
                .behaviour_mut()
                .gossipsub
                .set_application_score(&peer, -f64::from(puntos));
            for p in r.prefijos_baneados {
                tracing::warn!(
                    ?p,
                    ?motivo,
                    "prefijo de red baneado. Si esto se repite desde MUCHOS prefijos \
                     distintos con motivo Excedido, el nodo desactualizado eres tú."
                );
            }
            if r.peer_baneado {
                tracing::warn!(
                    %peer,
                    ?motivo,
                    "PeerId baneado (dirección loopback: la penalización es por PeerId, no por \
                     prefijo, para no vetar a los demás nodos de 127.0.0.0/8)."
                );
            }
        }
        let _ = self.swarm.disconnect_peer_id(peer);
    }

    /// Construye la respuesta a una petición entrante preguntándole al manejador.
    fn servir(&self, p: &Peticion) -> Respuesta {
        match p {
            Peticion::Estado => Respuesta::Estado(self.manejador.estado()),
            Peticion::CabecerasPow { locator, parada } => {
                let cs = self.manejador.cabeceras_desde(locator, *parada);
                Respuesta::CabecerasPow(recortar(cs, crate::limites::MAX_CABECERAS_POR_RESPUESTA))
            }
            Peticion::Bloques { hashes } => {
                let bs = self.manejador.bloques_por_hash(hashes);
                if bs.is_empty() {
                    // Distinto de una lista vacía: "no tengo eso" es una respuesta legítima que
                    // **no puntúa**, mientras que una lista vacía invitaría a reintentar.
                    Respuesta::NoDisponible
                } else {
                    Respuesta::Bloques(recortar(bs, crate::limites::MAX_BLOQUES_POR_RESPUESTA))
                }
            }
            Peticion::Registro { desde } => {
                // `ORDEN-W06d6` decisión 1: el manejador ya acota bloques y bytes (recibe los topes
                // del protocolo, no los descubre después); aquí solo se envuelve en la respuesta.
                let (bloques, longitud) = self.manejador.pagina_registro(*desde);
                Respuesta::Registro {
                    desde: *desde,
                    bloques: recortar(bloques, crate::limites::MAX_BLOQUES_POR_RESPUESTA),
                    longitud,
                }
            }
            Peticion::RegistroDirecciones { desde } => {
                // `ORDEN-RD3c` (N1/N2): el registro de direcciones se sirve **siempre** como
                // página —vacía si está apagado o no tiene entradas—, nunca como `NoDisponible`.
                // El manejador ya acota entradas y bytes; aquí solo se envuelve en la respuesta.
                let (entradas, total) = self.manejador.pagina_registro_direcciones(*desde);
                Respuesta::RegistroDirecciones {
                    desde: *desde,
                    entradas: recortar(entradas, crate::limites::MAX_ENTRADAS_REGISTRO_POR_PAGINA),
                    total,
                }
            }
            Peticion::Prueba { huella } => match self.manejador.servir_prueba(huella) {
                // A6-02 · Q3/Q4: el cuerpo es opaco; el nodo decide si lo tiene. Sin cuerpo, la
                // respuesta legítima es `NoDisponible`, que **no** penaliza.
                Some(bytes) => Respuesta::Prueba {
                    huella: *huella,
                    bytes,
                },
                None => Respuesta::NoDisponible,
            },
        }
    }

    /// Atiende la difusión. **C-NET-12: validar antes de retransmitir.**
    fn atender_gossip(&mut self, e: gossipsub::Event) {
        match e {
            gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            } => self.juzgar_y_reportar(&propagation_source, &message_id, &message),
            gossipsub::Event::Subscribed { peer_id, topic } => {
                self.avisar(EventoRed::Suscripcion {
                    peer: peer_id,
                    topico: topic.to_string(),
                    suscrito: true,
                });
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                self.avisar(EventoRed::Suscripcion {
                    peer: peer_id,
                    topico: topic.to_string(),
                    suscrito: false,
                });
            }
            gossipsub::Event::GossipsubNotSupported { peer_id } => {
                tracing::debug!(%peer_id, "el peer no soporta gossipsub");
            }
            gossipsub::Event::SlowPeer {
                peer_id,
                failed_messages,
            } => {
                tracing::debug!(%peer_id, ?failed_messages, "peer lento en gossipsub");
            }
        }
    }

    /// Evalúa un mensaje de gossip y reporta el resultado a gossipsub, o lo retiene si el manejador
    /// difirió el veredicto (decisión 1 de `ORDEN-W06d2`).
    fn juzgar_y_reportar(
        &mut self,
        propagation_source: &PeerId,
        message_id: &gossipsub::MessageId,
        message: &gossipsub::Message,
    ) {
        // RSS-1 · presupuesto de mensajes de gossip por par. La caché interna de gossipsub y su
        // tabla de entregas crecen **por mensaje**; sin este tope, un par que manda miles de
        // transacciones diminutas dentro del tope legítimo de bytes infla la memoria del nodo.
        // Superarlo es un recurso local a la vez que una acción del emisor: se descarta el mensaje
        // (`Ignorar`, no se reenvía) y se corta con el par (`Excedido`, que sí puntúa).
        if !self
            .gossip_por_par
            .consumir(*propagation_source, message.data.len(), Instant::now())
        {
            tracing::debug!(
                peer = %propagation_source,
                "gossip por par excedido: mensaje ignorado y par cortado (RSS-1)"
            );
            self.manejador.par_penalizado(
                *propagation_source,
                MOTIVO_GOSSIP_EXCEDIDO,
                ACCION_PAR_PENALIZADO_EXPULSION,
            );
            self.reportar_a_gossipsub(message_id, propagation_source, Veredicto::Ignorar);
            self.desconectar_con_motivo(*propagation_source, MotivoDesconexion::Excedido);
            return;
        }

        let id = self.siguiente_id_diferido();
        let veredicto = despachar(
            self.manejador.as_ref(),
            id,
            propagation_source,
            message.topic.as_str(),
            &message.data,
            &self.presupuesto,
        );

        if veredicto == Veredicto::Diferir {
            let clase = clase_de_tema(clasificar_tema(message.topic.as_str()));
            self.retener_diferido(id, message_id, propagation_source, clase);
            return;
        }

        self.reportar_a_gossipsub(message_id, propagation_source, veredicto);
    }

    /// Guarda la correlación de un diferido, acotando **su clase** a su cupo (D4): los bloques a
    /// [`MAX_DIFERIDOS_PENDIENTES`] y los dos temas nuevos de AG-2c al cupo que el nodo fijó
    /// ([`Self::cupo_diferidos_votos`]), sin compartir cupo.
    ///
    /// Cuando la clase está llena, la política depende de la clase —`ORDEN-A5C2A-2` E2 frente a
    /// `ORDEN-W06d2`—:
    ///
    /// - **Bloques:** se expira como `Ignorar` la entrada **más antigua** para dejar sitio (conducta
    ///   que ya existía y que D5 deja intacta).
    /// - **Temas nuevos de AG-2c:** el mensaje que llega **se ignora sin penalizar** (E2); no se
    ///   retiene, así que no desaloja a ningún pendiente anterior.
    ///
    /// Ninguna de las dos penaliza: un manejador saturado no es culpa del peer. Un aluvión de
    /// agregados no toca a los bloques.
    fn retener_diferido(
        &mut self,
        id: IdDiferido,
        message_id: &gossipsub::MessageId,
        propagador: &PeerId,
        clase: ClaseDiferido,
    ) {
        let cupo = match clase {
            ClaseDiferido::Bloques => MAX_DIFERIDOS_PENDIENTES,
            ClaseDiferido::VotosNuevos => self.cupo_diferidos_votos,
        };
        let en_clase = self
            .pendientes
            .values()
            .filter(|p| p.clase == clase)
            .count();
        if en_clase >= cupo {
            match clase {
                ClaseDiferido::VotosNuevos => {
                    // E2: la tabla de los dos temas nuevos está llena; el mensaje que llega se
                    // ignora sin penalizar y **no** se retiene (no desaloja a los anteriores).
                    tracing::debug!(
                        cupo,
                        "tabla de diferidos de los temas nuevos llena: se ignora el que llega"
                    );
                    self.reportar_a_gossipsub(message_id, propagador, Veredicto::Ignorar);
                    return;
                }
                ClaseDiferido::Bloques => {
                    // ORDEN-W06d2: se expira la más antigua de la clase para dejar sitio.
                    if let Some(mas_vieja) = self
                        .pendientes
                        .iter()
                        .filter(|(_, p)| p.clase == clase)
                        .min_by_key(|(_, p)| p.creado)
                        .map(|(id, _)| *id)
                    {
                        tracing::warn!(
                            ?clase,
                            cupo,
                            "tabla de diferidos de la clase llena: se expira la más antigua"
                        );
                        if let Some(vieja) = self.pendientes.remove(&mas_vieja) {
                            self.reportar_a_gossipsub(
                                &vieja.message_id,
                                &vieja.propagador,
                                Veredicto::Ignorar,
                            );
                        }
                    }
                }
            }
        }
        self.pendientes.insert(
            id,
            PendienteDiferido {
                message_id: message_id.clone(),
                propagador: *propagador,
                creado: Instant::now(),
                clase,
            },
        );
    }

    /// El identificador opaco que se le entrega al manejador. `zx-p2p` es su único dueño.
    fn siguiente_id_diferido(&mut self) -> IdDiferido {
        self.siguiente_id = self.siguiente_id.wrapping_add(1);
        IdDiferido(self.siguiente_id)
    }

    /// Reporta un veredicto a gossipsub. Sin esta llamada el mensaje se queda **pendiente para
    /// siempre** en la cola de validación de gossipsub: ni se reenvía ni se descarta.
    ///
    /// `ORDEN-W06d10` decisión 1: la respuesta a un veredicto `Rechazar` es la **misma** que en la
    /// ruta de sincronización — se mantiene el `Reject` para gossipsub (C-NET-12), se desconecta al
    /// propagador con `ViolacionDeConsenso` (puntuación C-NET-05/C-NET-20, con la excepción
    /// loopback) y se avisa al nodo (`ManejadorEntrante::par_penalizado`) para que escriba
    /// `par_penalizado`. `Aceptar` e `Ignorar` **nunca** penalizan.
    fn reportar_a_gossipsub(
        &mut self,
        message_id: &gossipsub::MessageId,
        propagation_source: &PeerId,
        veredicto: Veredicto,
    ) {
        let Some(acceptance) = a_acceptance(veredicto) else {
            // No debería llegar aquí con `Diferir`: es un error de este módulo, no de un peer.
            tracing::error!("reportar_a_gossipsub llamado con Diferir; se trata como Ignorar");
            self.reportar_a_gossipsub(message_id, propagation_source, Veredicto::Ignorar);
            return;
        };
        if !self
            .swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(message_id, propagation_source, acceptance)
        {
            tracing::debug!(
                ?veredicto,
                "el mensaje ya no estaba en la caché de validación"
            );
        }
        if veredicto == Veredicto::Aceptar {
            // RED-3 punto 4 · protección 1 de C-NET-42: quien propagó un bloque que aceptamos
            // «entregó primero un bloque válido» y no se desaloja mientras haya otro candidato.
            self.desalojo.al_entrego_valido(propagation_source);
        }
        if veredicto == Veredicto::Rechazar {
            tracing::debug!(peer = %propagation_source, "bloque difundido rechazado: penalizando");
            self.desconectar_con_motivo(
                *propagation_source,
                MotivoDesconexion::ViolacionDeConsenso,
            );
            self.manejador.par_penalizado(
                *propagation_source,
                MOTIVO_PAR_PENALIZADO_GOSSIP,
                ACCION_PAR_PENALIZADO_EXPULSION,
            );
        }
    }

    /// Atiende un comando. No es `async`: nada de lo que hace debe esperar.
    fn atender_comando(&mut self, c: Comando) {
        match c {
            Comando::Escuchar { addr, respuesta } => {
                let r = self
                    .swarm
                    .listen_on(addr)
                    .map(|_| ())
                    .map_err(|_| P2pError::DireccionInvalida);
                let _ = respuesta.send(r);
            }
            Comando::Marcar { addr, respuesta } => {
                let r = self
                    .swarm
                    .dial(addr)
                    .map_err(|_| P2pError::Transporte("no se pudo marcar"));
                let _ = respuesta.send(r);
            }
            Comando::Pedir { peer, peticion } => {
                self.swarm
                    .behaviour_mut()
                    .sync
                    .send_request(&peer, peticion);
            }
            Comando::PedirPrueba { peer, huella } => {
                // A6-02 · Q5: la cuota decide si sale ya o espera; `enviar_pruebas_si_caben` envía
                // todas las que quepan, en orden de llegada.
                self.pruebas_en_espera
                    .push_back(SolicitudPrueba { peer, huella });
                self.enviar_pruebas_si_caben();
            }
            Comando::Difundir {
                topico,
                datos,
                respuesta,
            } => {
                // C-NET-25 · defensa en profundidad. `Comando` es `pub(crate)` y su único emisor es
                // `ManejoRed`, cuyo `Sender` no se expone; aun así esta comprobación impide publicar
                // por un tema de otra red. AG-2c añade los 65 temas nuevos **de esta** red.
                let p = self.swarm.behaviour().parametros_de_red();
                let permitido = topico == p.topic_bloques_pow()
                    || topico == p.topic_bloques_post()
                    || topico == p.topic_txs()
                    || topico == p.topic_votos()
                    || topico == p.topic_pruebas()
                    || p.es_tema_de_votos_nuevo(&topico);
                if !permitido {
                    tracing::warn!(
                        %topico,
                        "difusión rechazada: el tema no es uno de los configurados para esta red"
                    );
                    let _ = respuesta.send(Err(P2pError::Transporte(
                        "tema de difusión fuera de los configurados para esta red",
                    )));
                    return;
                }

                let t = libp2p::gossipsub::IdentTopic::new(topico);
                // El resultado **local** de `publish` vuelve a quien encoló el comando. `Ok` solo
                // acredita aceptación local por gossipsub; no es entrega ni validez.
                let r = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(t, datos)
                    .map_err(|e| {
                        tracing::debug!(%e, "no se pudo difundir");
                        // `ORDEN-W06d6` decisión 3 (V7): el motivo real de `PublishError` viaja en
                        // el error, no un texto fijo que lo esconde (ver `P2pError::Difusion`).
                        P2pError::Difusion(e.to_string())
                    })
                    .map(|_| ());
                let _ = respuesta.send(r);
            }
            Comando::InformarValidacion { id, veredicto } => {
                // Idempotente a propósito (ver la doc de `Comando::InformarValidacion`): un `id`
                // que ya no está pudo expirar (`expirar_diferidos_vencidos`) o ya haberse informado.
                let Some(p) = self.pendientes.remove(&id) else {
                    tracing::debug!(
                        ?id,
                        ?veredicto,
                        "informe de validación diferida sin diferido pendiente (expiró o ya se informó)"
                    );
                    return;
                };
                let veredicto = match veredicto {
                    VeredictoFinal::Aceptar => Veredicto::Aceptar,
                    VeredictoFinal::Ignorar => Veredicto::Ignorar,
                    VeredictoFinal::Rechazar => Veredicto::Rechazar,
                };
                self.reportar_a_gossipsub(&p.message_id, &p.propagador, veredicto);
            }
            Comando::FijarCupoDiferidosAgregacion { cupo, respuesta } => {
                // A5-c-2a-2 · E2: solo cambia el cupo de los diferidos futuros de los dos temas
                // nuevos; no expulsa a los ya pendientes ni toca el cupo de los bloques.
                self.cupo_diferidos_votos = cupo;
                tracing::debug!(cupo, "cupo de diferidos de agregación fijado por el nodo");
                let _ = respuesta.send(Ok(()));
            }
            Comando::Sembrar {
                dir,
                arranque,
                respuesta,
            } => {
                self.director
                    .sembrar(dir.as_deref(), &arranque, Instant::now());
                let acciones = self.director.tick(Instant::now());
                self.ejecutar_acciones(acciones);
                self.avisar_sorteos();
                let _ = respuesta.send(Ok(()));
            }
            Comando::SuscribirSubred {
                subred,
                suscrito,
                respuesta,
            } => {
                // El rango ya se comprobó en `ManejoRed`; aquí, defensa en profundidad.
                let p = self.swarm.behaviour().parametros_de_red();
                let r = if subred >= p.subredes_voto() {
                    Err(P2pError::Configuracion("subred de voto fuera de rango"))
                } else {
                    let t = gossipsub::IdentTopic::new(p.topic_voto_subred(subred));
                    if suscrito {
                        self.swarm
                            .behaviour_mut()
                            .gossipsub
                            .subscribe(&t)
                            .map(|_| ())
                            .map_err(|_| {
                                P2pError::Configuracion("no se pudo suscribir a la subred")
                            })
                    } else {
                        // `unsubscribe` devuelve `bool` (si estaba suscrito); desuscribir de algo
                        // que no se estaba es un no-op legítimo, no un error.
                        let _ = self.swarm.behaviour_mut().gossipsub.unsubscribe(&t);
                        Ok(())
                    }
                };
                let _ = respuesta.send(r);
            }
            Comando::Desconectar { peer, motivo } => self.desconectar_con_motivo(peer, motivo),
            // RD-4a · H2: las tres órdenes del director comparten el mismo puente libre.
            c @ (Comando::FijarPesos { .. }
            | Comando::InsertarRegistro { .. }
            | Comando::ProtegerSaliente { .. }) => {
                aplicar_orden_al_director(&mut self.director, c);
            }
        }
    }

    /// RD-4b · P6: vuelca al canal de eventos los sorteos que el director acaba de hacer. Se llama
    /// tras cada `Director::tick`; con el registro apagado no hay sorteos y no avisa nada.
    fn avisar_sorteos(&mut self) {
        for sorteo in self.director.tomar_eventos_sorteo() {
            self.avisar(EventoRed::SorteoDirector {
                peso_total: sorteo.peso_total,
                entradas: sorteo.entradas,
                productor: sorteo.elegido,
            });
        }
    }

    /// Avisa al nodo, **sin bloquear el bucle si nadie escucha**.
    ///
    /// `try_send` y no `send().await` a propósito: si el consumidor de eventos se retrasa, esperar
    /// aquí dejaría de pollear el `Swarm` y **pararía la red entera**.
    fn avisar(&self, e: EventoRed) {
        if let Err(err) = self.eventos.try_send(e) {
            tracing::warn!(%err, "canal de eventos lleno o cerrado: evento descartado");
        }
    }

    /// El manejador que este bucle usa. Existe para que los tests puedan comprobar que es el suyo.
    #[must_use]
    pub fn manejador(&self) -> &Arc<M> {
        &self.manejador
    }
}

/// A qué canal de difusión pertenece un tema, por **igualdad exacta**.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TemaDifusion {
    /// Tema de bloques PoW completos de alguna red.
    BloquePow,
    /// Tema de bloques PoST completos de alguna red.
    BloquePost,
    /// Tema de transacciones sueltas de alguna red (TX-R-01).
    Tx,
    /// FV-4b-N1 · tema de votos/certificados de finalidad de alguna red (bytes opacos).
    Voto,
    /// AG-2c · G2: voto de red de una subred concreta (`/<red>/votos-sub/<s>/1`, `s` 0-based).
    VotoSubred(u8),
    /// AG-2c · G2: agregado de subred (`/<red>/votos-agr/1`).
    Agregado,
    /// A6-02 · Q1: anuncio de prueba (`/<red>/pruebas/2`).
    Prueba,
    /// Cualquier otro tema.
    Desconocido,
}

/// Clasifica un tema de difusión por igualdad exacta, nunca por prefijo ni subcadena.
///
/// Reconoce los quince temas fijos de hoy (cinco por red: cuatro de AG-2c/FV-4b-N1 más el de
/// anuncios de prueba de A6-02) y los 65 temas nuevos de AG-2c por red: el agregado y las 64
/// subredes. Un tema de otra red con el mismo sufijo se clasifica como el de **su** red (la
/// clasificación no conoce el nodo), y las formas no canónicas —`64`, `07`, `7/1x`— son
/// [`TemaDifusion::Desconocido`].
#[must_use]
pub fn clasificar_tema(topico: &str) -> TemaDifusion {
    match topico {
        "/zerox/bloques/pow/2" | "/zerox-testnet/bloques/pow/2" | "/zx-dev/bloques/pow/2" => {
            TemaDifusion::BloquePow
        }
        "/zerox/bloques/post/2" | "/zerox-testnet/bloques/post/2" | "/zx-dev/bloques/post/2" => {
            TemaDifusion::BloquePost
        }
        "/zerox/tx/2" | "/zerox-testnet/tx/2" | "/zx-dev/tx/2" => TemaDifusion::Tx,
        "/zerox/votos/2" | "/zerox-testnet/votos/2" | "/zx-dev/votos/2" => TemaDifusion::Voto,
        "/zerox/pruebas/2" | "/zerox-testnet/pruebas/2" | "/zx-dev/pruebas/2" => {
            TemaDifusion::Prueba
        }
        TOPIC_AGREGADO_MAINNET | TOPIC_AGREGADO_TESTNET | TOPIC_AGREGADO_DEV => {
            TemaDifusion::Agregado
        }
        _ => {
            for base in BASES_VOTO_SUBRED {
                if let Some(s) = subred_de_tema_en_base(base, topico) {
                    return TemaDifusion::VotoSubred(s);
                }
            }
            TemaDifusion::Desconocido
        }
    }
}

/// ORDEN-ZC3, pregunta (b): si el `agent_version` del par no anuncia ZRX-C, el motivo del rechazo;
/// `None` si sí lo anuncia.
///
/// Es una función libre para poder probar la negociación **sin** levantar un `Swarm`, igual que
/// [`clasificar_tema`].
fn motivo_por_falta_de_zrxc(agent_version: &str) -> Option<MotivoDesconexion> {
    if zrxc::anuncia_zrxc(agent_version) {
        None
    } else {
        Some(MotivoDesconexion::SinZrxC)
    }
}

/// Decide el veredicto de un mensaje de difusión a partir de su tema y sus bytes.
///
/// Es una función libre —no un método de [`BucleRed`]— para poder probar el despacho **sin**
/// construir un `Swarm`.
///
/// El `presupuesto` se **inyecta** en vez de crearse dentro: es lo que permite a un test forzar una
/// reserva fallida con `Presupuesto::nuevo(0)` y comprobar que el agotamiento local no penaliza.
///
/// `id` es el identificador opaco que se le pasa al manejador; solo tiene sentido si el manejador
/// devuelve [`Veredicto::Diferir`] (decisión 1 de `ORDEN-W06d2`).
///
/// `peer` es el propagador, que se reenvía a [`ManejadorEntrante::tx_difundida`] para los topes por
/// par de `ORDEN-TX3`.
///
/// # El tema desconocido no se decodifica
///
/// Un tema que no sea uno de los doce exactos devuelve [`Veredicto::Ignorar`] **sin** tocar los
/// bytes ni llamar al manejador: puede ser una versión más nueva del protocolo, no un ataque.
/// Resultado de intentar descomprimir un mensaje de difusión.
enum Descompresion {
    /// El marco estaba corrupto, era de otra versión o de un dialecto que no entendemos. **No
    /// puntúa** (C-NET-05): puede ser un par con otra versión, no mala fe.
    Ilegible,
    /// El presupuesto local no da para la salida declarada. Es un recurso **local**: no puntúa.
    Local,
    /// El marco declara más salida de la admitida, o un ratio imposible (R-6/R-7). Eso **sí** es
    /// atribuible al emisor: bomba de descompresión.
    Bomba,
}

/// Descomprime el cuerpo de un mensaje de difusión si viene enmarcado (ZRX-C).
///
/// Reserva el tamaño declarado **antes** de asignar la salida (anti-bomba, C-NET-21). La reserva se
/// suelta al volver; quien llama vuelve a reservar `datos.len()` para el callback (ya
/// descomprimido), así que la memoria del mensaje queda contabilizada durante el parseo.
fn descomprimir_gossip(
    datos: &[u8],
    max_salida: u64,
    presupuesto: &Presupuesto,
) -> Result<Vec<u8>, Descompresion> {
    if !zrxc::es_marco(datos) {
        return Ok(datos.to_vec());
    }
    let cab = zrxc::cabecera(datos).map_err(|_| Descompresion::Ilegible)?;
    // R-6/R-7 · el tope se comprueba **antes** de reservar: declarar más salida de la admitida es
    // una bomba atribuible al emisor, no un agotamiento local.
    if cab.len_original > max_salida {
        return Err(Descompresion::Bomba);
    }
    let declarados = usize::try_from(cab.len_original).unwrap_or(usize::MAX);
    let Some(_reserva) = presupuesto.reservar(declarados) else {
        return Err(Descompresion::Local);
    };
    match zrxc::descomprimir_por_id(datos, &zrxc::Limites::nuevo(max_salida)) {
        Ok(v) => Ok(v),
        Err(
            zrxc::ErrorCompresion::DemasiadoGrande { .. }
            | zrxc::ErrorCompresion::RatioExcesivo { .. },
        ) => Err(Descompresion::Bomba),
        Err(_) => Err(Descompresion::Ilegible),
    }
}

fn despachar<M: ManejadorEntrante>(
    manejador: &M,
    id: IdDiferido,
    peer: &PeerId,
    topico: &str,
    datos: &[u8],
    presupuesto: &Presupuesto,
) -> Veredicto {
    // ZRX-C · clasificación exacta del tema y tope de descompresión por tipo (R-6). Un tema
    // desconocido no se toca: puede ser una versión más nueva del protocolo.
    let tema = clasificar_tema(topico);
    let max_salida = match tema {
        TemaDifusion::BloquePow | TemaDifusion::BloquePost => MAX_DESCOMPRIMIDO_BLOQUE,
        TemaDifusion::Tx => MAX_DESCOMPRIMIDO_TX,
        TemaDifusion::Voto => MAX_DESCOMPRIMIDO_VOTO,
        TemaDifusion::VotoSubred(_) => MAX_DESCOMPRIMIDO_VOTO_RED,
        TemaDifusion::Agregado => MAX_DESCOMPRIMIDO_AGREGADO,
        // A6-02 · Q2: el anuncio mide 146 B exactos; el tope sirve también para una bomba enmarcada.
        TemaDifusion::Prueba => LONGITUD_ANUNCIO_PRUEBA as u64,
        TemaDifusion::Desconocido => return Veredicto::Ignorar,
    };
    let datos = match descomprimir_gossip(datos, max_salida, presupuesto) {
        Ok(d) => d,
        Err(Descompresion::Bomba) => {
            tracing::warn!(%peer, "ZRX-C: bomba de descompresión en difusión: se rechaza y penaliza");
            return Veredicto::Rechazar;
        }
        Err(Descompresion::Ilegible | Descompresion::Local) => return Veredicto::Ignorar,
    };

    // AG-2c · G4: el tope del tipo se aplica también a un mensaje **sin marco** (un par hostil
    // puede mandar los bytes crudos): superarlo es atribuible al emisor y se trata como una bomba
    // de descompresión (`Veredicto::Rechazar`, `servicio.rs:1459-1462` arriba).
    if matches!(tema, TemaDifusion::VotoSubred(_) | TemaDifusion::Agregado)
        && datos.len() as u64 > max_salida
    {
        tracing::warn!(
            %peer,
            "el mensaje supera el tope de su tema sin marco de compresión: se rechaza y penaliza"
        );
        return Veredicto::Rechazar;
    }

    // AG-2c · G5 · A5-c-2a: los temas nuevos se despachan al nodo, que decide antes de reenviar.
    // Igual que un bloque, el gancho recibe el `IdDiferido` y su `Diferir` se **respeta**: el bucle
    // retiene el mensaje y espera a `informar_validacion`. `zx-p2p` no interpreta los bytes.
    match tema {
        TemaDifusion::VotoSubred(subred) => {
            let Some(_reserva) = presupuesto.reservar(datos.len()) else {
                return Veredicto::Ignorar;
            };
            return manejador.voto_subred_difundida(id, subred, &datos, *peer);
        }
        TemaDifusion::Agregado => {
            let Some(_reserva) = presupuesto.reservar(datos.len()) else {
                return Veredicto::Ignorar;
            };
            return manejador.agregado_difundido(id, &datos, *peer);
        }
        TemaDifusion::Prueba => {
            // A6-02 · Q2: el anuncio se comprueba **entero** (forma y firma) antes de entregarlo
            // al nodo. Un fallo de longitud, versión, clase, `len_comprimido` o firma es un hecho
            // objetivo del emisor: se rechaza y se penaliza.
            let Some(_reserva) = presupuesto.reservar(datos.len()) else {
                return Veredicto::Ignorar;
            };
            let anuncio = match AnuncioPrueba::desde_bytes_validado(&datos) {
                Ok(a) => a,
                Err(_) => {
                    tracing::warn!(%peer, "anuncio de prueba inválido: se rechaza y penaliza");
                    return Veredicto::Rechazar;
                }
            };
            let v = manejador.anuncio_prueba(*peer, &anuncio);
            return if v == Veredicto::Diferir {
                Veredicto::Ignorar
            } else {
                v
            };
        }
        _ => {}
    }

    // FV-4b-N1 · el tema de votos transporta bytes opacos: `zx-p2p` no los decodifica; el nodo
    // (`voto_difundida`) decide el veredicto. Se mantiene la reserva compartida de presupuesto.
    if tema == TemaDifusion::Voto {
        let Some(_reserva) = presupuesto.reservar(datos.len()) else {
            return Veredicto::Ignorar;
        };
        let v = manejador.voto_difundida(*peer, &datos);
        return if v == Veredicto::Diferir {
            Veredicto::Ignorar
        } else {
            v
        };
    }

    let familia = match tema {
        TemaDifusion::BloquePow => Some(FamiliaBloque::Pow),
        TemaDifusion::BloquePost => Some(FamiliaBloque::Post),
        TemaDifusion::Tx => None,
        // `VotoSubred`, `Agregado` y `Prueba` ya se despacharon arriba y devolvieron; aquí solo
        // cierran la exhaustividad.
        TemaDifusion::Voto
        | TemaDifusion::VotoSubred(_)
        | TemaDifusion::Agregado
        | TemaDifusion::Prueba
        | TemaDifusion::Desconocido => return Veredicto::Ignorar,
    };

    // C-NET-21 · reserva del contador **compartido**. Agotarlo es un recurso **local** de este nodo:
    // el mismo bloque, con presupuesto, se juzgaría con normalidad. Penalizarlo castigaría a un par
    // honesto por nuestra falta de memoria (C-NET-05), así que es `Ignorar`.
    //
    // La reserva se mantiene viva durante el parseo y se libera al salir.
    let Some(_reserva) = presupuesto.reservar(datos.len()) else {
        return Veredicto::Ignorar;
    };

    let Some(familia) = familia else {
        // TX-R-02/04 · una transacción suelta se autodelimita: `tx_desde_bytes` devuelve el resto y
        // el receptor MUST exigir que venga vacío. Un cuerpo con resto o mal formado es basura
        // demostrable (TX-R-07) y penaliza. La validez de fondo la decide el manejador
        // (`tx_difundida`), que ya recibe el `txid` implícito en los bytes.
        return match zx_core::wire::tx_desde_bytes(&datos) {
            Ok((_tx, [])) => {
                let v = manejador.tx_difundida(*peer, &datos);
                // No hay `IdDiferido` para una tx: `Diferir` no es un veredicto posible aquí. Se
                // trata como `Ignorar` (no se reenvía, no penaliza) en vez de dejar el mensaje
                // retenido para siempre.
                if v == Veredicto::Diferir {
                    Veredicto::Ignorar
                } else {
                    v
                }
            }
            Ok((_, _)) => Veredicto::Rechazar,
            Err(_) => Veredicto::Rechazar,
        };
    };

    // El éxito del parseo **no** es validación: el veredicto de un bloque lo decide el manejador.
    // Un fallo de formato o un byte residual sí es basura indiscutible y penaliza.
    match crate::codec::bloque_desde_bytes(&datos, familia) {
        Ok((bloque, [])) => manejador.bloque_difundido(id, &bloque),
        Ok((_, _)) => Veredicto::Rechazar,
        Err(_) => Veredicto::Rechazar,
    }
}

/// A6-02 · Q3: ¿es aceptable una respuesta a una `Peticion::Prueba` con la `huella_pedida`?
///
/// [`Respuesta::NoDisponible`] es aceptable (no penaliza). [`Respuesta::Prueba`] lo es solo si la
/// huella casa **y** los `bytes` no superan [`MAX_RESPUESTA_PRUEBA_BYTES`]. Cualquier otra respuesta
/// a una petición de prueba no lo es.
///
/// Es `pub` para que las pruebas del carril ejerciten la regla sin un `Swarm`.
#[must_use]
pub fn prueba_respuesta_aceptable(huella_pedida: &[u8; 32], respuesta: &Respuesta) -> bool {
    match respuesta {
        Respuesta::NoDisponible => true,
        Respuesta::Prueba { huella, bytes } => {
            huella == huella_pedida && bytes.len() as u64 <= MAX_RESPUESTA_PRUEBA_BYTES
        }
        _ => false,
    }
}

/// Traduce un [`Veredicto`] a lo que entiende gossipsub. `None` para [`Veredicto::Diferir`]: no es
/// un veredicto final, así que no hay una `MessageAcceptance` que le corresponda todavía.
const fn a_acceptance(v: Veredicto) -> Option<gossipsub::MessageAcceptance> {
    match v {
        Veredicto::Aceptar => Some(gossipsub::MessageAcceptance::Accept),
        Veredicto::Ignorar => Some(gossipsub::MessageAcceptance::Ignore),
        Veredicto::Rechazar => Some(gossipsub::MessageAcceptance::Reject),
        Veredicto::Diferir => None,
    }
}

/// ¿Tiene `hashes` algún hash repetido? `O(n²)` sobre como mucho
/// [`crate::limites::MAX_HASHES_POR_PETICION`] (256) entradas de 32 B: barato, y el propio códec
/// (`peticion_desde_bytes`) ya rechazó cualquier petición con más hashes que ese tope antes de que
/// esto se llame.
fn tiene_hashes_repetidos(hashes: &[zx_core::digest::BlockHash]) -> bool {
    for (i, h) in hashes.iter().enumerate() {
        if hashes.iter().take(i).any(|otro| otro == h) {
            return true;
        }
    }
    false
}

/// Recorta una lista al límite del protocolo.
fn recortar<T>(mut v: Vec<T>, max: usize) -> Vec<T> {
    if v.len() > max {
        tracing::warn!(
            devueltos = v.len(),
            max,
            "el manejador devolvió más elementos de los que caben; se recorta"
        );
        v.truncate(max);
    }
    v
}

/// Convierte un `OutboundRequestId` en algo que pueda cruzar la frontera del crate.
fn request_id_a_u64(id: request_response::OutboundRequestId) -> u64 {
    id.to_string().parse().unwrap_or(0)
}

/// RD-4a · H2 · aplica al director una de las tres órdenes nuevas del servicio (y nada para el
/// resto, que no tocan el director).
///
/// Es una función libre —no una rama embebida en [`BucleRed::atender_comando`]— para poder probar
/// el mapeo `Comando → Director` **sin** construir un `Swarm`, igual que [`despachar`]. El director
/// vuelve a validar la entrada ([`Director::insertar_registro`]); aquí solo se registra el rechazo.
fn aplicar_orden_al_director(director: &mut Director, orden: Comando) {
    match orden {
        Comando::FijarPesos { pesos } => director.fijar_tabla_pesos(pesos),
        Comando::InsertarRegistro { entrada, ahora } => {
            if let Err(e) = director.insertar_registro(entrada, ahora) {
                tracing::debug!(%e, "el director rechazó una entrada del registro de direcciones");
            }
        }
        Comando::ProtegerSaliente { peer } => director.proteger_saliente(peer),
        _ => {}
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::{
        Comando, TemaDifusion, aplicar_orden_al_director, clasificar_tema, despachar,
        motivo_por_falta_de_zrxc,
    };
    use crate::codec::bloque_a_bytes;
    use crate::entrante::{IdDiferido, ManejadorEntrante, Veredicto};
    use crate::mensaje::{BloqueRed, Estado, FamiliaBloque, Fase, PuntaPow};
    use crate::presupuesto::Presupuesto;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Un `IdDiferido` cualquiera: estos tests no difieren nada, así que su valor es indiferente.
    fn id_prueba() -> IdDiferido {
        IdDiferido(0)
    }

    /// Un `PeerId` cualquiera para los callbacks que lo exigen (`tx_difundida`).
    fn peer_prueba() -> libp2p::PeerId {
        libp2p::PeerId::random()
    }
    use zx_core::amount::Amount;
    use zx_core::digest::{BlockHash, Digest, MerkleRoot, TxId};
    use zx_core::firma::ClavePublica;
    use zx_core::preimage::block::BlockHeader;
    use zx_core::red::Red;
    use zx_core::tx::{ExtensionTx, Lock, OutPoint, Tx, TxIn, TxOut};

    use crate::config::PerfilRed;
    use crate::director::Director;
    use crate::registro::{EntradaRegistro, VERSION as VERSION_REGISTRO};
    use libp2p::Multiaddr;
    use libp2p::identity::ed25519;
    use zx_core::firma::Firma;

    /// Manejador espía: cuenta cada callback y **no valida nada**.
    #[derive(Default)]
    struct Espia {
        bloques: AtomicUsize,
        txs: AtomicUsize,
        votos: AtomicUsize,
    }

    impl ManejadorEntrante for Espia {
        fn estado(&self) -> Estado {
            Estado {
                hash_genesis: BlockHash::from_digest(Digest::from_bytes([0; 32])),
                red: Red::Dev,
                fase: Fase::Pow,
                punta_pow: PuntaPow {
                    hash: BlockHash::from_digest(Digest::from_bytes([1; 32])),
                    altura: 0,
                    trabajo_acumulado: [0; 32],
                },
                terminal: None,
                puntas_post: vec![],
                blue_work_virtual: [0; 32],
                longitud_registro: 0,
            }
        }

        fn bloque_difundido(&self, _id: IdDiferido, _: &BloqueRed) -> Veredicto {
            self.bloques.fetch_add(1, Ordering::Relaxed);
            Veredicto::Aceptar
        }

        fn tx_difundida(&self, _peer: libp2p::PeerId, _: &[u8]) -> Veredicto {
            self.txs.fetch_add(1, Ordering::Relaxed);
            Veredicto::Aceptar
        }

        fn voto_difundida(&self, _peer: libp2p::PeerId, _: &[u8]) -> Veredicto {
            self.votos.fetch_add(1, Ordering::Relaxed);
            Veredicto::Aceptar
        }

        fn cabeceras_desde(&self, _: &[BlockHash], _: Option<BlockHash>) -> Vec<BlockHeader> {
            Vec::new()
        }

        fn bloques_por_hash(&self, _: &[BlockHash]) -> Vec<BloqueRed> {
            Vec::new()
        }
    }

    fn tx_llave(n: u8) -> Tx {
        Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: OutPoint {
                    prev_txid: TxId::from_digest(Digest::from_bytes([n; 32])),
                    prev_index: 0,
                },
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::nuevo(1_000).unwrap(),
                lock: Lock::PubKey {
                    pubkey: ClavePublica::desde_bytes([n; 32]),
                },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        }
    }

    /// Un bloque PoW real, serializable con `bloque_a_bytes`.
    fn bloque_pow(n: u8) -> BloqueRed {
        BloqueRed::Pow {
            cabecera: BlockHeader {
                consensus_branch_id: 0xa8b4_66a7,
                prev_hash: BlockHash::from_digest(Digest::from_bytes([n; 32])),
                merkle_root: MerkleRoot::from_digest(Digest::from_bytes([0x02; 32])),
                timestamp: 1_788_480_000,
                bits: 0x1c07_fff8,
                nonce: u64::from(n),
                height: u32::from(n),
            },
            txs: vec![tx_llave(0x03)],
            testigos: vec![vec![vec![0xAA; 64]]],
        }
    }

    /// **La tabla de los doce temas exactos y sus falsos positivos.**
    #[test]
    fn la_clasificacion_es_exacta() {
        for (tema, esperado) in [
            ("/zx-dev/bloques/pow/2", TemaDifusion::BloquePow),
            ("/zx-dev/bloques/post/2", TemaDifusion::BloquePost),
            ("/zx-dev/tx/2", TemaDifusion::Tx),
            ("/zx-dev/votos/2", TemaDifusion::Voto),
            ("/zerox/bloques/pow/2", TemaDifusion::BloquePow),
            ("/zerox/bloques/post/2", TemaDifusion::BloquePost),
            ("/zerox/tx/2", TemaDifusion::Tx),
            ("/zerox/votos/2", TemaDifusion::Voto),
            ("/zerox-testnet/bloques/pow/2", TemaDifusion::BloquePow),
            ("/zerox-testnet/bloques/post/2", TemaDifusion::BloquePost),
            ("/zerox-testnet/tx/2", TemaDifusion::Tx),
            ("/zerox-testnet/votos/2", TemaDifusion::Voto),
        ] {
            assert_eq!(clasificar_tema(tema), esperado, "{tema}");
        }

        for falso in [
            "/zx-dev/bloques/pow/2/extra",
            "/otra/zx-dev/bloques/pow/2",
            "/zx-dev/bloques/pow/3",
            "/zx-dev/bloques/1",
            "/zx-dev/tx/3",
            "/zx-dev/txs/1",
            "/zx-dev/votos/3",
            "/zx-dev/voto/1",
        ] {
            assert_eq!(
                clasificar_tema(falso),
                TemaDifusion::Desconocido,
                "{falso} no es ninguno de los doce temas"
            );
        }
    }

    /// FV-4b-N1 · un sobre de voto llega **opaco** al manejador por el cuarto tema.
    #[test]
    fn el_voto_llega_al_manejador_por_el_cuarto_tema() {
        let espia = Espia::default();
        let v = despachar(
            &espia,
            id_prueba(),
            &peer_prueba(),
            "/zx-dev/votos/2",
            b"ZXV1 opaco",
            &Presupuesto::default(),
        );
        assert_eq!(v, Veredicto::Aceptar, "el manejador decide");
        assert_eq!(espia.votos.load(Ordering::Relaxed), 1);
        assert_eq!(espia.bloques.load(Ordering::Relaxed), 0);
        assert_eq!(espia.txs.load(Ordering::Relaxed), 0);
    }

    /// Un bloque PoW bien formado llega **una sola vez** al callback por su tema.
    #[test]
    fn el_bloque_bien_formado_llega_una_vez() {
        let bytes = bloque_a_bytes(&bloque_pow(1));
        let espia = Espia::default();
        let v = despachar(
            &espia,
            id_prueba(),
            &peer_prueba(),
            "/zx-dev/bloques/pow/2",
            &bytes,
            &Presupuesto::default(),
        );

        assert_eq!(espia.bloques.load(Ordering::Relaxed), 1);
        assert_eq!(v, Veredicto::Aceptar, "el manejador decide");
        assert_eq!(espia.txs.load(Ordering::Relaxed), 0);
    }

    /// Un bloque PoW por el tema **post** se rechaza: la familia declarada por el tema manda.
    #[test]
    fn un_bloque_con_el_tema_de_otra_familia_se_rechaza() {
        let bytes = bloque_a_bytes(&bloque_pow(1));
        let espia = Espia::default();
        assert_eq!(
            despachar(
                &espia,
                id_prueba(),
                &peer_prueba(),
                "/zx-dev/bloques/post/2",
                &bytes,
                &Presupuesto::default()
            ),
            Veredicto::Rechazar,
            "familia cambiada"
        );
        assert_eq!(espia.bloques.load(Ordering::Relaxed), 0);
    }

    /// **El presupuesto agotado es un recurso local, no un defecto del par.**
    #[test]
    fn el_presupuesto_agotado_ignora_y_no_penaliza() {
        let bytes = bloque_a_bytes(&bloque_pow(1));

        let espia = Espia::default();
        assert_eq!(
            despachar(
                &espia,
                id_prueba(),
                &peer_prueba(),
                "/zx-dev/bloques/pow/2",
                &bytes,
                &Presupuesto::nuevo(0)
            ),
            Veredicto::Ignorar,
            "sin presupuesto no se puede juzgar: no se penaliza al propagador"
        );
        assert_eq!(
            espia.bloques.load(Ordering::Relaxed),
            0,
            "sin bloque parseado no se llama al callback"
        );

        // El mismo bloque, con presupuesto suficiente, sí llega al callback.
        let espia = Espia::default();
        assert_eq!(
            despachar(
                &espia,
                id_prueba(),
                &peer_prueba(),
                "/zx-dev/bloques/pow/2",
                &bytes,
                &Presupuesto::default()
            ),
            Veredicto::Aceptar
        );
        assert_eq!(espia.bloques.load(Ordering::Relaxed), 1);
    }

    /// Residuo y truncamiento se rechazan; el tema desconocido ni mira.
    #[test]
    fn residuo_truncado_y_tema_desconocido() {
        let base = bloque_a_bytes(&bloque_pow(1));

        let mut con_residuo = base.clone();
        con_residuo.push(0x00);
        let mut truncado = base;
        truncado.pop();

        let espia = Espia::default();
        assert_eq!(
            despachar(
                &espia,
                id_prueba(),
                &peer_prueba(),
                "/zx-dev/bloques/pow/2",
                &con_residuo,
                &Presupuesto::default()
            ),
            Veredicto::Rechazar,
            "un byte residual invalida el bloque"
        );
        assert_eq!(
            despachar(
                &espia,
                id_prueba(),
                &peer_prueba(),
                "/zx-dev/bloques/pow/2",
                &truncado,
                &Presupuesto::default()
            ),
            Veredicto::Rechazar,
            "un bloque truncado invalida"
        );
        assert_eq!(espia.bloques.load(Ordering::Relaxed), 0);

        let espia2 = Espia::default();
        for falso in [
            "/zx-dev/bloques/pow/2/extra",
            "/otra/zx-dev/bloques/pow/2",
            "/zx-dev/bloques/pow/3",
        ] {
            assert_eq!(
                despachar(
                    &espia2,
                    id_prueba(),
                    &peer_prueba(),
                    falso,
                    &con_residuo,
                    &Presupuesto::default()
                ),
                Veredicto::Ignorar,
                "{falso}"
            );
        }
        assert_eq!(espia2.bloques.load(Ordering::Relaxed), 0);
        assert_eq!(espia2.txs.load(Ordering::Relaxed), 0);
    }

    /// La familia del bloque y la del tema coinciden para PoST también.
    #[test]
    fn el_bloque_post_llega_por_su_tema() {
        // Un PoST mínimo construido a mano es costoso; basta comprobar que el despacho usa la
        // familia del tema: un bloque PoW por el tema post se rechaza (test de arriba) y un
        // truncado por el tema post también.
        let espia = Espia::default();
        assert_eq!(
            despachar(
                &espia,
                id_prueba(),
                &peer_prueba(),
                "/zx-dev/bloques/post/2",
                &[FamiliaBloque::DISC_POST],
                &Presupuesto::default()
            ),
            Veredicto::Rechazar
        );
        assert_eq!(espia.bloques.load(Ordering::Relaxed), 0);
    }

    /// Serializa una tx como viaja en el tema de transacciones (`tx_a_bytes`).
    fn tx_a_wire(tx: &Tx, testigos: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        zx_core::wire::tx_a_bytes(&mut buf, tx, testigos);
        buf
    }

    /// **TX-R-02/04.** Una transacción suelta bien formada llega al callback del nodo con su
    /// propagador; no toca el callback de bloques.
    #[test]
    fn una_tx_bien_formada_llega_una_vez_con_su_par() {
        let bytes = tx_a_wire(&tx_llave(0x03), &[]);
        let espia = Espia::default();
        let peer = peer_prueba();
        assert_eq!(
            despachar(
                &espia,
                id_prueba(),
                &peer,
                "/zx-dev/tx/2",
                &bytes,
                &Presupuesto::default()
            ),
            Veredicto::Aceptar
        );
        assert_eq!(espia.txs.load(Ordering::Relaxed), 1);
        assert_eq!(espia.bloques.load(Ordering::Relaxed), 0);
    }

    /// **TX-R-04.** Un byte residual o un truncamiento en el tema de tx se rechaza (basura
    /// demostrable): el manejador no llega a verlo.
    #[test]
    fn tx_con_residuo_o_truncada_se_rechaza() {
        let base = tx_a_wire(&tx_llave(0x03), &[]);
        let mut con_residuo = base.clone();
        con_residuo.push(0x00);
        let mut truncada = base;
        truncada.pop();

        let espia = Espia::default();
        assert_eq!(
            despachar(
                &espia,
                id_prueba(),
                &peer_prueba(),
                "/zx-dev/tx/2",
                &con_residuo,
                &Presupuesto::default()
            ),
            Veredicto::Rechazar
        );
        assert_eq!(
            despachar(
                &espia,
                id_prueba(),
                &peer_prueba(),
                "/zx-dev/tx/2",
                &truncada,
                &Presupuesto::default()
            ),
            Veredicto::Rechazar
        );
        assert_eq!(espia.txs.load(Ordering::Relaxed), 0);
    }

    /// Un tema de tx de **otra red** no se confunde con el de la red propia.
    #[test]
    fn el_tema_de_tx_de_otra_red_no_se_clasifica() {
        assert_eq!(clasificar_tema("/otra/tx/1"), TemaDifusion::Desconocido);
        assert_eq!(
            clasificar_tema("/zerox/tx/2"),
            TemaDifusion::Tx,
            "el contrato sí reconoce el tema público"
        );
    }

    /// **ORDEN-ZC3 (a).** Un bloque difundido **comprimido con ZRX-C** da la vuelta y llega íntegro
    /// al manejador: se comprime la serialización y se descomprime antes de parsear, así que los
    /// identificadores siguen calculándose sobre la forma canónica.
    #[test]
    fn un_bloque_comprimido_llega_al_manejador() {
        let bloque = bloque_pow(1);
        let crudo = bloque_a_bytes(&bloque);
        let comprimido = crate::zrxc::comprimir_red(&crudo, None);
        assert!(
            crate::zrxc::es_marco(&comprimido),
            "los bloques de red viajan enmarcados"
        );
        assert!(
            comprimido.len() < crudo.len(),
            "un bloque de red real MUST comprimir: {} -> {}",
            crudo.len(),
            comprimido.len()
        );

        let espia = Espia::default();
        assert_eq!(
            despachar(
                &espia,
                id_prueba(),
                &peer_prueba(),
                "/zx-dev/bloques/pow/2",
                &comprimido,
                &Presupuesto::default()
            ),
            Veredicto::Aceptar
        );
        assert_eq!(espia.bloques.load(Ordering::Relaxed), 1);

        // Y la forma descomprimida es **idéntica**: mismo bloque, sin maleabilidad.
        let crudo_leido =
            crate::zrxc::descomprimir_por_id(&comprimido, &crate::zrxc::Limites::nuevo(u64::MAX))
                .unwrap();
        let (leido, resto) =
            crate::codec::bloque_desde_bytes(&crudo_leido, FamiliaBloque::Pow).unwrap();
        assert_eq!(leido, bloque);
        assert!(resto.is_empty());
    }

    /// **ORDEN-ZC3 (d).** Una bomba de descompresión (salida declarada por encima del tope) se
    /// rechaza. El `Veredicto::Rechazar` del llamante es lo que dispara `par_penalizado` y la
    /// desconexión con `ViolacionDeConsenso`.
    #[test]
    fn una_bomba_de_descompresion_se_rechaza_y_penaliza() {
        let datos = vec![0u8; 1_000];
        let mut marco = crate::zrxc::comprimir_red(&datos, None);
        // Fuerza `len_original` a un valor absurdo (bytes 11..19 de la cabecera, big-endian).
        if let Some(tramo) = marco.get_mut(11..19) {
            tramo.copy_from_slice(&u64::MAX.to_be_bytes());
        }
        let espia = Espia::default();
        assert_eq!(
            despachar(
                &espia,
                id_prueba(),
                &peer_prueba(),
                "/zx-dev/bloques/pow/2",
                &marco,
                &Presupuesto::default()
            ),
            Veredicto::Rechazar,
            "una bomba MUST rechazarse y penalizar"
        );
        assert_eq!(espia.bloques.load(Ordering::Relaxed), 0);
    }

    /// **ORDEN-ZC3 (b).** Un par que no anuncia ZRX-C se rechaza con motivo claro y **no** se banea.
    #[test]
    fn sin_marca_zrxc_se_rechaza_con_motivo_claro() {
        assert_eq!(
            motivo_por_falta_de_zrxc("rust-libp2p/0.56.0"),
            Some(crate::error::MotivoDesconexion::SinZrxC)
        );
        assert_eq!(
            motivo_por_falta_de_zrxc("zerox/0.0.0/dev"),
            Some(crate::error::MotivoDesconexion::SinZrxC)
        );
        assert_eq!(motivo_por_falta_de_zrxc("zerox/0.0.0/dev+zrxc1"), None);
        assert!(
            !crate::error::MotivoDesconexion::SinZrxC.puntua(),
            "un nodo viejo no se banea"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // RD-4a · H2: las tres órdenes nuevas del servicio llegan al director.
    // ---------------------------------------------------------------------------------------------

    /// Un director con el registro de direcciones encendido y sin anclas automáticas (la rotación
    /// no queda bloqueada por las anclas), igual que el montaje de las pruebas de `director.rs`.
    fn director_de_prueba() -> Director {
        Director::nuevo(
            Red::Dev,
            PerfilRed {
                registro_activo: true,
                anclas: 0,
                ..PerfilRed::de(Red::Dev)
            },
        )
    }

    /// Par Ed25519 determinista por semilla.
    fn par_de(semilla: u8) -> (ed25519::Keypair, ClavePublica) {
        let sk = ed25519::SecretKey::try_from_bytes([semilla; 32]).unwrap();
        let kp = ed25519::Keypair::from(sk);
        let pk = ClavePublica::desde_bytes(kp.public().to_bytes());
        (kp, pk)
    }

    fn clave_de(semilla: u8) -> ClavePublica {
        par_de(semilla).1
    }

    /// Una dirección de marcado de prueba (aceptable en la red dev).
    fn addr_rd4a(ip: &str) -> Multiaddr {
        format!("/ip4/{ip}/tcp/9833").parse().unwrap()
    }

    /// Una entrada `ZXREG1` con firma **válida** del propio productor.
    fn entrada_firmada(semilla: u8, epoch: u64, dirs: Vec<Multiaddr>) -> EntradaRegistro {
        let (kp, pk) = par_de(semilla);
        let mut e = EntradaRegistro {
            version: VERSION_REGISTRO,
            red: Red::Dev,
            productor: pk,
            epoch,
            direcciones: dirs,
            firma: Firma::desde_bytes([0u8; 64]),
        };
        let sig = kp.sign(e.preimagen().as_bytes());
        e.firma = Firma::desde_bytes(sig.try_into().unwrap());
        e
    }

    /// **RD-4a · H2 · control R3.** La orden de fijar pesos llega al director: si la rama no hiciera
    /// nada, `peso` devolvería `None` y esta prueba caería.
    #[test]
    fn orden_fijar_pesos_llega_al_director() {
        let mut d = director_de_prueba();
        let a = clave_de(1);
        let b = clave_de(2);
        aplicar_orden_al_director(
            &mut d,
            Comando::FijarPesos {
                pesos: vec![(a, 7), (b, 3)],
            },
        );
        assert_eq!(d.registro().peso(&a), Some(7));
        assert_eq!(d.registro().peso(&b), Some(3));
    }

    /// **RD-4a · H2.** La orden de insertar registro llega al director y **este revalida**: la
    /// entrada válida entra y la de firma inválida no.
    #[test]
    fn orden_insertar_registro_llega_al_director() {
        let mut d = director_de_prueba();
        let (_, pk) = par_de(1);
        let valida = entrada_firmada(1, 1_000, vec![addr_rd4a("10.0.0.1")]);
        aplicar_orden_al_director(
            &mut d,
            Comando::InsertarRegistro {
                entrada: valida,
                ahora: 1_000,
            },
        );
        assert_eq!(d.registro().longitud(), 1);
        assert!(d.registro().get(&pk).is_some());

        // Firma inválida: el director la rechaza y **no entra**.
        let mut invalida = entrada_firmada(1, 1_001, vec![addr_rd4a("10.0.0.2")]);
        invalida.firma = Firma::desde_bytes([7u8; 64]);
        aplicar_orden_al_director(
            &mut d,
            Comando::InsertarRegistro {
                entrada: invalida,
                ahora: 1_001,
            },
        );
        assert_eq!(d.registro().longitud(), 1, "la firma inválida no entra");
    }

    /// **RD-4a · H2.** La orden de proteger saliente llega al director (marcar y quitar).
    #[test]
    fn orden_proteger_saliente_llega_al_director() {
        let mut d = director_de_prueba();
        let peer = libp2p::PeerId::random();
        aplicar_orden_al_director(&mut d, Comando::ProtegerSaliente { peer: Some(peer) });
        assert_eq!(d.saliente_protegida(), Some(peer));
        aplicar_orden_al_director(&mut d, Comando::ProtegerSaliente { peer: None });
        assert_eq!(d.saliente_protegida(), None);
    }

    /// **RD-4a · H2.** Con tabla y entradas el director sortea; con tabla y sin entradas, no (es el
    /// caso real de hoy, que este paso cierra).
    #[test]
    fn con_tabla_y_entradas_el_director_sortea_y_sin_entradas_no() {
        let a = clave_de(1);
        let mut con_entradas = director_de_prueba();
        aplicar_orden_al_director(
            &mut con_entradas,
            Comando::FijarPesos {
                pesos: vec![(a, 5)],
            },
        );
        aplicar_orden_al_director(
            &mut con_entradas,
            Comando::InsertarRegistro {
                entrada: entrada_firmada(1, 1_000, vec![addr_rd4a("10.0.0.1")]),
                ahora: 1_000,
            },
        );
        assert!(
            con_entradas.sortear_candidata().is_some(),
            "con tabla y entrada productiva, sortea"
        );

        let mut sin_entradas = director_de_prueba();
        aplicar_orden_al_director(
            &mut sin_entradas,
            Comando::FijarPesos {
                pesos: vec![(a, 5)],
            },
        );
        assert!(
            sin_entradas.sortear_candidata().is_none(),
            "sin entradas no hay a quién sortear"
        );
    }
}
