//! Sincronización (`ORDEN-W06d2` decisión 4): saludo, localizador PoW y recorrido hacia atrás del
//! DAG por padres.
//!
//! # Por qué esto es una tarea `tokio` aparte, y no el hilo de consenso
//!
//! Orquestar peticiones (a quién le pido qué, cuándo reintentar) es protocolo, no consenso: no
//! necesita `zx-cadena`. Vive en su propia tarea asíncrona, hablando con [`zx_p2p::servicio::ManejoRed`]
//! directamente y leyendo [`super::vista::VistaRed`] para saber qué nos falta. Los bloques que
//! consigue no se admiten aquí: se encolan como [`super::TrabajoRed::BloqueDeSincronizacion`] para
//! que el hilo de consenso los pase por la tubería única — la misma que usa un bloque llegado por
//! gossip. Así ningún bloque de red evita la validación completa (decisión 2 de la orden), venga por
//! donde venga.
//!
//! # El recorrido del DAG reutiliza el depósito de huérfanos
//!
//! Esta tarea no implementa un algoritmo de recorrido de DAG propio: pide como `Bloques` las puntas
//! PoST que un par anuncia en su saludo. Si no tenemos sus padres, el hilo de consenso los deposita
//! como huérfanos y pide él mismo los padres que faltan (decisión 3) — la misma cascada que resuelve
//! un huérfano llegado por gossip resuelve, sin código nuevo, el "recorrido hacia atrás desde las
//! puntas del par" que pide la decisión 4. El límite de saltos
//! ([`super::LIMITE_SALTOS_RECORRIDO_ATRAS`]) lo aplica el hilo de consenso, no esta tarea.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use tokio::sync::mpsc;
use tokio::time::{self, MissedTickBehavior};

use zx_p2p::error::MotivoDesconexion;
use zx_p2p::mensaje::{BloqueRed, Peticion, Respuesta};
use zx_p2p::servicio::{EventoRed, ManejoRed};

use super::registro_direcciones::{
    PlanificadorRegistro, PublicacionPropia, RegistroRed, aplicar_pagina_recibida,
    debe_pedir_pagina, unix_ahora,
};
use super::vista::VistaRed;
use super::{EmisorTrabajoRed, ResultadoEnvioTrabajo, TrabajoRed};
use crate::registro::Registro;

/// Cuántos hashes se piden a la vez en una `Peticion::Bloques` de sincronización (el tope del
/// protocolo, no un valor propio: pedir más de golpe es un `Excedido` seguro).
const LOTE_BLOQUES: usize = zx_p2p::limites::MAX_HASHES_POR_PETICION;

/// Cada cuánto se repite el saludo a los pares **ya conectados**, no solo al conectar.
///
/// `ORDEN-W06d3`, diagnóstico de la decisión 4 (`PROGRESO.md`): un bloque perdido por gossip —por
/// ejemplo, publicado antes de que la malla de gossipsub terminara de formarse tras conectar— deja
/// una cadena de huérfanos que **nadie vuelve a pedir**: `intentar_admitir_*_de_red` solo pide
/// activamente el padre que falta cuando conoce el origen (`Some(peer)`, la ruta de sincronización),
/// nunca para un huérfano llegado por gossip (`origen = None`, no se sabe quién lo propagó), y el
/// único disparador de un nuevo `Peticion::CabecerasPow`/`Peticion::Bloques` era el saludo **al
/// conectar**. Sin un reintento periódico, un nodo que se queda atrás una sola vez no se recupera
/// nunca por sí solo, aunque la red entera siga viva y minando. Valor dev: generoso frente al ritmo
/// de bloques PoW (dificultad trivial, sub-segundo) para no saturar de peticiones un par que va bien.
const PLAZO_REINTENTO_SALUDO: Duration = Duration::from_secs(5);

/// `T_par`: cada cuánto, como mucho, se pide una página del registro de direcciones a un mismo par
/// (`ORDEN-RD3c` N3; contrato `PCRD2`: `T_par = 60 s`).
const T_PAR_REGISTRO_DIRECCIONES: Duration = Duration::from_secs(60);

/// Qué sabemos de un par para no repetirle la misma petición sin sentido.
///
/// `ORDEN-W06d6` decisión 1: `cursor`, `longitud_conocida`, `pagina_en_vuelo` y `pendientes` son la
/// sincronización por páginas del registro de admisión — la vía **principal** de puesta al día
/// (la resolución por padres, ya existente, se queda para los huecos pequeños). Un valor `Default`
/// nuevo (`cursor = 0`) es exactamente "empieza en 0 al conectar": `PeerDesconectado` quita la
/// entrada entera del mapa, así que una reconexión siempre arranca con un `EstadoPeer` fresco —
/// tras cada reconexión se vuelve a transferir el registro entero del par (límite declarado,
/// coste lineal en la historia; aceptable en la red dev, como E-10).
#[derive(Default)]
struct EstadoPeer {
    saludo_pedido: bool,
    /// Siguiente índice del registro de admisión de este par que todavía no hemos encolado.
    cursor: u64,
    /// Mayor `longitud_registro` que este par ha declarado (saludo o `Respuesta::Registro`).
    longitud_conocida: u64,
    /// ¿Hay una `Peticion::Registro` de este par sin responder todavía? **Una página en vuelo por
    /// par**: no se pide la siguiente mientras esta sea `true`.
    pagina_en_vuelo: bool,
    /// Bloques de la última página que todavía no se han podido encolar hacia el hilo de consenso
    /// (cola llena, RI-3a #3): se reintentan en cada barrido periódico, en el mismo orden, antes de
    /// pedir la página siguiente. Esto es la **contrapresión real** de la decisión 1: la siguiente
    /// página se pide cuando el hilo de consenso ha hecho sitio para la anterior (la cola acotada
    /// lo señala con `Lleno`), no en un temporizador fijo.
    pendientes: VecDeque<BloqueRed>,
    /// `ORDEN-RD3c` N3: planificador de las peticiones de página del registro de direcciones a este
    /// par (una por `T_par`, nunca con otra del mismo tipo sin responder).
    planificador_registro: PlanificadorRegistro,
    /// `ORDEN-RD3c` N3: siguiente índice del registro de direcciones de este par que toca pedir.
    cursor_registro_direcciones: u64,
}

/// Corre para siempre (hasta que el canal de eventos se cierra): la tarea de sincronización.
pub async fn tarea_sincronizacion(
    mut eventos: mpsc::Receiver<EventoRed>,
    manejo: ManejoRed,
    vista: Arc<VistaRed>,
    trabajo: EmisorTrabajoRed,
    registro: Arc<Registro>,
    registro_direcciones: Arc<RegistroRed>,
    publicacion: Option<PublicacionPropia>,
) {
    let mut peers: HashMap<PeerId, EstadoPeer> = HashMap::new();
    let mut reintento = time::interval(PLAZO_REINTENTO_SALUDO);
    reintento.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // `ORDEN-RD3c` N7: instante de la última publicación propia, para republicar cada
    // `REGISTRO_REPUBLICACION_S`.
    let mut ultima_publicacion = Instant::now();
    // El primer `tick()` de un `interval` es inmediato: se consume aquí, antes del bucle, para no
    // repetir el saludo del `PeerConectado` inicial un instante después de haberlo pedido ya.
    reintento.tick().await;
    loop {
        tokio::select! {
            evento = eventos.recv() => {
                let Some(evento) = evento else { break; };
                match evento {
                    EventoRed::PeerConectado(peer) => {
                        // `ORDEN-W07a`: traza de conexión (no crítica). `direccion` no es
                        // computable aquí (`EventoRed::PeerConectado` solo trae el `PeerId`), así
                        // que el campo se omite (§0).
                        let evento = registro
                            .evento("par_conectado")
                            .str("par", &peer.to_string());
                        let _ = registro.escribir(evento, false);
                        peers.entry(peer).or_default();
                        if manejo.pedir(peer, Peticion::Estado).await.is_err() {
                            tracing::debug!(%peer, "no se pudo pedir el saludo: el bucle de red ya no está");
                        }
                        // `ORDEN-RD3c` N3: al conectar, si el registro está encendido y toca,
                        // pide la primera página de direcciones a este par.
                        pedir_pagina_registro_si_toca(
                            peer,
                            &mut peers,
                            &manejo,
                            &registro_direcciones,
                        )
                        .await;
                    }
                    EventoRed::PeerDesconectado(peer) => {
                        let evento = registro
                            .evento("par_desconectado")
                            .str("par", &peer.to_string());
                        let _ = registro.escribir(evento, false);
                        peers.remove(&peer);
                    }
                    EventoRed::ConexionSaliente(peer) => {
                        // RED-2 · traza de las salientes elegidas por el nodo (para V5): deja en el
                        // registro qué pares ocupan las 24 salientes.
                        let evento = registro
                            .evento("conexion_saliente")
                            .str("par", &peer.to_string());
                        let _ = registro.escribir(evento, false);
                    }
                    EventoRed::SorteoDirector {
                        peso_total,
                        entradas,
                        productor,
                    } => {
                        // RD-4b · P6: mismo camino que `conexion_saliente` (el evento llega por el
                        // canal de `EventoRed` y esta tarea lo escribe). Un sorteo por rotación con
                        // el registro encendido; con el registro apagado el director no sortea.
                        let mut evento = registro
                            .evento("sorteo_director")
                            .u64("peso_total", peso_total)
                            .u64("entradas_con_peso_y_direccion", entradas)
                            .bool("eligio", productor.is_some());
                        if let Some(p) = productor {
                            let hex: String = p.iter().map(|b| format!("{b:02x}")).collect();
                            evento = evento.str("productor", &hex);
                        }
                        let _ = registro.escribir(evento, false);
                    }
                    EventoRed::PeticionFallida { peer } => {
                        tracing::debug!(%peer, "una petición de sincronización no llegó a completarse");
                        // Pudo ser la `Peticion::Registro` en vuelo: sin esto, `pagina_en_vuelo`
                        // se quedaría en `true` para siempre y este par dejaría de sincronizar por
                        // registro hasta la próxima reconexión.
                        if let Some(e) = peers.get_mut(&peer) {
                            e.pagina_en_vuelo = false;
                            // `ORDEN-RD3c` N3: una petición de direcciones fallida deja de estar en
                            // vuelo (el plazo de `T_par` sigue corriendo).
                            e.planificador_registro.peticion_fallida();
                        }
                        pedir_pagina_si_toca(peer, &mut peers, &manejo).await;
                        pedir_pagina_registro_si_toca(
                            peer,
                            &mut peers,
                            &manejo,
                            &registro_direcciones,
                        )
                        .await;
                    }
                    EventoRed::Respuesta { peer, respuesta, .. } => {
                        atender_respuesta(&manejo, &vista, &trabajo, &registro, &mut peers, &registro_direcciones, peer, *respuesta).await;
                        drenar_pendientes(peer, &mut peers, &trabajo);
                        pedir_pagina_si_toca(peer, &mut peers, &manejo).await;
                        pedir_pagina_registro_si_toca(
                            peer,
                            &mut peers,
                            &manejo,
                            &registro_direcciones,
                        )
                        .await;
                    }
                    EventoRed::Escuchando(_) | EventoRed::Suscripcion { .. } => {}
                }
            }
            _ = reintento.tick() => {
                for peer in peers.keys().copied().collect::<Vec<_>>() {
                    if manejo.pedir(peer, Peticion::Estado).await.is_err() {
                        tracing::debug!(%peer, "no se pudo repetir el saludo periódico");
                    }
                    // `ORDEN-W06d6` decisión 1: reintenta encolar lo que se quedó atascado por la
                    // cola llena, y si ya está todo encolado y toca, pide la siguiente página.
                    drenar_pendientes(peer, &mut peers, &trabajo);
                    pedir_pagina_si_toca(peer, &mut peers, &manejo).await;
                    // `ORDEN-RD3c` N3: una página de direcciones por par y `T_par` como mucho.
                    pedir_pagina_registro_si_toca(
                        peer,
                        &mut peers,
                        &manejo,
                        &registro_direcciones,
                    )
                    .await;
                }
                // `ORDEN-RD3c` N4/N7: caducidad de pendientes y republicación de la entrada propia.
                registro_direcciones.expirar(unix_ahora());
                if let Some(p) = &publicacion
                    && ultima_publicacion.elapsed() >= p.intervalo
                {
                    ultima_publicacion = Instant::now();
                    let ahora = unix_ahora();
                    match registro_direcciones
                        .publicar_propia(&p.productor, &p.direcciones, ahora)
                    {
                        Ok(true) => {
                            let evento = registro
                                .evento("registro_direccion_publicada")
                                .u64("epoch", ahora);
                            let _ = registro.escribir(evento, false);
                        }
                        Ok(false) => {}
                        Err(e) => tracing::warn!(
                            %e,
                            "no se pudo republicar la entrada propia del registro de direcciones"
                        ),
                    }
                }
            }
        }
    }
}

/// Reintenta encolar hacia el hilo de consenso lo que quedó pendiente de la última página de este
/// par (RI-3a #3: la cola puede estar llena). Avanza `cursor` por cada bloque que sí se encola;
/// para en el primero que no quepa (se reintenta en el próximo barrido, en el mismo orden).
fn drenar_pendientes(
    peer: PeerId,
    peers: &mut HashMap<PeerId, EstadoPeer>,
    trabajo: &EmisorTrabajoRed,
) {
    let Some(e) = peers.get_mut(&peer) else {
        return;
    };
    while let Some(bloque) = e.pendientes.pop_front() {
        match trabajo.intentar_enviar(TrabajoRed::BloqueDeSincronizacion {
            de: peer,
            bloque,
            llegada: Instant::now(),
        }) {
            ResultadoEnvioTrabajo::Encolado => {
                e.cursor = e.cursor.saturating_add(1);
            }
            ResultadoEnvioTrabajo::Lleno(TrabajoRed::BloqueDeSincronizacion { bloque, .. }) => {
                // Todavía llena: se devuelve al frente y se para — ni este ni los que le siguen se
                // reordenan (el registro es un orden causal, RI-3a #3 exige no bloquear la red,
                // así que simplemente no se sigue intentando esta vuelta).
                e.pendientes.push_front(bloque);
                break;
            }
            ResultadoEnvioTrabajo::Lleno(_) => {
                // No debería ocurrir (este bucle solo encola `BloqueDeSincronizacion`): se registra
                // y se sigue, en vez de entrar en pánico por una variante que no se puede dar.
                tracing::error!(
                    "drenar_pendientes: intentar_enviar devolvió una variante inesperada"
                );
                break;
            }
            ResultadoEnvioTrabajo::Cerrado(_) => {
                // El hilo de consenso ya no existe: nada más que hacer con esta página. El bucle
                // principal lo descubrirá pronto por su cuenta (el canal de eventos también se
                // cerrará cuando el nodo entero termine).
                e.pendientes.clear();
                break;
            }
        }
    }
}

/// Pide la siguiente página del registro de admisión de `peer` si: no hay ya una en vuelo, no
/// quedan bloques pendientes de encolar de la anterior (la contrapresión de la decisión 1), y el
/// cursor todavía no alcanzó la longitud que ese par declaró.
async fn pedir_pagina_si_toca(
    peer: PeerId,
    peers: &mut HashMap<PeerId, EstadoPeer>,
    manejo: &ManejoRed,
) {
    let Some(e) = peers.get_mut(&peer) else {
        return;
    };
    if e.pagina_en_vuelo || !e.pendientes.is_empty() || e.cursor >= e.longitud_conocida {
        return;
    }
    e.pagina_en_vuelo = true;
    let desde = e.cursor;
    if manejo
        .pedir(peer, Peticion::Registro { desde })
        .await
        .is_err()
    {
        tracing::debug!(%peer, desde, "no se pudo pedir una página del registro de admisión");
        if let Some(e) = peers.get_mut(&peer) {
            e.pagina_en_vuelo = false;
        }
    }
}

/// `ORDEN-RD3c`: la firma ya cablea red, vista, trabajo, registro estructurado y registro de
/// direcciones; agruparlas en un `struct` de contexto no aclararía más y tocaría a los llamantes.
#[expect(
    clippy::too_many_arguments,
    reason = "contexto de la tarea de sincronización, ya agotado antes de RD-3c"
)]
async fn atender_respuesta(
    manejo: &ManejoRed,
    vista: &VistaRed,
    trabajo: &EmisorTrabajoRed,
    registro: &Registro,
    peers: &mut HashMap<PeerId, EstadoPeer>,
    registro_direcciones: &RegistroRed,
    peer: PeerId,
    respuesta: Respuesta,
) {
    match respuesta {
        Respuesta::Estado(otro) => {
            let nuestro = vista.estado();
            if otro.hash_genesis != nuestro.hash_genesis || otro.red != nuestro.red {
                tracing::warn!(%peer, "génesis o red ajenos: desconectando");
                let evento = registro
                    .evento("par_penalizado")
                    .str("par", &peer.to_string())
                    .str("motivo", "génesis o red ajenos")
                    .str("accion", "expulsion");
                let _ = registro.escribir(evento, false);
                manejo
                    .desconectar(peer, MotivoDesconexion::ViolacionDeConsenso)
                    .await
                    .ok();
                return;
            }
            if let Some(e) = peers.get_mut(&peer) {
                e.saludo_pedido = true;
                // `ORDEN-W06d6` decisión 1: el saludo trae la longitud del registro del par; es lo
                // que dispara la primera página (o una más, si el par avanzó desde la última vez).
                e.longitud_conocida = e.longitud_conocida.max(otro.longitud_registro);
            }
            vista.actualizar_mejor_longitud_par(otro.longitud_registro);

            // Fase PoW: pedimos cabeceras si el par declara más altura que nosotros, **o** si su
            // punta declarada es un hash que no reconocemos todavía (aunque su altura sea igual o
            // menor). `ORDEN-W06d3`, hallazgo en vivo (`PROGRESO.md`): comparar solo la altura
            // asume que "más alto" es siempre "más trabajo", lo que es falso frente a una
            // bifurcación real — un nodo que ha estado minando **en solitario** (p. ej. porque el
            // primer bloque de otro par se perdió antes de que la malla de gossipsub terminara de
            // formarse, el mismo diagnóstico de la decisión 4) puede alcanzar, sin compartir ningún
            // bloque con nadie, una altura igual o mayor que la de la red compartida, y entonces
            // esta condición **nunca** se disparaba: el nodo aislado se quedaba así para siempre,
            // sin pedir jamás las cabeceras de la rama que en realidad pesa más (`FC-3` lo decidiría
            // bien si llegara a verla; el problema es que nunca llega). Pedir también por "punta
            // desconocida" no cuesta más que una petición de más cuando de verdad coincide.
            let punta_desconocida = !vista.tiene_cuerpo(&otro.punta_pow.hash);
            if otro.punta_pow.altura > vista.altura_pow() || punta_desconocida {
                let locator = vista.locator();
                if manejo
                    .pedir(
                        peer,
                        Peticion::CabecerasPow {
                            locator,
                            parada: None,
                        },
                    )
                    .await
                    .is_err()
                {
                    tracing::debug!(%peer, "no se pudo pedir cabeceras PoW");
                }
            }

            // Fase PoST: pedimos directamente sus puntas que no tengamos ya. Si sus padres nos
            // faltan, el hilo de consenso los deposita como huérfanos y pide él mismo lo que falte
            // (ver el docstring del módulo): esto basta para arrancar el recorrido hacia atrás.
            let puntas_ausentes: Vec<_> = otro
                .puntas_post
                .iter()
                .copied()
                .filter(|h| !vista.tiene_cuerpo(h))
                .collect();
            for lote in puntas_ausentes.chunks(LOTE_BLOQUES) {
                if manejo
                    .pedir(
                        peer,
                        Peticion::Bloques {
                            hashes: lote.to_vec(),
                        },
                    )
                    .await
                    .is_err()
                {
                    tracing::debug!(%peer, "no se pudo pedir puntas PoST");
                }
            }
        }
        Respuesta::CabecerasPow(cabeceras) => {
            // No se valida aquí (esta tarea no ve consenso): se piden los cuerpos completos en
            // lotes, y es la tubería única del hilo de consenso la que decide si son válidas.
            let hashes: Vec<_> = cabeceras
                .iter()
                .map(zx_core::preimage::block::BlockHeader::block_hash)
                .filter(|h| !vista.tiene_cuerpo(h))
                .collect();
            for lote in hashes.chunks(LOTE_BLOQUES) {
                if manejo
                    .pedir(
                        peer,
                        Peticion::Bloques {
                            hashes: lote.to_vec(),
                        },
                    )
                    .await
                    .is_err()
                {
                    tracing::debug!(%peer, "no se pudo pedir cuerpos PoW");
                }
            }
        }
        Respuesta::Bloques(bloques) => {
            for bloque in bloques {
                // `ORDEN-W06d6` (RI-3a #3): un tope lleno (sin bloquear la red) descarta y sigue —
                // el bloque perdido se recupera por la propia sincronización (el cursor no avanza
                // hasta que el hilo de consenso procese, decisión 1) o por la petición de padres.
                // Solo el canal **cerrado** (hilo de consenso muerto) termina esta tarea.
                match trabajo.intentar_enviar(TrabajoRed::BloqueDeSincronizacion {
                    de: peer,
                    bloque,
                    llegada: Instant::now(),
                }) {
                    ResultadoEnvioTrabajo::Encolado => {}
                    ResultadoEnvioTrabajo::Lleno(_) => {
                        tracing::warn!(
                            %peer,
                            "cola de trabajo llena: bloque de sincronización descartado \
                             (límite alcanzado, RI-3a #3)"
                        );
                    }
                    ResultadoEnvioTrabajo::Cerrado(_) => {
                        tracing::error!(
                            "hilo de consenso caído: bloque de sincronización descartado"
                        );
                        return;
                    }
                }
            }
        }
        Respuesta::NoDisponible => {
            // Legítimo (el par podó esa rama, o nunca la tuvo): no penaliza (C-NET-05).
        }
        Respuesta::Prueba { .. } => {
            // A6-02 · CP-C3: el nodo todavía no pide pruebas (lo cablea CP-C4). Una respuesta de
            // prueba que nadie pidió se trata como una respuesta inesperada: se ignora, igual que
            // `NoDisponible` arriba. No penaliza.
        }
        Respuesta::Registro {
            bloques, longitud, ..
        } => {
            // `ORDEN-W06d6` decisión 1: la página en vuelo terminó (haya traído algo o no). Se
            // encola aquí mismo lo que se pueda (RI-3a #3 acota); lo que no quepa se guarda en
            // `pendientes` y `drenar_pendientes`/`pedir_pagina_si_toca` (llamadas por el bucle
            // principal justo después de esto) hacen el resto: reintentar y, cuando ya no quede
            // nada pendiente, pedir la página siguiente.
            vista.actualizar_mejor_longitud_par(longitud);
            if let Some(e) = peers.get_mut(&peer) {
                e.pagina_en_vuelo = false;
                e.longitud_conocida = e.longitud_conocida.max(longitud);
                if bloques.is_empty() {
                    // El par no tenía nada nuevo en `desde` (p. ej. su propia `longitud` bajó de
                    // estimación, o ya estábamos al día): no se avanza el cursor; se reintentará
                    // cuando su `longitud_conocida` vuelva a subir (saludo periódico u otra
                    // página).
                } else {
                    e.pendientes.extend(bloques);
                }
            }
        }
        Respuesta::RegistroDirecciones {
            desde,
            entradas,
            total,
        } => {
            // `ORDEN-RD3c` N4: la página llegó. Se aplica al registro compartido; una firma
            // inválida es un hecho objetivo y penaliza al par como las demás respuestas inválidas.
            let ahora = unix_ahora();
            let recibidas = entradas.len() as u64;
            if let Some(e) = peers.get_mut(&peer) {
                e.planificador_registro.respuesta_llego();
                let siguiente = desde.saturating_add(recibidas);
                e.cursor_registro_direcciones = if siguiente >= total { 0 } else { siguiente };
            }
            // `ORDEN-RD3c` (análisis del humo encendido): cuántos mensajes y bytes de registro se
            // cruzaron y cuántas entradas quedan retenidas.
            let bytes: u64 = entradas
                .iter()
                .map(|e| zx_p2p::registro::entrada_a_bytes(e).len() as u64)
                .sum();
            let penaliza = aplicar_pagina_recibida(registro_direcciones, &entradas, ahora);
            let evento = registro
                .evento("registro_direcciones_recibida")
                .str("par", &peer.to_string())
                .u64("desde", desde)
                .u64("entradas", recibidas)
                .u64("bytes", bytes)
                .u64("total", total)
                .u64("retenidas", registro_direcciones.longitud())
                .bool("penaliza", penaliza);
            let _ = registro.escribir(evento, false);
            if penaliza {
                let evento = registro
                    .evento("par_penalizado")
                    .str("par", &peer.to_string())
                    .str(
                        "motivo",
                        "entrada del registro de direcciones con firma inválida",
                    )
                    .str("accion", "expulsion");
                let _ = registro.escribir(evento, false);
                manejo
                    .desconectar(peer, MotivoDesconexion::ViolacionDeConsenso)
                    .await
                    .ok();
            }
        }
    }
}

/// `ORDEN-RD3c` N3: pide una página del registro de direcciones a `peer` si el registro está
/// encendido y el planificador de ese par lo permite (ni hay otra petición del mismo tipo sin
/// responder, ni se ha pedido ya dentro del `T_par` corriente).
async fn pedir_pagina_registro_si_toca(
    peer: PeerId,
    peers: &mut HashMap<PeerId, EstadoPeer>,
    manejo: &ManejoRed,
    registro_direcciones: &RegistroRed,
) {
    if !registro_direcciones.activo() {
        return;
    }
    let ahora = Instant::now();
    let Some(e) = peers.get_mut(&peer) else {
        return;
    };
    if !debe_pedir_pagina(registro_direcciones, &e.planificador_registro, ahora) {
        return;
    }
    e.planificador_registro
        .registrar_peticion(ahora, T_PAR_REGISTRO_DIRECCIONES);
    let desde = e.cursor_registro_direcciones;
    if manejo
        .pedir(peer, Peticion::RegistroDirecciones { desde })
        .await
        .is_err()
    {
        tracing::debug!(%peer, desde, "no se pudo pedir una página del registro de direcciones");
        if let Some(e) = peers.get_mut(&peer) {
            e.planificador_registro.peticion_fallida();
        }
    }
}
