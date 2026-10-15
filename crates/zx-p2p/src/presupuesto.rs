//! Presupuesto **agregado** de memoria en vuelo (SPEC §16.3, C-NET-21).
//!
//! # Lo que el `.take(MAX)` por petición no cubre
//!
//! Cada lectura del códec está acotada: nadie puede hacer que una sola respuesta reserve más de
//! `MAX_RESPUESTA_BYTES`. Eso está bien y no basta, porque **el límite por petición no acota el
//! producto**:
//!
//! ```text
//! MAX_RESPUESTA_BYTES (25,6 MB) × MAX_STREAMS_SYNC (8) × MAX_PEERS_ENTRANTES (72) = 14,7 GB
//! ```
//!
//! Bajar `MAX_STREAMS_SYNC` de 100 a 8 quitó un orden de magnitud y dejó el problema. Casi quince
//! gigabytes reservables por peticiones que un atacante emite gratis siguen siendo un OOM.
//!
//! ⚠️ **Ese 14,7 empezó siendo 7,2 en estos comentarios, y estaba mal.** El arreglo de C-NET-13
//! dobló `MAX_GOSSIP_BYTES` —pasó de derivarse de `ZONA_LIBRE` a derivarse de `LIMITE_BLOQUE_GENESIS`,
//! que es el doble— y los comentarios que narraban la aritmética se quedaron con el número viejo.
//! Tercera vez que este proyecto escribe a mano un número que es función de una constante. Por eso
//! ahora hay un test que **deriva** las cifras en vez de repetirlas.
//!
//! # Por qué un contador global y no más límites por peer
//!
//! Porque el recurso que se agota es **global**. Repartirlo por peer significa elegir entre dos
//! males: o el reparto es generoso y la suma sigue sin acotar, o es estrecho y un nodo con muchos
//! peers honestos se estrangula a sí mismo.
//!
//! Un presupuesto compartido no tiene ese problema: **el techo es el techo**, y quien llega tarde
//! espera o se le dice que no. Es como funciona cualquier reserva de recursos que de verdad acote.
//!
//! # La reserva se libera sola
//!
//! [`Reserva`] devuelve lo suyo al soltarse — incluido si quien la tenía entra en pánico o el
//! futuro se cancela a mitad. Un contador que hubiera que decrementar a mano tendría una fuga por
//! cada camino de error que alguien olvidara, y **una fuga en un contador de presupuesto es un DoS
//! diferido**: el nodo deja de aceptar peticiones sin que nada esté pasando.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use libp2p::PeerId;

/// Techo de bytes reservados a la vez por peticiones de red en vuelo.
///
/// **256 MiB.** No sale de una medición sino de un razonamiento de orden de magnitud: es holgado
/// para un nodo sirviendo a decenas de peers a la vez —cada respuesta llena de cabeceras son
/// ~184 KB, así que caben más de mil simultáneas— y sigue siendo un techo que un servidor modesto
/// puede permitirse sin morir.
///
/// 🔶 Revisable con medición real cuando exista la testnet pública (P-019).
pub const PRESUPUESTO_BYTES: usize = 256 * 1024 * 1024;

/// Contador compartido de bytes en vuelo.
#[derive(Clone, Debug)]
pub struct Presupuesto {
    en_vuelo: Arc<AtomicUsize>,
    techo: usize,
}

impl Default for Presupuesto {
    fn default() -> Self {
        Self::nuevo(PRESUPUESTO_BYTES)
    }
}

impl Presupuesto {
    /// Uno con el techo dado.
    #[must_use]
    pub fn nuevo(techo: usize) -> Self {
        Self {
            en_vuelo: Arc::new(AtomicUsize::new(0)),
            techo,
        }
    }

    /// Intenta reservar `bytes`. Devuelve `None` si no caben.
    ///
    /// Usa `fetch_update`, no un `load` seguido de un `store`: entre esos dos, otro hilo puede
    /// reservar y el techo se supera. Con la operación atómica de comparar-e-intercambiar, dos
    /// reservas concurrentes **no pueden** pasar las dos.
    #[must_use]
    pub fn reservar(&self, bytes: usize) -> Option<Reserva> {
        let techo = self.techo;
        self.en_vuelo
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |actual| {
                let nuevo = actual.checked_add(bytes)?;
                (nuevo <= techo).then_some(nuevo)
            })
            .ok()?;

        Some(Reserva {
            contador: Arc::clone(&self.en_vuelo),
            bytes,
        })
    }

    /// Bytes reservados ahora mismo.
    #[must_use]
    pub fn en_vuelo(&self) -> usize {
        self.en_vuelo.load(Ordering::Acquire)
    }

    /// Cuánto queda libre.
    #[must_use]
    pub fn disponible(&self) -> usize {
        self.techo.saturating_sub(self.en_vuelo())
    }
}

/// Bytes reservados. **Se devuelven al soltarse.**
///
/// No hay forma de olvidarse de liberar: no existe un método para hacerlo, así que el único camino
/// es el `Drop`. Un contador que hubiera que decrementar a mano tendría una fuga por cada `return`
/// temprano que alguien no viera.
#[derive(Debug)]
pub struct Reserva {
    contador: Arc<AtomicUsize>,
    bytes: usize,
}

impl Reserva {
    /// Cuántos bytes tiene reservados.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for Reserva {
    fn drop(&mut self) {
        // `fetch_sub` sobre lo que esta reserva puso: no puede bajar de cero porque solo se
        // devuelve lo que se reservó, y la reserva se creó sumando exactamente esto.
        self.contador.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Ventana del presupuesto de gossip por par, en segundos (RSS-1).
pub const GOSSIP_VENTANA_S: u64 = 10;

/// Bytes de gossip admitidos por par y ventana (RSS-1).
///
/// Holgado a propósito: un par honesto que retransmite bloques completos (≤ 2 MiB cada uno) y
/// transacciones dentro del tope de DR-07 (1 MiB/s) no se acerca. El ataque de RSS-1 no se pasa de
/// bytes —va justo en el tope declarado— pero sí de **número de mensajes**.
pub const MAX_GOSSIP_POR_PAR_BYTES: usize = 64 * 1024 * 1024;

/// Mensajes de gossip admitidos por par y ventana (RSS-1).
///
/// Es el tope que de verdad defiende: las cachés internas de gossipsub (`mcache`, la tabla
/// `deliveries` de `peer_score`, la cola de eventos) crecen por **mensaje**, no por byte. Miles de
/// transacciones diminutas (≈161 B) dentro del tope legítimo de 1 MiB/s bastan para reservar
/// gigabytes si no se acota el número. 8 192 mensajes en 10 s son ~819 msg/s: decenas de veces lo
/// que genera un nodo honesto de la red dev, y una fracción pequeña de la inundación medida.
pub const MAX_GOSSIP_POR_PAR_MENSAJES: usize = 8_192;

/// Presupuesto de **mensajes de gossip** por par y ventana (RSS-1).
///
/// La caché de mensajes de gossipsub y la tabla de entregas de `peer_score` se alimentan por
/// mensaje y no las controlamos desde fuera del crate. Lo que sí controlamos es **cuántos mensajes
/// aceptamos de cada par**: al superar el presupuesto se descarta el mensaje (`Ignorar`, sin
/// penalizar por sí solo) y [`crate::servicio::BucleRed`] corta con el par (`Excedido`), de modo que
/// la entrada deja de crecer. Los pares honestos quedan muy por debajo del tope.
#[derive(Debug)]
pub struct PresupuestoGossipPar {
    ventana: Duration,
    max_bytes: usize,
    max_mensajes: usize,
    por_par: HashMap<PeerId, CuentaPar>,
}

#[derive(Debug)]
struct CuentaPar {
    desde: Instant,
    bytes: usize,
    mensajes: usize,
}

impl PresupuestoGossipPar {
    /// Uno con la ventana y los dos topes dados.
    #[must_use]
    pub fn nuevo(ventana: Duration, max_bytes: usize, max_mensajes: usize) -> Self {
        Self {
            ventana,
            max_bytes,
            max_mensajes,
            por_par: HashMap::new(),
        }
    }

    /// El presupuesto de producción (RSS-1).
    #[must_use]
    pub fn de_produccion() -> Self {
        Self::nuevo(
            Duration::from_secs(GOSSIP_VENTANA_S),
            MAX_GOSSIP_POR_PAR_BYTES,
            MAX_GOSSIP_POR_PAR_MENSAJES,
        )
    }

    /// Consume `bytes` del presupuesto de `peer`. Devuelve `false` si el par ya lo agotó: quien
    /// llama debe descartar el mensaje **sin** penalizarlo por ese solo hecho.
    ///
    /// La ventana se reinicia por par de forma perezosa, así que la tabla no necesita un barrido.
    pub fn consumir(&mut self, peer: PeerId, bytes: usize, ahora: Instant) -> bool {
        let cuenta = self.por_par.entry(peer).or_insert(CuentaPar {
            desde: ahora,
            bytes: 0,
            mensajes: 0,
        });
        if ahora.duration_since(cuenta.desde) >= self.ventana {
            cuenta.desde = ahora;
            cuenta.bytes = 0;
            cuenta.mensajes = 0;
        }
        if cuenta.mensajes >= self.max_mensajes
            || cuenta.bytes.saturating_add(bytes) > self.max_bytes
        {
            return false;
        }
        cuenta.mensajes = cuenta.mensajes.saturating_add(1);
        cuenta.bytes = cuenta.bytes.saturating_add(bytes);
        true
    }

    /// Olvida a un par (al cerrarse su conexión): la tabla no crece con las reconexiones.
    pub fn olvidar(&mut self, peer: &PeerId) {
        self.por_par.remove(peer);
    }

    /// Cuántos pares tienen cuenta abierta ahora mismo (diagnóstico y tests).
    #[must_use]
    pub fn pares(&self) -> usize {
        self.por_par.len()
    }
}

// ── A6-02 · cuota del cuerpo de prueba (CP-R-13, Q5) ─────────────────────────

/// A6-02 · `CP-R-13`: peticiones de prueba **en vuelo por par**, como mucho.
///
/// Valor del contrato, **provisional**: «a calibrar en la verificación» (`CP-R-13`; la orden Q5 lo
/// repite). Una petición que exceda la cuota **espera**: queda encolada hasta que se libere un
/// hueco, igual que libp2p encola una petición que supera `max_concurrent_streams`
/// (`crate::behaviour`, donde se fija `MAX_STREAMS_SYNC`).
pub const MAX_PRUEBAS_EN_VUELO_POR_PAR: usize = 1;

/// A6-02 · `CP-R-13`: peticiones de prueba **en vuelo en todo el nodo**, como mucho.
///
/// Valor del contrato, **provisional**: «a calibrar en la verificación» (`CP-R-13`; la orden Q5 lo
/// repite).
pub const MAX_PRUEBAS_EN_VUELO_NODO: usize = 4;

/// A6-02 · Q5: ¿cabe una petición de prueba con estos recuentos en vuelo?
///
/// Es la regla de cuota, aislada para poder probarla sin un `Swarm` y para que la ruta de envío
/// (`crate::servicio::BucleRed`) tenga un único punto de verdad.
#[must_use]
pub const fn cabe_prueba(en_vuelo_par: usize, en_vuelo_total: usize) -> bool {
    en_vuelo_par < MAX_PRUEBAS_EN_VUELO_POR_PAR && en_vuelo_total < MAX_PRUEBAS_EN_VUELO_NODO
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::integer_division,
    reason = "los tests fallan con panic por diseño; la división entera es deliberada"
)]
mod tests {
    use super::{PRESUPUESTO_BYTES, Presupuesto, PresupuestoGossipPar};

    #[test]
    fn una_reserva_ocupa_y_al_soltarse_libera() {
        let p = Presupuesto::nuevo(1_000);
        assert_eq!(p.en_vuelo(), 0);

        {
            let r = p.reservar(400).unwrap();
            assert_eq!(r.bytes(), 400);
            assert_eq!(p.en_vuelo(), 400);
            assert_eq!(p.disponible(), 600);
        }
        assert_eq!(p.en_vuelo(), 0, "al soltarse se devuelve");
    }

    /// **El techo es el techo.** Es la propiedad entera de este módulo.
    #[test]
    fn no_se_puede_pasar_del_techo() {
        let p = Presupuesto::nuevo(1_000);
        let _a = p.reservar(600).unwrap();
        let _b = p.reservar(400).unwrap();
        assert_eq!(p.en_vuelo(), 1_000);

        assert!(p.reservar(1).is_none(), "ni un byte más");
        assert!(p.reservar(usize::MAX).is_none());
    }

    /// El borde exacto entra; uno más, no.
    #[test]
    fn el_borde_exacto_del_techo() {
        let p = Presupuesto::nuevo(1_000);
        assert!(p.reservar(1_000).is_some(), "el techo justo entra");

        let p = Presupuesto::nuevo(1_000);
        assert!(p.reservar(1_001).is_none(), "uno más, no");
    }

    /// **Una reserva liberada deja sitio para otra.** Sin esto, el presupuesto se agotaría solo.
    #[test]
    fn liberar_deja_sitio() {
        let p = Presupuesto::nuevo(1_000);
        let a = p.reservar(1_000).unwrap();
        assert!(p.reservar(1).is_none());

        drop(a);
        assert!(p.reservar(1_000).is_some(), "el sitio vuelve");
    }

    /// **Una reserva soltada por un pánico también libera.**
    ///
    /// Es la razón de que sea un `Drop` y no un método: un camino de error que alguien olvide
    /// decrementar es una fuga, y una fuga en un contador de presupuesto es un DoS diferido — el
    /// nodo deja de aceptar peticiones sin que esté pasando nada.
    #[test]
    fn un_panico_tambien_libera() {
        let p = Presupuesto::nuevo(1_000);
        let p2 = p.clone();

        let h = std::thread::spawn(move || {
            let _r = p2.reservar(800).unwrap();
            #[expect(clippy::panic, reason = "el pánico es el objeto del test")]
            {
                panic!("soltando la reserva por la vía dolorosa");
            }
        });
        assert!(h.join().is_err(), "el hilo debía entrar en pánico");
        assert_eq!(p.en_vuelo(), 0, "el pánico también devuelve la reserva");
    }

    /// **Dos reservas concurrentes no pueden pasarse las dos del techo.**
    ///
    /// Con un `load` seguido de un `store`, entre ambos otro hilo reserva y el techo se supera. Por
    /// eso se usa `fetch_update`, que es comparar-e-intercambiar.
    #[test]
    fn la_concurrencia_no_puede_superar_el_techo() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let p = Presupuesto::nuevo(100_000);
        let concedidas = Arc::new(AtomicUsize::new(0));
        let mut hilos = Vec::new();

        // 64 hilos pidiendo 10 000 cada uno contra un techo de 100 000: como mucho 10 pueden
        // tenerlo a la vez.
        for _ in 0..64 {
            let p = p.clone();
            let c = Arc::clone(&concedidas);
            hilos.push(std::thread::spawn(move || {
                let mut mias = Vec::new();
                for _ in 0..20 {
                    if let Some(r) = p.reservar(10_000) {
                        c.fetch_add(1, Ordering::Relaxed);
                        mias.push(r);
                    }
                }
                // Se comprueba **con las reservas todavía vivas**: es cuando el invariante puede
                // romperse.
                assert!(
                    p.en_vuelo() <= 100_000,
                    "el techo se superó: {}",
                    p.en_vuelo()
                );
                mias
            }));
        }

        let mut todas = Vec::new();
        for h in hilos {
            todas.extend(h.join().expect("ningún hilo debe entrar en pánico"));
        }
        assert!(p.en_vuelo() <= 100_000);
        assert_eq!(todas.len() * 10_000, p.en_vuelo(), "la cuenta cuadra");

        drop(todas);
        assert_eq!(p.en_vuelo(), 0, "todo vuelve");
    }

    /// **El presupuesto acota el peor caso, y las cifras se DERIVAN.**
    ///
    /// Este test existe por un fallo concreto: los comentarios de este módulo decían 12,8 MB y
    /// 7,2 GB, y los valores reales son **25,6 MB y 14,7 GB**. El arreglo de C-NET-13 dobló la
    /// constante de la que salen, y la narración se quedó atrás.
    ///
    /// Así que aquí no se escribe ningún número a mano salvo el techo: todo lo demás se calcula
    /// desde las constantes reales, y las cotas comprueban el **orden de magnitud**, que es lo que
    /// de verdad importa y lo que un cambio futuro no debe romper en silencio.
    #[test]
    fn el_presupuesto_por_defecto_acota_el_peor_caso() {
        use crate::limites::{MAX_PEERS_ENTRANTES, MAX_RESPUESTA_BYTES, MAX_STREAMS_SYNC};

        // Lo que se podía reservar SIN presupuesto agregado.
        let sin_presupuesto =
            MAX_RESPUESTA_BYTES * MAX_STREAMS_SYNC as u64 * u64::from(MAX_PEERS_ENTRANTES);
        assert!(
            sin_presupuesto > 7_000_000_000,
            "el peor caso sin presupuesto eran ~7,2 GB: {sin_presupuesto}"
        );

        // Y lo que se puede ahora, sin importar peers ni streams.
        assert!(
            (PRESUPUESTO_BYTES as u64) < sin_presupuesto / 20,
            "el presupuesto debe quitar al menos un orden de magnitud"
        );
        assert_eq!(PRESUPUESTO_BYTES, 268_435_456, "256 MiB");
    }

    /// **RSS-1 · el tope por mensajes corta al par que inunda y no a los demás.**
    ///
    /// Es la propiedad que de verdad defiende la memoria: un par que manda miles de mensajes
    /// diminutos dentro del tope de bytes legítimo agota el cupo de **mensajes**, mientras un par
    /// honesto con pocos mensajes grandes sigue dentro.
    #[test]
    fn el_tope_por_mensajes_corta_al_par_que_inunda_y_no_al_honesto() {
        use libp2p::PeerId;
        use std::time::{Duration, Instant};

        let mut p = PresupuestoGossipPar::nuevo(Duration::from_secs(10), 64 * 1024 * 1024, 3);
        let ahora = Instant::now();
        let inundador = PeerId::random();
        let honesto = PeerId::random();

        // El inundador agota los 3 mensajes de la ventana; el cuarto ya no pasa.
        assert!(p.consumir(inundador, 161, ahora));
        assert!(p.consumir(inundador, 161, ahora));
        assert!(p.consumir(inundador, 161, ahora));
        assert!(
            !p.consumir(inundador, 161, ahora),
            "el cuarto mensaje MUST quedar fuera"
        );

        // El honesto no paga por el abuso del otro: conserva su propio cupo.
        assert!(
            p.consumir(honesto, 2 * 1024 * 1024, ahora),
            "un bloque de 2 MiB cabe en el cupo de bytes del honesto"
        );
        assert_eq!(p.pares(), 2, "una cuenta por par, sin crecer sin límite");
    }

    /// **RSS-1 · la ventana se renueva** y el tope de bytes también se respeta.
    #[test]
    fn la_ventana_se_renueva_y_el_tope_de_bytes_tambien() {
        use libp2p::PeerId;
        use std::time::{Duration, Instant};

        let ventana = Duration::from_secs(10);
        let mut p = PresupuestoGossipPar::nuevo(ventana, 1_000, 10);
        let par = PeerId::random();
        let ahora = Instant::now();

        assert!(p.consumir(par, 900, ahora));
        assert!(!p.consumir(par, 200, ahora), "900 + 200 > 1 000");

        // Dentro de la misma ventana quedan 100 B: se consumen y ya no cabe nada más.
        assert!(p.consumir(par, 100, ahora + ventana / 2));
        assert!(!p.consumir(par, 1, ahora + ventana / 2));
        assert!(
            p.consumir(par, 1_000, ahora + ventana),
            "la ventana vencida devuelve el cupo"
        );
    }

    /// **RSS-1 · olvidar a un par lo saca de la tabla.**
    #[test]
    fn olvidar_a_un_par_libera_su_cuenta() {
        use libp2p::PeerId;
        use std::time::Instant;

        let mut p = PresupuestoGossipPar::de_produccion();
        let par = PeerId::random();
        assert!(p.consumir(par, 1, Instant::now()));
        assert_eq!(p.pares(), 1);
        p.olvidar(&par);
        assert_eq!(p.pares(), 0, "al desconectar no queda cuenta colgada");
    }
}
