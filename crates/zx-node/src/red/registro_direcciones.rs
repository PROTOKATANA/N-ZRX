//! Registro firmado de direcciones en el lado del nodo (`ORDEN-RD3c`, N1–N5).
//!
//! El tipo y el formato de la entrada son los de `zx-p2p` (`zx_p2p::registro::EntradaRegistro`,
//! `RegistroDirecciones`). Aquí vive solo lo que el **paso 3** necesita:
//!
//! - la configuración de arranque (N1: apagado por defecto) y el almacén compartido que sirve la
//!   página a `ManejadorEntrante::pagina_registro_direcciones` (N2);
//! - las funciones puras que **aplican una respuesta** (`aplicar_pagina_recibida`, N4) y
//!   **planifican las peticiones** (`PlanificadorRegistro`, N3), para poder probarlas sin red;
//! - la publicación de la entrada propia (`construir_entrada_propia`, N5).
//!
//! # Nada de consenso
//!
//! La tabla de pesos (`productor → bloques certificados`) es el paso 4 y **no** se toca: todas las
//! entradas quedan como pendientes (N6).

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::Multiaddr;
use zx_core::firma::Firma;
use zx_core::red::Red;
use zx_p2p::registro::{ClaseRegistro, EntradaRegistro, ErrorRegistro, RegistroDirecciones};

use crate::claves::ClaveDev;

/// Reloj de pared del registro: segundos desde la época Unix.
#[must_use]
pub fn unix_ahora() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Configuración de arranque del registro de direcciones (N1, N5, N7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigRegistro {
    /// ¿Está encendido el registro (N1)?
    pub activo: bool,
    /// ¿Publica el nodo su propia entrada (N5)?
    pub publicar: bool,
    /// Semiancho `V` de la ventana de época.
    pub v_epoca: u64,
    /// Tope de entradas pendientes.
    pub max_pendientes: usize,
    /// Caducidad de una entrada pendiente.
    pub ttl_pendiente: u64,
}

impl ConfigRegistro {
    /// Apagado (N1): ni pide ni guarda entradas, y sirve una página vacía.
    pub const APAGADO: Self = Self {
        activo: false,
        publicar: false,
        v_epoca: crate::perfil::REGISTRO_EPOCA_V_S,
        max_pendientes: crate::perfil::REGISTRO_PENDIENTES_MAX,
        ttl_pendiente: crate::perfil::REGISTRO_TTL_S,
    };

    /// Encendido (N1), con la publicación propia (N5) activada o no.
    #[must_use]
    pub const fn encendido(publicar: bool) -> Self {
        Self {
            activo: true,
            publicar,
            v_epoca: crate::perfil::REGISTRO_EPOCA_V_S,
            max_pendientes: crate::perfil::REGISTRO_PENDIENTES_MAX,
            ttl_pendiente: crate::perfil::REGISTRO_TTL_S,
        }
    }
}

/// Publicación propia del nodo (N5): qué clave firma, qué direcciones anuncia y cada cuánto
/// republica.
#[derive(Clone)]
pub struct PublicacionPropia {
    /// Clave de productor que firma la entrada.
    pub productor: ClaveDev,
    /// Direcciones de marcado publicadas.
    pub direcciones: Vec<Multiaddr>,
    /// Intervalo de republicación.
    pub intervalo: Duration,
}

/// RD-4a · H3 · Destino de las entradas que el [`RegistroRed`] **acepta**: el registro del director
/// de `zx-p2p`, al que se reenvían con la orden `InsertarRegistro` de H2.
///
/// Se abstrae en un rasgo para poder probar el puente sin red: la ruta de producción encola hacia
/// [`zx_p2p::servicio::ManejoRed::insertar_registro`]; una prueba lo implementa sobre un
/// [`zx_p2p::director::Director`] real. Una entrada que el nodo **rechaza** no se reenvía.
pub trait ReenvioAlDirector: Send + Sync {
    /// Reenvía una entrada que el registro del nodo acaba de aceptar.
    fn insertar_registro(&self, entrada: &EntradaRegistro);
}

/// El registro de direcciones compartido del nodo.
///
/// Lo escriben la tarea de sincronización (respuestas recibidas y republicación propia) y lo lee el
/// manejador de red para servir `Peticion::RegistroDirecciones` (N2); de ahí el `RwLock`.
pub struct RegistroRed {
    red: Red,
    config: ConfigRegistro,
    interior: RwLock<RegistroDirecciones>,
    /// RD-4a · H3: a dónde van las entradas aceptadas (el registro del director). `None` hasta que
    /// se conecta; sin él no se reenvía nada.
    reenvio: RwLock<Option<Arc<dyn ReenvioAlDirector>>>,
}

impl std::fmt::Debug for RegistroRed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let con_reenvio = self.reenvio.read().map(|r| r.is_some()).unwrap_or(false);
        f.debug_struct("RegistroRed")
            .field("red", &self.red)
            .field("config", &self.config)
            .field("interior", &self.interior)
            .field("con_reenvio", &con_reenvio)
            .finish()
    }
}

impl RegistroRed {
    /// Un registro nuevo con su configuración de arranque.
    #[must_use]
    pub fn nuevo(red: Red, config: ConfigRegistro) -> Self {
        let interior = RegistroDirecciones::nuevo(
            red,
            config.v_epoca,
            config.max_pendientes,
            config.ttl_pendiente,
            config.activo,
        );
        Self {
            red,
            config,
            interior: RwLock::new(interior),
            reenvio: RwLock::new(None),
        }
    }

    /// RD-4a · H3: conecta (o sustituye) el destino de las entradas aceptadas. Sin esto, el puente
    /// está apagado y no se reenvía nada (es el estado por defecto).
    pub fn conectar_reenvio(&self, destino: Arc<dyn ReenvioAlDirector>) {
        match self.reenvio.write() {
            Ok(mut r) => *r = Some(destino),
            Err(envenenado) => *envenenado.into_inner() = Some(destino),
        }
    }

    /// La configuración de arranque.
    #[must_use]
    pub const fn config(&self) -> ConfigRegistro {
        self.config
    }

    /// ¿Está encendido el registro (N1)?
    #[must_use]
    pub const fn activo(&self) -> bool {
        self.config.activo
    }

    /// ¿Publica el nodo su propia entrada (N5)?
    #[must_use]
    pub const fn publica(&self) -> bool {
        self.config.publicar
    }

    /// La red de la entrada.
    #[must_use]
    pub const fn red(&self) -> Red {
        self.red
    }

    /// Cuántas entradas retenidas hay.
    #[must_use]
    pub fn longitud(&self) -> u64 {
        self.interior.read().map(|g| g.longitud()).unwrap_or(0)
    }

    /// RD-4b · P4: todas las entradas retenidas ahora mismo (productivas y pendientes), para la
    /// resincronización del puente al director cuando el canal se llenó y hubo que descartar.
    #[must_use]
    pub fn entradas_vigentes(&self) -> Vec<EntradaRegistro> {
        let g = match self.interior.read() {
            Ok(g) => g,
            Err(envenenado) => envenenado.into_inner(),
        };
        g.pagina(0, usize::MAX, u64::MAX).0
    }

    /// Retiene una entrada ya validada (N4). Con el registro apagado no guarda nada.
    ///
    /// # Errores
    /// Los de [`RegistroDirecciones::insertar`].
    pub fn insertar(&self, e: EntradaRegistro, ahora: u64) -> Result<ClaseRegistro, ErrorRegistro> {
        // RD-4a · H3: se lee el puente una vez; solo se reenvía si el registro **acepta** la
        // entrada (mismo resultado que la escritura). El clon solo se paga para poder reenviarla.
        let destino = match self.reenvio.read() {
            Ok(r) => r.clone(),
            Err(envenenado) => envenenado.into_inner().clone(),
        };
        let clase = {
            let mut g = match self.interior.write() {
                Ok(g) => g,
                Err(envenenado) => envenenado.into_inner(),
            };
            g.insertar(e.clone(), ahora)?
        };
        if let Some(d) = &destino {
            d.insertar_registro(&e);
        }
        Ok(clase)
    }

    /// Una página para servir (N2). Con el registro apagado, **siempre** vacía (N1).
    #[must_use]
    pub fn pagina(
        &self,
        desde: u64,
        max_entradas: usize,
        max_bytes: u64,
    ) -> (Vec<EntradaRegistro>, u64) {
        if !self.config.activo {
            return (Vec::new(), 0);
        }
        let g = match self.interior.read() {
            Ok(g) => g,
            Err(envenenado) => envenenado.into_inner(),
        };
        g.pagina(desde, max_entradas, max_bytes)
    }

    /// Caduca las entradas pendientes que vencieron.
    pub fn expirar(&self, ahora: u64) {
        if let Ok(mut g) = self.interior.write() {
            g.expirar(ahora);
        }
    }

    /// Firma y retiene la entrada propia del nodo (N5), si toca publicar.
    ///
    /// Devuelve `Ok(false)` (sin error) si el registro está apagado, la publicación está apagada o
    /// no hay direcciones que anunciar; una entrada así **no** se sirve.
    ///
    /// # Errores
    /// Los de [`RegistroDirecciones::insertar`] si la entrada no se puede retener.
    pub fn publicar_propia(
        &self,
        productor: &ClaveDev,
        direcciones: &[Multiaddr],
        epoch: u64,
    ) -> Result<bool, ErrorRegistro> {
        if !self.config.activo || !self.config.publicar || direcciones.is_empty() {
            return Ok(false);
        }
        let e = construir_entrada_propia(productor, direcciones, epoch, self.red);
        self.insertar(e, epoch)?;
        Ok(true)
    }
}

/// Construye y firma la entrada propia (`ZXREG1`) con la clave de productor del nodo.
///
/// La firma cubre `SHA3-256("ZXREG01" ‖ cuerpo)` y se verifica con `zx_core::firma::verificar`;
/// `epoch` es el reloj de pared en segundos.
#[must_use]
pub fn construir_entrada_propia(
    productor: &ClaveDev,
    direcciones: &[Multiaddr],
    epoch: u64,
    red: Red,
) -> EntradaRegistro {
    let mut e = EntradaRegistro {
        version: zx_p2p::registro::VERSION,
        red,
        productor: productor.pk,
        epoch,
        direcciones: direcciones.to_vec(),
        firma: Firma::desde_bytes([0u8; 64]),
    };
    let firma: [u8; 64] = productor.sk.sign(e.preimagen().as_bytes()).into();
    e.firma = Firma::desde_bytes(firma);
    e
}

/// Aplica una página recibida al registro (N4).
///
/// Cada entrada pasa por la verificación de `zx-p2p`: con el registro apagado no se guarda nada;
/// una firma inválida es un hecho objetivo y devuelve `true` (el llamante **penaliza** al par); una
/// entrada válida pero vieja, repetida o que no se puede retener se descarta **sin** penalizar.
#[must_use]
pub fn aplicar_pagina_recibida(
    reg: &RegistroRed,
    entradas: &[EntradaRegistro],
    ahora: u64,
) -> bool {
    if !reg.activo() {
        return false;
    }
    for e in entradas {
        if e.verificar_firma().is_err() {
            return true;
        }
        let _ = reg.insertar(e.clone(), ahora);
    }
    false
}

/// ¿Toca pedir una página a un par? (N1/N3: registro encendido y el planificador lo permite).
#[must_use]
pub fn debe_pedir_pagina(reg: &RegistroRed, plan: &PlanificadorRegistro, ahora: Instant) -> bool {
    reg.activo() && plan.debe_pedir(ahora)
}

/// Planificador de las peticiones de página de **un** par (N3).
///
/// Garantiza dos cosas: **una** petición de página por par y por `T_par` como mucho, y **nunca**
/// una nueva mientras la anterior siga sin responder.
#[derive(Debug, Clone, Default)]
pub struct PlanificadorRegistro {
    en_vuelo: bool,
    proximo_permitido: Option<Instant>,
}

impl PlanificadorRegistro {
    /// ¿Se puede pedir ahora? Falso si hay una petición sin responder o si no pasó `T_par`.
    #[must_use]
    pub fn debe_pedir(&self, ahora: Instant) -> bool {
        !self.en_vuelo && self.proximo_permitido.is_none_or(|t| ahora >= t)
    }

    /// Registra que se acaba de pedir una página: queda en vuelo y no se repite antes de `T_par`.
    pub fn registrar_peticion(&mut self, ahora: Instant, t_par: Duration) {
        self.en_vuelo = true;
        self.proximo_permitido = Some(ahora.checked_add(t_par).unwrap_or(ahora));
    }

    /// La página llegó: ya no hay petición en vuelo (el plazo de `T_par` sigue corriendo).
    pub fn respuesta_llego(&mut self) {
        self.en_vuelo = false;
    }

    /// La petición falló: ya no hay petición en vuelo (el plazo de `T_par` sigue corriendo).
    pub fn peticion_fallida(&mut self) {
        self.en_vuelo = false;
    }

    /// ¿Hay una petición sin responder?
    #[must_use]
    pub const fn en_vuelo(&self) -> bool {
        self.en_vuelo
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use zx_p2p::config::PerfilRed;
    use zx_p2p::director::Director;

    /// Un director con el registro de direcciones encendido y sin anclas automáticas (mismo
    /// montaje que las pruebas de `director.rs`).
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

    /// RD-4a · H3 · destino de prueba: reenvía al registro de un `Director` real con reloj fijo.
    struct DirectorDePrueba {
        director: Arc<Mutex<Director>>,
        ahora: u64,
    }

    impl ReenvioAlDirector for DirectorDePrueba {
        fn insertar_registro(&self, entrada: &EntradaRegistro) {
            let mut d = self.director.lock().unwrap();
            let _ = d.insertar_registro(entrada.clone(), self.ahora);
        }
    }

    fn puente(director: &Arc<Mutex<Director>>, ahora: u64) -> Arc<DirectorDePrueba> {
        Arc::new(DirectorDePrueba {
            director: Arc::clone(director),
            ahora,
        })
    }

    fn dir_prueba(ip: &str) -> Multiaddr {
        format!("/ip4/{ip}/tcp/9833").parse().unwrap()
    }

    /// **RD-4a · H3 · control R2.** Una entrada recibida en una página y aceptada por el
    /// `RegistroRed` llega también al registro del director; si el puente no enviara, el registro
    /// del director quedaría vacío y esta prueba caería.
    #[test]
    fn entrada_recibida_llega_al_registro_del_director() {
        let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::encendido(true));
        let director = Arc::new(Mutex::new(director_de_prueba()));
        let ahora = 1_000;
        reg.conectar_reenvio(puente(&director, ahora));

        let clave = ClaveDev::derivar(1, 0);
        let entrada = construir_entrada_propia(&clave, &[dir_prueba("10.0.0.1")], ahora, Red::Dev);
        let penaliza = aplicar_pagina_recibida(&reg, &[entrada], ahora);
        assert!(!penaliza, "la página era válida");
        assert_eq!(
            reg.longitud(),
            1,
            "la entrada queda en el registro del nodo"
        );
        assert!(
            director.lock().unwrap().registro().get(&clave.pk).is_some(),
            "la entrada aceptada llega al registro del director"
        );
    }

    /// **RD-4a · H3.** La entrada propia publicada (N5) también llega al registro del director.
    #[test]
    fn entrada_propia_publicada_llega_al_registro_del_director() {
        let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::encendido(true));
        let director = Arc::new(Mutex::new(director_de_prueba()));
        let ahora = 1_000;
        reg.conectar_reenvio(puente(&director, ahora));

        let clave = ClaveDev::derivar(2, 0);
        let publicado = reg
            .publicar_propia(&clave, &[dir_prueba("10.0.0.1")], ahora)
            .unwrap();
        assert!(publicado, "con publicar=true se firma y retiene");
        assert_eq!(reg.longitud(), 1);
        assert!(
            director.lock().unwrap().registro().get(&clave.pk).is_some(),
            "la entrada propia llega al registro del director"
        );
    }

    /// **RD-4a · H3.** Con el registro apagado no se acepta nada y **no** se envía nada al director.
    #[test]
    fn registro_apagado_no_envia_nada_al_director() {
        let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::APAGADO);
        let director = Arc::new(Mutex::new(director_de_prueba()));
        let ahora = 1_000;
        reg.conectar_reenvio(puente(&director, ahora));

        let clave = ClaveDev::derivar(3, 0);
        let entrada = construir_entrada_propia(&clave, &[dir_prueba("10.0.0.1")], ahora, Red::Dev);
        let _ = aplicar_pagina_recibida(&reg, &[entrada], ahora);
        let _ = reg.publicar_propia(&clave, &[dir_prueba("10.0.0.1")], ahora);
        assert_eq!(reg.longitud(), 0);
        assert!(
            director.lock().unwrap().registro().esta_vacio(),
            "con el registro apagado no se envía nada al director"
        );
    }

    /// **RD-4b · P4/P6.** Con el registro apagado no se firma ni se publica la entrada propia: no
    /// hay entrada retenida ni bytes que difundir.
    #[test]
    fn rd4b_registro_apagado_no_publica() {
        let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::APAGADO);
        let clave = ClaveDev::derivar(4, 0);
        let publicado = reg
            .publicar_propia(&clave, &[dir_prueba("10.0.0.1")], 1_000)
            .unwrap();
        assert!(!publicado, "con el registro apagado no se publica");
        assert_eq!(reg.longitud(), 0, "no queda entrada retenida");
        assert!(reg.pagina(0, usize::MAX, u64::MAX).0.is_empty());
    }

    /// **RD-4b · P4.** `entradas_vigentes` devuelve **todas** las entradas, que es lo que la
    /// resincronización vuelve a entregar al director tras un descarte.
    #[test]
    fn rd4b_entradas_vigentes_devuelve_todas() {
        let reg = RegistroRed::nuevo(Red::Dev, ConfigRegistro::encendido(true));
        for i in 0..3u32 {
            let clave = ClaveDev::derivar(7, i);
            let e = construir_entrada_propia(
                &clave,
                &[dir_prueba("10.0.0.1")],
                1_000 + u64::from(i),
                Red::Dev,
            );
            reg.insertar(e, 1_000 + u64::from(i)).unwrap();
        }
        assert_eq!(reg.entradas_vigentes().len(), 3);
    }
}
