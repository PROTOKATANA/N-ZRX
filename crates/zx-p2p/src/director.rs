//! Director de descubrimiento y mantenimiento de salientes (C-NET-34/38/39/40/41).
//!
//! El director es una **máquina de estados sin E/S**: acumula lo que el bucle de `Swarm` observa
//! (`identify`, `Kademlia`, conexiones) y, en cada latido, devuelve [`Accion`]es que el bucle
//! ejecuta. Así la política —diversidad, anclas, sondeo, rotación, `test-before-evict`— se puede
//! probar sin construir un `Swarm`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use libp2p::{Multiaddr, PeerId};
use zx_core::red::Red;

use crate::config::PerfilRed;
use crate::gestor::{Entrada, ErrorGestor, GestorDirecciones, GrupoAncho, Insercion};
use crate::registro::{ClaseRegistro, EntradaRegistro, ErrorRegistro, RegistroDirecciones};
use zx_core::firma::ClavePublica;

/// Lo que el director pide al bucle de red que haga.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Accion {
    /// Marcar (dial) una dirección.
    Marcar(Multiaddr),
    /// Cortar con un par.
    Desconectar(PeerId),
    /// Lanzar un paseo aleatorio de Kademlia con esta clave.
    Paseo([u8; 32]),
}

/// Una saliente viva.
#[derive(Clone, Debug)]
struct Saliente {
    addr: Multiaddr,
    grupo: GrupoAncho,
    desde: Instant,
}

/// RD-4b · P6: resumen de un sorteo del director, para el evento `sorteo_director` del nodo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventoSorteoDirector {
    /// Suma de los pesos de la tabla vigente.
    pub peso_total: u64,
    /// Entradas de la tabla con peso y dirección de marcado aceptable.
    pub entradas: u64,
    /// 8 primeros bytes de la clave del productor elegido, o `None` si no se eligió a nadie.
    pub elegido: Option<[u8; 8]>,
}

/// Un dial en curso, con su motivo.
#[derive(Clone, Debug)]
struct EnCurso {
    desde: Instant,
    es_evict: bool,
    candidata: Option<Entrada>,
    victima: Option<Entrada>,
}

/// Director de descubrimiento y salientes.
pub struct Director {
    red: Red,
    perfil: PerfilRed,
    gestor: GestorDirecciones,
    dir_datos: Option<PathBuf>,
    salientes: HashMap<PeerId, Saliente>,
    en_curso: HashMap<Multiaddr, EnCurso>,
    arranque: Vec<Entrada>,
    ultimo_paseo: Instant,
    ultimo_feeler: Instant,
    ultima_rotacion: Instant,
    contador: u64,
    sembrado: bool,
    sucio: bool,
    registro: RegistroDirecciones,
    protegida: Option<PeerId>,
    sorteos: u64,
    /// RD-4b · P6: sorteos hechos y aún no volcados al evento `sorteo_director`.
    eventos_sorteo: Vec<EventoSorteoDirector>,
}

impl Director {
    /// Un director vacío (sin gestor sembrado todavía).
    #[must_use]
    pub fn nuevo(red: Red, perfil: PerfilRed) -> Self {
        Self::con_gestor(red, perfil, GestorDirecciones::nuevo(red, perfil))
    }

    /// Igual, con una `nKey` explícita del gestor (pruebas reproducibles del sorteo).
    #[must_use]
    pub fn con_n_key(red: Red, perfil: PerfilRed, n_key: [u8; 32]) -> Self {
        Self::con_gestor(
            red,
            perfil,
            GestorDirecciones::con_n_key(red, perfil, n_key),
        )
    }

    fn con_gestor(red: Red, perfil: PerfilRed, gestor: GestorDirecciones) -> Self {
        let ahora = Instant::now();
        Self {
            red,
            perfil,
            gestor,
            dir_datos: None,
            salientes: HashMap::new(),
            en_curso: HashMap::new(),
            arranque: Vec::new(),
            ultimo_paseo: ahora,
            ultimo_feeler: ahora,
            ultima_rotacion: ahora,
            contador: 0,
            sembrado: false,
            sucio: false,
            registro: RegistroDirecciones::nuevo(
                red,
                perfil.registro_v,
                perfil.registro_pendientes,
                perfil.registro_ttl,
                perfil.registro_activo,
            ),
            protegida: None,
            sorteos: 0,
            eventos_sorteo: Vec::new(),
        }
    }

    /// El gestor de direcciones subyacente.
    #[must_use]
    pub const fn gestor(&self) -> &GestorDirecciones {
        &self.gestor
    }

    /// Fija la **tabla de pesos vigente** (`G3`): `productor → bloques certificados`. El director no
    /// la calcula; la recibe de fuera (el nodo, cuando el paso 4 la publique).
    pub fn fijar_tabla_pesos<I>(&mut self, pesos: I)
    where
        I: IntoIterator<Item = (ClavePublica, u64)>,
    {
        self.registro.fijar_pesos(pesos);
    }

    /// Vacía la tabla de pesos. Sin tabla, el director vuelve a la elección de hoy (`G3`).
    pub fn limpiar_tabla_pesos(&mut self) {
        self.registro.limpiar_pesos();
    }

    /// Retiene una entrada `ZXREG1` recibida del wire, con las reglas de `G1`/`G2`.
    ///
    /// # Errores
    /// [`ErrorRegistro`] si no valida o el registro la rechaza.
    pub fn insertar_registro(
        &mut self,
        e: EntradaRegistro,
        ahora: u64,
    ) -> Result<ClaseRegistro, ErrorRegistro> {
        self.registro.insertar(e, ahora)
    }

    /// Marca la saliente **protegida** (`G5`): como mucho una; si hay otra que rotar, se rota esa
    /// en su lugar.
    pub fn proteger_saliente(&mut self, peer: Option<PeerId>) {
        self.protegida = peer;
    }

    /// La saliente protegida actual.
    #[must_use]
    pub const fn saliente_protegida(&self) -> Option<PeerId> {
        self.protegida
    }

    /// Cuántos sorteos ha hecho el director (uno por rotación con el registro encendido).
    #[must_use]
    pub const fn sorteos_realizados(&self) -> u64 {
        self.sorteos
    }

    /// El registro firmado de direcciones subyacente.
    #[must_use]
    pub fn registro(&self) -> &RegistroDirecciones {
        &self.registro
    }

    /// Realiza **un** sorteo de candidata productiva con el generador del director (`G7`).
    ///
    /// Devuelve la dirección de marcado de la entrada sorteada, o `None` si el registro está
    /// apagado, no hay tabla o no hay productivas alcanzables. No se sortea dos veces por rotación:
    /// el bucle de rotación llama a esto una vez y, si la guarda impide marcar, usa la elección de
    /// hoy.
    pub fn sortear_candidata(&mut self) -> Option<Entrada> {
        if !self.perfil.registro_activo {
            return None;
        }
        self.sorteos = self.sorteos.saturating_add(1);
        // RD-4b · P6: el resumen del sorteo se calcula **siempre** (haya o no elegido), para que el
        // evento `sorteo_director` diga el peso total y cuántas entradas eran elegibles.
        let (peso_total, entradas) = self.peso_y_entradas();
        let r = self.entropia();
        let c = self.registro.sortear(r);
        let elegido = c.as_ref().map(|c| {
            c.productor
                .bytes()
                .first_chunk::<8>()
                .copied()
                .unwrap_or([0u8; 8])
        });
        self.eventos_sorteo.push(EventoSorteoDirector {
            peso_total,
            entradas,
            elegido,
        });
        let c = c?;
        Entrada::de_multiaddr(c.addr, None)
    }

    /// RD-4b · P6: sorteos hechos y aún no volcados al evento (los consume el bucle de red).
    #[must_use]
    pub fn tomar_eventos_sorteo(&mut self) -> Vec<EventoSorteoDirector> {
        std::mem::take(&mut self.eventos_sorteo)
    }

    /// RD-4b · P6: peso total de la tabla vigente y número de entradas con peso **y** dirección de
    /// marcado aceptable (las únicas elegibles por [`RegistroDirecciones::sortear`]).
    fn peso_y_entradas(&self) -> (u64, u64) {
        let (todas, _) = self.registro.pagina(0, usize::MAX, u64::MAX);
        let mut peso_total: u64 = 0;
        let mut elegibles: u64 = 0;
        for e in &todas {
            let Some(peso) = self.registro.peso(&e.productor) else {
                continue;
            };
            if peso == 0 {
                continue;
            }
            if e.direcciones
                .iter()
                .any(|a| crate::registro::direccion_aceptable(a, self.red))
            {
                peso_total = peso_total.saturating_add(peso);
                elegibles = elegibles.saturating_add(1);
            }
        }
        (peso_total, elegibles)
    }

    /// Entropía del director: `SHA3-256(nKey ‖ contador)`. Es el mismo generador determinista que
    /// ya usa [`clave_paseo`] para el paseo aleatorio.
    fn entropia(&mut self) -> u64 {
        self.contador = self.contador.wrapping_add(1);
        let mut b = Vec::with_capacity(40);
        b.extend_from_slice(self.gestor.n_key());
        b.extend_from_slice(&self.contador.to_be_bytes());
        let d = zx_core::sha3_256_publico(&b);
        let mut out = [0u8; 8];
        out.copy_from_slice(d.as_bytes().get(..8).unwrap_or(&[0u8; 8]));
        u64::from_be_bytes(out)
    }

    /// El perfil con el que trabaja el director.
    #[must_use]
    pub const fn perfil(&self) -> PerfilRed {
        self.perfil
    }

    /// Cuántas salientes hay registradas.
    #[must_use]
    pub fn salientes(&self) -> usize {
        self.salientes.len()
    }

    /// Si hay cambios sin persistir.
    #[must_use]
    pub const fn es_sucio(&self) -> bool {
        self.sucio
    }

    /// Carga la persistencia (si hay directorio) y siembra las direcciones de arranque.
    ///
    /// Las direcciones de `--red-marcar` son **solo arranque**: se insertan como `probados` de
    /// confianza del operador y el director las marca primero; a partir de ahí manda el
    /// descubrimiento (C-NET-34).
    pub fn sembrar(&mut self, dir: Option<&Path>, arranque: &[Multiaddr], ahora: Instant) {
        if let Some(d) = dir {
            if let Ok(g) = GestorDirecciones::cargar(self.red, self.perfil, d) {
                self.gestor = g;
            }
            self.dir_datos = Some(d.to_path_buf());
        }
        for a in arranque {
            if let Some(e) = Entrada::de_multiaddr(a.clone(), None) {
                let _ = self.gestor.insertar_probado(e.clone());
                if !self.arranque.iter().any(|x| x.addr == e.addr) {
                    self.arranque.push(e);
                }
            }
        }
        if self.gestor.anclas().is_empty() {
            let _ = self.gestor.elegir_anclas();
        }
        self.ultimo_paseo = ahora;
        self.ultimo_feeler = ahora;
        self.ultima_rotacion = ahora;
        self.sembrado = true;
        self.sucio = true;
    }

    /// Registra las direcciones que un par anunció por `identify`, con cuota por par y ventana.
    pub fn on_identify(&mut self, peer: PeerId, addrs: &[Multiaddr], ahora: Instant) {
        let admitidas = self.gestor.admitir_direcciones(peer, addrs.len(), ahora);
        for a in addrs.iter().take(admitidas) {
            if let Some(e) = Entrada::de_multiaddr(a.clone(), Some(peer))
                && !self.gestor.esta_probado(&e)
            {
                let _ = self.gestor.insertar_nuevo(e);
                self.sucio = true;
            }
        }
    }

    /// Registra direcciones aprendidas de la tabla de Kademlia.
    pub fn on_routing(&mut self, addrs: &[Multiaddr]) {
        for a in addrs {
            if let Some(e) = Entrada::de_multiaddr(a.clone(), None)
                && !self.gestor.esta_probado(&e)
            {
                let _ = self.gestor.insertar_nuevo(e);
                self.sucio = true;
            }
        }
    }

    /// Registra una conexión establecida. Devuelve acciones (p. ej. el sondeo de `test-before-evict`).
    pub fn on_establecido(
        &mut self,
        peer: PeerId,
        addr: &Multiaddr,
        saliente: bool,
        ahora: Instant,
    ) -> Vec<Accion> {
        self.en_curso.remove(addr);
        if !saliente {
            return Vec::new();
        }
        let Some(e) = Entrada::de_multiaddr(addr.clone(), Some(peer)) else {
            return Vec::new();
        };
        let grupo = self.gestor.grupo_ancho(&e);
        self.sucio = true;
        if let Insercion::Colision { desaloja } = self.gestor.promover(&e) {
            // `test-before-evict` (C-NET-40): probar a la incumbente antes de desalojarla.
            self.en_curso.insert(
                desaloja.addr.clone(),
                EnCurso {
                    desde: ahora,
                    es_evict: true,
                    candidata: Some(e),
                    victima: Some(desaloja.clone()),
                },
            );
            return vec![Accion::Marcar(desaloja.addr.clone())];
        }
        self.salientes.insert(
            peer,
            Saliente {
                addr: e.addr,
                grupo,
                desde: ahora,
            },
        );
        Vec::new()
    }

    /// Registra la caída de una conexión.
    pub fn on_desconectado(&mut self, peer: PeerId) {
        if self.salientes.remove(&peer).is_some() {
            self.sucio = true;
        }
    }

    /// Persiste el gestor si hay directorio y había cambios.
    ///
    /// # Errores
    /// [`ErrorGestor`] si falla la escritura.
    pub fn guardar(&mut self) -> Result<(), ErrorGestor> {
        if let Some(d) = self.dir_datos.clone() {
            self.gestor.guardar(&d)?;
            self.sucio = false;
        }
        Ok(())
    }

    /// Un latido: expira diales, lanza paseo/sondeo, rota y rellena salientes.
    pub fn tick(&mut self, ahora: Instant) -> Vec<Accion> {
        let mut acciones = Vec::new();

        // Diales en curso vencidos: si era un sondeo de desalojo y no respondió, se desaloja.
        let plazo = self.perfil.plazo_feeler.max(self.perfil.ventana_evict);
        let vencidos: Vec<Multiaddr> = self
            .en_curso
            .iter()
            .filter(|(_, e)| ahora.duration_since(e.desde) >= plazo)
            .map(|(a, _)| a.clone())
            .collect();
        for a in vencidos {
            if let Some(e) = self.en_curso.remove(&a)
                && e.es_evict
                && let (Some(victima), Some(candidata)) = (e.victima, e.candidata)
            {
                let _ = self
                    .gestor
                    .desalojar_y_insertar(&victima, candidata.clone());
                self.sucio = true;
                acciones.push(Accion::Marcar(candidata.addr));
            }
        }

        if !self.sembrado {
            return acciones;
        }

        // C-NET-39/DN-04: mantener las 2 anclas en grupos anchos distintos en cuanto `probados`
        // tenga candidatos. No se rotan nunca (C-NET-41).
        if self.gestor.anclas().len() < self.perfil.anclas
            && !self.gestor.elegir_anclas().is_empty()
        {
            self.sucio = true;
        }

        if ahora.duration_since(self.ultimo_paseo) >= self.perfil.t_paseo {
            self.ultimo_paseo = ahora;
            self.contador = self.contador.wrapping_add(1);
            acciones.push(Accion::Paseo(clave_paseo(
                self.gestor.n_key(),
                self.contador,
            )));
        }

        if ahora.duration_since(self.ultima_rotacion) >= self.perfil.t_par
            && let Some(peer) = self.saliente_a_rotar()
        {
            self.ultima_rotacion = ahora;
            self.salientes.remove(&peer);
            self.sucio = true;
            acciones.push(Accion::Desconectar(peer));

            // G4: en cada rotación, como mucho **un** sorteo. Si la sorteada no se puede marcar por
            // una guarda (grupo de red, límites por prefijo…), esta rotación usa la elección de hoy:
            // el bucle de relleno de más abajo, que no vuelve a sortear.
            if let Some(e) = self.sortear_candidata() {
                let grupo = self.gestor.grupo_ancho(&e);
                if self.puede_marcar(&e.addr, grupo) {
                    self.en_curso.insert(
                        e.addr.clone(),
                        EnCurso {
                            desde: ahora,
                            es_evict: false,
                            candidata: Some(e.clone()),
                            victima: None,
                        },
                    );
                    acciones.push(Accion::Marcar(e.addr));
                }
            }
        }

        if ahora.duration_since(self.ultimo_feeler) >= self.perfil.t_feeler {
            self.ultimo_feeler = ahora;
            self.contador = self.contador.wrapping_add(1);
            if let Some(e) = self.gestor.elegir_nuevo(self.contador) {
                let grupo = self.gestor.grupo_ancho(&e);
                if self.puede_marcar(&e.addr, grupo) {
                    self.en_curso.insert(
                        e.addr.clone(),
                        EnCurso {
                            desde: ahora,
                            es_evict: false,
                            candidata: Some(e.clone()),
                            victima: None,
                        },
                    );
                    acciones.push(Accion::Marcar(e.addr));
                }
            }
        }

        let mut intentos = 0;
        while (self.salientes.len() as u32) < self.perfil.omega && intentos < 8 {
            intentos += 1;
            let Some(e) = self.siguiente_candidata() else {
                break;
            };
            let grupo = self.gestor.grupo_ancho(&e);
            if !self.puede_marcar(&e.addr, grupo) {
                continue;
            }
            self.en_curso.insert(
                e.addr.clone(),
                EnCurso {
                    desde: ahora,
                    es_evict: false,
                    candidata: Some(e.clone()),
                    victima: None,
                },
            );
            acciones.push(Accion::Marcar(e.addr));
        }

        acciones
    }

    /// La saliente que toca rotar (`G5`): la más vieja que no sea ancla, **saltando la protegida**
    /// si hay otra; si no hay otra, la protegida. Nunca un ancla.
    fn saliente_a_rotar(&self) -> Option<PeerId> {
        let no_ancla = |peer: &PeerId, s: &Saliente| {
            Entrada::de_multiaddr(s.addr.clone(), Some(*peer))
                .is_none_or(|e| !self.gestor.es_ancla(&e))
        };
        if let Some(p) = self
            .salientes
            .iter()
            .filter(|(p, s)| no_ancla(p, s) && Some(**p) != self.protegida)
            .min_by_key(|(_, s)| s.desde)
            .map(|(p, _)| *p)
        {
            return Some(p);
        }
        self.salientes
            .iter()
            .filter(|(p, s)| no_ancla(p, s))
            .min_by_key(|(_, s)| s.desde)
            .map(|(p, _)| *p)
    }

    fn siguiente_candidata(&mut self) -> Option<Entrada> {
        let ocupada = |en_curso: &HashMap<Multiaddr, EnCurso>,
                       salientes: &HashMap<PeerId, Saliente>,
                       addr: &Multiaddr| {
            en_curso.contains_key(addr) || salientes.values().any(|s| s.addr == *addr)
        };
        for e in &self.arranque {
            if !ocupada(&self.en_curso, &self.salientes, &e.addr) {
                return Some(e.clone());
            }
        }
        self.contador = self.contador.wrapping_add(1);
        if let Some(e) = self.gestor.elegir_probado(self.contador)
            && !ocupada(&self.en_curso, &self.salientes, &e.addr)
        {
            return Some(e);
        }
        self.contador = self.contador.wrapping_add(1);
        self.gestor.elegir_nuevo(self.contador)
    }

    fn puede_marcar(&self, addr: &Multiaddr, grupo: GrupoAncho) -> bool {
        if self.en_curso.contains_key(addr) {
            return false;
        }
        if self.salientes.values().any(|s| s.addr == *addr) {
            return false;
        }
        // C-NET-38: como mucho UNA saliente por grupo ancho. En dev loopback el grupo es el
        // `PeerId`, así que varios nodos loopback distintos sí caben.
        if self.salientes.values().any(|s| s.grupo == grupo) {
            return false;
        }
        // Un grupo ya comprometido por un dial en curso (sondeo o candidata) tampoco se repite.
        let en_curso = self.en_curso.values().any(|e| {
            e.candidata
                .as_ref()
                .is_some_and(|c| self.gestor.grupo_ancho(c) == grupo)
                || e.victima
                    .as_ref()
                    .is_some_and(|v| self.gestor.grupo_ancho(v) == grupo)
        });
        !en_curso
    }
}

/// Clave de un paseo aleatorio: impredecible sin la `nKey`.
fn clave_paseo(n_key: &[u8; 32], contador: u64) -> [u8; 32] {
    let mut b = Vec::with_capacity(40);
    b.extend_from_slice(n_key);
    b.extend_from_slice(&contador.to_be_bytes());
    *zx_core::sha3_256_publico(&b).as_bytes()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::*;
    use libp2p::identity::ed25519;
    use std::time::{Duration, Instant};
    use zx_core::firma::Firma;

    fn director() -> Director {
        Director::nuevo(Red::Dev, PerfilRed::de(Red::Dev))
    }

    /// Perfil con el registro de direcciones encendido y **sin anclas automáticas** (solo
    /// pruebas: así la rotación no queda bloqueada por las anclas).
    fn perfil_activo() -> PerfilRed {
        PerfilRed {
            registro_activo: true,
            anclas: 0,
            ..PerfilRed::de(Red::Dev)
        }
    }

    /// Director con `nKey` fija, para que el sorteo sea reproducible.
    fn director_activo() -> Director {
        Director::con_n_key(Red::Dev, perfil_activo(), [0x5a; 32])
    }

    fn par(semilla: u8) -> (ed25519::Keypair, ClavePublica) {
        let sk = ed25519::SecretKey::try_from_bytes([semilla; 32]).unwrap();
        let kp = ed25519::Keypair::from(sk);
        let pk = ClavePublica::desde_bytes(kp.public().to_bytes());
        (kp, pk)
    }

    fn prod(semilla: u8) -> ClavePublica {
        par(semilla).1
    }

    fn entrada(semilla: u8, epoch: u64, dirs: Vec<Multiaddr>) -> EntradaRegistro {
        let (kp, pk) = par(semilla);
        let mut e = EntradaRegistro {
            version: crate::registro::VERSION,
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

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn desconectados(acciones: &[Accion]) -> Vec<PeerId> {
        acciones
            .iter()
            .filter_map(|a| match a {
                Accion::Desconectar(p) => Some(*p),
                _ => None,
            })
            .collect()
    }

    /// Pone `n` salientes no ancla, con `desde` creciente (la primera es la más vieja).
    fn pon_salientes(d: &mut Director, t0: Instant, n: u8) -> Vec<PeerId> {
        let mut peers = Vec::new();
        for i in 0..n {
            let peer = PeerId::random();
            let a = addr(&format!("/ip4/10.{}.0.1/tcp/9833", i + 1));
            d.on_establecido(peer, &a, true, t0 + Duration::from_secs(u64::from(i)));
            peers.push(peer);
        }
        peers
    }

    /// **C-NET-34.** Las direcciones de arranque son solo el comienzo: se marcan y se mantienen.
    #[test]
    fn siembra_y_marca_el_arranque() {
        let mut d = director();
        let t0 = Instant::now();
        d.sembrar(None, &[addr("/ip4/93.184.216.34/tcp/9833")], t0);
        let acciones = d.tick(t0 + Duration::from_secs(1));
        assert!(
            acciones.iter().any(|a| matches!(a, Accion::Marcar(_))),
            "el arranque MUST marcarse"
        );
    }

    /// **C-NET-38.** No se marca una segunda saliente del mismo grupo ancho.
    #[test]
    fn una_saliente_por_grupo_ancho() {
        let mut d = director();
        let t0 = Instant::now();
        d.sembrar(
            None,
            &[
                addr("/ip4/93.184.1.1/tcp/9833"),
                addr("/ip4/93.184.2.1/tcp/9833"),
            ],
            t0,
        );
        let acciones = d.tick(t0 + Duration::from_secs(1));
        let marcadas: Vec<&Multiaddr> = acciones
            .iter()
            .filter_map(|a| match a {
                Accion::Marcar(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(marcadas.len(), 1, "mismo /16: solo una saliente");
    }

    /// **C-NET-41.** La rotación corta una saliente no ancla pasado `T_par`.
    ///
    /// Con 3 salientes, las 2 anclas quedan protegidas y la tercera rota. Con 1 o 2, no hay
    /// rotación posible sin aislarse: todas son anclas (DN-04).
    #[test]
    fn rota_una_saliente_pasado_t_par() {
        let mut d = director();
        let t0 = Instant::now();
        d.sembrar(None, &[], t0);
        for (i, puerto) in [1u16, 2, 3].into_iter().enumerate() {
            let peer = PeerId::random();
            let a = addr(&format!("/ip4/93.184.{}.1/tcp/{}", i + 1, 9833 + puerto));
            d.on_establecido(peer, &a, true, t0);
        }
        assert_eq!(d.salientes(), 3);
        // Un latido antes de T_par no rota.
        let acciones = d.tick(t0 + Duration::from_secs(59));
        assert!(!acciones.iter().any(|a| matches!(a, Accion::Desconectar(_))));
        // Pasado T_par rota exactamente una (la única no ancla).
        let acciones = d.tick(t0 + Duration::from_secs(61));
        assert_eq!(
            acciones
                .iter()
                .filter(|a| matches!(a, Accion::Desconectar(_)))
                .count(),
            1
        );
    }

    /// **C-NET-39.** Las anclas no se rotan.
    #[test]
    fn las_anclas_no_se_rotan() {
        let mut d = director();
        let t0 = Instant::now();
        let peer = PeerId::random();
        d.sembrar(None, &[], t0);
        d.on_establecido(peer, &addr("/ip4/93.184.1.1/tcp/9833"), true, t0);
        // Fijar como ancla la dirección de esa saliente.
        let e = crate::gestor::Entrada::de_multiaddr(addr("/ip4/93.184.1.1/tcp/9833"), Some(peer))
            .unwrap();
        assert!(d.gestor.fijar_ancla(e));
        let acciones = d.tick(t0 + Duration::from_secs(61));
        assert!(
            !acciones.iter().any(|a| matches!(a, Accion::Desconectar(_))),
            "un ancla no se rota"
        );
    }

    /// **ORDEN-RD1c (G4).** El sorteo es proporcional al peso: 10 000 sorteos con semilla fija;
    /// cada frecuencia queda dentro de 4 desviaciones típicas.
    #[test]
    fn sorteo_proporcional_al_peso() {
        let mut d = director_activo();
        let ahora = 100_000u64;
        d.fijar_tabla_pesos([(prod(1), 1u64), (prod(2), 2), (prod(3), 3)]);
        for (i, s) in [1u8, 2, 3].into_iter().enumerate() {
            let puerto = 1001 + i as u16;
            let a = addr(&format!("/ip4/10.0.0.{s}/tcp/{puerto}"));
            d.insertar_registro(entrada(s, ahora, vec![a]), ahora)
                .unwrap();
        }

        let n = 10_000u32;
        let mut cuenta: HashMap<u16, u32> = HashMap::new();
        for _ in 0..n {
            let e = d.sortear_candidata().unwrap();
            *cuenta.entry(e.puerto).or_insert(0) += 1;
        }
        for (puerto, peso) in [(1001u16, 1u64), (1002, 2), (1003, 3)] {
            let p = peso as f64 / 6.0;
            let esperado = p * f64::from(n);
            let sigma = (esperado * (1.0 - p)).sqrt();
            let c = f64::from(*cuenta.get(&puerto).unwrap_or(&0));
            assert!(
                (c - esperado).abs() <= 4.0 * sigma,
                "puerto {puerto}: {c} vs {esperado} (4σ = {})",
                4.0 * sigma
            );
        }
    }

    /// **ORDEN-RD1c (G4).** Un productor con peso pero **sin dirección publicada** no se elige.
    #[test]
    fn sorteo_no_elige_sin_direccion_publicada() {
        let mut d = director_activo();
        let ahora = 100_000u64;
        let p = prod(1);
        let q = prod(2);
        d.fijar_tabla_pesos([(p, 1u64), (q, 1_000)]);
        d.insertar_registro(
            entrada(1, ahora, vec![addr("/ip4/10.0.0.1/tcp/1001")]),
            ahora,
        )
        .unwrap();
        for _ in 0..1_000 {
            let e = d.sortear_candidata().unwrap();
            assert_eq!(e.puerto, 1001, "q no tiene dirección publicada");
        }
    }

    /// **ORDEN-RD1c (G3).** Sin tabla de pesos no hay sorteo y el director rota como hoy.
    #[test]
    fn sorteo_sin_tabla_es_el_director_de_hoy() {
        let mut d = director_activo();
        let t0 = Instant::now();
        d.sembrar(None, &[], t0);
        let peers = pon_salientes(&mut d, t0, 3);

        assert!(d.sortear_candidata().is_none(), "sin tabla no hay sorteo");
        let acciones = d.tick(t0 + Duration::from_secs(61));
        assert_eq!(
            desconectados(&acciones),
            vec![peers[0]],
            "rota la saliente más vieja, como hoy"
        );
    }

    /// **ORDEN-RD1c (G4).** La sorteada que no se puede marcar por una guarda de grupo no se marca;
    /// esa rotación usa la elección de hoy. Las anclas no se rotan.
    #[test]
    fn sorteo_respeta_guarda_de_grupo_y_anclas() {
        let perfil = PerfilRed {
            registro_activo: true,
            anclas: 1,
            ..PerfilRed::de(Red::Dev)
        };
        let mut d = Director::con_n_key(Red::Dev, perfil, [0x5a; 32]);
        let t0 = Instant::now();
        d.sembrar(None, &[], t0);
        let ahora = 100_000u64;
        let p = prod(1);
        d.fijar_tabla_pesos([(p, 100u64)]);
        let sorteada = addr("/ip4/10.0.0.9/tcp/1099");
        d.insertar_registro(entrada(1, ahora, vec![sorteada.clone()]), ahora)
            .unwrap();

        // La sorteada cae en el /16 de 10.0.0.0, que quedará ocupado por `mismo` (más joven que
        // `viejo`, así que la rotación se lleva a `viejo` y deja el grupo ocupado).
        let viejo = PeerId::random();
        d.on_establecido(viejo, &addr("/ip4/10.0.0.1/tcp/1001"), true, t0);
        let mismo = PeerId::random();
        d.on_establecido(
            mismo,
            &addr("/ip4/10.0.1.2/tcp/1002"),
            true,
            t0 + Duration::from_secs(1),
        );
        // Otra en un grupo distinto, fijada como ancla (no se rota).
        let ancla = PeerId::random();
        let addr_ancla = addr("/ip4/10.1.0.1/tcp/1003");
        d.on_establecido(ancla, &addr_ancla, true, t0 + Duration::from_secs(2));
        let e_ancla = Entrada::de_multiaddr(addr_ancla, Some(ancla)).unwrap();
        assert!(d.gestor.fijar_ancla(e_ancla));

        let acciones = d.tick(t0 + Duration::from_secs(61));
        assert_eq!(d.sorteos_realizados(), 1, "un sorteo por rotación");
        assert!(
            !acciones
                .iter()
                .any(|a| matches!(a, Accion::Marcar(m) if *m == sorteada)),
            "la guarda de grupo impide marcar la sorteada"
        );
        let dcs = desconectados(&acciones);
        assert_eq!(dcs.len(), 1);
        assert_eq!(dcs[0], viejo, "rota la más vieja no ancla");
        assert!(!dcs.contains(&ancla), "el ancla no se rota");
    }

    /// **ORDEN-RD1c (G4).** Exactamente un sorteo por rotación.
    #[test]
    fn un_sorteo_por_rotacion() {
        let mut d = director_activo();
        let t0 = Instant::now();
        d.sembrar(None, &[], t0);
        let ahora = 100_000u64;
        d.fijar_tabla_pesos([(prod(1), 5u64)]);
        d.insertar_registro(
            entrada(1, ahora, vec![addr("/ip4/10.9.0.1/tcp/1001")]),
            ahora,
        )
        .unwrap();
        let _ = pon_salientes(&mut d, t0, 3);

        assert_eq!(d.sorteos_realizados(), 0);
        d.tick(t0 + Duration::from_secs(61));
        assert_eq!(d.sorteos_realizados(), 1, "un sorteo en la 1.ª rotación");
        d.tick(t0 + Duration::from_secs(122));
        assert_eq!(d.sorteos_realizados(), 2, "un sorteo en la 2.ª rotación");
    }

    /// **ORDEN-RD1c (G5).** La saliente protegida se salta si hay otra que rotar.
    #[test]
    fn saliente_protegida_se_salta_y_rota_otra() {
        let mut d = director_activo();
        let t0 = Instant::now();
        d.sembrar(None, &[], t0);
        let peers = pon_salientes(&mut d, t0, 3);
        d.proteger_saliente(Some(peers[0]));

        let acciones = d.tick(t0 + Duration::from_secs(61));
        let dcs = desconectados(&acciones);
        assert_eq!(dcs.len(), 1);
        assert_ne!(dcs[0], peers[0], "se salta la protegida");
        assert_eq!(dcs[0], peers[1], "rota la siguiente más vieja");
    }

    /// **ORDEN-RD1c (G5).** Si no hay otra, se rota la protegida.
    #[test]
    fn saliente_protegida_unica_y_se_rota_si_no_hay_otra() {
        let mut d = director_activo();
        let t0 = Instant::now();
        d.sembrar(None, &[], t0);
        let peers = pon_salientes(&mut d, t0, 1);
        d.proteger_saliente(Some(peers[0]));

        let acciones = d.tick(t0 + Duration::from_secs(61));
        assert_eq!(
            desconectados(&acciones),
            vec![peers[0]],
            "sin otra, se rota la protegida"
        );
    }

    /// **RD-4b · P6.** Un sorteo con la tabla puesta deja un evento con el peso total, cuántas
    /// entradas eran elegibles y el productor elegido.
    #[test]
    fn rd4b_sorteo_emite_su_evento() {
        let mut d = director_activo();
        let ahora = 100_000u64;
        d.fijar_tabla_pesos([(prod(1), 5u64)]);
        d.insertar_registro(
            entrada(1, ahora, vec![addr("/ip4/10.9.0.1/tcp/1001")]),
            ahora,
        )
        .unwrap();

        assert!(d.tomar_eventos_sorteo().is_empty(), "aún no hubo sorteo");
        assert!(
            d.sortear_candidata().is_some(),
            "la entrada elegible se sortea"
        );
        let eventos = d.tomar_eventos_sorteo();
        assert_eq!(eventos.len(), 1, "un evento por sorteo");
        assert_eq!(eventos[0].peso_total, 5);
        assert_eq!(eventos[0].entradas, 1);
        assert!(
            eventos[0].elegido.is_some(),
            "el evento dice a quién eligió"
        );
        assert!(
            d.tomar_eventos_sorteo().is_empty(),
            "el evento se consume una sola vez"
        );
    }

    /// **RD-4b · P6.** Con el registro apagado el director no sortea y no hay evento.
    #[test]
    fn rd4b_sin_registro_no_hay_evento_de_sorteo() {
        let mut d = Director::nuevo(
            Red::Dev,
            PerfilRed {
                registro_activo: false,
                ..PerfilRed::de(Red::Dev)
            },
        );
        assert!(
            d.sortear_candidata().is_none(),
            "registro apagado: no hay sorteo"
        );
        assert!(
            d.tomar_eventos_sorteo().is_empty(),
            "registro apagado: no hay evento de sorteo"
        );
    }
}
