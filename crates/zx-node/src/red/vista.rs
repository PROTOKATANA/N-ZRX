//! Instantánea de solo lectura de lo que el nodo tiene admitido, compartida entre el hilo de
//! consenso (que la escribe tras cada admisión) y el bucle asíncrono de `zx-p2p` (que la lee para
//! responder al saludo y a las peticiones de sincronización, decisión 4 de `ORDEN-W06d2`).
//!
//! # Por qué una instantánea, y no una llamada al hilo de consenso
//!
//! [`zx_p2p::entrante::ManejadorEntrante`] exige métodos **rápidos y no bloqueantes** (se llaman
//! desde el bucle de eventos de `zx-p2p`; mientras uno corre, el `Swarm` no se pollea). Pedirle la
//! respuesta al hilo de consenso por un canal y esperarla bloquearía exactamente ese bucle. Una
//! instantánea protegida por `RwLock`, actualizada por el hilo de consenso cada vez que cambia algo
//! que el saludo o la sincronización necesitan, resuelve la lectura sin ida y vuelta.

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

use zx_core::digest::BlockHash;
use zx_core::preimage::block::BlockHeader;
use zx_p2p::mensaje::{BloqueRed, Estado};

struct Interior {
    estado: Estado,
    /// Cabeceras PoW admitidas, en orden de altura ascendente (índice == altura).
    cabeceras_pow: Vec<BlockHeader>,
    cuerpos_pow: BTreeMap<BlockHash, BloqueRed>,
    cuerpos_post: BTreeMap<BlockHash, BloqueRed>,
    /// `ORDEN-W06d6` (RI-3a #4): hash → altura en `cabeceras_pow`, para que `cabeceras_desde` no
    /// tenga que recorrer todo el historial por cada hash del locator (`REVISION-RI-3a.md`,
    /// hallazgo 4). Se reconstruye entera cada vez que `fijar_cabeceras_pow` reemplaza el vector
    /// (una reorganización): nunca queda una entrada apuntando a una altura que ya no es esa.
    indice_altura: HashMap<BlockHash, usize>,
    /// `ORDEN-W06d6` decisión 1: los hashes (PoW y PoST) **en el orden real en que este nodo los
    /// admitió** — el mismo orden del registro de admisión de `zx-storage` (D-N03′), porque se
    /// añade aquí en los mismos puntos donde el hilo de consenso ya llama a
    /// `registrar_pow`/`registrar_post` tras `cadena.admitir` (nunca antes). Solo crece; sirve
    /// `Peticion::Registro` (sincronización por páginas del registro de admisión).
    registro_admision: Vec<BlockHash>,
}

/// La instantánea. Ver el docstring del módulo.
pub struct VistaRed {
    interior: RwLock<Interior>,
    /// `ORDEN-W06d6` decisión 1: la mayor `longitud_registro` que la tarea de sincronización ha
    /// visto declarar a **cualquier** par conectado (saludo o `Respuesta::Registro`). Es un
    /// `Atomic`, no parte de `Interior`: lo escribe la tarea async de sincronización y lo lee el
    /// hilo de consenso (síncrono) para decidir si "estamos sincronizando" (`Self::sincronizando`),
    /// sin tomar el `RwLock` completo por una sola comparación.
    mejor_longitud_par: std::sync::atomic::AtomicU64,
}

impl VistaRed {
    /// Una instantánea nueva con el saludo inicial (normalmente, justo tras el génesis).
    #[must_use]
    pub fn nueva(estado_inicial: Estado) -> Self {
        Self {
            mejor_longitud_par: std::sync::atomic::AtomicU64::new(0),
            interior: RwLock::new(Interior {
                estado: estado_inicial,
                cabeceras_pow: Vec::new(),
                cuerpos_pow: BTreeMap::new(),
                cuerpos_post: BTreeMap::new(),
                indice_altura: HashMap::new(),
                registro_admision: Vec::new(),
            }),
        }
    }

    /// Registra el **génesis** PoW en la vista: `arranque_limpio` no pasa por
    /// [`Self::registrar_pow`] (fija `cabeceras_pow` directamente con
    /// [`Self::fijar_cabeceras_pow`] para no dejar un hueco de altura permanente en el primer
    /// bloque real, `ORDEN-W06d3` hallazgo en vivo), así que sin esta llamada el cuerpo del génesis
    /// nunca entraba en `cuerpos_pow` ni en el registro de admisión. `ORDEN-W06d6` la añade porque
    /// el registro de admisión (decisión 1) tiene que empezar en el génesis, igual que el registro
    /// real de `zx-storage`.
    pub fn registrar_genesis_pow(&self, bloque: BloqueRed) {
        let Ok(mut i) = self.interior.write() else {
            return;
        };
        let BloqueRed::Pow { cabecera, .. } = &bloque else {
            // Invariante del llamante: los dos únicos llamantes (`Nodo::arranque_limpio` y
            // `Nodo::admitir_pow_interno`) construyen siempre un `BloqueRed::Pow`. Se defiende sin
            // pánico (antes `debug_assert!`) en vez de poder tirar el proceso en modo debug.
            tracing::error!("registrar_genesis_pow con un bloque que no es PoW");
            return;
        };
        let hash = cabecera.block_hash();
        i.indice_altura.insert(hash, 0);
        i.registro_admision.push(hash);
        i.cuerpos_pow.insert(hash, bloque);
    }

    /// El hilo de consenso reemplaza el saludo tras cada cambio de punta.
    pub fn actualizar_estado(&self, estado: Estado) {
        if let Ok(mut i) = self.interior.write() {
            i.estado = estado;
        }
    }

    /// El hilo de consenso registra un bloque PoW recién admitido (para servir `CabecerasPow` y
    /// `Bloques`). `altura` MUST ser exactamente `cabeceras_pow.len()` (secuencial, sin huecos): la
    /// fase PoW nunca reordena.
    ///
    /// # `registro_admision` recibe **todos** los admitidos, también los laterales
    ///
    /// RED-3 punto 2: antes el hash solo entraba en `registro_admision` si la altura era la
    /// siguiente (`altura == esperado`). Un bloque PoW de una rama lateral —admitido y persistido en
    /// `zx-storage`, con su cuerpo en `cuerpos_pow`— quedaba **fuera** del registro de admisión, así
    /// que `Peticion::Registro` nunca lo servía: los nodos que no lo habían recibido por gossip no
    /// tenían forma de pedirlo y su `compendio_bloques` divergía (el humo de RED-2). El registro
    /// refleja el orden real de admisión del almacén (D-N03′); las cabeceras de la rama seleccionada
    /// siguen siendo solo las secuenciales.
    pub fn registrar_pow(&self, altura: u32, bloque: BloqueRed) {
        let Ok(mut i) = self.interior.write() else {
            return;
        };
        let BloqueRed::Pow { cabecera, .. } = &bloque else {
            // Invariante del llamante: solo `Nodo::admitir_pow_interno` llama aquí, y siempre con
            // un `BloqueRed::Pow`. Se defiende sin pánico (antes `debug_assert!`).
            tracing::error!("registrar_pow con un bloque que no es PoW");
            return;
        };
        let hash = cabecera.block_hash();
        let esperado = i.cabeceras_pow.len();
        if altura as usize == esperado {
            i.cabeceras_pow.push(*cabecera);
            i.indice_altura.insert(hash, esperado);
        } else if (altura as usize) < esperado {
            // Repetición al reiniciar (D-N03′): ya está, no se duplica.
        } else {
            // Un hueco de verdad sería un bug del llamante; no hay nada seguro que hacer aquí salvo
            // no corromper el índice por altura (dejarlo tal cual y solo indexar el cuerpo).
            tracing::error!(
                altura,
                esperado,
                "registrar_pow con un hueco de altura: la vista de cabeceras queda incompleta"
            );
        }
        // `insert` devuelve `Some` si el hash ya estaba (repetición): solo el primero entra en el
        // registro, para que `pagina_registro` no sirva el mismo bloque dos veces.
        if i.cuerpos_pow.insert(hash, bloque).is_none() {
            i.registro_admision.push(hash);
        }
    }

    /// El hilo de consenso fija la secuencia **completa** de cabeceras de la punta PoW
    /// seleccionada, tras admitir un bloque o tras una reorganización (`ORDEN-W06d3` decisión 3).
    ///
    /// `registrar_pow` (arriba) es *append-only por altura*: una vez que una altura tiene cabecera,
    /// nunca la sustituye, aunque `zx-cadena` reorganice y esa altura pase a pertenecer a **otro**
    /// bloque. Sin esto, el locator y `cabeceras_desde` seguirían ofreciendo a los pares la rama que
    /// ya se descartó localmente — observado en vivo (`PROGRESO.md`): un nodo que reorganiza sobre
    /// sí mismo puede acabar sirviendo un historial que ni él mismo considera ya canónico. Se llama
    /// con `historial_pow` completo (siempre empieza en el génesis): reemplaza `cabeceras_pow`
    /// entero, no solo la cola divergente, para no tener que calcular aquí el punto de corte.
    /// `cuerpos_pow` no se toca: los cuerpos de bloques de una rama descartada siguen siendo cuerpos
    /// válidos que se pueden servir si alguien los pide por hash.
    pub fn fijar_cabeceras_pow(&self, cabeceras: &[BlockHeader]) {
        if let Ok(mut i) = self.interior.write() {
            i.cabeceras_pow.clear();
            i.cabeceras_pow.extend_from_slice(cabeceras);
            // `ORDEN-W06d6` (RI-3a #4): el índice hash→altura se reconstruye entero junto con
            // `cabeceras_pow` — nunca debe quedar una entrada que apunte a una altura que ya
            // pertenece a otro bloque tras la reorganización.
            i.indice_altura.clear();
            for (altura, c) in cabeceras.iter().enumerate() {
                i.indice_altura.insert(c.block_hash(), altura);
            }
        }
    }

    /// El hilo de consenso registra un bloque PoST recién admitido.
    pub fn registrar_post(&self, hash: BlockHash, bloque: BloqueRed) {
        if let Ok(mut i) = self.interior.write() {
            i.cuerpos_post.insert(hash, bloque);
            // `ORDEN-W06d6` decisión 1: orden real de admisión (PoW y PoST juntos).
            i.registro_admision.push(hash);
        }
    }

    /// El saludo actual (para responder `Peticion::Estado`).
    #[must_use]
    pub fn estado(&self) -> Estado {
        self.interior
            .read()
            .map(|i| i.estado.clone())
            .unwrap_or_else(|e| e.into_inner().estado.clone())
    }

    /// Cabeceras PoW desde el primer hash del locator que reconozcamos, hasta `hasta` o hasta donde
    /// tengamos. Vacío si no reconocemos nada del locator (respuesta legítima, ver
    /// [`zx_p2p::entrante::ManejadorEntrante::cabeceras_desde`]).
    ///
    /// `ORDEN-W06d6` (RI-3a #4, `REVISION-RI-3a.md` hallazgo 4, bajo/plausible): antes recorría
    /// `cabeceras_pow` entero por cada hash del locator (`O(locator × historia)`); ahora es un
    /// `HashMap` que da la altura en O(1) por hash — `O(locator)` en total.
    #[must_use]
    pub fn cabeceras_desde(
        &self,
        locator: &[BlockHash],
        hasta: Option<BlockHash>,
    ) -> Vec<BlockHeader> {
        let Ok(i) = self.interior.read() else {
            return Vec::new();
        };
        let Some(inicio) = locator.iter().find_map(|h| i.indice_altura.get(h).copied()) else {
            return Vec::new();
        };
        let mut salida = Vec::new();
        for c in i.cabeceras_pow.iter().skip(inicio + 1) {
            salida.push(*c);
            if Some(c.block_hash()) == hasta {
                break;
            }
        }
        salida
    }

    /// Los bloques completos (PoW o PoST) que tengamos de los pedidos, en el orden pedido.
    ///
    /// `ORDEN-W06d6` (RI-3a #1, `REVISION-RI-3a.md` hallazgo 1): los hashes se **deduplican y se
    /// recortan a `MAX_BLOQUES_POR_RESPUESTA` antes de clonar nada**, no después. Antes, una
    /// petición con el mismo hash repetido hasta `MAX_HASHES_POR_PETICION` (256) veces producía 256
    /// clones completos del bloque —hasta `256 × MAX_BLOQUE_RED_BYTES`— y **luego** `zx-p2p`
    /// recortaba a `MAX_BLOQUES_POR_RESPUESTA` (16): 240 de esos clones se tiraban sin usarse,
    /// dentro del mismo hilo que pollea el `Swarm` (confirmado, `resultados-RI-3a/
    /// ri3a_bloques_por_hash_duplicados.rs`). Deduplicar primero hace que el peor caso sea
    /// exactamente `MAX_BLOQUES_POR_RESPUESTA` clones, nunca más, sin depender de que `zx-p2p`
    /// recorte después.
    #[must_use]
    pub fn bloques_por_hash(&self, hashes: &[BlockHash]) -> Vec<BloqueRed> {
        let Ok(i) = self.interior.read() else {
            return Vec::new();
        };
        let mut vistos: Vec<BlockHash> = Vec::new();
        let mut salida = Vec::new();
        for h in hashes {
            if vistos.contains(h) {
                continue;
            }
            vistos.push(*h);
            if let Some(bloque) = i.cuerpos_pow.get(h).or_else(|| i.cuerpos_post.get(h)) {
                salida.push(bloque.clone());
                if salida.len() >= zx_p2p::limites::MAX_BLOQUES_POR_RESPUESTA {
                    break;
                }
            }
        }
        salida
    }

    /// ¿Tenemos ya el cuerpo de este hash (PoW o PoST), lo pidamos o no otra vez?
    #[must_use]
    pub fn tiene_cuerpo(&self, hash: &BlockHash) -> bool {
        self.interior
            .read()
            .is_ok_and(|i| i.cuerpos_pow.contains_key(hash) || i.cuerpos_post.contains_key(hash))
    }

    /// Longitud actual del registro de admisión (`ORDEN-W06d6` decisión 1): para el `longitud` del
    /// saludo y de `Respuesta::Registro`.
    #[must_use]
    pub fn longitud_registro(&self) -> u64 {
        self.interior
            .read()
            .map(|i| i.registro_admision.len() as u64)
            .unwrap_or(0)
    }

    /// La tarea de sincronización llama a esto cada vez que un par declara su `longitud_registro`
    /// (saludo o `Respuesta::Registro`): mantiene el máximo visto hasta ahora (`ORDEN-W06d6`
    /// decisión 1). Un par que se desconecta no baja el máximo: es una cota de "cuánto sabemos que
    /// existe en la red", no "cuánto tiene el par actual".
    pub fn actualizar_mejor_longitud_par(&self, longitud: u64) {
        self.mejor_longitud_par
            .fetch_max(longitud, std::sync::atomic::Ordering::AcqRel);
    }

    /// La mayor `longitud_registro` vista declarar a cualquier par hasta ahora.
    #[must_use]
    pub fn mejor_longitud_par(&self) -> u64 {
        self.mejor_longitud_par
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// ¿Este nodo va a más de [`super::UMBRAL_SINCRONIZANDO`] bloques por detrás del par más
    /// avanzado que conoce (`ORDEN-W06d6` decisión 1)? Mientras sea `true`, los bloques PoST de
    /// **gossip** (no los que trae la propia sincronización por registro) cuyo padre falte se
    /// descartan en vez de ir al depósito de huérfanos: llegarán por el registro, y depositarlos
    /// solo alimentaría una avalancha de huérfanos que la producción sigue adelantando (la causa
    /// raíz de V5/V6(b) en `REVISION-W06d5.md`).
    #[must_use]
    pub fn sincronizando(&self) -> bool {
        self.longitud_registro()
            .saturating_add(super::UMBRAL_SINCRONIZANDO)
            < self.mejor_longitud_par()
    }

    /// Una página del registro de admisión, empezando en el índice `desde` (`ORDEN-W06d6`
    /// decisión 1): como mucho `max_bloques` bloques y `max_bytes` bytes totales (estimados por su
    /// tamaño en el wire), en el orden real de admisión. Devuelve también la longitud **actual**
    /// del registro (puede haber crecido desde que quien pregunta fijó el `longitud` que recuerda).
    /// Siempre incluye al menos un bloque si `desde` está dentro de rango y hay presupuesto para
    /// nada más: una página vacía por exceso de tamaño de un único bloque dejaría al que sincroniza
    /// sin poder avanzar nunca.
    #[must_use]
    pub fn pagina_registro(
        &self,
        desde: u64,
        max_bloques: usize,
        max_bytes: u64,
    ) -> (Vec<BloqueRed>, u64) {
        let Ok(i) = self.interior.read() else {
            return (Vec::new(), 0);
        };
        let longitud = i.registro_admision.len() as u64;
        let inicio = usize::try_from(desde).unwrap_or(usize::MAX);
        let mut salida = Vec::new();
        let mut bytes_acumulados: u64 = 0;
        for hash in i.registro_admision.iter().skip(inicio).take(max_bloques) {
            let Some(bloque) = i.cuerpos_pow.get(hash).or_else(|| i.cuerpos_post.get(hash)) else {
                // No debería ocurrir (registro y cuerpos se llenan en el mismo punto de código),
                // pero un hueco aquí no debe tirar la página entera: se para donde se pueda seguir.
                tracing::error!(%hash, "pagina_registro: hash del registro sin cuerpo en la vista");
                break;
            };
            let tam = zx_p2p::codec::bloque_a_bytes(bloque).len() as u64;
            if !salida.is_empty() && bytes_acumulados.saturating_add(tam) > max_bytes {
                break;
            }
            salida.push(bloque.clone());
            bytes_acumulados = bytes_acumulados.saturating_add(tam);
        }
        (salida, longitud)
    }

    /// Un *locator* al estilo Bitcoin: denso cerca de la punta, espaciado hacia atrás,
    /// **siempre** termina en el génesis (`ORDEN-W06d2`, decisión 4). Sirve para pedirle a un par
    /// `CabecerasPow` sin suponer que las dos cadenas coinciden más allá del primer hash que
    /// reconozca.
    #[must_use]
    pub fn locator(&self) -> Vec<BlockHash> {
        let Ok(i) = self.interior.read() else {
            return Vec::new();
        };
        let n = i.cabeceras_pow.len();
        if n == 0 {
            return Vec::new();
        }
        let mut salida = Vec::new();
        let mut paso: usize = 1;
        let mut idx = n - 1;
        loop {
            #[expect(
                clippy::indexing_slicing,
                reason = "idx siempre es < n por construcción del bucle"
            )]
            salida.push(i.cabeceras_pow[idx].block_hash());
            if idx == 0 {
                break;
            }
            idx = idx.saturating_sub(paso);
            paso = paso.saturating_mul(2);
        }
        salida
    }

    /// Nuestra altura PoW más alta conocida (0 si solo tenemos el génesis o nada aún).
    #[must_use]
    pub fn altura_pow(&self) -> u32 {
        self.interior
            .read()
            .map(|i| i.cabeceras_pow.len().saturating_sub(1) as u32)
            .unwrap_or(0)
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "los tests fallan con panic por diseño"
)]
mod tests {
    use super::VistaRed;
    use zx_core::digest::{BlockHash, Digest, MerkleRoot};
    use zx_core::preimage::block::BlockHeader;
    use zx_core::red::Red;
    use zx_p2p::mensaje::{BloqueRed, Estado, Fase, PuntaPow};

    fn h(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn estado_vacio() -> Estado {
        Estado {
            hash_genesis: h(0),
            red: Red::Dev,
            fase: Fase::Pow,
            punta_pow: PuntaPow {
                hash: h(0),
                altura: 0,
                trabajo_acumulado: [0; 32],
            },
            terminal: None,
            puntas_post: Vec::new(),
            blue_work_virtual: [0; 32],
            longitud_registro: 0,
        }
    }

    fn cabecera(altura: u32, prev: BlockHash) -> BlockHeader {
        BlockHeader {
            consensus_branch_id: 0xa8b4_66a7,
            prev_hash: prev,
            merkle_root: MerkleRoot::from_digest(Digest::from_bytes([9; 32])),
            timestamp: 1_000 + u64::from(altura),
            bits: 0x1c07_fff8,
            nonce: u64::from(altura),
            height: altura,
        }
    }

    fn bloque_pow(altura: u32, prev: BlockHash) -> BloqueRed {
        BloqueRed::Pow {
            cabecera: cabecera(altura, prev),
            txs: Vec::new(),
            testigos: Vec::new(),
        }
    }

    #[test]
    fn sin_nada_registrado_las_cabeceras_desde_cualquier_locator_estan_vacias() {
        let v = VistaRed::nueva(estado_vacio());
        assert!(v.cabeceras_desde(&[h(5)], None).is_empty());
    }

    #[test]
    fn el_locator_devuelve_lo_que_sigue_al_primero_reconocido() {
        let v = VistaRed::nueva(estado_vacio());
        let mut prev = h(0);
        for altura in 0..5u32 {
            let b = bloque_pow(altura, prev);
            let BloqueRed::Pow { cabecera, .. } = &b else {
                unreachable!()
            };
            prev = cabecera.block_hash();
            v.registrar_pow(altura, b);
        }
        // El locator reconoce la altura 2; deben volver las alturas 3 y 4.
        let hash_altura_2 = {
            let mut p = h(0);
            for altura in 0..3u32 {
                let c = cabecera(altura, p);
                p = c.block_hash();
            }
            p
        };
        let resultado = v.cabeceras_desde(&[hash_altura_2], None);
        assert_eq!(resultado.len(), 2);
        assert_eq!(resultado[0].height, 3);
        assert_eq!(resultado[1].height, 4);
    }

    #[test]
    fn el_locator_siempre_termina_en_el_genesis_y_es_denso_cerca_de_la_punta() {
        let v = VistaRed::nueva(estado_vacio());
        let mut prev = h(0);
        let mut hashes = Vec::new();
        for altura in 0..20u32 {
            let b = bloque_pow(altura, prev);
            let BloqueRed::Pow { cabecera, .. } = &b else {
                unreachable!()
            };
            prev = cabecera.block_hash();
            hashes.push(prev);
            v.registrar_pow(altura, b);
        }
        let locator = v.locator();
        assert_eq!(locator.first(), Some(&hashes[19]), "empieza en la punta");
        assert_eq!(locator.last(), Some(&hashes[0]), "termina en el génesis");
        // Denso al principio: los dos primeros pasos son de distancia 1 y 2.
        assert_eq!(locator[1], hashes[18]);
        assert_eq!(locator[2], hashes[16]);
    }

    #[test]
    fn bloques_por_hash_respeta_el_orden_pedido_y_omite_lo_ausente() {
        let v = VistaRed::nueva(estado_vacio());
        let b0 = bloque_pow(0, h(0));
        let BloqueRed::Pow { cabecera: c0, .. } = &b0 else {
            unreachable!()
        };
        let hash0 = c0.block_hash();
        v.registrar_pow(0, b0);

        let ausente = h(200);
        let salida = v.bloques_por_hash(&[ausente, hash0]);
        assert_eq!(salida.len(), 1);
        assert!(
            matches!(&salida[0], BloqueRed::Pow { cabecera, .. } if cabecera.block_hash() == hash0)
        );
    }

    /// **`ORDEN-W06d3`, hallazgo en vivo.** `registrar_pow` nunca sustituye una altura ya ocupada
    /// (`PROGRESO.md`): tras una reorganización, `fijar_cabeceras_pow` es lo único que corrige la
    /// secuencia para que el localizador refleje la rama seleccionada de verdad, no la primera que
    /// ocupó cada altura.
    #[test]
    fn fijar_cabeceras_pow_sustituye_una_altura_ya_ocupada_por_registrar_pow() {
        let v = VistaRed::nueva(estado_vacio());
        let c0 = cabecera(0, h(0));
        v.registrar_pow(0, bloque_pow(0, h(0)));
        let c1_vieja = cabecera(1, c0.block_hash());
        v.registrar_pow(1, bloque_pow(1, c0.block_hash()));
        assert_eq!(v.altura_pow(), 1);
        assert_eq!(v.locator().first(), Some(&c1_vieja.block_hash()));

        // Una reorganización cambia la altura 1 por un bloque distinto.
        let c1_nueva = cabecera(1, c0.block_hash());
        // `cabecera(1, ..)` con la misma entrada da el mismo hash (determinista): se fuerza un
        // contenido distinto para simular de verdad "otro bloque en la misma altura".
        let mut c1_nueva_distinta = c1_nueva;
        c1_nueva_distinta.nonce = 9_999;
        v.fijar_cabeceras_pow(&[c0, c1_nueva_distinta]);

        assert_eq!(v.altura_pow(), 1, "la altura no cambia, solo el contenido");
        assert_eq!(
            v.locator().first(),
            Some(&c1_nueva_distinta.block_hash()),
            "la vista ya no ofrece la rama descartada en la altura 1"
        );
    }

    /// **RED-3 punto 2.** Un bloque PoW de una rama lateral, admitido a una altura ya ocupada,
    /// entra en el registro de admisión (y por tanto se sirve por `Peticion::Registro`); si no, los
    /// nodos que no lo reciben por gossip no pueden pedirlo y el `compendio_bloques` diverge.
    #[test]
    fn un_bloque_lateral_entra_en_el_registro_de_admision() {
        let v = VistaRed::nueva(estado_vacio());
        let c0 = cabecera(0, h(0));
        v.registrar_pow(0, bloque_pow(0, h(0)));
        let c1 = cabecera(1, c0.block_hash());
        v.registrar_pow(1, bloque_pow(1, c0.block_hash()));
        assert_eq!(v.longitud_registro(), 2, "génesis + canónico");

        // Mismo padre y misma altura que `c1`, contenido distinto: un bloque lateral.
        let mut lateral = bloque_pow(1, c0.block_hash());
        let BloqueRed::Pow { cabecera, .. } = &mut lateral else {
            unreachable!()
        };
        cabecera.nonce = 7_777;
        let hash_lateral = cabecera.block_hash();
        v.registrar_pow(1, lateral);

        assert_eq!(v.longitud_registro(), 3, "el lateral también entra");
        let (pagina, longitud) = v.pagina_registro(0, 10, u64::MAX);
        assert_eq!(longitud, 3);
        let hashes: Vec<BlockHash> = pagina
            .iter()
            .map(|b| match b {
                BloqueRed::Pow { cabecera, .. } => cabecera.block_hash(),
                BloqueRed::Post { cabecera, .. } => cabecera.block_hash(),
            })
            .collect();
        assert!(
            hashes.contains(&hash_lateral),
            "la página del registro MUST incluir el bloque lateral"
        );
        assert_eq!(
            v.locator().first(),
            Some(&c1.block_hash()),
            "las cabeceras secuenciales siguen siendo las canónicas"
        );
    }
}
