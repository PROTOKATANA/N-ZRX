//! Índice de alcanzabilidad por intervalos sobre el árbol de padres seleccionados.
//!
//! # Origen y licencia
//!
//! Reimplementación desde el algoritmo de **rusty-kaspa** (`consensus/src/processes/reachability/`),
//! commit `c338d495bec29e4dc8b5149f99e8db6fa916ed4a`, licencia ISC (ver `PROCEDENCIA.md`). No se
//! copia código: se reescribe el algoritmo adaptado a índices densos (`Idx`) y a los arrays
//! paralelos de [`crate::ghostdag::AlmacenGhostdag`].
//!
//! # Qué resuelve
//!
//! `es_ancestro(a, b)` (¿`a ∈ pasado(b) ∪ {b}`?) en tiempo logarítmico, sin el conjunto de bits
//! denso `anc` que costaba `O(N)` por bloque. La estructura son tres piezas:
//!
//! 1. **Árbol** de padres seleccionados: cada bloque tiene `padre = sp`, `hijos` y una `altura`.
//! 2. **Intervalos** `[inicio, fin]` anidados: `a` es ancestro de cadena de `b` si el intervalo de
//!    `a` contiene el de `b`. Los hijos reparten la capacidad restante del padre; cuando se agota,
//!    un **reindexado** reasigna intervalos desde el ancestro con holgura.
//! 3. **Conjuntos de cobertura del futuro** (`cubrientes`): por cada bloque `m` fusionado por un
//!    bloque nuevo `n`, se anota `n` en `cubrientes[m]`. Así, `a` es ancestro DAG de `b` (aunque no
//!    sea de cadena) si algún `c ∈ cubrientes[a]` es ancestro de cadena de `b`. La lista está
//!    ordenada por `inicio` de intervalo, así que la consulta es una búsqueda binaria.
//!
//! El coste por inserción y por consulta es `O(log N)` amortizado (el reindexado es amortizado).

#![expect(
    clippy::indexing_slicing,
    reason = "arrays densos internos: el reindexado y la construcción garantizan el rango"
)]

use std::collections::{HashMap, VecDeque};

use crate::error::ErrorDag;
use crate::ghostdag::Idx;

/// Profundidad del reindexado bajo el ancestro seleccionado (Kaspa:
/// `DEFAULT_REINDEX_DEPTH`).
const PROFUNDIDAD_REINDEX: u64 = 100;
/// Holgura reservada por bloque de cadena al reindexar (Kaspa:
/// `DEFAULT_REINDEX_SLACK`).
const HOLGURA_REINDEX: u64 = 1 << 14;

fn incoherente(motivo: &'static str) -> ErrorDag {
    ErrorDag::GhostdagIncoherente { motivo }
}

/// Intervalo cerrado `[inicio, fin]` sobre el eje de la cadena seleccionada.
///
/// El vacío es `fin == inicio − 1`; el maximal deja margen en ambos extremos para poder reducirlo.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Intervalo {
    pub(crate) inicio: u64,
    pub(crate) fin: u64,
}

impl Intervalo {
    pub(crate) const fn nuevo(inicio: u64, fin: u64) -> Self {
        debug_assert!(fin + 1 >= inicio);
        debug_assert!(inicio > 0);
        debug_assert!(fin < u64::MAX);
        Self { inicio, fin }
    }

    pub(crate) const fn vacio() -> Self {
        Self { inicio: 1, fin: 0 }
    }

    pub(crate) const fn maximo() -> Self {
        Self {
            inicio: 1,
            fin: u64::MAX - 1,
        }
    }

    pub(crate) const fn tamano(&self) -> u64 {
        (self.fin + 1) - self.inicio
    }

    pub(crate) const fn es_vacio(&self) -> bool {
        self.tamano() == 0
    }

    pub(crate) const fn aumentar(&self, d: u64) -> Self {
        Self::nuevo(self.inicio + d, self.fin + d)
    }

    pub(crate) const fn disminuir(&self, d: u64) -> Self {
        Self::nuevo(self.inicio - d, self.fin - d)
    }

    pub(crate) const fn aumentar_inicio(&self, d: u64) -> Self {
        Self::nuevo(self.inicio + d, self.fin)
    }

    pub(crate) const fn disminuir_inicio(&self, d: u64) -> Self {
        Self::nuevo(self.inicio - d, self.fin)
    }

    pub(crate) const fn aumentar_fin(&self, d: u64) -> Self {
        Self::nuevo(self.inicio, self.fin + d)
    }

    pub(crate) const fn disminuir_fin(&self, d: u64) -> Self {
        Self::nuevo(self.inicio, self.fin - d)
    }

    pub(crate) const fn contiene(&self, otra: Self) -> bool {
        self.inicio <= otra.inicio && otra.fin <= self.fin
    }

    pub(crate) const fn contiene_estricto(&self, otra: Self) -> bool {
        self.inicio <= otra.inicio && otra.fin < self.fin
    }

    fn dividir_fraccion(&self, fraccion: f32) -> (Self, Self) {
        let izq = f32::ceil(self.tamano() as f32 * fraccion) as u64;
        (
            Self::nuevo(self.inicio, self.inicio + izq - 1),
            Self::nuevo(self.inicio + izq, self.fin),
        )
    }

    pub(crate) fn dividir_mitad(&self) -> (Self, Self) {
        self.dividir_fraccion(0.5)
    }

    /// Reparte el intervalo en trozos de tamaños exactos `tamanos` (que deben sumar `tamano()`).
    pub(crate) fn dividir_exacto(&self, tamanos: &[u64]) -> Vec<Self> {
        debug_assert_eq!(
            tamanos.iter().sum::<u64>(),
            self.tamano(),
            "los tamaños deben sumar el intervalo"
        );
        let mut inicio = self.inicio;
        tamanos
            .iter()
            .map(|tam| {
                let intervalo = Self::nuevo(inicio, inicio + tam - 1);
                inicio += tam;
                intervalo
            })
            .collect()
    }

    /// Reparte `tamano()` entre `tamanos.len()` partes: cada una recibe al menos `tamanos[i]`; el
    /// sobrante se reparte con sesgo exponencial hacia los subárboles mayores.
    pub(crate) fn dividir_exponencial(&self, tamanos: &[u64]) -> Vec<Self> {
        let tam = self.tamano();
        let suma = tamanos.iter().sum::<u64>();
        debug_assert!(tam >= suma);
        debug_assert!(suma > 0, "no se puede repartir en 0 partes");
        if tam == suma {
            return self.dividir_exacto(tamanos);
        }
        let mut sobrante = tam - suma;
        let total_bias = sobrante as f64;
        let mut con_sesgo = Vec::with_capacity(tamanos.len());
        let fracciones = fracciones_exponenciales(tamanos);
        for (i, fraccion) in fracciones.iter().enumerate() {
            let sesgo: u64 = if i == fracciones.len() - 1 {
                sobrante
            } else {
                sobrante.min(f64::round(total_bias * fraccion) as u64)
            };
            con_sesgo.push(tamanos[i] + sesgo);
            sobrante -= sesgo;
        }
        self.dividir_exacto(&con_sesgo)
    }
}

/// `fraccion[i] = 2^tamanos[i] / Σ 2^tamanos[j]`, normalizado por el máximo para no desbordar.
fn fracciones_exponenciales(tamanos: &[u64]) -> Vec<f64> {
    let maximo = tamanos.iter().copied().max().unwrap_or_default();
    let mut fracciones = tamanos
        .iter()
        .map(|s| 1f64 / 2f64.powf((maximo - s) as f64))
        .collect::<Vec<f64>>();
    let suma = fracciones.iter().sum::<f64>();
    for f in &mut fracciones {
        *f /= suma;
    }
    fracciones
}

/// Índice de alcanzabilidad. Todos los arrays están indexados por `Idx` denso.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IndiceAlcanzabilidad {
    /// Padre en el árbol de selección (`sp`); `None` solo para la raíz.
    padre: Vec<Option<Idx>>,
    hijos: Vec<Vec<Idx>>,
    intervalos: Vec<Intervalo>,
    alturas: Vec<u64>,
    /// Conjunto de cobertura del futuro, ordenado por `inicio` de intervalo.
    cubrientes: Vec<Vec<Idx>>,
    raiz_reindex: Idx,
    /// Holgura reservada por bloque de cadena al reindexar. En producción vale
    /// [`HOLGURA_REINDEX`]; el constructor de test (`nuevo_con_capacidad`) puede reducirla para
    /// forzar reindexados con DAGs pequeños. No cambia la semántica, solo los valores de los
    /// intervalos.
    holgura: u64,
    /// Contador **solo de test**: reindexados por capacidad de intervalos agotada.
    #[cfg(test)]
    reindex_capacidad: u64,
    /// Contador **solo de test**: pasos de avance de la raíz de reindexado.
    #[cfg(test)]
    reindex_avance: u64,
}

/// Resultado de buscar un descendiente en una lista ordenada por `inicio`.
enum Busqueda {
    Encontrado,
    NoEncontrado(usize),
}

impl IndiceAlcanzabilidad {
    /// Índice con una única raíz (el terminal PoW, `Idx = 0`).
    pub(crate) fn nuevo() -> Self {
        Self {
            padre: vec![None],
            hijos: vec![Vec::new()],
            intervalos: vec![Intervalo::maximo()],
            alturas: vec![0],
            cubrientes: vec![Vec::new()],
            raiz_reindex: 0,
            holgura: HOLGURA_REINDEX,
            #[cfg(test)]
            reindex_capacidad: 0,
            #[cfg(test)]
            reindex_avance: 0,
        }
    }

    /// Constructor **solo de test**: igual que [`Self::nuevo`] pero con una capacidad de raíz y una
    /// holgura reducidas, para forzar muchos reindexados en DAGs pequeños. No cambia ninguna regla
    /// de ancestría; solo los valores de los intervalos.
    #[cfg(test)]
    pub(crate) fn nuevo_con_capacidad(capacidad: u64, holgura: u64) -> Self {
        let mut indice = Self::nuevo();
        indice.intervalos[0] = Intervalo::nuevo(1, capacidad);
        indice.holgura = holgura;
        indice
    }

    /// Reindexados contados (**solo test**): `(por capacidad agotada, pasos de avance de la raíz)`.
    #[cfg(test)]
    pub(crate) const fn reindexados(&self) -> (u64, u64) {
        (self.reindex_capacidad, self.reindex_avance)
    }

    /// Añade el bloque `nuevo` (que debe ser `len()`) al árbol con padre `sp` y actualiza los
    /// conjuntos de cobertura del futuro de cada bloque del mergeset.
    ///
    /// # Errores
    /// [`ErrorDag::GhostdagIncoherente`] si el reindexado detecta un estado imposible (nunca en un
    /// almacén coherente).
    pub(crate) fn agregar_bloque(
        &mut self,
        nuevo: Idx,
        sp: Idx,
        mergeset: &[Idx],
    ) -> Result<(), ErrorDag> {
        debug_assert_eq!(nuevo as usize, self.padre.len());
        self.padre.push(Some(sp));
        self.hijos.push(Vec::new());
        self.intervalos.push(Intervalo::vacio());
        self.alturas.push(0);
        self.cubrientes.push(Vec::new());
        self.agregar_arbol(nuevo, sp)?;
        for m in mergeset {
            self.insertar_cubriente(*m, nuevo)?;
        }
        Ok(())
    }

    /// Avanza el punto de reindexado hacia `pista` (el `sp` virtual o el bloque recién insertado).
    /// No cambia ningún resultado; solo mantiene el índice dentro de su cota amortizada.
    pub(crate) fn intentar_avanzar_raiz(&mut self, pista: Idx) -> Result<(), ErrorDag> {
        let actual = self.raiz_reindex;
        let (mut ancestro, siguiente) = self.siguiente_raiz(actual, pista)?;
        if actual == siguiente {
            return Ok(());
        }
        while ancestro != siguiente {
            // Kaspa usa la variante *sin comprobar*: durante el propio reindexado los intervalos
            // pueden estar modificados y no propagados todavía.
            let hijo = self.siguiente_ancestro_cadena_sin_comprobar(siguiente, ancestro)?;
            let mut ctx = ContextoReindex::nuevo();
            ctx.concentrar_intervalo(self, ancestro, hijo, hijo == siguiente)?;
            #[cfg(test)]
            {
                self.reindex_avance += 1;
            }
            ancestro = hijo;
        }
        self.raiz_reindex = siguiente;
        Ok(())
    }

    // ── Consultas ────────────────────────────────────────────────────────────

    /// ¿`a` es ancestro de cadena de `b`? (incluye `a == b`).
    pub(crate) fn es_ancestro_cadena(&self, a: Idx, b: Idx) -> bool {
        self.intervalos[a as usize].contiene(self.intervalos[b as usize])
    }

    /// ¿`a` es ancestro DAG de `b`? (incluye `a == b`).
    pub(crate) fn es_ancestro(&self, a: Idx, b: Idx) -> bool {
        if self.es_ancestro_cadena(a, b) {
            return true;
        }
        matches!(
            self.buscar_descendiente(&self.cubrientes[a as usize], b),
            Busqueda::Encontrado
        )
    }

    // ── Árbol ────────────────────────────────────────────────────────────────

    /// Longitud máxima de un conjunto de cobertura del futuro (diagnóstico de rendimiento).
    pub(crate) fn max_cubrientes(&self) -> usize {
        self.cubrientes.iter().map(Vec::len).max().unwrap_or(0)
    }

    /// Suma de las longitudes de todos los conjuntos de cobertura del futuro (diagnóstico).
    pub(crate) fn total_cubrientes(&self) -> usize {
        self.cubrientes.iter().map(Vec::len).sum()
    }

    fn capacidad_hijos(&self, b: Idx) -> Intervalo {
        self.intervalos[b as usize].disminuir_fin(1)
    }

    fn restante_antes(&self, b: Idx) -> Intervalo {
        let cap = self.capacidad_hijos(b);
        match self.hijos[b as usize].first() {
            Some(prim) => Intervalo::nuevo(cap.inicio, self.intervalos[*prim as usize].inicio - 1),
            None => cap,
        }
    }

    fn restante_despues(&self, b: Idx) -> Intervalo {
        let cap = self.capacidad_hijos(b);
        match self.hijos[b as usize].last() {
            Some(ult) => Intervalo::nuevo(self.intervalos[*ult as usize].fin + 1, cap.fin),
            None => cap,
        }
    }

    fn agregar_arbol(&mut self, nuevo: Idx, padre: Idx) -> Result<(), ErrorDag> {
        let restante = self.restante_despues(padre);
        self.hijos[padre as usize].push(nuevo);
        let altura_padre = self.alturas[padre as usize];
        if restante.es_vacio() {
            // Sin capacidad: se inicializa con el intervalo vacío exacto al final de la capacidad
            // y se lanza el reindexado.
            self.intervalos[nuevo as usize] = restante;
            self.alturas[nuevo as usize] = altura_padre + 1;
            let raiz = self.raiz_reindex;
            let mut ctx = ContextoReindex::nuevo();
            ctx.reindex_intervals(self, nuevo, raiz)?;
            #[cfg(test)]
            {
                self.reindex_capacidad += 1;
            }
        } else {
            let asignado = restante.dividir_mitad().0;
            self.intervalos[nuevo as usize] = asignado;
            self.alturas[nuevo as usize] = altura_padre + 1;
        }
        Ok(())
    }

    fn insertar_cubriente(&mut self, fusionado: Idx, nuevo: Idx) -> Result<(), ErrorDag> {
        match self.buscar_descendiente(&self.cubrientes[fusionado as usize], nuevo) {
            Busqueda::Encontrado => Err(incoherente(
                "un cobertor del futuro contradice que el bloque esté en el mergeset",
            )),
            Busqueda::NoEncontrado(i) => {
                self.cubrientes[fusionado as usize].insert(i, nuevo);
                Ok(())
            }
        }
    }

    fn buscar_descendiente(&self, lista: &[Idx], descendiente: Idx) -> Busqueda {
        // El `fin` del intervalo identifica de forma única al bloque.
        let punto = self.intervalos[descendiente as usize].fin;
        match lista.binary_search_by_key(&punto, |c| self.intervalos[*c as usize].inicio) {
            Ok(_) => Busqueda::Encontrado,
            Err(i) => {
                if i > 0 && self.es_ancestro_cadena(lista[i - 1], descendiente) {
                    Busqueda::Encontrado
                } else {
                    Busqueda::NoEncontrado(i)
                }
            }
        }
    }

    fn siguiente_ancestro_cadena_sin_comprobar(
        &self,
        descendiente: Idx,
        ancestro: Idx,
    ) -> Result<Idx, ErrorDag> {
        let punto = self.intervalos[descendiente as usize].fin;
        let hijos = &self.hijos[ancestro as usize];
        match hijos.binary_search_by_key(&punto, |c| self.intervalos[*c as usize].inicio) {
            Ok(i) => Ok(hijos[i]),
            Err(i) => {
                if i > 0 && self.es_ancestro_cadena(hijos[i - 1], descendiente) {
                    Ok(hijos[i - 1])
                } else {
                    Err(incoherente(
                        "no se encontró el hijo de cadena del descendiente",
                    ))
                }
            }
        }
    }

    fn ancestro_comun_mas_reciente(&self, bloque: Idx, raiz: Idx) -> Result<Idx, ErrorDag> {
        let mut actual = bloque;
        loop {
            if self.es_ancestro_cadena(actual, raiz) {
                return Ok(actual);
            }
            actual = self.padre[actual as usize]
                .ok_or_else(|| incoherente("se alcanzó la raíz del árbol sin ancestro común"))?;
        }
    }

    fn siguiente_raiz(&self, actual: Idx, pista: Idx) -> Result<(Idx, Idx), ErrorDag> {
        let mut ancestro = actual;
        let mut siguiente = actual;
        if actual == pista {
            return Ok((actual, actual));
        }
        let altura_pista = self.alturas[pista as usize];
        if !self.es_ancestro_cadena(actual, pista) {
            let altura_actual = self.alturas[actual as usize];
            if altura_pista < altura_actual || altura_pista - altura_actual < self.holgura {
                return Ok((actual, actual));
            }
            let comun = self.ancestro_comun_mas_reciente(pista, actual)?;
            ancestro = comun;
            siguiente = comun;
        }
        loop {
            let hijo = self.siguiente_ancestro_cadena_sin_comprobar(pista, siguiente)?;
            let altura_hijo = self.alturas[hijo as usize];
            if altura_pista < altura_hijo {
                return Err(incoherente(
                    "altura inconsistente al buscar la raíz de reindexado",
                ));
            }
            if altura_pista - altura_hijo < PROFUNDIDAD_REINDEX {
                break;
            }
            siguiente = hijo;
        }
        Ok((ancestro, siguiente))
    }
}

/// Contexto temporal de una operación de reindexado (caché de tamaños de subárbol).
struct ContextoReindex {
    tamanos: HashMap<Idx, u64>,
}

impl ContextoReindex {
    fn nuevo() -> Self {
        Self {
            tamanos: HashMap::new(),
        }
    }

    /// Reasigna intervalos desde `nuevo_hijo` buscando el primer ancestro con capacidad suficiente.
    fn reindex_intervals(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        nuevo_hijo: Idx,
        raiz_reindex: Idx,
    ) -> Result<(), ErrorDag> {
        let mut actual = nuevo_hijo;
        loop {
            let intervalo = store.intervalos[actual as usize];
            self.contar_subarboles(store, actual)?;
            if intervalo.tamano() >= self.tamanos[&actual] {
                break;
            }
            let padre = store.padre[actual as usize]
                .ok_or_else(|| incoherente("falta el padre del árbol durante el reindexado"))?;
            if actual == raiz_reindex {
                return Err(incoherente(
                    "la raíz de reindexado se quedó sin capacidad (más de ~2^52 bloques)",
                ));
            }
            if store.intervalos[padre as usize]
                .contiene_estricto(store.intervalos[raiz_reindex as usize])
            {
                let requerido = self.tamanos[&actual];
                return self.reindex_intervals_antes_de_raiz(
                    store,
                    actual,
                    raiz_reindex,
                    padre,
                    requerido,
                );
            }
            actual = padre;
        }
        self.propagar_intervalo(store, actual)
    }

    /// Cuenta el tamaño de cada subárbol de `bloque` con un BFS sin recursión.
    fn contar_subarboles(
        &mut self,
        store: &IndiceAlcanzabilidad,
        bloque: Idx,
    ) -> Result<(), ErrorDag> {
        if self.tamanos.contains_key(&bloque) {
            return Ok(());
        }
        let mut cola = VecDeque::from([bloque]);
        let mut cuentas: HashMap<Idx, u64> = HashMap::new();
        while let Some(mut actual) = cola.pop_front() {
            let hijos = store.hijos[actual as usize].clone();
            if hijos.is_empty() {
                self.tamanos.insert(actual, 1);
            } else if !self.tamanos.contains_key(&actual) {
                cola.extend(hijos.iter().copied());
                continue;
            }
            while actual != bloque {
                actual = store.padre[actual as usize]
                    .ok_or_else(|| incoherente("falta el padre al contar subárboles"))?;
                let hijos = store.hijos[actual as usize].clone();
                let cuenta = cuentas.entry(actual).or_insert(0);
                *cuenta += 1;
                if *cuenta < hijos.len() as u64 {
                    break;
                }
                let suma: u64 = hijos
                    .iter()
                    .map(|c| self.tamanos.get(c).copied().unwrap_or(0))
                    .sum();
                self.tamanos.insert(actual, suma + 1);
            }
        }
        Ok(())
    }

    /// Reparte los intervalos por el subárbol de `bloque` según los tamaños contados.
    fn propagar_intervalo(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        bloque: Idx,
    ) -> Result<(), ErrorDag> {
        self.contar_subarboles(store, bloque)?;
        let mut cola = VecDeque::from([bloque]);
        while let Some(actual) = cola.pop_front() {
            let hijos = store.hijos[actual as usize].clone();
            if hijos.is_empty() {
                continue;
            }
            let tamanos: Vec<u64> = hijos
                .iter()
                .map(|c| self.tamanos.get(c).copied().unwrap_or(0))
                .collect();
            let intervalo = store.capacidad_hijos(actual);
            let intervalos = intervalo.dividir_exponencial(&tamanos);
            for (c, ci) in hijos.iter().copied().zip(intervalos) {
                store.intervalos[c as usize] = ci;
            }
            cola.extend(hijos.iter().copied());
        }
        Ok(())
    }

    fn reindex_intervals_antes_de_raiz(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        bloque_asignado: Idx,
        raiz_reindex: Idx,
        ancestro_comun: Idx,
        requerido: u64,
    ) -> Result<(), ErrorDag> {
        let elegido =
            store.siguiente_ancestro_cadena_sin_comprobar(raiz_reindex, ancestro_comun)?;
        let intervalo_asignado = store.intervalos[bloque_asignado as usize];
        let intervalo_elegido = store.intervalos[elegido as usize];
        if intervalo_asignado.inicio < intervalo_elegido.inicio {
            self.reclamar_antes(
                store,
                bloque_asignado,
                ancestro_comun,
                elegido,
                raiz_reindex,
                requerido,
            )
        } else {
            self.reclamar_despues(
                store,
                bloque_asignado,
                ancestro_comun,
                elegido,
                raiz_reindex,
                requerido,
            )
        }
    }

    fn reclamar_antes(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        bloque_asignado: Idx,
        ancestro_comun: Idx,
        elegido: Idx,
        raiz_reindex: Idx,
        requerido: u64,
    ) -> Result<(), ErrorDag> {
        let mut holgura_suma = 0u64;
        let mut camino_len = 0u64;
        let mut holgura_camino = 0u64;
        let mut actual = elegido;
        loop {
            if actual == raiz_reindex {
                let offset = requerido + store.holgura * camino_len - holgura_suma;
                self.aplicar_y_propagar(store, actual, offset, Intervalo::aumentar_inicio)?;
                self.desplazar_hermanos_antes(store, bloque_asignado, actual, offset)?;
                holgura_camino = store.holgura;
                break;
            }
            let holgura_actual = store.restante_antes(actual).tamano();
            holgura_suma += holgura_actual;
            if holgura_suma >= requerido {
                let offset = holgura_actual - (holgura_suma - requerido);
                self.aplicar(store, actual, offset, Intervalo::aumentar_inicio)?;
                self.desplazar_hermanos_antes(store, bloque_asignado, actual, offset)?;
                break;
            }
            actual = store.siguiente_ancestro_cadena_sin_comprobar(raiz_reindex, actual)?;
            camino_len += 1;
        }
        loop {
            actual = store.padre[actual as usize]
                .ok_or_else(|| incoherente("falta el padre al reclamar holgura"))?;
            if actual == ancestro_comun {
                break;
            }
            let holgura_actual = store.restante_antes(actual).tamano();
            let offset = holgura_actual - holgura_camino;
            self.aplicar_y_propagar(store, actual, offset, Intervalo::aumentar_inicio)?;
            self.desplazar_hermanos_antes(store, bloque_asignado, actual, offset)?;
        }
        Ok(())
    }

    fn reclamar_despues(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        bloque_asignado: Idx,
        ancestro_comun: Idx,
        elegido: Idx,
        raiz_reindex: Idx,
        requerido: u64,
    ) -> Result<(), ErrorDag> {
        let mut holgura_suma = 0u64;
        let mut camino_len = 0u64;
        let mut holgura_camino = 0u64;
        let mut actual = elegido;
        loop {
            if actual == raiz_reindex {
                let offset = requerido + store.holgura * camino_len - holgura_suma;
                self.aplicar_y_propagar(store, actual, offset, Intervalo::disminuir_fin)?;
                self.desplazar_hermanos_despues(store, bloque_asignado, actual, offset)?;
                holgura_camino = store.holgura;
                break;
            }
            let holgura_actual = store.restante_despues(actual).tamano();
            holgura_suma += holgura_actual;
            if holgura_suma >= requerido {
                let offset = holgura_actual - (holgura_suma - requerido);
                self.aplicar(store, actual, offset, Intervalo::disminuir_fin)?;
                self.desplazar_hermanos_despues(store, bloque_asignado, actual, offset)?;
                break;
            }
            actual = store.siguiente_ancestro_cadena_sin_comprobar(raiz_reindex, actual)?;
            camino_len += 1;
        }
        loop {
            actual = store.padre[actual as usize]
                .ok_or_else(|| incoherente("falta el padre al reclamar holgura"))?;
            if actual == ancestro_comun {
                break;
            }
            let holgura_actual = store.restante_despues(actual).tamano();
            let offset = holgura_actual - holgura_camino;
            self.aplicar_y_propagar(store, actual, offset, Intervalo::disminuir_fin)?;
            self.desplazar_hermanos_despues(store, bloque_asignado, actual, offset)?;
        }
        Ok(())
    }

    fn desplazar_hermanos_antes(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        bloque_asignado: Idx,
        actual: Idx,
        offset: u64,
    ) -> Result<(), ErrorDag> {
        let padre = store.padre[actual as usize]
            .ok_or_else(|| incoherente("falta el padre al desplazar hermanos"))?;
        let (antes, _) = dividir_hijos(&store.hijos[padre as usize], actual)?;
        let antes: Vec<Idx> = antes.to_vec();
        for hermano in antes.into_iter().rev() {
            if hermano == bloque_asignado {
                self.aplicar_y_propagar(store, bloque_asignado, offset, Intervalo::aumentar_fin)?;
                break;
            }
            self.aplicar_y_propagar(store, hermano, offset, Intervalo::aumentar)?;
        }
        Ok(())
    }

    fn desplazar_hermanos_despues(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        bloque_asignado: Idx,
        actual: Idx,
        offset: u64,
    ) -> Result<(), ErrorDag> {
        let padre = store.padre[actual as usize]
            .ok_or_else(|| incoherente("falta el padre al desplazar hermanos"))?;
        let (_, despues) = dividir_hijos(&store.hijos[padre as usize], actual)?;
        let despues: Vec<Idx> = despues.to_vec();
        for hermano in despues {
            if hermano == bloque_asignado {
                self.aplicar_y_propagar(
                    store,
                    bloque_asignado,
                    offset,
                    Intervalo::disminuir_inicio,
                )?;
                break;
            }
            self.aplicar_y_propagar(store, hermano, offset, Intervalo::disminuir)?;
        }
        Ok(())
    }

    fn aplicar(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        bloque: Idx,
        offset: u64,
        op: fn(&Intervalo, u64) -> Intervalo,
    ) -> Result<(), ErrorDag> {
        store.intervalos[bloque as usize] = op(&store.intervalos[bloque as usize], offset);
        Ok(())
    }

    fn aplicar_y_propagar(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        bloque: Idx,
        offset: u64,
        op: fn(&Intervalo, u64) -> Intervalo,
    ) -> Result<(), ErrorDag> {
        self.aplicar(store, bloque, offset, op)?;
        self.propagar_intervalo(store, bloque)
    }

    /// Mueve la raíz de reindexado: aprieta los hermanos y expande el hijo elegido.
    fn concentrar_intervalo(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        padre: Idx,
        hijo: Idx,
        es_raiz_final: bool,
    ) -> Result<(), ErrorDag> {
        let hijos = store.hijos[padre as usize].clone();
        let (antes, despues) = dividir_hijos(&hijos, hijo)?;
        let antes: Vec<Idx> = antes.to_vec();
        let despues: Vec<Idx> = despues.to_vec();
        let suma_antes = self.apretar_antes(store, padre, &antes)?;
        let suma_despues = self.apretar_despues(store, padre, &despues)?;
        self.expandir_hacia_elegido(store, padre, hijo, suma_antes, suma_despues, es_raiz_final)
    }

    fn apretar_antes(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        padre: Idx,
        hijos_antes: &[Idx],
    ) -> Result<u64, ErrorDag> {
        let mut tamanos = Vec::with_capacity(hijos_antes.len());
        for b in hijos_antes {
            self.contar_subarboles(store, *b)?;
            tamanos.push(self.tamanos[b]);
        }
        let suma: u64 = tamanos.iter().sum();
        let intervalo = store.intervalos[padre as usize];
        let intervalo_antes = Intervalo::nuevo(
            intervalo.inicio + store.holgura,
            intervalo.inicio + store.holgura + suma - 1,
        );
        for (c, ci) in hijos_antes
            .iter()
            .copied()
            .zip(intervalo_antes.dividir_exacto(&tamanos))
        {
            store.intervalos[c as usize] = ci;
            self.propagar_intervalo(store, c)?;
        }
        Ok(suma)
    }

    fn apretar_despues(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        padre: Idx,
        hijos_despues: &[Idx],
    ) -> Result<u64, ErrorDag> {
        let mut tamanos = Vec::with_capacity(hijos_despues.len());
        for b in hijos_despues {
            self.contar_subarboles(store, *b)?;
            tamanos.push(self.tamanos[b]);
        }
        let suma: u64 = tamanos.iter().sum();
        let intervalo = store.intervalos[padre as usize];
        let intervalo_despues = Intervalo::nuevo(
            intervalo.fin - store.holgura - suma,
            intervalo.fin - store.holgura - 1,
        );
        for (c, ci) in hijos_despues
            .iter()
            .copied()
            .zip(intervalo_despues.dividir_exacto(&tamanos))
        {
            store.intervalos[c as usize] = ci;
            self.propagar_intervalo(store, c)?;
        }
        Ok(suma)
    }

    fn expandir_hacia_elegido(
        &mut self,
        store: &mut IndiceAlcanzabilidad,
        padre: Idx,
        hijo: Idx,
        suma_antes: u64,
        suma_despues: u64,
        es_raiz_final: bool,
    ) -> Result<(), ErrorDag> {
        let intervalo = store.intervalos[padre as usize];
        let asignacion = Intervalo::nuevo(
            intervalo.inicio + suma_antes + store.holgura,
            intervalo.fin - suma_despues - store.holgura - 1,
        );
        let actual = store.intervalos[hijo as usize];
        if es_raiz_final && !asignacion.contiene(actual) {
            let estrechado = Intervalo::nuevo(
                asignacion.inicio + store.holgura,
                asignacion.fin - store.holgura,
            );
            store.intervalos[hijo as usize] = estrechado;
            self.propagar_intervalo(store, hijo)?;
        }
        store.intervalos[hijo as usize] = asignacion;
        Ok(())
    }
}

/// Divide `hijos` en (antes de `pivote`, después de `pivote`).
fn dividir_hijos(hijos: &[Idx], pivote: Idx) -> Result<(&[Idx], &[Idx]), ErrorDag> {
    match hijos.iter().position(|c| *c == pivote) {
        Some(i) => Ok((&hijos[..i], &hijos[i + 1..])),
        None => Err(incoherente(
            "el pivote no es hijo del padre en el reindexado",
        )),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::*;

    /// Construye un árbol en anchura con `n` bloques (hijo `i` de `i/2`) y comprueba que la
    /// ancestría de cadena es exacta contra el cálculo por padres.
    #[test]
    fn ancestria_de_cadena_exacta_en_arbol_lleno() {
        let mut idx = IndiceAlcanzabilidad::nuevo();
        for i in 1u32..200 {
            idx.agregar_bloque(i, i >> 1, &[]).unwrap();
        }
        for a in 0u32..200 {
            for b in 0u32..200 {
                let mut esperado = a == b;
                let mut cur = b;
                while let Some(p) = idx.padre[cur as usize] {
                    if p == a {
                        esperado = true;
                        break;
                    }
                    cur = p;
                }
                assert_eq!(idx.es_ancestro_cadena(a, b), esperado, "a={a} b={b}");
            }
        }
    }

    /// La ancestría DAG incluye los bloques del mergeset (cobertura del futuro).
    #[test]
    fn ancestria_dag_incluye_mergeset() {
        // 1 <- 0; 2 <- 0; 3 <- {1, 2}; 4 <- 3
        let mut idx = IndiceAlcanzabilidad::nuevo();
        idx.agregar_bloque(1, 0, &[]).unwrap();
        idx.agregar_bloque(2, 0, &[]).unwrap();
        // mergeset de 3 = {2}
        idx.agregar_bloque(3, 1, &[2]).unwrap();
        idx.agregar_bloque(4, 3, &[]).unwrap();
        assert!(idx.es_ancestro(2, 3));
        assert!(idx.es_ancestro(2, 4));
        assert!(idx.es_ancestro(1, 4));
        assert!(!idx.es_ancestro(2, 1));
        assert!(!idx.es_ancestro(1, 2));
    }

    /// Muchos hijos del mismo padre fuerzan reindexados y la ancestría sigue siendo exacta.
    #[test]
    fn reindexado_mantiene_ancestria_exacta() {
        let mut idx = IndiceAlcanzabilidad::nuevo();
        let mut siguiente: Idx = 1;
        // 400 hermanos de la raíz, cada uno con una cadena de 5.
        for _ in 0..400 {
            let mut padre = 0;
            for _ in 0..5 {
                idx.agregar_bloque(siguiente, padre, &[]).unwrap();
                padre = siguiente;
                siguiente += 1;
            }
        }
        for b in 0..siguiente {
            let mut cur = b;
            let mut esperados = vec![b];
            while let Some(p) = idx.padre[cur as usize] {
                esperados.push(p);
                cur = p;
            }
            for a in 0..siguiente {
                assert_eq!(
                    idx.es_ancestro_cadena(a, b),
                    esperados.contains(&a),
                    "a={a} b={b}"
                );
            }
        }
    }
}

/// Tests del reindexado del índice con **capacidad de intervalos reducida** (constructor solo de
/// test). El oráculo es una búsqueda en anchura real sobre la relación de padres declarada; la
/// clausura transitiva se calcula por unión de padres (el mismo resultado que un BFS por consulta)
/// y se contrasta con un BFS explícito en una muestra. Cubre cadena lineal, anchura 3 y 10, y una
/// reorganización profunda, con ≥ 10⁶ pares muestreados y los pares justo antes y justo después de
/// cada reindexado.
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#[expect(
    clippy::integer_division,
    reason = "conjuntos de bits: la palabra y el bit son aritmética entera deliberada"
)]
#[allow(
    clippy::needless_range_loop,
    reason = "los índices densos son el sujeto del test"
)]
mod tests_reindexado {
    use super::*;

    /// xorshift64* con semilla fija: sin dependencias y reproducible.
    struct Azar(u64);

    impl Azar {
        const fn nuevo(semilla: u64) -> Self {
            Self(semilla)
        }

        fn siguiente(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn rango(&mut self, lo: usize, hi: usize) -> usize {
            if hi <= lo {
                return lo;
            }
            lo + (self.siguiente() % (hi - lo + 1) as u64) as usize
        }
    }

    /// Conjunto de bits denso sobre el universo de bloques del DAG.
    #[derive(Clone)]
    struct Bits(Vec<u64>);

    impl Bits {
        fn nuevos(n: usize) -> Self {
            Self(vec![0u64; n.div_ceil(64)])
        }

        fn fijar(&mut self, i: usize) {
            self.0[i / 64] |= 1u64 << (i % 64);
        }

        fn contiene(&self, i: usize) -> bool {
            self.0[i / 64] & (1u64 << (i % 64)) != 0
        }

        fn unir(&mut self, otro: &Self) {
            for (a, b) in self.0.iter_mut().zip(&otro.0) {
                *a |= *b;
            }
        }

        fn quitar(&mut self, otro: &Self) {
            for (a, b) in self.0.iter_mut().zip(&otro.0) {
                *a &= !*b;
            }
        }
    }

    /// DAG con los padres declarados, el `sp` y el `mergeset` que la admisión pasaría al índice,
    /// más la clausura transitiva del pasado estricto.
    struct Dag {
        universo: usize,
        padres: Vec<Vec<Idx>>,
        sp: Vec<Option<Idx>>,
        ms: Vec<Vec<Idx>>,
        pasado: Vec<Bits>,
    }

    impl Dag {
        fn nuevo(universo: usize) -> Self {
            Self {
                universo,
                padres: vec![Vec::new()],
                sp: vec![None],
                ms: vec![Vec::new()],
                pasado: vec![Bits::nuevos(universo)],
            }
        }

        /// Añade el bloque `i = len()` con padres declarados y `sp` (que debe estar en `padres`).
        /// El `mergeset` es `pasado(padres) \\ (pasado(sp) ∪ {sp})`, igual que la admisión.
        fn agregar(&mut self, padres: Vec<Idx>, sp: Idx) {
            assert!(self.padres.len() < self.universo);
            let mut pasado_i = Bits::nuevos(self.universo);
            for p in &padres {
                pasado_i.fijar(*p as usize);
                pasado_i.unir(&self.pasado[*p as usize]);
            }
            let mut sin_sp = self.pasado[sp as usize].clone();
            sin_sp.fijar(sp as usize);
            let mut ms = pasado_i.clone();
            ms.quitar(&sin_sp);
            let ms: Vec<Idx> = (0..self.universo)
                .filter(|i| ms.contiene(*i))
                .map(|i| i as Idx)
                .collect();
            self.padres.push(padres);
            self.sp.push(Some(sp));
            self.ms.push(ms);
            self.pasado.push(pasado_i);
        }

        fn n(&self) -> usize {
            self.padres.len()
        }
    }

    fn ancestro_dag(dag: &Dag, a: Idx, b: Idx) -> bool {
        a == b || dag.pasado[b as usize].contiene(a as usize)
    }

    fn ancestro_cadena(dag: &Dag, a: Idx, b: Idx) -> bool {
        let mut actual = Some(b);
        while let Some(c) = actual {
            if c == a {
                return true;
            }
            actual = dag.sp[c as usize];
        }
        false
    }

    /// BFS real hacia atrás desde `b` por la relación de padres declarada.
    fn bfs_ancestro(dag: &Dag, a: Idx, b: Idx) -> bool {
        if a == b {
            return true;
        }
        let mut visto = vec![false; dag.n()];
        let mut pila = vec![b];
        visto[b as usize] = true;
        while let Some(c) = pila.pop() {
            for p in &dag.padres[c as usize] {
                if *p == a {
                    return true;
                }
                if !visto[*p as usize] {
                    visto[*p as usize] = true;
                    pila.push(*p);
                }
            }
        }
        false
    }

    fn dag_lineal(n: usize) -> Dag {
        let mut dag = Dag::nuevo(n);
        for i in 1..n {
            let p = (i - 1) as Idx;
            dag.agregar(vec![p], p);
        }
        dag
    }

    fn dag_ancho(n: usize, anchura: usize, ventana: usize, semilla: u64) -> Dag {
        let mut rng = Azar::nuevo(semilla);
        let mut dag = Dag::nuevo(n);
        for i in 1..n {
            let lo = i.saturating_sub(ventana);
            let disponibles = i - lo;
            let max_padres = disponibles.min(anchura).max(1);
            let k = 1 + rng.rango(0, max_padres - 1);
            let mut padres: Vec<Idx> = Vec::new();
            while padres.len() < k {
                let p = (lo + rng.rango(0, disponibles - 1)) as Idx;
                if !padres.contains(&p) {
                    padres.push(p);
                }
            }
            let sp = *padres.iter().max().unwrap();
            dag.agregar(padres, sp);
        }
        dag
    }

    /// Construye el índice con capacidad reducida y devuelve `(índice, índices donde se agotó la
    /// capacidad)`. Si `avanzar`, mueve la raíz de reindexado hacia cada bloque recién insertado,
    /// como hace la admisión con `mejor_punta`.
    fn construir(
        dag: &Dag,
        capacidad: u64,
        holgura: u64,
        avanzar: bool,
    ) -> (IndiceAlcanzabilidad, Vec<Idx>) {
        let mut indice = IndiceAlcanzabilidad::nuevo_con_capacidad(capacidad, holgura);
        let mut eventos = Vec::new();
        let mut previa = 0u64;
        for i in 1..dag.n() {
            let sp = dag.sp[i].unwrap();
            indice.agregar_bloque(i as Idx, sp, &dag.ms[i]).unwrap();
            let (capacidad_actual, _) = indice.reindexados();
            if capacidad_actual > previa {
                eventos.push(i as Idx);
                previa = capacidad_actual;
            }
            if avanzar {
                indice.intentar_avanzar_raiz(i as Idx).unwrap();
            }
        }
        (indice, eventos)
    }

    /// Compara `es_ancestro` con el oráculo. Devuelve el número de pares comprobados. Incluye una
    /// muestra con BFS explícito, `muestras` pares aleatorios (todos si `n` es pequeño) y los pares
    /// con `b` justo antes y justo después de cada reindexado.
    fn comprobar(
        dag: &Dag,
        indice: &IndiceAlcanzabilidad,
        eventos: &[Idx],
        muestras: usize,
        semilla: u64,
    ) -> usize {
        let n = dag.n();
        let mut consultas = 0usize;
        let mut rng = Azar::nuevo(semilla);
        // Control del oráculo de clausura con BFS real.
        for _ in 0..2048 {
            let a = rng.rango(0, n - 1) as Idx;
            let b = rng.rango(0, n - 1) as Idx;
            assert_eq!(
                indice.es_ancestro(a, b),
                bfs_ancestro(dag, a, b),
                "BFS a={a} b={b}"
            );
        }
        if n <= 1000 {
            for a in 0..n as Idx {
                for b in 0..n as Idx {
                    assert_eq!(
                        indice.es_ancestro(a, b),
                        ancestro_dag(dag, a, b),
                        "a={a} b={b}"
                    );
                    consultas += 1;
                }
            }
        } else {
            for _ in 0..muestras {
                let a = rng.rango(0, n - 1) as Idx;
                let b = rng.rango(0, n - 1) as Idx;
                assert_eq!(
                    indice.es_ancestro(a, b),
                    ancestro_dag(dag, a, b),
                    "a={a} b={b}"
                );
                consultas += 1;
            }
        }
        // Pares justo antes y justo después de cada reindexado (todos los eventos, `a` con paso).
        let paso = (n / 256).max(1);
        for ev in eventos {
            for delta in [-1i64, 0, 1] {
                let b = *ev as i64 + delta;
                if b < 0 || b >= n as i64 {
                    continue;
                }
                let b = b as Idx;
                for a in (0..n as Idx).step_by(paso) {
                    assert_eq!(
                        indice.es_ancestro(a, b),
                        ancestro_dag(dag, a, b),
                        "reindexado ev={ev} a={a} b={b}"
                    );
                    consultas += 1;
                }
            }
        }
        // Ancestría de cadena, muestra.
        for _ in 0..2048 {
            let a = rng.rango(0, n - 1) as Idx;
            let b = rng.rango(0, n - 1) as Idx;
            assert_eq!(
                indice.es_ancestro_cadena(a, b),
                ancestro_cadena(dag, a, b),
                "cadena a={a} b={b}"
            );
        }
        consultas
    }

    const CAP: u64 = 1 << 19;
    const HOLG: u64 = 1;

    /// Cadena lineal, anchura 3 y anchura 10 con reindexado forzado: la ancestría coincide con el
    /// oráculo y el contador supera 1 000.
    #[test]
    fn reindexado_forzado_coincide_con_bfs() {
        let mut total = 0usize;

        let lineal = dag_lineal(20_000);
        // Sin mover la raíz de reindexado: la capacidad se agota cada ~16 niveles y se fuerzan
        // más de 1 000 reindexados por capacidad.
        let (indice, eventos) = construir(&lineal, CAP, HOLG, false);
        let (cap, avance) = indice.reindexados();
        assert!(cap >= 1_000, "reindexados por capacidad = {cap}");
        total += comprobar(&lineal, &indice, &eventos, 1_000_000, 0x11);
        println!("lineal n=20000 reindex_cap={cap} reindex_avance={avance}");

        for (etiqueta, n, anchura, ventana, semilla) in [
            ("ancho3", 4_000usize, 3usize, 12usize, 0xA3u64),
            ("ancho10", 4_000, 10, 40, 0xA10),
        ] {
            let dag = dag_ancho(n, anchura, ventana, semilla);
            let (indice, eventos) = construir(&dag, CAP, HOLG, true);
            let (cap, avance) = indice.reindexados();
            total += comprobar(&dag, &indice, &eventos, 1_000_000, semilla);
            println!("{etiqueta} n={n} reindex_cap={cap} reindex_avance={avance}");
        }

        // Caso pequeño exhaustivo (todos los pares).
        let pequeno = dag_ancho(700, 3, 12, 0x5E);
        let (indice, eventos) = construir(&pequeno, CAP, HOLG, true);
        total += comprobar(&pequeno, &indice, &eventos, 1_000_000, 0x5E);

        assert!(total >= 1_000_000, "pares comprobados = {total}");
        println!("pares comprobados totales = {total}");
    }

    /// Reorganización profunda: una rama rival más profunda que la raíz de reindexado hace que
    /// `intentar_avanzar_raiz` cruce al ancestro común. La ancestría sigue coincidiendo.
    #[test]
    fn reindexado_reorganizacion_profunda_coincide_con_bfs() {
        let rama = 2_000usize;
        let universo = 1 + 2 * rama;
        let mut dag = Dag::nuevo(universo);
        // Rama A: bloques 1..=rama.
        for j in 0..rama {
            let p = if j == 0 { 0 } else { j as Idx };
            dag.agregar(vec![p], p);
        }
        let mut indice = IndiceAlcanzabilidad::nuevo_con_capacidad(CAP, HOLG);
        let mut eventos = Vec::new();
        let mut previa = 0u64;
        for i in 1..=rama {
            let sp = dag.sp[i].unwrap();
            indice.agregar_bloque(i as Idx, sp, &dag.ms[i]).unwrap();
            if indice.reindexados().0 > previa {
                eventos.push(i as Idx);
                previa = indice.reindexados().0;
            }
            indice.intentar_avanzar_raiz(i as Idx).unwrap();
        }
        // Rama B: bloques (rama+1)..=2*rama, desde la raíz, más profunda que la raíz de reindexado.
        for j in 0..rama {
            let i = 1 + rama + j;
            let p = if j == 0 { 0 } else { (i - 1) as Idx };
            dag.agregar(vec![p], p);
        }
        for i in (1 + rama)..=2 * rama {
            let sp = dag.sp[i].unwrap();
            indice.agregar_bloque(i as Idx, sp, &dag.ms[i]).unwrap();
            if indice.reindexados().0 > previa {
                eventos.push(i as Idx);
                previa = indice.reindexados().0;
            }
            indice.intentar_avanzar_raiz(i as Idx).unwrap();
        }
        let (cap, avance) = indice.reindexados();
        let total = comprobar(&dag, &indice, &eventos, 1_000_000, 0xBEEF);
        assert!(total >= 1_000_000, "pares comprobados = {total}");
        println!(
            "reorg n={} reindex_cap={cap} reindex_avance={avance} pares={total}",
            dag.n()
        );
    }

    /// Cadena lineal de 10⁵ bloques: el oráculo BFS sobre los padres es exactamente `a <= b` (cada
    /// bloque tiene un solo padre `i − 1`). Se comprueban 10⁶ pares y los pares alrededor de cada
    /// reindexado.
    #[test]
    fn reindexado_cadena_100k_coincide_con_oraculo() {
        let n = 100_000u32;
        let mut indice = IndiceAlcanzabilidad::nuevo_con_capacidad(CAP, HOLG);
        let mut eventos = Vec::new();
        let mut previa = 0u64;
        for i in 1..n {
            indice.agregar_bloque(i, i - 1, &[]).unwrap();
            let (cap, _) = indice.reindexados();
            if cap > previa {
                eventos.push(i);
                previa = cap;
            }
        }
        let (cap, _) = indice.reindexados();
        assert!(cap >= 1_000, "reindexados por capacidad = {cap}");

        let mut rng = Azar::nuevo(0xC4D3);
        let mut consultas = 0usize;
        for _ in 0..1_000_000 {
            let a = rng.rango(0, n as usize - 1) as Idx;
            let b = rng.rango(0, n as usize - 1) as Idx;
            let esperado = a <= b;
            assert_eq!(indice.es_ancestro(a, b), esperado, "a={a} b={b}");
            assert_eq!(
                indice.es_ancestro_cadena(a, b),
                esperado,
                "cadena a={a} b={b}"
            );
            consultas += 1;
        }
        let paso = (n as usize / 256).max(1);
        for ev in &eventos {
            for delta in [-1i64, 0, 1] {
                let b = *ev as i64 + delta;
                if b < 0 || b >= i64::from(n) {
                    continue;
                }
                let b = b as Idx;
                for a in (0..n).step_by(paso) {
                    assert_eq!(indice.es_ancestro(a, b), a <= b, "reindexado a={a} b={b}");
                    consultas += 1;
                }
            }
        }
        println!(
            "cadena n={n} reindex_cap={cap} eventos={} consultas={consultas}",
            eventos.len()
        );
    }
}
