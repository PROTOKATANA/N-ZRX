//! GHOSTDAG y `rank` (SPEC §11 `C-GD-01`…`C-GD-09` y §7.2 `C-ORD-01`…`C-ORD-03`).
//!
//! # Qué implementa
//!
//! Dado un DAG de bloques `(id, padres, slot, solution_distance, rango de espacio SR,
//! identidad de billete)`, este módulo calcula, como **función exclusiva de `past(B)`**
//! (`C-GD-09`): el padre seleccionado `sp(B)` (`C-GD-03`), el mergeset (`C-GD-04`), su orden
//! (`C-GD-05`), el coloreo azul/`rojo_k`/`rojo_U3` (`C-GD-06`, `C-GD-07`), `blue_score` y
//! `blue_work` (`C-GD-08`), y `rank` con el orden de aplicación de `C-ORD-03`.
//!
//! # Raíz (D-P07)
//!
//! La raíz del almacén es el **terminal** PoW `T`, no un génesis DAG: [`AlmacenGhostdag::nuevo`]
//! acepta cualquier raíz y [`AlmacenGhostdag::con_raiz_terminal`] la fija como `T` con `slot = 0`,
//! `blue_work = 0` e identidad ausente. El primer bloque PoST hijo de `T` hereda `w(T)` como azul
//! de la raíz.
//!
//! # Aritmética (LINEO §9)
//!
//! **Ni un solo flotante.** `w(B) = ⌊2^128/(SR+1)⌋` (`C-GD-01`) es división entera exacta en
//! `U256`; todo `blue_work` va en `u256` (`C-GD-02`) con suma **comprobada**: un desbordamiento
//! devuelve [`ErrorDag::BlueWorkDesbordado`], nunca envuelve. No se hereda `Uint192`.
//!
//! # Representación elegida (LINEO §8.2) y su coste
//!
//! - **IDs densos.** Los `BlockHash` de 32 B viven una sola vez en `ids` + un `HashMap` de
//!   índice; todo el camino caliente compara `u32` densos (LINEO §4: «IDs densos `Int32/Int64`»)
//!   en vez de arrays de 32 B en mapas.
//! - **Adyacencia contigua.** `padres: Vec<Vec<u32>>` por bloque. El universo de un mergeset son
//!   los padres de `B` y sus ancestros dentro del anticono, ≤ 15 padres y mergeset ≤ 180
//!   (R-FIN-12), así que el coste por bloque está acotado por esos topes, no por `n`.
//! - **Conjuntos de bits densos.** El pasado estricto (`anc`) y el blue set de la referencia se
//!   guardan en `ConjuntoBits` (`Vec<u64>`), no en `HashSet` (LINEO §4).
//! - **Referencia + kernel.** Hay dos implementaciones: [`Algoritmo::Referencia`] recalcula la
//!   definición directa del k-cluster sobre el blue set completo, y [`Algoritmo::Kernel`]
//!   implementa el algoritmo incremental. El test diferencial los compara.
//!
//! El almacén es **en memoria** y de estudio. Su persistencia, su admisión PoST y su cableado a
//! `zx-node`/`zx-storage` quedan fuera de este crate.
//!
//! # Límites pendientes (no cerrar con esta orden)
//!
//! - **Coste (W08b).** La admisión ya no crece con `N`: el pasado estricto se resuelve con un
//!   índice de alcanzabilidad por intervalos (`alcanzabilidad`), U2 con un índice `identidad →
//!   bloques`, las identidades azules con un conjunto persistente (`conjunto_azul`) y los tamaños
//!   de anticono con un mapa disperso (`bas`). El bitset denso `anc` desaparece de la ruta de
//!   admisión; la definición directa sigue disponible como [`Algoritmo::Referencia`].
//! - **Fuente causal.** `admitir` deriva la identidad de la misma cabecera que aporta hash, slot y
//!   `SR`, pero **no** acredita la procedencia causal del `SR`, de la prueba PoT, de la PoAS, del
//!   cuerpo ni la profundidad de fusión con kosherización (regla aún sin código).

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};

use primitive_types::U256;
use zx_core::DagBlockHeader;
use zx_core::digest::{BlockHash, Digest};
use zx_core::preimage::dag::{MAX_PADRES, PadresDag};

use crate::alcanzabilidad::IndiceAlcanzabilidad;
use crate::bloque_dag::{ContextoDag, ContextoRangoDag, RangoSolucionValidado};
use crate::conjunto_azul::{self, NULO};
use crate::error::ErrorDag;
use crate::identidad::{IdentidadTicket, identidad_de_cabecera};

/// `k` por defecto de R-FIN-12 (elegido, `SPEC.md:1609`). Valor del consenso antiguo, condicional.
pub const K_POR_DEFECTO: u32 = 30;
/// Máximo de padres por bloque (R-FIN-12, `C-GD-04`). Valor del consenso antiguo, condicional.
pub const MAX_PADRES_POR_DEFECTO: u8 = 15;
/// Tope de mergeset: `|mergeset(B)| + 1 ≤ 180` (R-FIN-12, `C-GD-04`). Valor del consenso antiguo.
pub const MERGESET_LIMITE_POR_DEFECTO: u32 = 180;
/// `S_max = 150` slots (C-GD-04). Valor del consenso antiguo, condicional.
pub const S_MAX_POR_DEFECTO: u64 = 150;

/// Índice denso de un bloque dentro del [`AlmacenGhostdag`].
pub type Idx = u32;

/// Modo de selección del padre `sp(B)` (`C-GD-03`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModoSp {
    /// Regla C: mayor `blue_work`; empate → **menor** `sd`; empate → **menor** id. Dirección
    /// **mixta** decidida por Katana (opción C), deliberadamente distinta de Kaspa.
    Zerox,
    /// Modo histórico `:kaspa` (mayor `(bw, id)`); se conserva para los vectores oficiales.
    Kaspa,
}

/// Modo de orden del mergeset (colorear y aplicar, `C-GD-05`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModoMerge {
    /// Regla C: `(blue_work, solution_distance, id)` ascendente.
    Terna,
    /// Modo histórico `:kaspa`: `(blue_work, id)` ascendente, sin `sd`.
    Kaspa,
}

/// Qué implementación del coloreo ejecuta el almacén.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algoritmo {
    /// Definición directa del k-cluster sobre el blue set completo (clara, cuadrática).
    Referencia,
    /// Algoritmo incremental con el walk por la cadena del `sp` (el del nodo).
    Kernel,
}

/// Parámetros de GHOSTDAG (`C-GD-04`, R-FIN-12).
///
/// # Valores por defecto
///
/// `k = 30`, 15 padres, mergeset 180 y `S_max = 150` son **valores del consenso antiguo,
/// condicionales; la red dev fijará los suyos** (D-P10…D-P13 y `ParametrosPow` de W04). Se
/// conservan como valores por defecto para reproducir los oráculos y los tests antiguos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parametros {
    /// k del k-cluster.
    pub k: u32,
    /// Máximo de padres.
    pub max_padres: u8,
    /// Tope de `|mergeset| + 1`.
    pub mergeset_limite: u32,
    /// `S_max` en slots.
    pub s_max: u64,
    /// U2 activa (invalidez por billete repetido).
    pub u2: bool,
    /// U3″ dinámica activa.
    pub u3_dinamica: bool,
    /// Modo de `sp(B)`.
    pub sp: ModoSp,
    /// Modo de orden del mergeset.
    pub merge: ModoMerge,
}

impl Default for Parametros {
    fn default() -> Self {
        Self {
            k: K_POR_DEFECTO,
            max_padres: MAX_PADRES_POR_DEFECTO,
            mergeset_limite: MERGESET_LIMITE_POR_DEFECTO,
            s_max: S_MAX_POR_DEFECTO,
            u2: true,
            u3_dinamica: true,
            sp: ModoSp::Zerox,
            merge: ModoMerge::Terna,
        }
    }
}

/// Color de un candidato del mergeset en el bloque de cadena que lo fusiona (`C-GD-09`:
/// contextual).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    /// Azul: pasa las dos condiciones del k-cluster.
    Azul,
    /// Excluido por el tope de anticono azul del k-cluster (`C-GD-06`).
    RojoK,
    /// Excluido por unicidad de billete, sin evaluar el k-cluster (`C-GD-07`, U3″).
    RojoU3,
}

/// Identidad de billete de GHOSTDAG (`C-GD-07`/R-FIN-11).
///
/// # Por qué un enum y no un `u64`
///
/// `C-GD-07` define la identidad como la tupla literal
/// `(public_key, sector_index, history_size, chunk, slot)`, que [`IdentidadTicket`] representa.
/// Comprimirla a un `u64` **no es inyectivo**: dos billetes distintos podían pasar por iguales y
/// un billete real con bytes a cero podía pasar por ausencia. Este enum mantiene **separados** el
/// dominio real y el de fixture:
///
/// - [`IdentidadGhostdag::Billete`] compara la tupla literal mediante el `Eq` de
///   [`IdentidadTicket`]. **Nunca** `huella()[..8]`, un `u64`, un hash corto, la clave pública
///   sola ni el sello.
/// - [`IdentidadGhostdag::Sintetica`] es el `u64` de los vectores/oráculos históricos. Existe
///   **solo** para la vía sintética y **no** es una entrada de producción.
/// - [`IdentidadGhostdag::SinBillete`] es la ausencia; sustituye al antiguo centinela de fixture
///   `0`. Un `Billete` real con todos sus bytes a cero **no** es ausencia.
///
/// La vía de producción ([`AlmacenGhostdag::admitir`]) no acepta identidad del llamante: la deriva
/// de la cabecera con [`identidad_de_cabecera`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentidadGhostdag {
    /// Sin billete: el bloque no reclama una oportunidad.
    SinBillete,
    /// Identidad real de `C-GD-07`; la igualdad es la de [`IdentidadTicket`].
    Billete(IdentidadTicket),
    /// Identidad de fixture de los vectores históricos (`u64`). Nunca producción.
    Sintetica(u64),
}

impl IdentidadGhostdag {
    /// Convierte el `u64` de fixture de los vectores/oráculos al dominio sintético.
    ///
    /// El centinela `0` se traduce a [`IdentidadGhostdag::SinBillete`]: en los vectores históricos
    /// cero significaba «sin billete», no un billete. Es la única conversión admitida del `u64`
    /// de fixture y **no** es una identidad de producción.
    #[must_use]
    pub const fn de_fixture(valor: u64) -> Self {
        if valor == 0 {
            Self::SinBillete
        } else {
            Self::Sintetica(valor)
        }
    }
}

impl Hash for IdentidadGhostdag {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // El hash solo elige cubeta; la igualdad la decide `Eq` (tupla literal en `Billete`). Se
        // separan los dominios con un discriminante para que `Sintetica` y `Billete` nunca se
        // mezclen.
        match self {
            Self::SinBillete => state.write_u8(0),
            Self::Sintetica(n) => {
                state.write_u8(1);
                n.hash(state);
            }
            Self::Billete(t) => {
                state.write_u8(2);
                // Hash campo a campo en `identidad.rs`: **sin** `bytes_canonicos()` ni `Vec` por
                // consulta de `HashSet`.
                t.hash(state);
            }
        }
    }
}

impl Ord for IdentidadGhostdag {
    fn cmp(&self, other: &Self) -> Ordering {
        // Orden total determinista para el conjunto persistente de identidades. Es un detalle de
        // forma del acumulador, no una igualdad: la de `Billete` sigue siendo la tupla literal.
        match (self, other) {
            (Self::SinBillete, Self::SinBillete) => Ordering::Equal,
            (Self::Sintetica(a), Self::Sintetica(b)) => a.cmp(b),
            (Self::Billete(a), Self::Billete(b)) => a.cmp(b),
            (Self::SinBillete, _) => Ordering::Less,
            (_, Self::SinBillete) => Ordering::Greater,
            (Self::Sintetica(_), Self::Billete(_)) => Ordering::Less,
            (Self::Billete(_), Self::Sintetica(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for IdentidadGhostdag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for IdentidadGhostdag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SinBillete => f.write_str("sin billete"),
            Self::Sintetica(n) => write!(f, "sintetica({n})"),
            Self::Billete(t) => {
                // La huella es **solo** para diagnóstico; jamás decide igualdad.
                f.write_str("billete(")?;
                for b in t.huella() {
                    write!(f, "{b:02x}")?;
                }
                f.write_str(")")
            }
        }
    }
}

/// Bloque de entrada al almacén GHOSTDAG.
#[derive(Clone, Debug)]
pub struct BloqueGhostdag {
    /// Id de 32 bytes.
    pub id: BlockHash,
    /// Padres declarados (el orden es irrelevante: el `sp` se recalcula).
    pub padres: Vec<BlockHash>,
    /// Índice PoT declarado.
    pub slot: u64,
    /// `solution_distance` de la prueba PoAS/PoT.
    pub solution_distance: u64,
    /// `rango_solucion` que **superó C-HDR-06** si la inserción es de producción.
    ///
    /// La entrada de producción es [`AlmacenGhostdag::admitir`], que la construye con
    /// [`RangoSolucionValidado::validar`] y deriva el id de la misma cabecera. La entrada sintética
    /// de oráculos ([`AlmacenGhostdag::anadir_sintetico`]) acepta un rango sin validar; esa parte
    /// **no** es una frontera de seguridad (ver [`RangoSolucionValidado`]).
    pub rango_espacio: RangoSolucionValidado,
    /// Identidad de billete exacta ([`IdentidadGhostdag`]). La ausencia es
    /// [`IdentidadGhostdag::SinBillete`], **no** un cero: un billete real con bytes a cero sigue
    /// siendo un billete.
    pub identidad: IdentidadGhostdag,
}

/// `rank(B) = (blue_work, solution_distance, id)` (`C-ORD-01`), ascendente.
///
/// El orden derivado de los campos, en este orden, ES el de `C-ORD-01`: `U256` y `u64` son
/// órdenes totales y `BlockHash` compara 32 bytes lexicográficamente. Termina en el id, así que
/// bajo el supuesto de no colisión es **total**: `C-ORD-02` no necesita tercer desempate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rank {
    /// `blue_work` acumulado.
    pub blue_work: U256,
    /// `solution_distance`.
    pub solution_distance: u64,
    /// Id de 32 bytes.
    pub id: BlockHash,
}

/// Conjunto de bits sobre índices densos (`LINEO §4`).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
struct ConjuntoBits {
    palabras: Vec<u64>,
}

impl ConjuntoBits {
    fn nuevos() -> Self {
        Self {
            palabras: Vec::new(),
        }
    }

    fn contiene(&self, i: Idx) -> bool {
        let pos = i as usize;
        let (w, b) = (pos >> 6, pos & 63);
        self.palabras.get(w).is_some_and(|p| p & (1u64 << b) != 0)
    }

    fn insertar(&mut self, i: Idx) {
        let pos = i as usize;
        let (w, b) = (pos >> 6, pos & 63);
        if self.palabras.len() <= w {
            self.palabras.resize(w + 1, 0);
        }
        if let Some(p) = self.palabras.get_mut(w) {
            *p |= 1u64 << b;
        }
    }

    fn iter(&self) -> impl Iterator<Item = Idx> + '_ {
        self.palabras.iter().enumerate().flat_map(|(w, p)| {
            let p = *p;
            (0..64u32).filter_map(move |b| (p & (1u64 << b) != 0).then_some((w as u32) * 64 + b))
        })
    }
}

/// Estado interno específico del algoritmo, necesario para el bloque siguiente.
///
/// `tam` y `bas` se indexan por **índice denso de bloque**. Los índices son densos, así que la
/// consulta es un acceso a vector `O(1)` sin hashing (LINEO §4: universo denso ⇒ `Vector`, no
/// `HashMap`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum EstadoInterno {
    /// Blue set completo de `past(B) ∪ {B}` y `tam[b] = |anticone(b) ∩ blue set|`.
    Referencia {
        blueset: ConjuntoBits,
        tam: Vec<u32>,
    },
    /// `blues_anticone_sizes` del algoritmo incremental, por índice de bloque.
    ///
    /// Es un mapa **disperso** (no un `Vec` de tamaño `N`): solo guarda las entradas calculadas por
    /// este bloque y se heredan por el paseo de la cadena del `sp`, igual que en Kaspa. Así el coste
    /// y la memoria por bloque dependen del mergeset, no de `N`.
    Kernel { bas: HashMap<Idx, u32> },
}

/// Resultado de revisar un candidato contra un tramo de la cadena del `sp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Revision {
    /// Azul en este tramo (no hay que seguir subiendo).
    Azul,
    /// Rojo: el k-cluster se rompe.
    Rojo,
    /// Aún no decide; hay que seguir por la cadena del `sp`.
    Pendiente,
}

/// Dato GHOSTDAG almacenado de un bloque (`C-GD-09`: invariante frente al orden de llegada).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatosGhostdag {
    /// Padre seleccionado; `None` solo para la raíz (el terminal, D-P07).
    pub sp: Option<Idx>,
    /// Mergeset completo en el orden de coloreado (sin `sp`), `C-GD-05`.
    pub orden_mergeset: Vec<Idx>,
    /// `blues(B) = [sp] ++ azules del mergeset`, en orden de coloreado.
    pub blues: Vec<Idx>,
    /// `rojo_k` y `rojo_U3` en orden de coloreado.
    pub rojos: Vec<Idx>,
    /// Color de cada bloque rojo del mergeset (los azules están en `blues`).
    pub colores: Vec<(Idx, Color)>,
    /// Raíz del **conjunto persistente** de identidades azules acumuladas (`NULO` si no hay).
    ///
    /// Vive en `AlmacenGhostdag::arena_azul`; aquí solo se guarda la raíz. Sustituye a
    /// `blue_idents: Vec<IdentidadGhostdag>` (que se copiaba entero por bloque, `O(N²)`) y es la
    /// fuente de U3″ (`sp_bi`): `conjunto_azul::contiene(arena, raiz_azules, cid)`.
    raiz_azules: u32,
    /// `blue_score(B)` (conteo, `C-GD-08`).
    pub blue_score: u64,
    /// `blue_work(B)` (peso acumulado en `u256`, `C-GD-02`).
    pub blue_work: U256,
    estado: EstadoInterno,
}

/// `w(B) = ⌊2^128/(SR+1)⌋` (`C-GD-01`), división entera exacta.
///
/// `SR` es `u64`, así que el divisor es `≥ 1`. `SR = 0` da `2^128`; `SR = 2^64−1` da el mínimo
/// `2^64 > 0`.
///
/// Es la fórmula pura. La ruta de consenso **no** la llama con un `u64` suelto: `acumular` la
/// aplica al `SR` almacenado como [`RangoSolucionValidado`], que solo se construye validando
/// C-HDR-06 (o con el constructor sintético de oráculos).
#[must_use]
pub fn peso(rango_espacio: u64) -> U256 {
    (U256::one() << 128usize) / (U256::from(rango_espacio) + U256::one())
}

impl RangoSolucionValidado {
    /// `w(B)` de C-GD-01 sobre el `SR` **validado**.
    ///
    /// Es la vía de `acumular` (C-GD-08): el valor viene del tipo, no de un `u64` libre.
    #[must_use]
    pub fn peso(self) -> U256 {
        peso(self.valor())
    }
}

/// Suma comprobada de `blue_work` (`C-GD-02`, C-ENC-03).
///
/// # Errores
/// [`ErrorDag::BlueWorkDesbordado`] si el resultado no cabe en `u256`.
pub fn sumar_blue_work(a: U256, b: U256) -> Result<U256, ErrorDag> {
    a.checked_add(b).ok_or(ErrorDag::BlueWorkDesbordado)
}

fn hash_desde_id(id: &[u8; 32]) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes(*id))
}

/// Convierte un id textual ASCII en un `BlockHash` rellenando con ceros a la derecha, igual que
/// `hash_de_id` de GDR-v0.2. Es lo que usa el test del oráculo para casar ids.
#[must_use]
pub fn hash_de_id_textual(s: &str) -> BlockHash {
    let b = s.as_bytes();
    let mut id = [0u8; 32];
    let n = b.len().min(32);
    if let (Some(dst), Some(src)) = (id.get_mut(..n), b.get(..n)) {
        dst.copy_from_slice(src);
    }
    hash_desde_id(&id)
}

/// Almacén GHOSTDAG en memoria.
///
/// Construido con [`AlmacenGhostdag::nuevo`] —o, en la red dev, con
/// [`AlmacenGhostdag::con_raiz_terminal`]—. [`AlmacenGhostdag::admitir`] es la puerta que valida
/// el `SR` contra el contexto y deriva el id de la cabecera (validación **parcial**: no es una
/// admisión PoST de producción); [`AlmacenGhostdag::anadir_sintetico`] es la entrada de
/// oráculos/tests y **no** valida el rango.
#[derive(Clone)]
pub struct AlmacenGhostdag {
    params: Parametros,
    algoritmo: Algoritmo,
    /// Raíz del orden: en la red dev es el terminal `T` (D-P07).
    terminal: BlockHash,
    indice: HashMap<BlockHash, Idx>,
    ids: Vec<BlockHash>,
    padres: Vec<Vec<Idx>>,
    slots: Vec<u64>,
    sds: Vec<u64>,
    /// `SR` **validado** por bloque, en paralelo a `ids` (C-HDR-06 → C-GD-01/C-GD-08).
    srs: Vec<RangoSolucionValidado>,
    /// Identidad exacta de billete por bloque, en paralelo a `ids` (C-GD-07).
    idents: Vec<IdentidadGhostdag>,
    /// Índice `identidad → bloques que la llevan`, en orden de inserción (C-GD-07/U2). Permite
    /// resolver U2 con `es_ancestro` sobre los pocos bloques con esa identidad en lugar de recorrer
    /// el pasado entero del padre.
    indice_ident: HashMap<IdentidadGhostdag, Vec<Idx>>,
    /// Arena del **conjunto persistente** de identidades azules (U3″). Compartida por todos los
    /// bloques; cada `DatosGhostdag` guarda solo su raíz.
    arena_azul: Vec<conjunto_azul::Nodo>,
    /// Índice de alcanzabilidad por intervalos (sustituye al bitset denso `anc`).
    alcanzabilidad: IndiceAlcanzabilidad,
    /// Mejor punta conocida (mayor `rank`, `C-GD-03`): es el `sp` del virtual y la pista que mueve
    /// el punto de reindexado. Mantenerla explícita evita recorrer todas las puntas en cada bloque.
    mejor_punta: Option<Idx>,
    gd: Vec<DatosGhostdag>,
}

impl AlmacenGhostdag {
    /// Crea el almacén con una raíz arbitraria.
    ///
    /// El `SR` de la raíz entra ya como [`RangoSolucionValidado`]. Sembrarlo es un camino
    /// **sintético** —el *bootstrap* del controlador de C-HDR-06 sigue sin definir— y no forma
    /// parte de la admisión de bloques: los oráculos y los tests pasan
    /// [`RangoSolucionValidado::para_oraculos`].
    ///
    /// `ident_raiz` es el `u64` de fixture: se traduce con [`IdentidadGhostdag::de_fixture`],
    /// así que el centinela `0` queda como [`IdentidadGhostdag::SinBillete`]. Esta vía **no**
    /// acredita PoST ni procedencia de la identidad.
    ///
    /// En la red dev la raíz es el terminal PoW `T` (D-P07); para fijarlo sin riesgo de confundir
    /// los argumentos, usar [`Self::con_raiz_terminal`].
    #[must_use]
    pub fn nuevo(
        params: Parametros,
        algoritmo: Algoritmo,
        hash_raiz: BlockHash,
        slot_raiz: u64,
        sr_raiz: RangoSolucionValidado,
        ident_raiz: u64,
    ) -> Self {
        let ident_raiz = IdentidadGhostdag::de_fixture(ident_raiz);
        let raiz_idx: Idx = 0;
        let mut blueset = ConjuntoBits::nuevos();
        blueset.insertar(raiz_idx);
        let estado = match algoritmo {
            Algoritmo::Referencia => {
                let tam = vec![0u32; raiz_idx as usize + 1];
                EstadoInterno::Referencia { blueset, tam }
            }
            Algoritmo::Kernel => {
                let mut bas = HashMap::new();
                bas.insert(raiz_idx, 0);
                EstadoInterno::Kernel { bas }
            }
        };
        let mut arena_azul = Vec::new();
        let raiz_azules = if ident_raiz == IdentidadGhostdag::SinBillete {
            NULO
        } else {
            conjunto_azul::insertar(&mut arena_azul, NULO, ident_raiz)
        };
        let mut indice_ident = HashMap::new();
        if ident_raiz != IdentidadGhostdag::SinBillete {
            indice_ident.insert(ident_raiz, vec![raiz_idx]);
        }
        let gd = DatosGhostdag {
            sp: None,
            orden_mergeset: Vec::new(),
            blues: vec![raiz_idx],
            rojos: Vec::new(),
            colores: Vec::new(),
            raiz_azules,
            blue_score: 0,
            blue_work: U256::zero(),
            estado,
        };
        let mut indice = HashMap::new();
        indice.insert(hash_raiz, raiz_idx);
        Self {
            params,
            algoritmo,
            terminal: hash_raiz,
            indice,
            ids: vec![hash_raiz],
            padres: vec![Vec::new()],
            slots: vec![slot_raiz],
            sds: vec![0],
            srs: vec![sr_raiz],
            idents: vec![ident_raiz],
            indice_ident,
            arena_azul,
            alcanzabilidad: IndiceAlcanzabilidad::nuevo(),
            mejor_punta: Some(raiz_idx),
            gd: vec![gd],
        }
    }

    /// **D-P07 · constructor de conveniencia.** Crea el almacén con el **terminal** como raíz.
    ///
    /// Equivale a `nuevo(params, algoritmo, hash_terminal, 0, sr_raiz, 0)`: `slot = s_0 = 0`,
    /// identidad ausente y `blue_work` de la raíz 0. El primer bloque PoST hijo de `T` hereda
    /// `w(T)` como azul de la raíz.
    #[must_use]
    pub fn con_raiz_terminal(
        params: Parametros,
        algoritmo: Algoritmo,
        hash_terminal: BlockHash,
        sr_raiz: RangoSolucionValidado,
    ) -> Self {
        Self::nuevo(params, algoritmo, hash_terminal, 0, sr_raiz, 0)
    }

    /// Parámetros activos.
    #[must_use]
    pub const fn parametros(&self) -> &Parametros {
        &self.params
    }

    /// Algoritmo activo.
    #[must_use]
    pub const fn algoritmo(&self) -> Algoritmo {
        self.algoritmo
    }

    /// Número de bloques (incluida la raíz).
    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// ¿Está vacío? Nunca: siempre hay raíz.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Diagnóstico del índice de alcanzabilidad: `(longitud máxima de un conjunto de cobertura del
    /// futuro, suma total)`. Solo para los bancos: si `total` crece con `N`, la inserción en esos
    /// conjuntos deja de ser acotada.
    #[must_use]
    pub fn diagnostico_cubrientes(&self) -> (usize, usize) {
        (
            self.alcanzabilidad.max_cubrientes(),
            self.alcanzabilidad.total_cubrientes(),
        )
    }

    /// Hash de la raíz (el terminal en la red dev, D-P07).
    #[must_use]
    pub const fn terminal(&self) -> BlockHash {
        self.terminal
    }

    /// Datos GHOSTDAG del bloque `i`, si existe.
    #[must_use]
    pub fn datos(&self, i: Idx) -> Option<&DatosGhostdag> {
        self.gd.get(i as usize)
    }

    /// Datos GHOSTDAG que tendría un bloque **virtual** cuyos padres fueran los índices `padres`,
    /// **sin insertarlo** en el almacén.
    ///
    /// Lo usa `zx-cadena` para calcular la punta virtual sobre el almacén ya existente, en lugar de
    /// reconstruirlo entero: el índice de alcanzabilidad y el coloreo ya son incrementales. No
    /// comprueba cotas de admisión (slot, `S_max`, tope de mergeset): solo colorea.
    ///
    /// # Errores
    /// [`ErrorDag::GhostdagIncoherente`] si `padres` está vacío o algún índice no existe en el
    /// almacén; los del coloreo si el almacén está corrupto.
    pub fn datos_de_virtual(&self, padres: &[Idx], _slot: u64) -> Result<DatosGhostdag, ErrorDag> {
        if padres.is_empty() || padres.iter().any(|p| (*p as usize) >= self.ids.len()) {
            return Err(ErrorDag::GhostdagIncoherente {
                motivo: "el bloque virtual tiene un padre fuera del almacén",
            });
        }
        let sp = seleccionar_sp_generico(padres, |a, b| self.comparar_sp(a, b)).ok_or(
            ErrorDag::GhostdagIncoherente {
                motivo: "el bloque virtual no tiene padres",
            },
        )?;
        let ms = self.mergeset(sp, padres);
        let nuevo = self.ids.len() as Idx;
        let (dato, _nuevas) = match self.algoritmo {
            Algoritmo::Referencia => {
                self.colorear_referencia(sp, &ms, IdentidadGhostdag::SinBillete, nuevo)?
            }
            Algoritmo::Kernel => {
                self.colorear_kernel(sp, &ms, IdentidadGhostdag::SinBillete, nuevo)?
            }
        };
        Ok(dato)
    }

    /// Id externo del bloque `i`.
    #[must_use]
    pub fn id(&self, i: Idx) -> Option<BlockHash> {
        self.ids.get(i as usize).copied()
    }

    /// Padres del bloque `i`.
    #[must_use]
    pub fn padres_de(&self, i: Idx) -> Option<&[Idx]> {
        self.padres.get(i as usize).map(Vec::as_slice)
    }

    /// `rank(B)` (`C-ORD-01`).
    #[must_use]
    pub fn rank(&self, i: Idx) -> Option<Rank> {
        let pos = i as usize;
        Some(Rank {
            blue_work: self.gd.get(pos)?.blue_work,
            solution_distance: *self.sds.get(pos)?,
            id: *self.ids.get(pos)?,
        })
    }

    /// Color contextual de `cand` visto desde el bloque que lo fusiona `bloque`
    /// (`C-GD-09`). Devuelve `None` si `cand` no es del mergeset de `bloque`.
    #[must_use]
    pub fn color_en(&self, bloque: Idx, cand: Idx) -> Option<Color> {
        let gd = self.gd.get(bloque as usize)?;
        if gd.blues.contains(&cand) {
            return Some(Color::Azul);
        }
        gd.colores
            .iter()
            .find_map(|(c, color)| (*c == cand).then_some(*color))
    }

    /// `C-ORD-02` · ganadora entre copias del mismo billete.
    ///
    /// Entre las candidatas —azules y `rojo_k`; las `rojo_U3` quedan excluidas— gana la **azul**;
    /// en igualdad de color, la de **menor `rank`**. Sin tercer desempate: `rank` ya termina en el
    /// id (`C-ORD-01`).
    #[must_use]
    pub fn seleccionar_copia(&self, candidatas: &[(Idx, Color)]) -> Option<Idx> {
        candidatas
            .iter()
            .filter(|(_, c)| *c != Color::RojoU3)
            .min_by(|(ia, ca), (ib, cb)| {
                let color_a = u8::from(*ca == Color::RojoK);
                let color_b = u8::from(*cb == Color::RojoK);
                color_a
                    .cmp(&color_b)
                    .then_with(|| self.rank(*ia).cmp(&self.rank(*ib)))
            })
            .map(|(i, _)| *i)
    }

    /// Cadena seleccionada desde `tip` hasta la raíz (`C-ORD-03`).
    #[must_use]
    pub fn cadena_seleccionada(&self, tip: Idx) -> Vec<Idx> {
        let mut cadena = Vec::new();
        let mut cur = Some(tip);
        while let Some(c) = cur {
            cadena.push(c);
            cur = self.gd.get(c as usize).and_then(|g| g.sp);
        }
        cadena.reverse();
        cadena
    }

    /// Puntas del DAG visible (bloques sin hijos), ordenadas.
    #[must_use]
    pub fn puntas(&self) -> Vec<Idx> {
        let mut con_hijo = ConjuntoBits::nuevos();
        for ps in &self.padres {
            for p in ps {
                con_hijo.insertar(*p);
            }
        }
        (0..self.ids.len() as Idx)
            .filter(|i| !con_hijo.contiene(*i))
            .collect()
    }

    /// Punta virtual: el `sp` de C-GD-03 sobre las puntas (`C-GD-03`).
    #[must_use]
    pub fn punta_virtual(&self) -> Option<Idx> {
        let puntas = self.puntas();
        seleccionar_sp_generico(&puntas, |a, b| self.comparar_sp(a, b))
    }

    /// Orden de aplicación de `C-ORD-03` (R-FIN-8′(4)): por cada bloque `C` de la cadena
    /// seleccionada, `[sp(C)] ++ mergeset(C)` reordenado por `C-GD-05`, azules y `rojo_k`
    /// entrelazados, **saltando los `rojo_U3`**. La selección de `C-ORD-02` no altera este orden.
    #[must_use]
    pub fn orden_aplicacion(&self, tip: Idx) -> Vec<Idx> {
        let cadena = self.cadena_seleccionada(tip);
        let mut orden = Vec::new();
        if let Some(primero) = cadena.first() {
            orden.push(*primero);
        }
        for c in cadena.iter().skip(1) {
            let Some(gd) = self.gd.get(*c as usize) else {
                continue;
            };
            let mut ms: Vec<Idx> = gd
                .blues
                .iter()
                .copied()
                .filter(|x| Some(*x) != gd.sp)
                .collect();
            ms.extend(gd.rojos.iter().copied());
            ms.retain(|x| self.color_en(*c, *x) != Some(Color::RojoU3));
            ms.sort_by(|a, b| self.comparar_merge(*a, *b));
            orden.extend(ms);
            orden.push(*c);
        }
        orden
    }

    /// Puerta **parcial** de validación del `SR` (C-HDR-06 → C-GD-01/C-GD-08).
    ///
    /// **No** es una admisión PoST de producción: no verifica la prueba de espacio/tiempo, la
    /// firma, el cuerpo ni el resto de reglas de bloque, y ninguna ruta de `zx-node` la llama. Lo
    /// que sí cierra es la vía por la que un llamante podía elegir el `SR`, el id **o la
    /// identidad**: recibe la **misma cabecera cuyo `block_hash` se insertará**, obtiene el rango
    /// esperado del contexto, valida, deriva la identidad de esa cabecera con
    /// [`identidad_de_cabecera`] y solo entonces inserta. No acepta ni el `SR`, ni el id, ni la
    /// identidad.
    ///
    /// # Alcance exacto
    /// Lo que cierra es **solo la igualdad de `C-GD-07`**: la identidad que se almacena y con la
    /// que se comparan U2/U3 es la tupla literal derivada de la cabecera, no una proyección ni un
    /// valor del llamante. **No** cierra la procedencia causal del `SR`, de la prueba PoT, de la
    /// PoAS, del cuerpo ni la profundidad de fusión con kosherización que el SPEC deja pendiente:
    /// aquí no se comprueba ninguna de esas cosas.
    ///
    /// # Precondición pendiente
    /// La garantía vale lo que valga `ctx`: **debe** derivar `rango_esperado` del pasado validado y
    /// del flujo.
    ///
    /// # Errores
    /// [`ErrorDag::BloqueDuplicado`], [`ErrorDag::RangoIncorrecto`] y los de
    /// [`Self::anadir_sintetico`].
    pub fn admitir<C: ContextoRangoDag>(
        &mut self,
        cabecera: &DagBlockHeader,
        solution_distance: u64,
        ctx: &C,
    ) -> Result<Idx, ErrorDag> {
        // Duplicado de almacenamiento antes de consultar el contexto: no se revalida un bloque que
        // ya está, y no se depende de que el contexto responda para rechazarlo.
        let id = cabecera.block_hash();
        if self.indice.contains_key(&id) {
            return Err(ErrorDag::BloqueDuplicado { hash: id });
        }
        let rango_espacio = RangoSolucionValidado::validar(cabecera, ctx)?;
        // C-GD-07: la identidad sale de la MISMA cabecera que aporta hash, slot y SR. No hay
        // parámetro libre; `Billete` no admite proyección.
        let identidad = IdentidadGhostdag::Billete(identidad_de_cabecera(cabecera));
        let mut padres = Vec::with_capacity(usize::from(cabecera.padres.count()));
        if !cabecera.padres.es_genesis() {
            padres.push(cabecera.padres.seleccionado());
        }
        padres.extend(cabecera.padres.extras().iter().copied());
        self.anadir_sintetico(BloqueGhostdag {
            id,
            padres,
            slot: cabecera.slot,
            solution_distance,
            rango_espacio,
            identidad,
        })
    }

    /// Entrada **sintética** para oráculos y tests: inserta un bloque ya construido, con el `SR`
    /// que traiga `bloque.rango_espacio`, **sin validar C-HDR-06**.
    ///
    /// No es la puerta de validación; para esa, [`Self::admitir`]. Sigue siendo **API pública sin
    /// validación**: un llamante puede saltarse C-HDR-06 con
    /// [`RangoSolucionValidado::para_oraculos`]. Si el rango trae cabecera asociada (salió de
    /// `validar`) y no es la de este bloque, se rechaza: un resultado validado no se puede
    /// intercambiar entre bloques.
    ///
    /// Por la misma razón, una identidad [`IdentidadGhostdag::Billete`] que llegue por aquí es una
    /// **afirmación del llamante**: esta vía **nunca** acredita PoST, PoAS ni procedencia, y no es
    /// la admisión de producción. U2/U3 sí usan la igualdad exacta de esa identidad.
    ///
    /// # Errores
    /// [`ErrorDag`] con el motivo (`C-GD-04`, `C-GD-07/U2`, `C-HDR-05`,
    /// [`ErrorDag::BloqueDuplicado`], [`ErrorDag::RangoDeOtroBloque`], desbordamiento).
    pub fn anadir_sintetico(&mut self, bloque: BloqueGhostdag) -> Result<Idx, ErrorDag> {
        // Duplicado de almacenamiento: se rechaza ANTES de tocar índices, padres, slots, colores o
        // acumuladores. No es un veredicto sobre la prueba PoST ni una razón para penalizar al par.
        if self.indice.contains_key(&bloque.id) {
            return Err(ErrorDag::BloqueDuplicado { hash: bloque.id });
        }
        if let Some(validado_para) = bloque.rango_espacio.bloque()
            && validado_para != bloque.id
        {
            return Err(ErrorDag::RangoDeOtroBloque {
                bloque: bloque.id,
                validado_para,
            });
        }

        let mut padres: Vec<Idx> = Vec::with_capacity(bloque.padres.len());
        for p in &bloque.padres {
            let idx = *self
                .indice
                .get(p)
                .ok_or(ErrorDag::BloqueDesconocido { hash: *p })?;
            padre_push_unico(&mut padres, idx);
        }
        // C-GD-04 / R-FIN-12: tope de padres.
        let tope_padres = usize::from(self.params.max_padres).min(MAX_PADRES);
        if padres.len() > tope_padres {
            return Err(ErrorDag::DemasiadosPadresDag {
                declarados: padres.len() as u64,
                maximo: tope_padres as u64,
            });
        }

        // C-GD-07 / U2: la identidad no puede estar en un padre ni en su pasado estricto.
        // `SinBillete` no es un billete; un `Billete` con bytes a cero sí lo es. Una incoherencia
        // interna (identidad o pasado ausente) es error explícito antes de mutar.
        if self.params.u2 && bloque.identidad != IdentidadGhostdag::SinBillete {
            for p in &padres {
                if self.pasado_contiene_ident(*p, bloque.identidad)? {
                    return Err(ErrorDag::BilleteDuplicadoU2 {
                        identidad: bloque.identidad,
                    });
                }
            }
        }

        // Pasado estricto: ya no se materializa como bitset denso; `es_ancestro` consulta el índice
        // de alcanzabilidad por intervalos (C-GD-04/06/07).
        let sp = seleccionar_sp_generico(&padres, |a, b| self.comparar_sp(a, b)).ok_or(
            ErrorDag::DemasiadosPadresDag {
                declarados: 0,
                maximo: MAX_PADRES as u64,
            },
        )?;

        // C-HDR-05 · C-FLU-02: **todo** padre cumple `slot(p) ≤ slot(B)`, cota no estricta. Se
        // comprueba aquí, con los índices ya resueltos y **antes** de tocar índices, padres,
        // slots, colores o acumuladores: un rechazo deja el almacén exactamente como estaba.
        for p in &padres {
            let (slot_p, id_p) = self.slot_e_id_de(*p)?;
            if slot_p > bloque.slot {
                return Err(ErrorDag::SlotDePadrePosterior {
                    padre: id_p,
                    slot_padre: slot_p,
                    slot_b: bloque.slot,
                });
            }
        }

        // C-GD-04: el salto respecto del padre SELECCIONADO sigue acotado por `S_max`. Es una
        // regla distinta de la cota anterior —el número de portadores PoT cuenta
        // `slot(B) − slot(sp(B))`, no la diferencia con otro padre—, y se conserva tal cual.
        let slot_sp = self.slot_de_indice(sp)?;
        if bloque.slot - slot_sp > self.params.s_max {
            return Err(ErrorDag::SaltoMayorSmax {
                salto: bloque.slot - slot_sp,
            });
        }

        let ms = self.mergeset(sp, &padres);
        if ms.len() as u64 + 1 > u64::from(self.params.mergeset_limite) {
            return Err(ErrorDag::MergesetExcedeLimite {
                tamano: ms.len() as u64 + 1,
                maximo: u64::from(self.params.mergeset_limite),
            });
        }

        let nuevo = self.ids.len() as Idx;
        let (mut dato, nuevas_azules) = match self.algoritmo {
            Algoritmo::Referencia => self.colorear_referencia(sp, &ms, bloque.identidad, nuevo)?,
            Algoritmo::Kernel => self.colorear_kernel(sp, &ms, bloque.identidad, nuevo)?,
        };
        // El bloque extiende el conjunto azul del `sp` con las identidades nuevas de este bloque.
        let mut raiz_azules = dato.raiz_azules;
        for cid in &nuevas_azules {
            raiz_azules = conjunto_azul::insertar(&mut self.arena_azul, raiz_azules, *cid);
        }
        dato.raiz_azules = raiz_azules;

        // El árbol de alcanzabilidad se actualiza antes que los vectores paralelos: si el
        // reindexado interno fallase (nunca en un almacén coherente), no quedaría un bloque a
        // medias entre el índice y los vectores.
        self.alcanzabilidad.agregar_bloque(nuevo, sp, &ms)?;

        self.indice.insert(bloque.id, nuevo);
        self.ids.push(bloque.id);
        self.padres.push(padres);
        self.slots.push(bloque.slot);
        self.sds.push(bloque.solution_distance);
        self.srs.push(bloque.rango_espacio);
        self.idents.push(bloque.identidad);
        if bloque.identidad != IdentidadGhostdag::SinBillete {
            self.indice_ident
                .entry(bloque.identidad)
                .or_default()
                .push(nuevo);
        }
        self.gd.push(dato);

        // Mejor punta (mayor `rank`, `C-GD-03`): todo hijo supera a su padre en `blue_work`, así que
        // el máximo global es siempre una punta. Se usa como pista del reindexado, igual que Kaspa
        // usa el `virtual selected parent`; sin esto, en un DAG ancho el punto de reindexado no
        // sigue la cadena y los intervalos se agotan, degradando a `O(N)` por bloque.
        if self
            .mejor_punta
            .is_none_or(|m| self.comparar_sp(nuevo, m) == Ordering::Less)
        {
            self.mejor_punta = Some(nuevo);
        }
        if let Some(m) = self.mejor_punta {
            self.alcanzabilidad.intentar_avanzar_raiz(m)?;
        }
        Ok(nuevo)
    }

    /// ¿La identidad aparece en `raiz` o en su pasado estricto? (`C-GD-07`/U2).
    ///
    /// La comparación es la del tipo: `Billete` usa la tupla literal de [`IdentidadTicket`] y
    /// `Sintetica(n)` solo casa con `Sintetica(n)`.
    ///
    /// Sustituye el recorrido del bitset de pasado entero por el índice `identidad → bloques`:
    /// por cada bloque con esa identidad se pregunta `es_ancestro`. En un DAG válido, U2 garantiza
    /// a lo sumo una coincidencia en el pasado de un mismo padre; el índice puede tener varias
    /// entradas de ramas incomparables (billetes repetidos en ramas hermanas), y el coste es
    /// proporcional a esas entradas.
    ///
    /// # Errores
    /// [`ErrorDag::GhostdagIncoherente`] si falta la identidad de `raiz`.
    fn pasado_contiene_ident(
        &self,
        raiz: Idx,
        identidad: IdentidadGhostdag,
    ) -> Result<bool, ErrorDag> {
        if self.identidad_de(raiz)? == identidad {
            return Ok(true);
        }
        if let Some(bloques) = self.indice_ident.get(&identidad) {
            for b in bloques {
                if self.es_ancestro(*b, raiz) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Identidad almacenada de un índice ya resuelto.
    ///
    /// Un índice sin identidad es una incoherencia interna: se falla explícitamente, nunca se
    /// sustituye por «sin billete».
    fn identidad_de(&self, i: Idx) -> Result<IdentidadGhostdag, ErrorDag> {
        self.idents
            .get(i as usize)
            .copied()
            .ok_or(ErrorDag::GhostdagIncoherente {
                motivo: "el índice de bloque no tiene identidad almacenada",
            })
    }

    /// `slot` almacenado de un índice ya resuelto (C-HDR-05 · C-FLU-02).
    ///
    /// Un índice sin slot es una incoherencia interna: se falla explícitamente, nunca se
    /// sustituye por cero.
    fn slot_de_indice(&self, i: Idx) -> Result<u64, ErrorDag> {
        self.slots
            .get(i as usize)
            .copied()
            .ok_or(ErrorDag::GhostdagIncoherente {
                motivo: "el índice de bloque no tiene slot almacenado",
            })
    }

    /// `(slot, id)` de un índice ya resuelto, para informar del padre infractor.
    fn slot_e_id_de(&self, i: Idx) -> Result<(u64, BlockHash), ErrorDag> {
        let slot = self.slot_de_indice(i)?;
        let id = self
            .ids
            .get(i as usize)
            .copied()
            .ok_or(ErrorDag::GhostdagIncoherente {
                motivo: "el índice de bloque no tiene id almacenado",
            })?;
        Ok((slot, id))
    }

    // ── Comparadores ────────────────────────────────────────────────────────

    /// Comparador del kernel para el orden del mergeset (`C-GD-05`).
    fn comparar_merge(&self, a: Idx, b: Idx) -> Ordering {
        match self.params.merge {
            ModoMerge::Terna => {
                let da = self.datos(a);
                let db = self.datos(b);
                let (wa, wb) = (da.map(|d| d.blue_work), db.map(|d| d.blue_work));
                match wa.cmp(&wb) {
                    Ordering::Equal => {}
                    no_igual => return no_igual,
                }
                match self.sds.get(a as usize).cmp(&self.sds.get(b as usize)) {
                    Ordering::Equal => {}
                    no_igual => return no_igual,
                }
                self.ids.get(a as usize).cmp(&self.ids.get(b as usize))
            }
            ModoMerge::Kaspa => {
                let wa = self.datos(a).map(|d| d.blue_work);
                let wb = self.datos(b).map(|d| d.blue_work);
                match wa.cmp(&wb) {
                    Ordering::Equal => {}
                    no_igual => return no_igual,
                }
                self.ids.get(a as usize).cmp(&self.ids.get(b as usize))
            }
        }
    }

    /// Comparador del kernel para la selección del `sp` (`C-GD-03`, regla C).
    fn comparar_sp(&self, a: Idx, b: Idx) -> Ordering {
        match self.params.sp {
            ModoSp::Zerox => {
                // Mayor blue_work; empate → menor sd; empate → menor id. Dirección MIXTA.
                let wa = self.datos(a).map(|d| d.blue_work);
                let wb = self.datos(b).map(|d| d.blue_work);
                match wb.cmp(&wa) {
                    Ordering::Equal => {}
                    no_igual => return no_igual,
                }
                match self.sds.get(a as usize).cmp(&self.sds.get(b as usize)) {
                    Ordering::Equal => {}
                    no_igual => return no_igual,
                }
                self.ids.get(a as usize).cmp(&self.ids.get(b as usize))
            }
            ModoSp::Kaspa => {
                let wa = self.datos(a).map(|d| d.blue_work);
                let wb = self.datos(b).map(|d| d.blue_work);
                match wb.cmp(&wa) {
                    Ordering::Equal => {}
                    no_igual => return no_igual,
                }
                self.ids.get(b as usize).cmp(&self.ids.get(a as usize))
            }
        }
    }

    // ── Grafo ───────────────────────────────────────────────────────────────

    fn es_ancestro(&self, a: Idx, b: Idx) -> bool {
        self.alcanzabilidad.es_ancestro(a, b)
    }

    /// `mergeset(B) = past(B) \\ (past(sp) ∪ {sp})` (`C-GD-04`).
    ///
    /// El conjunto es **local** (`HashSet` de índices): usar un bitset denso indexado por `Idx`
    /// global haría que el mergeset de un bloque reciente reservara `O(N)` bits por bloque. El orden
    /// de salida no importa: el llamante reordena por `C-GD-05` con un orden total.
    fn mergeset(&self, sp: Idx, padres: &[Idx]) -> Vec<Idx> {
        let mut ms: HashSet<Idx> = HashSet::new();
        let mut cola: VecDeque<Idx> = VecDeque::new();
        for p in padres {
            if *p == sp || self.es_ancestro(*p, sp) || ms.contains(p) {
                continue;
            }
            ms.insert(*p);
            cola.push_back(*p);
        }
        while let Some(cur) = cola.pop_front() {
            if let Some(ps) = self.padres.get(cur as usize) {
                for p in ps {
                    if self.es_ancestro(*p, sp) || ms.contains(p) {
                        continue;
                    }
                    ms.insert(*p);
                    cola.push_back(*p);
                }
            }
        }
        ms.into_iter().collect()
    }

    /// Orden de coloreado del mergeset: `C-GD-05`.
    fn ordenar_mergeset(&self, cand: &mut [Idx]) {
        cand.sort_by(|a, b| self.comparar_merge(*a, *b));
    }

    /// `tam_anticono_azul` del kernel: busca en el mapa disperso del bloque actual y, si no está,
    /// sube por la cadena del `sp` (los mapas se guardan por bloque, no copiados).
    fn tam_anticono_azul(
        &self,
        bas_actual: &HashMap<Idx, u32>,
        sp_actual: Idx,
        bloque: Idx,
    ) -> Result<u32, ErrorDag> {
        if let Some(v) = bas_actual.get(&bloque) {
            return Ok(*v);
        }
        let mut cur = Some(sp_actual);
        while let Some(c) = cur {
            if let Some(EstadoInterno::Kernel { bas }) = self.gd.get(c as usize).map(|g| &g.estado)
                && let Some(v) = bas.get(&bloque)
            {
                return Ok(*v);
            }
            cur = self.gd.get(c as usize).and_then(|g| g.sp);
        }
        Err(ErrorDag::GhostdagIncoherente {
            motivo: "tam_anticono_azul no encontró el azul en la cadena del sp",
        })
    }

    /// `check_blue_candidate_with_chain_block`.
    ///
    /// La firma tiene más argumentos que el umbral de clippy porque reproduce 1:1 el contrato de
    /// `protocol.rs`; se documenta la excepción en vez de inventar un contexto artificial.
    #[expect(
        clippy::too_many_arguments,
        reason = "réplica directa de protocol.rs; cada argumento es una pieza del contrato"
    )]
    fn revisar_con_bloque_cadena(
        &self,
        bas_actual: &HashMap<Idx, u32>,
        sp_actual: Idx,
        blues_actuales: &[Idx],
        cadena: Option<Idx>,
        cand: Idx,
        cand_sizes: &mut Vec<(Idx, u32)>,
        cand_size_inicial: u32,
        k: u32,
    ) -> Result<(Revision, u32), ErrorDag> {
        if cadena.is_some_and(|c| self.es_ancestro(c, cand)) {
            return Ok((Revision::Azul, cand_size_inicial));
        }
        let peer_blues: Vec<Idx> = match cadena {
            None => blues_actuales.to_vec(),
            Some(c) => self
                .gd
                .get(c as usize)
                .map(|g| g.blues.clone())
                .unwrap_or_default(),
        };
        let mut cand_size = cand_size_inicial;
        for peer in peer_blues {
            if self.es_ancestro(peer, cand) {
                continue;
            }
            let pbas = self.tam_anticono_azul(bas_actual, sp_actual, peer)?;
            cand_sizes.push((peer, pbas));
            cand_size += 1;
            if cand_size > k || pbas == k {
                return Ok((Revision::Rojo, cand_size));
            }
        }
        Ok((Revision::Pendiente, cand_size))
    }

    /// `check_blue_candidate`. Devuelve `(azul, cand_size, cand_sizes)`.
    fn check_azul(
        &self,
        sp_actual: Idx,
        bas_actual: &HashMap<Idx, u32>,
        blues_actuales: &[Idx],
        cand: Idx,
        k: u32,
    ) -> Result<CheckAzul, ErrorDag> {
        if blues_actuales.len() as u32 == k + 1 {
            return Ok((false, 0, Vec::new()));
        }
        let mut cand_sizes: Vec<(Idx, u32)> = Vec::new();
        let mut cand_size = 0u32;
        let mut cadena: Option<Idx> = None;
        loop {
            let (revision, size) = self.revisar_con_bloque_cadena(
                bas_actual,
                sp_actual,
                blues_actuales,
                cadena,
                cand,
                &mut cand_sizes,
                cand_size,
                k,
            )?;
            cand_size = size;
            match revision {
                Revision::Azul => return Ok((true, cand_size, cand_sizes)),
                Revision::Rojo => return Ok((false, cand_size, cand_sizes)),
                Revision::Pendiente => {
                    // Continuar el walk por la cadena del `sp`.
                    let siguiente = match cadena {
                        None => Some(sp_actual),
                        Some(c) => self.gd.get(c as usize).and_then(|g| g.sp),
                    };
                    cadena = Some(siguiente.ok_or(ErrorDag::GhostdagIncoherente {
                        motivo: "raíz alcanzada sin resolver el candidato",
                    })?);
                }
            }
        }
    }

    fn colorear_kernel(
        &self,
        sp: Idx,
        ms: &[Idx],
        identidad: IdentidadGhostdag,
        _nuevo: Idx,
    ) -> Result<(DatosGhostdag, Vec<IdentidadGhostdag>), ErrorDag> {
        let mut ordenado = ms.to_vec();
        self.ordenar_mergeset(&mut ordenado);

        let sp_datos = self
            .gd
            .get(sp as usize)
            .ok_or(ErrorDag::GhostdagIncoherente {
                motivo: "índice interno del almacén fuera de rango",
            })?;
        let sp_raiz = sp_datos.raiz_azules;

        // `bas` disperso: solo lo calculado por este bloque; lo heredado se busca por la cadena.
        let mut bas: HashMap<Idx, u32> = HashMap::new();
        bas.insert(sp, 0);
        let mut blues: Vec<Idx> = vec![sp];
        let mut rojos: Vec<Idx> = Vec::new();
        let mut colores: Vec<(Idx, Color)> = Vec::new();
        let mut vistos: HashSet<IdentidadGhostdag> = HashSet::new();

        for cand in &ordenado {
            let cid = self.identidad_de(*cand)?;
            let filtrado = self.params.u3_dinamica
                && cid != IdentidadGhostdag::SinBillete
                && (conjunto_azul::contiene(&self.arena_azul, sp_raiz, &cid)
                    || vistos.contains(&cid));
            if filtrado {
                rojos.push(*cand);
                colores.push((*cand, Color::RojoU3));
                continue;
            }
            let (azul, tam, cand_sizes) =
                self.check_azul(sp, &bas, &blues, *cand, self.params.k)?;
            if azul {
                blues.push(*cand);
                bas.insert(*cand, tam);
                for (h, s) in cand_sizes {
                    bas.insert(h, s + 1);
                }
                if cid != IdentidadGhostdag::SinBillete {
                    vistos.insert(cid);
                }
            } else {
                rojos.push(*cand);
                colores.push((*cand, Color::RojoK));
            }
        }

        let (blue_work, blue_score, nuevas) = self.acumular(sp, identidad, &blues)?;
        Ok((
            DatosGhostdag {
                sp: Some(sp),
                orden_mergeset: ordenado,
                blues,
                rojos,
                colores,
                raiz_azules: sp_raiz,
                blue_score,
                blue_work,
                estado: EstadoInterno::Kernel { bas },
            },
            nuevas,
        ))
    }

    fn colorear_referencia(
        &self,
        sp: Idx,
        ms: &[Idx],
        identidad: IdentidadGhostdag,
        nuevo: Idx,
    ) -> Result<(DatosGhostdag, Vec<IdentidadGhostdag>), ErrorDag> {
        // Claves INDEPENDIENTES del kernel (Corrección 1 de GDR-v0.2): la referencia ordena por
        // una tupla (bw, sd, id) calculada aparte, no con `comparar_merge`.
        let mut ordenado = ms.to_vec();
        ordenado.sort_by(|a, b| {
            let ka = self.clave_referencia(*a, self.params.merge);
            let kb = self.clave_referencia(*b, self.params.merge);
            ka.cmp(&kb)
        });

        let sp_datos = self
            .gd
            .get(sp as usize)
            .ok_or(ErrorDag::GhostdagIncoherente {
                motivo: "índice interno del almacén fuera de rango",
            })?;
        let sp_raiz = sp_datos.raiz_azules;
        let (mut contexto, mut tam): (ConjuntoBits, Vec<u32>) = match &sp_datos.estado {
            EstadoInterno::Referencia { blueset, tam } => (blueset.clone(), tam.clone()),
            EstadoInterno::Kernel { .. } => {
                return Err(ErrorDag::GhostdagIncoherente {
                    motivo: "la referencia encontró un estado de kernel",
                });
            }
        };
        // `tam` cubre hasta el bloque nuevo; los índices intermedios no vistos valen 0.
        tam.resize(nuevo as usize + 1, 0);

        let mut blues: Vec<Idx> = vec![sp];
        let mut rojos: Vec<Idx> = Vec::new();
        let mut colores: Vec<(Idx, Color)> = Vec::new();
        let mut vistos: HashSet<IdentidadGhostdag> = HashSet::new();

        for cand in &ordenado {
            let cid = self.identidad_de(*cand)?;
            let filtrado = self.params.u3_dinamica
                && cid != IdentidadGhostdag::SinBillete
                && (conjunto_azul::contiene(&self.arena_azul, sp_raiz, &cid)
                    || vistos.contains(&cid));
            if filtrado {
                rojos.push(*cand);
                colores.push((*cand, Color::RojoU3));
                continue;
            }
            // Anticono directo dentro del contexto (la DEFINICIÓN, no el algoritmo incremental).
            let mut anticono: Vec<Idx> = Vec::new();
            for b in contexto.iter() {
                if !self.es_ancestro(b, *cand) && !self.es_ancestro(*cand, b) {
                    anticono.push(b);
                }
            }
            let cabe = anticono.len() as u32 <= self.params.k
                && anticono
                    .iter()
                    .all(|b| leer_tabla(&tam, *b, 0) < self.params.k);
            if cabe {
                for b in &anticono {
                    let actualizado = leer_tabla(&tam, *b, 0).saturating_add(1);
                    fijar_tabla(&mut tam, *b, actualizado);
                }
                fijar_tabla(&mut tam, *cand, anticono.len() as u32);
                contexto.insertar(*cand);
                blues.push(*cand);
                if cid != IdentidadGhostdag::SinBillete {
                    vistos.insert(cid);
                }
            } else {
                rojos.push(*cand);
                colores.push((*cand, Color::RojoK));
            }
        }

        let (blue_work, blue_score, nuevas) = self.acumular(sp, identidad, &blues)?;

        // Blue set final de past(B) ∪ {B}: el contexto más B.
        let mut blueset_final = contexto;
        blueset_final.insertar(nuevo);
        fijar_tabla(&mut tam, nuevo, 0);

        Ok((
            DatosGhostdag {
                sp: Some(sp),
                orden_mergeset: ordenado,
                blues,
                rojos,
                colores,
                raiz_azules: sp_raiz,
                blue_score,
                blue_work,
                estado: EstadoInterno::Referencia {
                    blueset: blueset_final,
                    tam,
                },
            },
            nuevas,
        ))
    }

    /// Clave independiente de la referencia para el orden del mergeset.
    fn clave_referencia(&self, i: Idx, modo: ModoMerge) -> (U256, u64, BlockHash) {
        let bw = self
            .gd
            .get(i as usize)
            .map_or(U256::zero(), |g| g.blue_work);
        let sd = self.sds.get(i as usize).copied().unwrap_or(0);
        let id = self
            .ids
            .get(i as usize)
            .copied()
            .unwrap_or_else(|| hash_desde_id(&[0; 32]));
        match modo {
            ModoMerge::Terna => (bw, sd, id),
            ModoMerge::Kaspa => (bw, 0, id),
        }
    }

    /// `blue_score`, `blue_work` y las **identidades nuevas** acumuladas (`C-GD-08`).
    ///
    /// Ya no devuelve la colección acumulada completa (que se copiaba por bloque): devuelve solo las
    /// identidades que este bloque aporta (sus azules y la propia). El llamante las inserta en el
    /// conjunto persistente del `sp`.
    fn acumular(
        &self,
        sp: Idx,
        identidad: IdentidadGhostdag,
        blues: &[Idx],
    ) -> Result<(U256, u64, Vec<IdentidadGhostdag>), ErrorDag> {
        let sp_datos = self
            .gd
            .get(sp as usize)
            .ok_or(ErrorDag::GhostdagIncoherente {
                motivo: "índice interno del almacén fuera de rango",
            })?;
        let mut bw = sp_datos.blue_work;
        for x in blues {
            // C-GD-08 sobre el `SR` validado. La ausencia **no** se sustituye por 0: cero es un
            // `SR` legítimo con peso máximo (`2^128`), no un centinela.
            let sr = self
                .srs
                .get(*x as usize)
                .copied()
                .ok_or(ErrorDag::GhostdagIncoherente {
                    motivo: "un bloque azul del mergeset no tiene SR almacenado",
                })?;
            bw = sumar_blue_work(bw, sr.peso())?;
        }
        let score = sp_datos
            .blue_score
            .checked_add(blues.len() as u64)
            .ok_or(ErrorDag::BlueWorkDesbordado)?;
        let mut nuevas: Vec<IdentidadGhostdag> = Vec::new();
        for x in blues {
            let cid = self.identidad_de(*x)?;
            if cid != IdentidadGhostdag::SinBillete {
                nuevas.push(cid);
            }
        }
        if identidad != IdentidadGhostdag::SinBillete {
            nuevas.push(identidad);
        }
        Ok((bw, score, nuevas))
    }
}

/// Salida de `check_azul`: azul, tamaño de anticono del candidato y tamaños por azul.
type CheckAzul = (bool, u32, Vec<(Idx, u32)>);

fn leer_tabla(tabla: &[u32], i: Idx, por_defecto: u32) -> u32 {
    tabla.get(i as usize).copied().unwrap_or(por_defecto)
}

fn fijar_tabla(tabla: &mut [u32], i: Idx, valor: u32) {
    if let Some(slot) = tabla.get_mut(i as usize) {
        *slot = valor;
    }
}

fn padre_push_unico(padres: &mut Vec<Idx>, idx: Idx) {
    if !padres.contains(&idx) {
        padres.push(idx);
    }
    padres.sort_unstable();
}

/// Selecciona el mejor de `candidatos` según `comparador` (que devuelve `Ordering::Less` si el
/// primer argumento es **mejor**).
fn seleccionar_sp_generico<F>(candidatos: &[Idx], mut comparador: F) -> Option<Idx>
where
    F: FnMut(Idx, Idx) -> Ordering,
{
    let mut mejor: Option<Idx> = None;
    for c in candidatos {
        match mejor {
            None => mejor = Some(*c),
            Some(m) => {
                if comparador(*c, m) == Ordering::Less {
                    mejor = Some(*c);
                }
            }
        }
    }
    mejor
}

// ─────────────────────────────────────────────────────────────────────────────
// Implementación real de `ContextoDag` (H-04, H-06), respaldada por el almacén.
// ─────────────────────────────────────────────────────────────────────────────

impl ContextoDag for AlmacenGhostdag {
    fn es_bloque_validado(&self, h: &BlockHash) -> bool {
        self.indice.contains_key(h)
    }

    fn esta_en_el_pasado_de(
        &self,
        antepasado: &BlockHash,
        descendiente: &BlockHash,
    ) -> Result<bool, ErrorDag> {
        let a = *self
            .indice
            .get(antepasado)
            .ok_or(ErrorDag::BloqueDesconocido { hash: *antepasado })?;
        let b = *self
            .indice
            .get(descendiente)
            .ok_or(ErrorDag::BloqueDesconocido {
                hash: *descendiente,
            })?;
        // Pasado ESTRICTO: `a == b` no es ancestro en el sentido de "estar en el pasado de".
        Ok(a != b && self.es_ancestro(a, b))
    }

    fn slot_de_padre(&self, h: &BlockHash) -> Result<u64, ErrorDag> {
        // El slot sale del almacén validado, nunca del candidato. Un padre desconocido y un slot
        // ausente son dos fallos explícitos distintos; ninguno se sustituye por cero.
        let idx = *self
            .indice
            .get(h)
            .ok_or(ErrorDag::PadreNoValidado { padre: *h })?;
        self.slots
            .get(idx as usize)
            .copied()
            .ok_or(ErrorDag::SlotDePadreAusente { padre: *h })
    }

    fn padre_seleccionado(&self, padres: &PadresDag) -> Result<BlockHash, ErrorDag> {
        // Se ignoran las posiciones declaradas: el `sp` se recalcula con C-GD-03.
        let mut indices: Vec<Idx> = Vec::with_capacity(usize::from(padres.count()));
        if !padres.es_genesis() {
            let s = *self
                .indice
                .get(&padres.seleccionado())
                .ok_or(ErrorDag::PadreNoValidado {
                    padre: padres.seleccionado(),
                })?;
            indices.push(s);
        }
        for p in padres.extras() {
            let idx = *self
                .indice
                .get(p)
                .ok_or(ErrorDag::PadreNoValidado { padre: *p })?;
            indices.push(idx);
        }
        let sp = seleccionar_sp_generico(&indices, |a, b| self.comparar_sp(a, b)).ok_or(
            ErrorDag::PadreNoValidado {
                padre: padres.seleccionado(),
            },
        )?;
        self.ids
            .get(sp as usize)
            .copied()
            .ok_or(ErrorDag::PadreNoValidado {
                padre: padres.seleccionado(),
            })
    }

    fn es_terminal(&self, h: &BlockHash) -> bool {
        *h == self.terminal
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::*;

    fn params() -> Parametros {
        Parametros::default()
    }

    fn id(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    /// Bloque **sintético** de este test: el `SR` no se valida (no hay contexto de controlador).
    fn bloque(bloque_id: BlockHash, padres: Vec<BlockHash>, slot: u64, sr: u64) -> BloqueGhostdag {
        BloqueGhostdag {
            id: bloque_id,
            padres,
            slot,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(sr),
            identidad: IdentidadGhostdag::SinBillete,
        }
    }

    /// C-GD-08: un azul sin `SR` almacenado es una incoherencia explícita, **no** un cero.
    ///
    /// La ausencia se provoca desde dentro del módulo; la API pública no puede crear el estado.
    #[test]
    fn acumular_sin_sr_almacenado_es_incoherencia() {
        let g = id(0x60);
        let mut almacen = AlmacenGhostdag::nuevo(
            params(),
            Algoritmo::Kernel,
            g,
            0,
            RangoSolucionValidado::para_oraculos(0),
            0,
        );
        let id_a = id(0xA1);
        almacen
            .anadir_sintetico(bloque(id_a, vec![g], 1, 5))
            .unwrap();

        // Se rompe el invariante interno a propósito: `A` se queda sin `SR`.
        let quitado = almacen.srs.pop();
        assert_eq!(quitado.map(RangoSolucionValidado::valor), Some(5));

        // El hijo incluye a `A` entre sus azules y `acumular` lo detecta.
        let err = almacen
            .anadir_sintetico(bloque(id(0xB2), vec![id_a], 2, 7))
            .unwrap_err();
        assert!(
            matches!(err, ErrorDag::GhostdagIncoherente { .. }),
            "{err:?}"
        );
        assert_eq!(almacen.len(), 2, "el rechazo no muta el almacén");
    }

    /// Un `block_hash` ya almacenado se rechaza como **duplicado de almacenamiento** antes de
    /// mutar nada: índice, vectores paralelos y datos GHOSTDAG quedan idénticos.
    #[test]
    fn el_duplicado_se_rechaza_antes_de_mutar_el_almacen() {
        let g = id(0x60);
        for algoritmo in [Algoritmo::Referencia, Algoritmo::Kernel] {
            let mut almacen = AlmacenGhostdag::nuevo(
                params(),
                algoritmo,
                g,
                0,
                RangoSolucionValidado::para_oraculos(0),
                0,
            );
            let id_a = id(0xA1);
            almacen
                .anadir_sintetico(bloque(id_a, vec![g], 1, 5))
                .unwrap();

            let huella = |a: &AlmacenGhostdag| {
                (
                    a.indice.clone(),
                    a.ids.clone(),
                    a.padres.clone(),
                    a.slots.clone(),
                    a.sds.clone(),
                    a.srs.clone(),
                    a.idents.clone(),
                    a.indice_ident.clone(),
                    a.arena_azul.clone(),
                    a.alcanzabilidad.clone(),
                    a.gd.clone(),
                )
            };
            let antes = huella(&almacen);

            // Mismo id con otros metadatos: antes sustituía el índice y hacía crecer `ids`.
            let err = almacen
                .anadir_sintetico(bloque(id_a, vec![g], 2, 7))
                .unwrap_err();
            assert_eq!(
                err,
                ErrorDag::BloqueDuplicado { hash: id_a },
                "{algoritmo:?}"
            );
            assert_eq!(huella(&almacen), antes, "{algoritmo:?}");
            assert_eq!(almacen.len(), 2, "{algoritmo:?}");
        }
    }

    /// C-GD-01: los extremos del `SR` dan `2^128` y `2^64`, y el peso del tipo validado coincide
    /// con la fórmula pura en todo el dominio probado.
    #[test]
    fn los_extremos_del_sr_validado_dan_los_pesos_de_c_gd_01() {
        assert_eq!(
            RangoSolucionValidado::para_oraculos(0).peso(),
            U256::one() << 128usize
        );
        assert_eq!(
            RangoSolucionValidado::para_oraculos(u64::MAX).peso(),
            U256::one() << 64usize
        );
        for sr in [0u64, 1, 2, 1 << 32, u64::MAX - 1, u64::MAX] {
            assert_eq!(RangoSolucionValidado::para_oraculos(sr).peso(), peso(sr));
        }
    }

    /// Billete real para los tests de U2 y de coherencia de la identidad.
    fn ticket(chunk: u8) -> IdentidadTicket {
        IdentidadTicket::vigente(
            zx_core::ClavePublica::desde_bytes([5u8; 32]),
            3,
            1 << 20,
            [chunk; 32],
            1,
        )
    }

    /// Bloque sintético con identidad explícita (el helper `bloque` de arriba siempre es
    /// `SinBillete`).
    fn bloque_con_ident(
        bloque_id: BlockHash,
        padres: Vec<BlockHash>,
        slot: u64,
        sr: u64,
        identidad: IdentidadGhostdag,
    ) -> BloqueGhostdag {
        BloqueGhostdag {
            id: bloque_id,
            padres,
            slot,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(sr),
            identidad,
        }
    }

    /// `Eq`, `Hash` y `Ord` de `IdentidadGhostdag` son consistentes: `Hash` igual cuando `Eq`
    /// igual y `cmp == Equal` si y solo si `Eq` igual. Dos tickets distintos que comparten prefijo
    /// canónico no son iguales ni comparan `Equal`.
    #[test]
    fn eq_hash_y_ord_de_la_identidad_son_consistentes() {
        use std::collections::hash_map::DefaultHasher;

        fn hash_de(v: &IdentidadGhostdag) -> u64 {
            let mut h = DefaultHasher::new();
            v.hash(&mut h);
            h.finish()
        }

        // Mismo prefijo canónico (clave pública, sector e historia) y `chunk` distinto.
        let t_a = ticket(1);
        let t_b = ticket(2);
        assert_eq!(
            t_a.bytes_canonicos().get(..42),
            t_b.bytes_canonicos().get(..42),
            "los dos tickets comparten prefijo canónico"
        );

        let a = IdentidadGhostdag::Billete(t_a);
        let a_igual = IdentidadGhostdag::Billete(ticket(1));
        let b = IdentidadGhostdag::Billete(t_b);
        assert_eq!(a, a_igual);
        assert_eq!(hash_de(&a), hash_de(&a_igual));
        assert_eq!(a.cmp(&a_igual), Ordering::Equal);
        assert_ne!(a, b);
        assert_ne!(a.cmp(&b), Ordering::Equal);
        assert_eq!(a.cmp(&b), b.cmp(&a).reverse());

        let s7 = IdentidadGhostdag::Sintetica(7);
        let s7_igual = IdentidadGhostdag::Sintetica(7);
        let s8 = IdentidadGhostdag::Sintetica(8);
        assert_eq!(s7, s7_igual);
        assert_eq!(hash_de(&s7), hash_de(&s7_igual));
        assert_eq!(s7.cmp(&s7_igual), Ordering::Equal);
        assert_ne!(s7, s8);
        assert_ne!(s7.cmp(&s8), Ordering::Equal);

        let sin = IdentidadGhostdag::SinBillete;
        assert_ne!(sin, a);
        assert_ne!(sin.cmp(&a), Ordering::Equal);
        assert_ne!(a, s7);
        assert_ne!(a.cmp(&s7), Ordering::Equal);

        // En un `HashSet`, `Eq`/`Hash` consistentes agrupan iguales y separan el resto.
        let mut conjunto = HashSet::new();
        conjunto.insert(a);
        conjunto.insert(a_igual);
        assert_eq!(conjunto.len(), 1, "dos iguales ocupan una sola entrada");
        conjunto.insert(b);
        conjunto.insert(s7);
        conjunto.insert(sin);
        assert_eq!(conjunto.len(), 4, "los distintos ocupan entradas distintas");

        // `cmp == Equal` si y solo si `Eq` igual, para los pares representativos.
        for (x, y) in [(&a, &a_igual), (&s7, &s7_igual)] {
            assert_eq!(x.cmp(y) == Ordering::Equal, x == y);
        }
        for (x, y) in [(&a, &b), (&s7, &s8), (&sin, &a), (&a, &s7)] {
            assert_eq!(x.cmp(y) == Ordering::Equal, x == y);
        }
    }

    /// U2 con el índice de identidades: una identidad de padre ausente es incoherencia explícita
    /// **antes** de mutar, nunca se interpreta como «no hay duplicado».
    ///
    /// (W08b sustituye el recorrido del bitset de pasado por el índice `identidad → bloques`; el
    /// caso de «pasado del padre ausente» ya no existe, pero se conserva la comprobación de
    /// no-mutación ante estado incoherente.)
    #[test]
    fn u2_con_estado_incoherente_falla_sin_mutar() {
        let g = id(0x60);
        let a = id(0xA1);
        let padre = IdentidadGhostdag::Billete(ticket(9));
        // Identidad distinta de la del padre: la comprobación no puede cortocircuitar en `raiz`.
        let hijo = IdentidadGhostdag::Billete(ticket(10));

        let mut almacen = AlmacenGhostdag::nuevo(
            params(),
            Algoritmo::Kernel,
            g,
            0,
            RangoSolucionValidado::para_oraculos(0),
            0,
        );
        almacen
            .anadir_sintetico(bloque_con_ident(a, vec![g], 1, 5, padre))
            .unwrap();

        // Estado incoherente: la identidad del padre desaparece de `idents`.
        assert_eq!(almacen.idents.pop(), Some(padre));

        let antes = (
            almacen.indice.clone(),
            almacen.ids.clone(),
            almacen.padres.clone(),
            almacen.slots.clone(),
            almacen.sds.clone(),
            almacen.srs.clone(),
            almacen.idents.clone(),
            almacen.alcanzabilidad.clone(),
            almacen.gd.clone(),
        );
        let err = almacen
            .anadir_sintetico(bloque_con_ident(id(0xB2), vec![a], 2, 7, hijo))
            .unwrap_err();
        assert!(
            matches!(err, ErrorDag::GhostdagIncoherente { .. }),
            "{err:?}"
        );
        let despues = (
            almacen.indice.clone(),
            almacen.ids.clone(),
            almacen.padres.clone(),
            almacen.slots.clone(),
            almacen.sds.clone(),
            almacen.srs.clone(),
            almacen.idents.clone(),
            almacen.alcanzabilidad.clone(),
            almacen.gd.clone(),
        );
        assert_eq!(antes, despues, "el rechazo no muta el almacén");
        assert_eq!(almacen.len(), 2);
    }

    /// U2 positivo con el índice: la misma identidad en el pasado de un padre se rechaza; en una
    /// rama hermana (incomparable) se acepta.
    #[test]
    fn u2_detecta_la_identidad_en_el_pasado() {
        let g = id(0x60);
        let a = id(0xA1);
        let b = id(0xB2);
        let c = id(0xC3);
        let t = IdentidadGhostdag::Billete(ticket(9));
        let mut almacen = AlmacenGhostdag::nuevo(
            params(),
            Algoritmo::Kernel,
            g,
            0,
            RangoSolucionValidado::para_oraculos(0),
            0,
        );
        almacen
            .anadir_sintetico(bloque_con_ident(a, vec![g], 1, 5, t))
            .unwrap();
        // `b` cuelga de `a` con la misma identidad: U2.
        let err = almacen
            .anadir_sintetico(bloque_con_ident(b, vec![a], 2, 5, t))
            .unwrap_err();
        assert_eq!(err, ErrorDag::BilleteDuplicadoU2 { identidad: t });
        // Rama hermana de `a` con la misma identidad: no está en su pasado, se acepta.
        almacen
            .anadir_sintetico(bloque_con_ident(c, vec![g], 1, 5, t))
            .unwrap();
        assert_eq!(almacen.len(), 3);
    }

    /// **D-P07.** `con_raiz_terminal` equivale a la raíz con `slot 0`, identidad ausente y
    /// `blue_work` 0, y el primer hijo hereda `w(T)` como azul de la raíz.
    #[test]
    fn con_raiz_terminal_fija_slot_cero_y_hereda_el_peso_de_t() {
        let terminal = id(0x77);
        let mut almacen = AlmacenGhostdag::con_raiz_terminal(
            params(),
            Algoritmo::Kernel,
            terminal,
            RangoSolucionValidado::para_oraculos(0),
        );
        assert_eq!(almacen.terminal(), terminal);
        assert_eq!(almacen.rank(0).unwrap().blue_work, U256::zero());

        let hijo = id(0x78);
        let idx = almacen
            .anadir_sintetico(bloque(hijo, vec![terminal], 1, 0))
            .unwrap();
        // El terminal (SR 0 ⇒ w = 2^128) es azul del hijo.
        assert_eq!(
            almacen.rank(idx).unwrap().blue_work,
            U256::one() << 128usize
        );
    }
}

/// Cierre de W08b-2: prueba de corrección del reindexado y de U2 contra un oráculo de fuerza bruta
/// (BFS sobre los padres declarados), más una reorganización profunda con rama rival ganadora.
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
#[expect(
    clippy::indexing_slicing,
    reason = "arrays densos del arnés: los índices son válidos por construcción"
)]
#[expect(
    clippy::integer_division,
    reason = "conjuntos de bits: la palabra y el bit son aritmética entera deliberada"
)]
#[allow(
    clippy::needless_range_loop,
    reason = "los índices densos son el sujeto del test"
)]
mod tests_w08b2 {
    use super::*;

    /// xorshift64* con semilla fija: reproducible sin dependencias.
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

    fn params() -> Parametros {
        Parametros::default()
    }

    fn bloque(
        bloque_id: BlockHash,
        padres: Vec<BlockHash>,
        slot: u64,
        sr: u64,
        identidad: IdentidadGhostdag,
    ) -> BloqueGhostdag {
        BloqueGhostdag {
            id: bloque_id,
            padres,
            slot,
            solution_distance: 0,
            rango_espacio: RangoSolucionValidado::para_oraculos(sr),
            identidad,
        }
    }

    /// Oráculo de U2: ¿la identidad de `raiz` o de algún ancestro **estricto** es `identidad`?
    fn pasado_contiene_ref(
        almacen: &AlmacenGhostdag,
        raiz: Idx,
        identidad: IdentidadGhostdag,
    ) -> bool {
        if almacen.identidad_de(raiz).unwrap() == identidad {
            return true;
        }
        let mut visto = vec![false; almacen.len()];
        visto[raiz as usize] = true;
        let mut pila: Vec<Idx> = almacen.padres_de(raiz).unwrap().to_vec();
        while let Some(c) = pila.pop() {
            if visto[c as usize] {
                continue;
            }
            visto[c as usize] = true;
            if almacen.identidad_de(c).unwrap() == identidad {
                return true;
            }
            for p in almacen.padres_de(c).unwrap() {
                if !visto[*p as usize] {
                    pila.push(*p);
                }
            }
        }
        false
    }

    /// BFS real hacia atrás sobre los padres declarados.
    fn bfs_almacen(almacen: &AlmacenGhostdag, a: Idx, b: Idx) -> bool {
        if a == b {
            return true;
        }
        let mut visto = vec![false; almacen.len()];
        visto[b as usize] = true;
        let mut pila = almacen.padres_de(b).unwrap().to_vec();
        while let Some(c) = pila.pop() {
            if c == a {
                return true;
            }
            if !visto[c as usize] {
                visto[c as usize] = true;
                for p in almacen.padres_de(c).unwrap() {
                    if !visto[*p as usize] {
                        pila.push(*p);
                    }
                }
            }
        }
        false
    }

    /// Clausura transitiva del pasado estricto por unión de padres (el mismo resultado que un BFS
    /// por consulta; se contrasta con `bfs_almacen` en una muestra).
    fn clausura(almacen: &AlmacenGhostdag) -> Vec<Vec<u64>> {
        let n = almacen.len();
        let palabras = n.div_ceil(64);
        let mut pasado = vec![vec![0u64; palabras]; n];
        for i in 0..n {
            for p in almacen.padres_de(i as Idx).unwrap() {
                pasado[i][*p as usize / 64] |= 1u64 << (*p % 64);
                let copia = pasado[*p as usize].clone();
                for (a, b) in pasado[i].iter_mut().zip(&copia) {
                    *a |= *b;
                }
            }
        }
        pasado
    }

    /// Compara `es_ancestro` con la clausura en `muestras` pares y con el BFS real en una muestra.
    fn comprobar_reach(almacen: &AlmacenGhostdag, muestras: usize, semilla: u64) -> usize {
        let n = almacen.len();
        let pasado = clausura(almacen);
        let mut rng = Azar::nuevo(semilla);
        let esperado = |a: Idx, b: Idx| {
            a == b || pasado[b as usize][a as usize / 64] & (1u64 << (a % 64)) != 0
        };
        // BFS real sobre una muestra.
        for _ in 0..4096 {
            let a = rng.rango(0, n - 1) as Idx;
            let b = rng.rango(0, n - 1) as Idx;
            assert_eq!(
                almacen.es_ancestro(a, b),
                bfs_almacen(almacen, a, b),
                "BFS a={a} b={b}"
            );
        }
        // Clausura en el resto.
        for _ in 0..muestras {
            let a = rng.rango(0, n - 1) as Idx;
            let b = rng.rango(0, n - 1) as Idx;
            assert_eq!(almacen.es_ancestro(a, b), esperado(a, b), "a={a} b={b}");
        }
        muestras
    }

    /// Propiedad: en 200 DAG aleatorios con identidades repetidas, todas las consultas de U2
    /// (índice de identidades + alcanzabilidad) coinciden con el oráculo de fuerza bruta.
    #[test]
    fn u2_indice_identidades_coincide_con_bfs() {
        let universo = [
            IdentidadGhostdag::de_fixture(1),
            IdentidadGhostdag::de_fixture(2),
            IdentidadGhostdag::de_fixture(3),
            IdentidadGhostdag::SinBillete,
        ];
        // Solo se consultan identidades reales: `pasado_contiene_ident` no indexa `SinBillete`
        // (la admisión nunca pregunta por él, y U2 no aplica a esa identidad).
        let consulta = [
            IdentidadGhostdag::de_fixture(1),
            IdentidadGhostdag::de_fixture(2),
            IdentidadGhostdag::de_fixture(3),
        ];
        let mut rng = Azar::nuevo(0x0202_0202_0202_0202);
        let mut consultas = 0usize;
        for caso in 0..200u32 {
            let g = hash_de_id_textual(&format!("G{caso}"));
            let mut almacen = AlmacenGhostdag::nuevo(
                params(),
                Algoritmo::Kernel,
                g,
                0,
                RangoSolucionValidado::para_oraculos(0),
                0,
            );
            let mut ids: Vec<BlockHash> = vec![g];
            let mut slots: Vec<u64> = vec![0];
            let objetivo = 20 + rng.rango(0, 40);
            let mut intentos = 0;
            while ids.len() < objetivo && intentos < objetivo * 4 {
                intentos += 1;
                let disponibles = ids.len();
                let ventana = disponibles.min(6);
                let n_padres = 1 + rng.rango(0, ventana.min(3) - 1);
                let mut padres: Vec<BlockHash> = Vec::new();
                let mut slot_max = 0u64;
                while padres.len() < n_padres {
                    let p = disponibles - 1 - rng.rango(0, ventana - 1);
                    if !padres.contains(&ids[p]) {
                        padres.push(ids[p]);
                        slot_max = slot_max.max(slots[p]);
                    }
                }
                let identidad = universo[rng.rango(0, universo.len() - 1)];
                let bloque = bloque(
                    hash_de_id_textual(&format!("B{caso}_{}", ids.len())),
                    padres,
                    slot_max + 1,
                    5 + rng.rango(0, 20) as u64,
                    identidad,
                );
                let bloque_id = bloque.id;
                if almacen.anadir_sintetico(bloque).is_ok() {
                    ids.push(bloque_id);
                    slots.push(slot_max + 1);
                }
            }
            assert!(
                almacen.len() >= 2,
                "caso {caso}: no se admitió ningún bloque"
            );
            for raiz in 0..almacen.len() as Idx {
                for identidad in consulta {
                    let esperado = pasado_contiene_ref(&almacen, raiz, identidad);
                    let obtenido = almacen.pasado_contiene_ident(raiz, identidad).unwrap();
                    assert_eq!(
                        obtenido, esperado,
                        "caso={caso} raiz={raiz} identidad={identidad:?}"
                    );
                    consultas += 1;
                }
            }
        }
        assert!(consultas >= 10_000, "consultas de U2 = {consultas}");
        println!("U2: 200 DAGs, consultas comprobadas = {consultas}");
    }

    /// Reorganización profunda con rama rival que gana: la rama B (más trabajo por bloque) supera a
    /// la A tras ~1 350 bloques, `mejor_punta` cambia y el reindexado cruza al ancestro común. La
    /// alcanzabilidad sigue coincidiendo con el oráculo.
    #[test]
    fn reindexado_reorganizacion_profunda_rama_rival() {
        let rama = 1_500usize;
        let mut almacen = AlmacenGhostdag::nuevo(
            params(),
            Algoritmo::Kernel,
            hash_de_id_textual("G"),
            0,
            RangoSolucionValidado::para_oraculos(0),
            0,
        );
        // Capacidad reducida (solo test) para forzar muchos reindexados.
        almacen.alcanzabilidad = IndiceAlcanzabilidad::nuevo_con_capacidad(1 << 19, 1);

        // Rama A: `SR = 100` (poco trabajo por bloque).
        let mut padre = hash_de_id_textual("G");
        let mut slot = 0u64;
        for j in 0..rama {
            slot += 1;
            let bloque = bloque(
                hash_de_id_textual(&format!("A{j}")),
                vec![padre],
                slot,
                100,
                IdentidadGhostdag::SinBillete,
            );
            padre = bloque.id;
            almacen.anadir_sintetico(bloque).unwrap();
        }
        let punta_a = almacen.mejor_punta.unwrap();

        // Rama B: `SR = 90` (más trabajo por bloque), desde la raíz.
        let mut padre = hash_de_id_textual("G");
        let mut slot = 0u64;
        for j in 0..rama {
            slot += 1;
            let bloque = bloque(
                hash_de_id_textual(&format!("B{j}")),
                vec![padre],
                slot,
                90,
                IdentidadGhostdag::SinBillete,
            );
            padre = bloque.id;
            almacen.anadir_sintetico(bloque).unwrap();
        }
        let punta_b = almacen.mejor_punta.unwrap();

        assert_ne!(punta_a, punta_b, "la rama rival debe ganar");
        assert!(
            almacen.datos(punta_b).unwrap().blue_work > almacen.datos(punta_a).unwrap().blue_work
        );
        // Las dos ramas solo comparten la raíz: ningún bloque interno es ancestro del otro.
        assert!(!almacen.es_ancestro(1, rama as Idx + 1));
        assert!(!almacen.es_ancestro(rama as Idx + 1, 1));
        assert!(almacen.es_ancestro(0, rama as Idx + 1));

        let total = comprobar_reach(&almacen, 1_000_000, 0xDEAD_BEEF);
        let (cap, avance) = almacen.alcanzabilidad.reindexados();
        assert!(total >= 1_000_000, "pares comprobados = {total}");
        assert!(cap + avance >= 1_000, "reindexados = {cap} + {avance}");
        println!(
            "reorg rama={rama} reindex_cap={cap} reindex_avance={avance} pares={total} \
             mejora_punta_a={punta_a} punta_b={punta_b}"
        );
    }
}
