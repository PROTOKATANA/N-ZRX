//! Evaluación **por peso** del certificado compacto y del acta (contrato `CONTRATO-VOTOS-v2.md`,
//! parte A: A1–A6) y diferencial contra los 21 vectores del oráculo FV-3 v3 (`PDM1/vectores/`).
//!
//! # Qué implementa
//!
//! - **A1 · peso efectivo y total** `w_i`/`W` reutilizando [`crate::binomial::peso_efectivo`] y
//!   [`crate::binomial::peso_total`]. Una clave inactiva pesa 0 (el `peso_efectivo` del crate ignora
//!   `activo`; aquí se anula antes de sumar).
//! - **A2 · quórum** `3·Σ ≥ 2·W` en `u128` (`MOTIVOS_PESO`, [`quorum_peso`], [`umbral_peso`]).
//! - **A3 · mensaje del voto** `SHA-256(n_u64_be ‖ candidato[32] ‖ h_t_siguiente[32] ‖
//!   raíz_de_estado[32])` ([`mensaje_voto_peso`]); la firma es BLS en [`DOMINIO_VOTO`].
//! - **A5 · certificado compacto** ([`CertificadoPeso`]) con mapa de bits de `⌈N/8⌉` bytes; el cuerpo
//!   es la parte fija más el mapa y **nada detrás** (T2 del contrato v1.2). La huella declarada debe
//!   ser una de las derivadas que el estado acepta ([`EntradaPeso::h_t_siguiente_aceptadas`]).
//! - **A6 · acta de presencia**: mismo formato, sin exigir quórum (`EntradaPeso::acta`).
//!
//! # Motivos (vocabulario **cerrado** y ordenado, `CONTRATO-FV-v3.md` + T3 del contrato v1.2)
//!
//! `ventana`, `sin_peso`, `mapa_longitud`, `mapa_fuera_tabla`, `firmante_inactivo`, `encadenado`,
//! `ancla`, `raiz_estado`, `firma_falsa`, `tabla_no_derivada`, `quorum`.
//! Los dos motivos de mapa **detienen** la verificación y devuelven únicamente ese motivo (sin mapa
//! bien formado no hay conjunto de firmantes).
//!
//! # Orden del mapa de bits
//!
//! El mapa indexa [`Tabla::claves`] **en el orden en que está almacenada**; el hash canónico
//! [`crate::serial::hash_tabla`] sí ordena por bytes de `pk`. A4 pide que el mapa vaya sobre el orden
//! canónico, así que quien exija A4 debe entregar la tabla ya ordenada. D1 (los 21 vectores del
//! oráculo, resueltos sobre la tabla tal como la escriben) exige este orden: ver `PROGRESO.md` §2.2.
//!
//! # Serialización canónica
//!
//! `200 bytes fijos` (`n:u64 ‖ candidato ‖ h_t_siguiente ‖ raíz_de_estado ‖ firma BLS 96 B`) `‖ mapa`
//! y **nada más** (T2). La lectura necesita `n_claves_vigente` para fijar la longitud del mapa; todo
//! byte detrás del mapa es un rechazo **por forma**.

use num_traits::ToPrimitive;
use zx_bls::{ClavePublica, Firma, FirmaAgregada, agregar_firmas, fast_aggregate_verify};

use crate::binomial::{peso_efectivo, peso_total};
use crate::bls::DOMINIO_VOTO;
use crate::error::ErrorVotos;
use crate::serial::{hash_bytes, hash_tabla};
use crate::tipos::{Clave, Hash, LONGITUD_HASH, Tabla};

/// Vocabulario **cerrado** de motivos, en su orden canónico de contrato.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MotivoPeso {
    /// El certificado afirma otra instancia (A5.1).
    Ventana,
    /// `W = 0`: no hay quórum posible (A5.2).
    SinPeso,
    /// El mapa no mide `⌈N/8⌉` bytes (A5.3); **detiene**.
    MapaLongitud,
    /// El mapa marca un bit fuera de `1..N` (A5.3); **detiene**.
    MapaFueraTabla,
    /// Algún firmante está inactivo (A5.4).
    FirmanteInactivo,
    /// No encadena con el certificado previo (A5.5).
    Encadenado,
    /// La tabla no casa con el ancla comprometida (A5.5).
    Ancla,
    /// La raíz de estado declarada no es la firmada (A5.6).
    RaizEstado,
    /// La firma agregada no verifica (dato `firma_ok`) (A5.6).
    FirmaFalsa,
    /// La huella siguiente declarada no es ninguna de las tablas derivadas que el estado acepta
    /// (T3/T5/T6 del contrato v1.2; sustituye a `HashTablaSiguiente` y `TablaSiguienteAusente`).
    TablaNoDerivada,
    /// `3·Σ < 2·W` (A2/A5.8), salvo acta (A6).
    Quorum,
}

impl MotivoPeso {
    /// Todos los motivos, en el orden del contrato.
    pub const TODOS: [MotivoPeso; 11] = [
        MotivoPeso::Ventana,
        MotivoPeso::SinPeso,
        MotivoPeso::MapaLongitud,
        MotivoPeso::MapaFueraTabla,
        MotivoPeso::FirmanteInactivo,
        MotivoPeso::Encadenado,
        MotivoPeso::Ancla,
        MotivoPeso::RaizEstado,
        MotivoPeso::FirmaFalsa,
        MotivoPeso::TablaNoDerivada,
        MotivoPeso::Quorum,
    ];

    /// Texto exacto del motivo (el de `CONTRATO-FV-v3.md`).
    #[must_use]
    pub const fn como_texto(self) -> &'static str {
        match self {
            MotivoPeso::Ventana => "ventana",
            MotivoPeso::SinPeso => "sin_peso",
            MotivoPeso::MapaLongitud => "mapa_longitud",
            MotivoPeso::MapaFueraTabla => "mapa_fuera_tabla",
            MotivoPeso::FirmanteInactivo => "firmante_inactivo",
            MotivoPeso::Encadenado => "encadenado",
            MotivoPeso::Ancla => "ancla",
            MotivoPeso::RaizEstado => "raiz_estado",
            MotivoPeso::FirmaFalsa => "firma_falsa",
            MotivoPeso::TablaNoDerivada => "tabla_no_derivada",
            MotivoPeso::Quorum => "quorum",
        }
    }

    /// Reconoce el texto de un motivo del vocabulario cerrado.
    #[must_use]
    pub fn desde_texto(texto: &str) -> Option<Self> {
        Self::TODOS
            .iter()
            .copied()
            .find(|motivo| motivo.como_texto() == texto)
    }
}

/// Longitud fija del certificado compacto (bytes): `n:8 + candidato:32 + h_t_siguiente:32 +
/// raíz:32 + firma:96`.
pub const LONGITUD_FIJA_CERTIFICADO_PESO: usize = 8 + 3 * LONGITUD_HASH + 96;

/// Certificado previo reducido a lo que exige el encadenado por peso (A5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertPrevioPeso {
    /// Instancia del certificado previo.
    pub n: u64,
    /// `h_T` que ese certificado comprometió como tabla siguiente.
    pub h_t_siguiente: Hash,
}

/// Entrada de la evaluación por peso (todos los datos fijados; las primitivas entran como dato).
#[derive(Clone, Copy, Debug)]
pub struct EntradaPeso<'a> {
    /// Prima de disponibilidad `b` (1 o 2).
    pub b: u64,
    /// `true` si es génesis (`n = 0`, sin `C_{−1}`).
    pub genesis: bool,
    /// Instancia que el certificado afirma.
    pub n_certificado: u64,
    /// Instancia realmente evaluada (`ventana`).
    pub ventana: u64,
    /// Tabla vigente `T_n`.
    pub tabla_vigente: &'a Tabla,
    /// Certificado previo `C_{n−1}` (o `None`).
    pub cert_previo: Option<CertPrevioPeso>,
    /// `h_T(n)` comprometido (`ancla_n`).
    pub tabla_comprometida: &'a Hash,
    /// Raíz de estado declarada.
    pub raiz_estado: &'a Hash,
    /// Raíz de estado realmente firmada.
    pub raiz_firmada: &'a Hash,
    /// Validez de la firma agregada (dato; el oráculo no ejecuta BLS).
    pub firma_ok: bool,
    /// `h_t_siguiente` declarado en el certificado.
    pub h_t_siguiente_declarada: &'a Hash,
    /// Huellas de tabla que el estado en que se aplica acepta como siguiente: la cola `Q(E)` en el
    /// camino con base (T3), o la única huella vigente sin base (T5) o de la instantánea de ciclo
    /// (T6). Si la declarada no está aquí, el motivo es [`MotivoPeso::TablaNoDerivada`].
    pub h_t_siguiente_aceptadas: &'a [Hash],
    /// `true` si es acta de presencia (mismo formato, sin exigir quórum).
    pub acta: bool,
    /// Mapa de bits de firmantes (`⌈N/8⌉` bytes).
    pub mapa_bits: &'a [u8],
}

/// Resultado de la evaluación por peso.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultadoPeso {
    /// `true` ⇔ [`ResultadoPeso::motivos`] vacía.
    pub valido: bool,
    /// Motivos aplicables, en el orden del contrato.
    pub motivos: Vec<MotivoPeso>,
    /// `Σ_{i∈S} w_i` de los firmantes (0 si el mapa es inválido).
    pub peso_firmantes: u128,
    /// `⌈2·W/3⌉` (umbral equivalente a `3·Σ ≥ 2·W`).
    pub umbral: u128,
    /// `W = Σ_i w_i`.
    pub w: u128,
    /// `true` si se evaluó como acta.
    pub acta: bool,
}

/// Certificado compacto por peso (A5/A6).
#[derive(Clone, Debug)]
pub struct CertificadoPeso {
    /// Instancia `n`.
    pub n: u64,
    /// Candidato sellado.
    pub candidato: Hash,
    /// `h_T(n+1)` declarado.
    pub h_t_siguiente: Hash,
    /// Raíz de estado firmada (`0^32` hasta PK-24 B).
    pub raiz_estado: Hash,
    /// Firma BLS agregada de los firmantes marcados.
    pub firma: FirmaAgregada,
    /// Mapa de bits sobre `T_n`.
    pub mapa: Vec<u8>,
}

impl PartialEq for CertificadoPeso {
    fn eq(&self, otra: &Self) -> bool {
        self.n == otra.n
            && self.candidato == otra.candidato
            && self.h_t_siguiente == otra.h_t_siguiente
            && self.raiz_estado == otra.raiz_estado
            && self.firma.bytes() == otra.firma.bytes()
            && self.mapa == otra.mapa
    }
}

impl Eq for CertificadoPeso {}

/// Peso efectivo `w_i` en `u128`: 0 si la clave está inactiva (A1).
///
/// # Errores
/// [`ErrorVotos::Desbordamiento`] si `w_i` no cabe en `u128`.
pub fn peso_de_clave(clave: &Clave, b: u64) -> Result<u128, ErrorVotos> {
    if !clave.activo {
        return Ok(0);
    }
    a_u128(&peso_efectivo(clave, b)?)
}

/// Peso total `W = Σ_i w_i` en `u128` (A1).
///
/// # Errores
/// [`ErrorVotos::Desbordamiento`] si `W` no cabe en `u128`.
pub fn peso_total_u128(tabla: &Tabla, b: u64) -> Result<u128, ErrorVotos> {
    a_u128(&peso_total(tabla, b)?)
}

/// Umbral equivalente a `3·Σ ≥ 2·W`: `⌈2W/3⌉` (A2).
#[must_use]
pub fn umbral_peso(w: u128) -> u128 {
    (2u128.saturating_mul(w)).div_ceil(3)
}

/// `true` si `3·Σ ≥ 2·W` (A2), exacto en `u128`.
#[must_use]
pub fn quorum_peso(sigma: u128, w: u128) -> bool {
    3u128.saturating_mul(sigma) >= 2u128.saturating_mul(w)
}

/// Índices (1-based) marcados en un mapa de bits; el bit `i` del byte `j` es la clave `8j+i+1`.
#[must_use]
pub fn firmantes_de_mapa(mapa: &[u8]) -> Vec<usize> {
    let mut indices = Vec::new();
    for (j, byte) in mapa.iter().enumerate() {
        for bit in 0..8u32 {
            if (byte >> bit) & 1 == 1 {
                indices.push((j << 3) + bit as usize + 1);
            }
        }
    }
    indices
}

/// Mensaje que firma un voto: `SHA-256(n_u64_be ‖ candidato ‖ h_t_siguiente ‖ raíz_de_estado)` (A3).
#[must_use]
pub fn mensaje_voto_peso(
    n: u64,
    candidato: &Hash,
    h_t_siguiente: &Hash,
    raiz_estado: &Hash,
) -> Hash {
    let mut bytes = Vec::with_capacity(8 + 3 * LONGITUD_HASH);
    bytes.extend_from_slice(&n.to_be_bytes());
    bytes.extend_from_slice(candidato);
    bytes.extend_from_slice(h_t_siguiente);
    bytes.extend_from_slice(raiz_estado);
    hash_bytes(&bytes)
}

/// Evalúa un certificado (o acta) por peso contra A1–A6.
///
/// Acumula **todos** los motivos aplicables en el orden del contrato, salvo los dos de mapa, que
/// devuelven únicamente ese motivo y detienen la verificación.
///
/// # Errores
/// Solo [`ErrorVotos::Desbordamiento`] si un peso no cabe en `u128`; ninguna entrada del contrato
/// provoca `panic`.
pub fn evaluar_certificado(entrada: &EntradaPeso<'_>) -> Result<ResultadoPeso, ErrorVotos> {
    let mut motivos: Vec<MotivoPeso> = Vec::new();

    if entrada.n_certificado != entrada.ventana {
        motivos.push(MotivoPeso::Ventana);
    }

    let claves = &entrada.tabla_vigente.claves;
    let n = claves.len();
    let b = entrada.b;
    let w = peso_total_u128(entrada.tabla_vigente, b)?;
    if w == 0 {
        motivos.push(MotivoPeso::SinPeso);
    }

    let mapa = entrada.mapa_bits;
    if mapa.len() != n.div_ceil(8) {
        return Ok(parada_por_mapa(MotivoPeso::MapaLongitud, w, entrada.acta));
    }
    let firmantes = firmantes_de_mapa(mapa);
    if firmantes.iter().any(|indice| *indice > n) {
        return Ok(parada_por_mapa(MotivoPeso::MapaFueraTabla, w, entrada.acta));
    }

    for indice in &firmantes {
        if let Some(clave) = indice
            .checked_sub(1)
            .and_then(|posicion| claves.get(posicion))
            && !clave.activo
        {
            motivos.push(MotivoPeso::FirmanteInactivo);
        }
    }

    let h_vig = hash_tabla(entrada.tabla_vigente);

    if !entrada.genesis {
        match entrada.cert_previo {
            None => motivos.push(MotivoPeso::Encadenado),
            Some(previo) => {
                if previo.n >= entrada.n_certificado {
                    motivos.push(MotivoPeso::Encadenado);
                }
                if previo.h_t_siguiente != h_vig {
                    motivos.push(MotivoPeso::Encadenado);
                }
            }
        }
    }
    if *entrada.tabla_comprometida != h_vig {
        motivos.push(MotivoPeso::Ancla);
    }
    if *entrada.raiz_estado != *entrada.raiz_firmada {
        motivos.push(MotivoPeso::RaizEstado);
    }
    if !entrada.firma_ok {
        motivos.push(MotivoPeso::FirmaFalsa);
    }

    // T3/T5/T6 · la huella siguiente declarada tiene que ser una de las que el estado acepta. En el
    // camino con base son las de la cola `Q(E)`; sin base o en rearranque, la única vigente. La
    // decisión no valida claves ni firmas.
    if !entrada
        .h_t_siguiente_aceptadas
        .contains(entrada.h_t_siguiente_declarada)
    {
        motivos.push(MotivoPeso::TablaNoDerivada);
    }

    let mut peso_firmantes: u128 = 0;
    for indice in &firmantes {
        if let Some(clave) = indice
            .checked_sub(1)
            .and_then(|posicion| claves.get(posicion))
        {
            peso_firmantes = peso_firmantes
                .checked_add(peso_de_clave(clave, b)?)
                .ok_or(ErrorVotos::Desbordamiento)?;
        }
    }

    let umbral = umbral_peso(w);
    if !entrada.acta && !quorum_peso(peso_firmantes, w) {
        motivos.push(MotivoPeso::Quorum);
    }

    Ok(ResultadoPeso {
        valido: motivos.is_empty(),
        motivos,
        peso_firmantes,
        umbral,
        w,
        acta: entrada.acta,
    })
}

/// Construye la firma agregada y el mapa a partir de votos sueltos (P3).
///
/// `votos` son pares `(índice 1-based en la tabla, firma individual sobre A3)`. Los índices repetidos
/// son idempotentes en el mapa, pero sus firmas se agregan igual (el llamador es responsable de no
/// repetir firmantes; la verificación no lo exige aquí).
///
/// # Errores
/// [`ErrorVotos::ClaveNoRegistrada`] si un índice cae fuera de `1..=N`;
/// [`ErrorVotos::Bls`] si la agregación falla (por ejemplo, lista vacía).
pub fn construir_certificado(
    n: u64,
    candidato: Hash,
    h_t_siguiente: Hash,
    raiz_estado: Hash,
    tabla: &Tabla,
    votos: &[(usize, Firma)],
) -> Result<CertificadoPeso, ErrorVotos> {
    let n_claves = tabla.claves.len();
    let mut mapa = vec![0u8; n_claves.div_ceil(8)];
    let mut firmas: Vec<&Firma> = Vec::with_capacity(votos.len());
    for (indice, firma) in votos {
        let posicion = indice
            .checked_sub(1)
            .filter(|posicion| *posicion < n_claves)
            .ok_or(ErrorVotos::ClaveNoRegistrada)?;
        if let Some(byte) = mapa.get_mut(posicion >> 3) {
            *byte |= 1 << (posicion & 7);
        }
        firmas.push(firma);
    }
    let firma = agregar_firmas(&firmas)?;
    Ok(CertificadoPeso {
        n,
        candidato,
        h_t_siguiente,
        raiz_estado,
        firma,
        mapa,
    })
}

/// Verifica la firma BLS agregada sobre A3 con las claves públicas que marca el mapa (P3).
///
/// # Errores
/// [`ErrorVotos::LongitudesIncompatibles`] si `claves.len() != tabla.claves.len()`;
/// [`ErrorVotos::LongitudInesperada`] si el mapa no mide `⌈N/8⌉`;
/// [`ErrorVotos::ClaveNoRegistrada`] si el mapa marca un bit fuera de `1..N`;
/// [`ErrorVotos::Bls`] si la firma agregada no verifica.
pub fn verificar_firma_peso(
    tabla: &Tabla,
    claves: &[ClavePublica],
    certificado: &CertificadoPeso,
) -> Result<(), ErrorVotos> {
    if claves.len() != tabla.claves.len() {
        return Err(ErrorVotos::LongitudesIncompatibles {
            claves: claves.len(),
            plazas: tabla.claves.len(),
        });
    }
    let n = tabla.claves.len();
    let esperado = n.div_ceil(8);
    if certificado.mapa.len() != esperado {
        return Err(ErrorVotos::LongitudInesperada {
            esperado,
            obtenido: certificado.mapa.len(),
        });
    }
    let mut publicas: Vec<&ClavePublica> = Vec::new();
    for indice in firmantes_de_mapa(&certificado.mapa) {
        let posicion = indice
            .checked_sub(1)
            .filter(|posicion| *posicion < n)
            .ok_or(ErrorVotos::ClaveNoRegistrada)?;
        publicas.push(claves.get(posicion).ok_or(ErrorVotos::ClaveNoRegistrada)?);
    }
    let mensaje = mensaje_voto_peso(
        certificado.n,
        &certificado.candidato,
        &certificado.h_t_siguiente,
        &certificado.raiz_estado,
    );
    fast_aggregate_verify(&publicas, &certificado.firma, DOMINIO_VOTO, &mensaje)?;
    Ok(())
}

/// Verifica A3 descomprimiendo y validando solo las claves marcadas por el mapa.
///
/// Los bytes se toman de `tabla.claves` en su orden almacenado; no se consulta la memoria global
/// de claves. La forma completa del mapa se comprueba antes de descomprimir. Una clave inválida
/// **no firmante** no se examina: a diferencia de preparar la tabla entera, no causa rechazo.
/// La equivalencia con el camino actual exige que todas las claves de la tabla sean válidas;
/// posesión, autenticación de la tabla y demás reglas de consenso siguen siendo externas.
///
/// # Errores
/// Los mismos errores de mapa, mapa vacío, suma infinita y firma falsa que
/// [`verificar_firma_peso`]. [`ErrorVotos::Bls`] si una clave **firmante** es inválida.
pub fn verificar_firma_peso_selectiva(
    tabla: &Tabla,
    certificado: &CertificadoPeso,
) -> Result<(), ErrorVotos> {
    let n = tabla.claves.len();
    let esperado = n.div_ceil(8);
    if certificado.mapa.len() != esperado {
        return Err(ErrorVotos::LongitudInesperada {
            esperado,
            obtenido: certificado.mapa.len(),
        });
    }
    let indices = firmantes_de_mapa(&certificado.mapa);
    if indices.iter().any(|indice| *indice > n) {
        return Err(ErrorVotos::ClaveNoRegistrada);
    }
    let mut claves = Vec::with_capacity(indices.len());
    for indice in indices {
        let bytes = tabla
            .claves
            .get(indice - 1)
            .ok_or(ErrorVotos::ClaveNoRegistrada)?;
        claves.push(ClavePublica::desde_bytes(&bytes.clave)?);
    }
    let publicas: Vec<&ClavePublica> = claves.iter().collect();
    let mensaje = mensaje_voto_peso(
        certificado.n,
        &certificado.candidato,
        &certificado.h_t_siguiente,
        &certificado.raiz_estado,
    );
    fast_aggregate_verify(&publicas, &certificado.firma, DOMINIO_VOTO, &mensaje)?;
    Ok(())
}

/// Verifica A3 con una tabla de puntos ya validados, sin volver a descomprimirlos ni validarlos.
///
/// `claves` debe proceder de los bytes de `tabla.claves` **en el mismo orden**, como el vector
/// que recibe [`verificar_firma_peso`]. La tabla preparada no acredita PoP, origen ni pesos.
/// Reutiliza exactamente el verificador existente, incluidos sus errores y su precedencia.
///
/// # Errores
/// Los mismos que [`verificar_firma_peso`], incluida la longitud incompatible de las tablas.
pub fn verificar_firma_peso_preparada(
    tabla: &Tabla,
    claves: &zx_bls::ClavesPreparadas,
    certificado: &CertificadoPeso,
) -> Result<(), ErrorVotos> {
    verificar_firma_peso(tabla, claves.claves(), certificado)
}

/// Serializa canónicamente un certificado compacto (A5/P4/T2).
///
/// El cuerpo es la parte fija más el mapa, **nada detrás**.
#[must_use]
pub fn serial_certificado_peso(certificado: &CertificadoPeso) -> Vec<u8> {
    let mut salida = Vec::with_capacity(LONGITUD_FIJA_CERTIFICADO_PESO + certificado.mapa.len());
    salida.extend_from_slice(&certificado.n.to_be_bytes());
    salida.extend_from_slice(&certificado.candidato);
    salida.extend_from_slice(&certificado.h_t_siguiente);
    salida.extend_from_slice(&certificado.raiz_estado);
    salida.extend_from_slice(&certificado.firma.bytes());
    salida.extend_from_slice(&certificado.mapa);
    salida
}

/// Deserializa la forma canónica de [`serial_certificado_peso`].
///
/// `n_claves_vigente` fija la longitud del mapa (`⌈N/8⌉`). Un solo byte detrás del mapa es un
/// rechazo **por forma** (T2).
///
/// # Errores
/// [`ErrorVotos::LongitudInesperada`] si el flujo se trunca;
/// [`ErrorVotos::BytesSobrantes`] si hay algo detrás del mapa;
/// [`ErrorVotos::Bls`] si la firma no es un punto válido de G2.
pub fn deserializar_certificado_peso(
    bytes: &[u8],
    n_claves_vigente: usize,
) -> Result<CertificadoPeso, ErrorVotos> {
    let longitud_mapa = n_claves_vigente.div_ceil(8);
    let minimo = LONGITUD_FIJA_CERTIFICADO_PESO + longitud_mapa;
    if bytes.len() < minimo {
        return Err(ErrorVotos::LongitudInesperada {
            esperado: minimo,
            obtenido: bytes.len(),
        });
    }
    if bytes.len() > minimo {
        return Err(ErrorVotos::BytesSobrantes {
            sobran: bytes.len() - minimo,
        });
    }
    let n = u64_be(bytes, 0)?;
    let candidato = hash_be(bytes, 8)?;
    let h_t_siguiente = hash_be(bytes, 40)?;
    let raiz_estado = hash_be(bytes, 72)?;
    let firma_individual = Firma::desde_bytes(trozo(bytes, 104, 96)?)?;
    let firma = FirmaAgregada::desde_firma(&firma_individual);
    let mapa = trozo(bytes, LONGITUD_FIJA_CERTIFICADO_PESO, longitud_mapa)?.to_vec();

    Ok(CertificadoPeso {
        n,
        candidato,
        h_t_siguiente,
        raiz_estado,
        firma,
        mapa,
    })
}

/// Materializa el resultado que devuelven los dos motivos de mapa (detienen la verificación).
fn parada_por_mapa(motivo: MotivoPeso, w: u128, acta: bool) -> ResultadoPeso {
    ResultadoPeso {
        valido: false,
        motivos: vec![motivo],
        peso_firmantes: 0,
        umbral: umbral_peso(w),
        w,
        acta,
    }
}

/// `BigUint` → `u128` con error de desbordamiento.
fn a_u128(valor: &num_bigint::BigUint) -> Result<u128, ErrorVotos> {
    valor.to_u128().ok_or(ErrorVotos::Desbordamiento)
}

/// Trozo acotado `[inicio, inicio+n)`.
fn trozo(bytes: &[u8], inicio: usize, n: usize) -> Result<&[u8], ErrorVotos> {
    let fin = inicio.checked_add(n).ok_or(ErrorVotos::Desbordamiento)?;
    bytes
        .get(inicio..fin)
        .ok_or(ErrorVotos::LongitudInesperada {
            esperado: fin,
            obtenido: bytes.len(),
        })
}

/// `u64` big-endian en `inicio`.
fn u64_be(bytes: &[u8], inicio: usize) -> Result<u64, ErrorVotos> {
    let mut arreglo = [0u8; 8];
    arreglo.copy_from_slice(trozo(bytes, inicio, 8)?);
    Ok(u64::from_be_bytes(arreglo))
}

/// Hash de 32 bytes en `inicio`.
fn hash_be(bytes: &[u8], inicio: usize) -> Result<Hash, ErrorVotos> {
    let mut hash = [0u8; LONGITUD_HASH];
    hash.copy_from_slice(trozo(bytes, inicio, LONGITUD_HASH)?);
    Ok(hash)
}

#[cfg(test)]
mod pruebas {
    use super::{
        CertPrevioPeso, CertificadoPeso, EntradaPeso, LONGITUD_FIJA_CERTIFICADO_PESO, MotivoPeso,
        construir_certificado, deserializar_certificado_peso, evaluar_certificado,
        firmantes_de_mapa, mensaje_voto_peso, peso_total_u128, quorum_peso,
        serial_certificado_peso, verificar_firma_peso,
    };
    use crate::bls::DOMINIO_VOTO;
    use crate::error::ErrorVotos;
    use crate::json::Json;
    use crate::serial::hash_tabla;
    use crate::tipos::{Clave, Hash, LONGITUD_HASH, Tabla};
    use zx_bls::{ClaveSecreta, Firma, firmar};

    /// Vectores del oráculo FV-3 v3 (copiados a `tests/datos/pdm1/`).
    const POSITIVOS: &str = include_str!("../tests/datos/pdm1/positivos.jsonl");
    const NEGATIVOS: &str = include_str!("../tests/datos/pdm1/negativos.jsonl");

    // ── utilidades de generación determinista ────────────────────────────────────────────────

    /// SplitMix64: RNG determinista para las propiedades (semilla explícita, sin estado global).
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn siguiente(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn byte(&mut self) -> u8 {
            (self.siguiente() & 0xff) as u8
        }

        fn clave(&mut self, longitud: usize) -> Vec<u8> {
            let mut clave = vec![0u8; longitud];
            for byte in &mut clave {
                *byte = self.byte();
            }
            clave
        }
    }

    /// Tabla con claves arbitrarias de `longitud_clave` bytes (sin BLS).
    fn tabla_falsa(rng: &mut SplitMix64, n: usize, longitud_clave: usize, b: u64) -> Tabla {
        let mut claves = Vec::with_capacity(n);
        for _ in 0..n {
            claves.push(Clave {
                clave: rng.clave(longitud_clave),
                peso: u64::from(rng.byte() % 4),
                activo: !rng.byte().is_multiple_of(5),
                prueba: b == 2 && rng.byte().is_multiple_of(3),
                garantia: 0,
            });
        }
        Tabla { n: 0, claves }
    }

    /// Tabla plana y determinista: `n` claves iguales (sin BLS).
    fn tabla_plana(n: usize, peso: u64, activo: bool, prueba: bool) -> Tabla {
        Tabla {
            n: 0,
            claves: (0..n)
                .map(|i| Clave {
                    clave: vec![(i & 0xff) as u8; 32],
                    peso,
                    activo,
                    prueba,
                    garantia: 0,
                })
                .collect(),
        }
    }

    fn mapa_de_indices(n: usize, indices: &[usize]) -> Vec<u8> {
        let mut mapa = vec![0u8; n.div_ceil(8)];
        for indice in indices {
            if let Some(posicion) = indice.checked_sub(1)
                && let Some(byte) = mapa.get_mut(posicion >> 3)
            {
                *byte |= 1 << (posicion & 7);
            }
        }
        mapa
    }

    fn motivos_texto(resultado: &super::ResultadoPeso) -> Vec<String> {
        resultado
            .motivos
            .iter()
            .map(|motivo| motivo.como_texto().to_string())
            .collect()
    }

    // ── D1 · diferencial contra los 21 vectores ──────────────────────────────────────────────

    fn json_u8_vec(valor: &Json) -> Result<Vec<u8>, ErrorVotos> {
        let arreglo = valor
            .como_arreglo()
            .ok_or(ErrorVotos::CampoAusente("arreglo de bytes"))?;
        let mut salida = Vec::with_capacity(arreglo.len());
        for elemento in arreglo {
            let entero = elemento
                .como_entero()
                .ok_or(ErrorVotos::CampoAusente("byte"))?;
            salida.push(
                u8::try_from(entero).map_err(|_| ErrorVotos::Json("byte fuera de u8".into()))?,
            );
        }
        Ok(salida)
    }

    fn json_hash(valor: &Json) -> Result<Hash, ErrorVotos> {
        let bytes = json_u8_vec(valor)?;
        if bytes.len() != LONGITUD_HASH {
            return Err(ErrorVotos::LongitudInesperada {
                esperado: LONGITUD_HASH,
                obtenido: bytes.len(),
            });
        }
        let mut hash = [0u8; LONGITUD_HASH];
        for (destino, origen) in hash.iter_mut().zip(bytes.iter()) {
            *destino = *origen;
        }
        Ok(hash)
    }

    fn json_u64(valor: &Json, campo: &'static str) -> Result<u64, ErrorVotos> {
        let entero = valor.como_entero().ok_or(ErrorVotos::CampoAusente(campo))?;
        u64::try_from(entero).map_err(|_| ErrorVotos::Json("entero negativo".into()))
    }

    fn json_tabla(valor: &Json) -> Result<Tabla, ErrorVotos> {
        let claves_json = valor
            .campo("claves")
            .and_then(Json::como_arreglo)
            .ok_or(ErrorVotos::CampoAusente("claves"))?;
        let mut claves = Vec::with_capacity(claves_json.len());
        for clave_json in claves_json {
            claves.push(Clave {
                clave: json_u8_vec(
                    clave_json
                        .campo("clave")
                        .ok_or(ErrorVotos::CampoAusente("clave"))?,
                )?,
                peso: json_u64(
                    clave_json
                        .campo("peso")
                        .ok_or(ErrorVotos::CampoAusente("peso"))?,
                    "peso",
                )?,
                activo: clave_json
                    .campo("activo")
                    .and_then(Json::como_bool)
                    .ok_or(ErrorVotos::CampoAusente("activo"))?,
                prueba: clave_json
                    .campo("prueba")
                    .and_then(Json::como_bool)
                    .ok_or(ErrorVotos::CampoAusente("prueba"))?,
                garantia: 0,
            });
        }
        Ok(Tabla { n: 0, claves })
    }

    /// Compara un vector con el veredicto del módulo. Devuelve `true` si coincide del todo.
    fn comprobar_vector(json: &Json) -> Result<(bool, Vec<String>), ErrorVotos> {
        let b = json_u64(json.campo("b").ok_or(ErrorVotos::CampoAusente("b"))?, "b")?;
        let genesis = json
            .campo("genesis")
            .and_then(Json::como_bool)
            .ok_or(ErrorVotos::CampoAusente("genesis"))?;
        let n = json_u64(json.campo("n").ok_or(ErrorVotos::CampoAusente("n"))?, "n")?;
        let ventana = json_u64(
            json.campo("ventana")
                .ok_or(ErrorVotos::CampoAusente("ventana"))?,
            "ventana",
        )?;
        let tabla_vigente = json_tabla(
            json.campo("tabla_vigente")
                .ok_or(ErrorVotos::CampoAusente("tabla_vigente"))?,
        )?;
        let cert_previo = match json.campo("cert_previo") {
            None | Some(Json::Null) => None,
            Some(valor) => Some(CertPrevioPeso {
                n: json_u64(valor.campo("n").ok_or(ErrorVotos::CampoAusente("n"))?, "n")?,
                h_t_siguiente: json_hash(
                    valor
                        .campo("h_t_siguiente")
                        .ok_or(ErrorVotos::CampoAusente("h_t_siguiente"))?,
                )?,
            }),
        };
        let tabla_comprometida = json_hash(
            json.campo("tabla_comprometida")
                .ok_or(ErrorVotos::CampoAusente("tabla_comprometida"))?,
        )?;
        let raiz_estado = json_hash(
            json.campo("raiz_estado")
                .ok_or(ErrorVotos::CampoAusente("raiz_estado"))?,
        )?;
        let raiz_firmada = json_hash(
            json.campo("raiz_firmada")
                .ok_or(ErrorVotos::CampoAusente("raiz_firmada"))?,
        )?;
        let firma_ok = json
            .campo("firma_ok")
            .and_then(Json::como_bool)
            .ok_or(ErrorVotos::CampoAusente("firma_ok"))?;
        let h_t_siguiente_declarada = json_hash(
            json.campo("h_t_siguiente_declarada")
                .ok_or(ErrorVotos::CampoAusente("h_t_siguiente_declarada"))?,
        )?;
        let tabla_siguiente = match json.campo("tabla_siguiente") {
            None | Some(Json::Null) => None,
            Some(valor) => Some(json_tabla(valor)?),
        };
        // T3/T5/T6 · huellas aceptadas: la tabla derivada que el vector declara (si la trae) o, en
        // su defecto, la vigente. Es la `Q` mínima que reproduce el vector.
        let h_vigente = hash_tabla(&tabla_vigente);
        let h_aceptadas: Vec<Hash> = match tabla_siguiente.as_ref() {
            Some(siguiente) => vec![hash_tabla(siguiente)],
            None => vec![h_vigente],
        };
        let acta = json
            .campo("acta")
            .and_then(Json::como_bool)
            .ok_or(ErrorVotos::CampoAusente("acta"))?;
        let mapa_bits = json_u8_vec(
            json.campo("mapa_bits")
                .ok_or(ErrorVotos::CampoAusente("mapa_bits"))?,
        )?;

        let entrada = EntradaPeso {
            b,
            genesis,
            n_certificado: n,
            ventana,
            tabla_vigente: &tabla_vigente,
            cert_previo,
            tabla_comprometida: &tabla_comprometida,
            raiz_estado: &raiz_estado,
            raiz_firmada: &raiz_firmada,
            firma_ok,
            h_t_siguiente_declarada: &h_t_siguiente_declarada,
            h_t_siguiente_aceptadas: &h_aceptadas,
            acta,
            mapa_bits: &mapa_bits,
        };
        let resultado = evaluar_certificado(&entrada)?;

        let esperado = json
            .campo("esperado")
            .ok_or(ErrorVotos::CampoAusente("esperado"))?;
        let esperado_valido = esperado
            .campo("certificado_valido")
            .and_then(Json::como_bool)
            .ok_or(ErrorVotos::CampoAusente("certificado_valido"))?;
        let esperado_motivos: Vec<String> = esperado
            .campo("motivos")
            .and_then(Json::como_arreglo)
            .ok_or(ErrorVotos::CampoAusente("motivos"))?
            .iter()
            .filter_map(|motivo| motivo.como_texto().map(str::to_string))
            // T3 · los dos motivos de tabla siguiente se funden en `tabla_no_derivada`. La
            // afirmación del vector no cambia; solo su nombre.
            .map(|motivo| match motivo.as_str() {
                "hash_tabla_siguiente" | "tabla_siguiente_ausente" => {
                    "tabla_no_derivada".to_string()
                }
                _ => motivo,
            })
            .collect();
        let esperado_peso = json_u64(
            esperado
                .campo("peso_firmantes")
                .ok_or(ErrorVotos::CampoAusente("peso_firmantes"))?,
            "peso_firmantes",
        )?;
        let esperado_umbral: u128 = esperado
            .campo("umbral")
            .and_then(Json::como_texto)
            .ok_or(ErrorVotos::CampoAusente("umbral"))?
            .parse()
            .map_err(|_| ErrorVotos::Json("umbral no entero".into()))?;
        let esperado_w = json_u64(
            esperado.campo("W").ok_or(ErrorVotos::CampoAusente("W"))?,
            "W",
        )?;

        let motivos = motivos_texto(&resultado);
        let coincide = resultado.valido == esperado_valido
            && motivos == esperado_motivos
            && resultado.peso_firmantes == u128::from(esperado_peso)
            && resultado.umbral == esperado_umbral
            && resultado.w == u128::from(esperado_w);
        Ok((coincide, motivos))
    }

    #[test]
    fn d1_21_vectores_sin_discrepancias() -> Result<(), ErrorVotos> {
        let mut total = 0usize;
        let mut discrepancias = 0usize;
        for (nombre, texto) in [("positivos", POSITIVOS), ("negativos", NEGATIVOS)] {
            for linea in texto.lines() {
                if linea.trim().is_empty() {
                    continue;
                }
                total += 1;
                let json = Json::parsear(linea)?;
                let (coincide, _) = comprobar_vector(&json)?;
                if !coincide {
                    discrepancias += 1;
                    let id = json
                        .campo("id")
                        .and_then(Json::como_texto)
                        .unwrap_or(nombre);
                    std::eprintln!("discrepancia en {id}");
                }
            }
        }
        assert_eq!(total, 21, "se esperaban 21 vectores");
        assert_eq!(discrepancias, 0, "discrepancias contra el oráculo");
        Ok(())
    }

    /// Gemela de `d1_21_vectores_sin_discrepancias` con la lectura **con cola** (T3): los mismos 21
    /// vectores, con `h_t_siguiente_aceptadas` como `Q` y el motivo `tabla_no_derivada` en lugar de
    /// los dos motivos retirados. Comprueba además que los dos vectores que miraban la tabla
    /// siguiente son los que ahora dan `tabla_no_derivada`.
    #[test]
    fn d1_21_vectores_con_cola() -> Result<(), ErrorVotos> {
        let mut total = 0usize;
        let mut con_motivo_nuevo = 0usize;
        for (nombre, texto) in [("positivos", POSITIVOS), ("negativos", NEGATIVOS)] {
            for linea in texto.lines() {
                if linea.trim().is_empty() {
                    continue;
                }
                total += 1;
                let json = Json::parsear(linea)?;
                let (coincide, motivos) = comprobar_vector(&json)?;
                assert!(coincide, "{nombre}: discrepancia con Q");
                if motivos.iter().any(|m| m == "tabla_no_derivada") {
                    con_motivo_nuevo += 1;
                }
            }
        }
        assert_eq!(total, 21, "se esperaban 21 vectores");
        assert_eq!(
            con_motivo_nuevo, 2,
            "los dos vectores de tabla siguiente deben dar tabla_no_derivada"
        );
        Ok(())
    }

    // ── D2 · borde del quórum ────────────────────────────────────────────────────────────────

    #[test]
    fn d2_borde_del_quorum() -> Result<(), ErrorVotos> {
        let tabla = tabla_plana(3, 1, true, false);
        // W = 3 (tres claves activas de peso 1).
        let w = peso_total_u128(&tabla, 1)?;
        assert_eq!(w, 3);
        let h = hash_tabla(&tabla);
        let cero = [0u8; LONGITUD_HASH];

        let evaluar = |mapa: &[u8]| {
            evaluar_certificado(&EntradaPeso {
                b: 1,
                genesis: true,
                n_certificado: 0,
                ventana: 0,
                tabla_vigente: &tabla,
                cert_previo: None,
                tabla_comprometida: &h,
                raiz_estado: &cero,
                raiz_firmada: &cero,
                firma_ok: true,
                h_t_siguiente_declarada: &h,
                h_t_siguiente_aceptadas: std::slice::from_ref(&h),
                acta: false,
                mapa_bits: mapa,
            })
        };

        // 3·Σ = 2·W exacto: Σ = 2, 3·2 = 6 = 2·3 → válido.
        let exacto = evaluar(&mapa_de_indices(3, &[1, 2]))?;
        assert!(exacto.valido, "borde exacto debe ser válido: {exacto:?}");
        assert!(quorum_peso(2, 3));

        // Una unidad menos: Σ = 1 → quorum.
        let insuficiente = evaluar(&mapa_de_indices(3, &[1]))?;
        assert!(!insuficiente.valido);
        assert_eq!(motivos_texto(&insuficiente), vec!["quorum"]);
        Ok(())
    }

    // ── D3 · propiedad de intersección (12 semillas) ─────────────────────────────────────────

    #[test]
    fn d3_interseccion_al_menos_un_tercio() -> Result<(), ErrorVotos> {
        for semilla in 0..12u64 {
            let mut rng = SplitMix64(0xD3_0000 + semilla.wrapping_mul(0x9e37));
            let n = 20usize;
            let tabla = tabla_falsa(&mut rng, n, 24, 1);
            let w = peso_total_u128(&tabla, 1)?;
            assert!(w > 0, "semilla {semilla}: W = 0");
            let h = hash_tabla(&tabla);
            let cero = [0u8; LONGITUD_HASH];

            // Dos subconjuntos quórum independientes (muestreo por rechazo).
            let muestrear = |rng: &mut SplitMix64| -> Vec<usize> {
                for _ in 0..200_000 {
                    let mascara = rng.siguiente();
                    let mut indices = Vec::new();
                    let mut sigma: u128 = 0;
                    for i in 0..n {
                        if (mascara >> i) & 1 == 1
                            && let Some(clave) = tabla.claves.get(i)
                            && clave.activo
                        {
                            indices.push(i + 1);
                            sigma += u128::from(clave.peso);
                        }
                    }
                    if quorum_peso(sigma, w) {
                        return indices;
                    }
                }
                Vec::new()
            };
            let s1 = muestrear(&mut rng);
            let s2 = muestrear(&mut rng);
            assert!(
                !s1.is_empty() && !s2.is_empty(),
                "semilla {semilla}: sin quórum"
            );

            let evaluar = |mapa: &[u8]| {
                evaluar_certificado(&EntradaPeso {
                    b: 1,
                    genesis: true,
                    n_certificado: 0,
                    ventana: 0,
                    tabla_vigente: &tabla,
                    cert_previo: None,
                    tabla_comprometida: &h,
                    raiz_estado: &cero,
                    raiz_firmada: &cero,
                    firma_ok: true,
                    h_t_siguiente_declarada: &h,
                    h_t_siguiente_aceptadas: std::slice::from_ref(&h),
                    acta: false,
                    mapa_bits: mapa,
                })
            };
            let r1 = evaluar(&mapa_de_indices(n, &s1))?;
            let r2 = evaluar(&mapa_de_indices(n, &s2))?;
            assert!(
                r1.valido && r2.valido,
                "semilla {semilla}: certificados no válidos"
            );

            // Intersección por índice; el peso de un índice activo es su peso bruto (b=1).
            let mut inter: u128 = 0;
            for indice in &s1 {
                if s2.contains(indice)
                    && let Some(clave) = indice
                        .checked_sub(1)
                        .and_then(|posicion| tabla.claves.get(posicion))
                {
                    inter += u128::from(if clave.activo { clave.peso } else { 0 });
                }
            }
            assert!(
                3 * inter >= w,
                "semilla {semilla}: intersección {inter} < W/3 = {}",
                w
            );
        }
        Ok(())
    }

    // ── D4 · motivos de mapa (detienen) ──────────────────────────────────────────────────────

    #[test]
    fn d4_mapa_detiene() -> Result<(), ErrorVotos> {
        let tabla = tabla_plana(3, 1, true, false);
        let h = hash_tabla(&tabla);
        let cero = [0u8; LONGITUD_HASH];
        let distinto = [9u8; LONGITUD_HASH];

        let evaluar = |mapa: &[u8]| {
            evaluar_certificado(&EntradaPeso {
                b: 1,
                genesis: true,
                n_certificado: 0,
                ventana: 0,
                tabla_vigente: &tabla,
                cert_previo: None,
                // Aunque la raíz y la firma también fallen, el mapa detiene y manda solo.
                tabla_comprometida: &h,
                raiz_estado: &distinto,
                raiz_firmada: &cero,
                firma_ok: false,
                h_t_siguiente_declarada: &h,
                h_t_siguiente_aceptadas: std::slice::from_ref(&h),
                acta: false,
                mapa_bits: mapa,
            })
        };

        let longitud = evaluar(&[0u8, 0, 0])?;
        assert_eq!(motivos_texto(&longitud), vec!["mapa_longitud"]);
        assert_eq!(longitud.peso_firmantes, 0);

        let fuera = evaluar(&[0b1111_1000])?;
        assert_eq!(motivos_texto(&fuera), vec!["mapa_fuera_tabla"]);
        assert_eq!(fuera.peso_firmantes, 0);
        Ok(())
    }

    // ── D5 · firma BLS real ──────────────────────────────────────────────────────────────────

    fn par_bls(semilla: u64) -> Result<(ClaveSecreta, zx_bls::ClavePublica), ErrorVotos> {
        let mut ikm = [0u8; 32];
        for (i, byte) in ikm.iter_mut().enumerate() {
            *byte = ((semilla.wrapping_add(i as u64)) & 0xff) as u8;
        }
        let secreta = ClaveSecreta::generar(&ikm)?;
        let publica = secreta.clave_publica();
        Ok((secreta, publica))
    }

    #[test]
    fn d5_firma_agregada_real() -> Result<(), ErrorVotos> {
        let mut secreta = Vec::new();
        let mut publica = Vec::new();
        for semilla in 0..4u64 {
            let (sk, pk) = par_bls(0xD5_0000 + semilla)?;
            secreta.push(sk);
            publica.push(pk);
        }
        let tabla = Tabla {
            n: 1,
            claves: publica
                .iter()
                .map(|pk| Clave {
                    clave: pk.bytes().to_vec(),
                    peso: 1,
                    activo: true,
                    prueba: false,
                    garantia: 0,
                })
                .collect(),
        };
        let candidato = [3u8; LONGITUD_HASH];
        let h_t_siguiente = [4u8; LONGITUD_HASH];
        let raiz = [0u8; LONGITUD_HASH];
        let mensaje = mensaje_voto_peso(1, &candidato, &h_t_siguiente, &raiz);
        let mut votos: Vec<(usize, Firma)> = Vec::new();
        for (indice, sk) in secreta.iter().enumerate() {
            votos.push((indice + 1, firmar(sk, DOMINIO_VOTO, mensaje.as_slice())?));
        }
        let certificado = construir_certificado(
            1,
            candidato,
            h_t_siguiente,
            raiz,
            &tabla,
            votos.get(0..3).ok_or(ErrorVotos::CampoAusente("votos"))?,
        )?;
        verificar_firma_peso(&tabla, &publica, &certificado)?;

        // Un firmante cambiado: la firma agregada es de {0,1,3}, el mapa marca {0,1,2}.
        let cambiado = CertificadoPeso {
            firma: {
                let firmas: Vec<&Firma> = votos
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != 2)
                    .map(|(_, (_, firma))| firma)
                    .collect();
                zx_bls::agregar_firmas(&firmas)?
            },
            ..certificado
        };
        assert!(verificar_firma_peso(&tabla, &publica, &cambiado).is_err());
        Ok(())
    }

    // ── D6 · acta bajo quórum ────────────────────────────────────────────────────────────────

    #[test]
    fn d6_acta_bajo_quorum() -> Result<(), ErrorVotos> {
        let tabla = tabla_plana(3, 1, true, false);
        let h = hash_tabla(&tabla);
        let cero = [0u8; LONGITUD_HASH];
        let mapa = mapa_de_indices(3, &[1]); // Σ = 1 < 2 = ⌈2·3/3⌉.
        let evaluar = |acta: bool| {
            evaluar_certificado(&EntradaPeso {
                b: 1,
                genesis: true,
                n_certificado: 0,
                ventana: 0,
                tabla_vigente: &tabla,
                cert_previo: None,
                tabla_comprometida: &h,
                raiz_estado: &cero,
                raiz_firmada: &cero,
                firma_ok: true,
                h_t_siguiente_declarada: &h,
                h_t_siguiente_aceptadas: std::slice::from_ref(&h),
                acta,
                mapa_bits: &mapa,
            })
        };
        let acta = evaluar(true)?;
        assert!(acta.valido && acta.acta);
        let certificado = evaluar(false)?;
        assert_eq!(motivos_texto(&certificado), vec!["quorum"]);
        Ok(())
    }

    // ── D7 · serialización ───────────────────────────────────────────────────────────────────

    fn certificado_de_prueba(n_claves: usize) -> Result<CertificadoPeso, ErrorVotos> {
        let (secreta, publica) = par_bls(0xD7)?;
        let tabla = Tabla {
            n: 0,
            claves: (0..n_claves)
                .map(|i| Clave {
                    clave: vec![(i & 0xff) as u8; 48],
                    peso: 1,
                    activo: true,
                    prueba: false,
                    garantia: 0,
                })
                .collect(),
        };
        // La clave real firma; las demás claves de relleno no hace falta que sean válidas para el
        // round-trip (solo se serializan bytes).
        let candidato = [5u8; LONGITUD_HASH];
        let h_t_siguiente = [6u8; LONGITUD_HASH];
        let raiz = [0u8; LONGITUD_HASH];
        let mensaje = mensaje_voto_peso(2, &candidato, &h_t_siguiente, &raiz);
        let firma_real = firmar(&secreta, DOMINIO_VOTO, mensaje.as_slice())?;
        let _ = publica;
        construir_certificado(
            2,
            candidato,
            h_t_siguiente,
            raiz,
            &tabla,
            &[(1, firma_real)],
        )
    }

    #[test]
    fn d7_codec_sin_cola() -> Result<(), ErrorVotos> {
        for n in [3usize, 1_000, 65_536] {
            let certificado = certificado_de_prueba(n)?;
            let bytes = serial_certificado_peso(&certificado);
            assert_eq!(bytes.len(), LONGITUD_FIJA_CERTIFICADO_PESO + n.div_ceil(8));
            let vuelta = deserializar_certificado_peso(&bytes, n)?;
            assert_eq!(vuelta, certificado);
        }
        Ok(())
    }

    /// T2 · cualquier byte detrás del mapa se rechaza **por forma**: el códec ya no lee ninguna
    /// tabla siguiente, ni con un byte ni con la tabla entera.
    #[test]
    fn d9_sin_cola_se_rechaza_por_forma() -> Result<(), ErrorVotos> {
        let certificado = certificado_de_prueba(3)?;
        let mut bytes = serial_certificado_peso(&certificado);
        bytes.push(0);
        let error = deserializar_certificado_peso(&bytes, 3);
        assert!(
            matches!(error, Err(ErrorVotos::BytesSobrantes { sobran: 1 })),
            "un byte detrás debe ser BytesSobrantes(1): {error:?}"
        );
        // Una tabla entera detrás tampoco se interpreta.
        let tabla = Tabla {
            n: 3,
            claves: (0..3)
                .map(|i| Clave {
                    clave: vec![(i + 1) as u8; 48],
                    peso: 7,
                    activo: true,
                    prueba: true,
                    garantia: 0,
                })
                .collect(),
        };
        bytes.truncate(LONGITUD_FIJA_CERTIFICADO_PESO + 1);
        bytes.extend_from_slice(&crate::serial::serial_tabla(&tabla));
        assert!(deserializar_certificado_peso(&bytes, 3).is_err());
        Ok(())
    }

    // ── D8 · tiempos (ignorado por defecto; se ejecuta a mano y se guarda en logs/) ──────────

    #[test]
    #[ignore = "D8: comparación de tiempos; se ejecuta explícitamente"]
    fn d8_tiempos() -> Result<(), ErrorVotos> {
        let mut rng = SplitMix64(0xD8);
        for n in [4usize, 64, 1_024, 4_096] {
            // Tabla de claves reales + firmas reales sobre A3.
            let mut secretas = Vec::with_capacity(n);
            let mut publicas = Vec::with_capacity(n);
            let mut claves = Vec::with_capacity(n);
            for _ in 0..n {
                let (sk, pk) = par_bls(rng.siguiente())?;
                claves.push(Clave {
                    clave: pk.bytes().to_vec(),
                    peso: 1,
                    activo: true,
                    prueba: false,
                    garantia: 0,
                });
                secretas.push(sk);
                publicas.push(pk);
            }
            let tabla = Tabla { n: 0, claves };
            let candidato = [8u8; LONGITUD_HASH];
            let h_t_siguiente = hash_tabla(&tabla);
            let raiz = [0u8; LONGITUD_HASH];
            let mensaje = mensaje_voto_peso(0, &candidato, &h_t_siguiente, &raiz);
            let mut votos: Vec<(usize, Firma)> = Vec::with_capacity(n);
            for (indice, sk) in secretas.iter().enumerate() {
                votos.push((indice + 1, firmar(sk, DOMINIO_VOTO, mensaje.as_slice())?));
            }
            let certificado =
                construir_certificado(0, candidato, h_t_siguiente, raiz, &tabla, &votos)?;
            let mapa = mapa_de_indices(n, &(1..=n).collect::<Vec<_>>());

            let evaluar = |mapa: &[u8]| -> Result<(), ErrorVotos> {
                let _ = evaluar_certificado(&EntradaPeso {
                    b: 1,
                    genesis: true,
                    n_certificado: 0,
                    ventana: 0,
                    tabla_vigente: &tabla,
                    cert_previo: None,
                    tabla_comprometida: &h_t_siguiente,
                    raiz_estado: &raiz,
                    raiz_firmada: &raiz,
                    firma_ok: true,
                    h_t_siguiente_declarada: &h_t_siguiente,
                    h_t_siguiente_aceptadas: std::slice::from_ref(&h_t_siguiente),
                    acta: false,
                    mapa_bits: mapa,
                })?;
                Ok(())
            };
            let verificar = || -> Result<(), ErrorVotos> {
                verificar_firma_peso(&tabla, &publicas, &certificado)
            };
            assert!(evaluar(&mapa).is_ok());
            assert!(verificar().is_ok());

            let mediana = |mut muestras: Vec<u128>| -> u128 {
                muestras.sort_unstable();
                muestras.get(muestras.len() >> 1).copied().unwrap_or(0)
            };
            let mut evaluacion = Vec::new();
            let mut firma = Vec::new();
            for _ in 0..30 {
                let inicio = std::time::Instant::now();
                evaluar(&mapa)?;
                evaluacion.push(inicio.elapsed().as_nanos());
                let inicio = std::time::Instant::now();
                verificar()?;
                firma.push(inicio.elapsed().as_nanos());
            }
            let hilos = std::thread::available_parallelism();
            std::eprintln!(
                "D8 N={n} mediana_evaluacion={}ns mediana_firma={}ns hilos={hilos:?}",
                mediana(evaluacion),
                mediana(firma)
            );
        }
        Ok(())
    }

    /// El vocabulario cerrado está completo y en el orden del contrato.
    #[test]
    fn vocabulario_cerrado() {
        assert_eq!(MotivoPeso::TODOS.len(), 11);
        for (indice, motivo) in MotivoPeso::TODOS.iter().enumerate() {
            assert_eq!(
                MotivoPeso::TODOS.get(indice).copied(),
                Some(*motivo),
                "índice"
            );
            assert_eq!(MotivoPeso::desde_texto(motivo.como_texto()), Some(*motivo));
        }
        assert_eq!(firmantes_de_mapa(&[0b0000_0110]), vec![2, 3]);
    }
}
