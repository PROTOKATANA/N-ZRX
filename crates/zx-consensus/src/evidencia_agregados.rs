//! EA-VERIFY-0: verificación pura de los dos objetos de una evidencia v3.
//!
//! El proveedor acredita contexto original y PoP conocidas. No se consulta estado, no se
//! determina falta entre ventanas, no se aplica castigo ni se imponen cuotas. No hay conexión
//! con la transición. Rechazos baratos preceden a cualquier operación sobre curvas.

use std::collections::{BTreeMap, BTreeSet};

use zx_bls::{ClaveAgregada, ClavePublica, ClavesPreparadas, ErrorBLS, Firma, FirmaAgregada};
use zx_core::evidencia_agregados::{
    ContenidoObjeto, ErrorEvidenciaAgregados, EvidenciaAgregadosV3, MAX_CLAVES, ObjetoEvidencia,
    OrigenReferencia, validar_forma,
};
use zx_votos::agregacion::{Reparto, subred};
use zx_votos::bls::DOMINIO_VOTO;
use zx_votos::peso::mensaje_voto_peso;
use zx_votos::tipos::{Clave, Tabla};

/// Identidad BLS completa, sin interpretación criptográfica.
pub type Clave48 = [u8; 48];

/// Objeto al que corresponde un error o una ecuación.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumeroObjeto {
    /// Primer objeto (mensaje menor).
    Uno,
    /// Segundo objeto (mensaje mayor).
    Dos,
}

/// Fallo al autenticar un contexto original.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorContexto {
    /// Faltan datos: inadmisible y reintentable, sin afirmar invalidez.
    NoDisponible,
    /// El proveedor ha comprobado que el locator/contexto es inválido.
    Invalido,
}

/// Tabla global del contexto original, con PoP autenticadas para sus sumandos.
///
/// Ambas variantes deben conservar el orden canónico estricto por los 48 bytes. La variante
/// preparada incorpora validación individual de curva, subgrupo y no infinito por construcción.
/// No se acepta un vector de puntos separado de los bytes que identifica.
#[derive(Clone, Copy, Debug)]
pub enum TablaContexto<'a> {
    /// Bytes; solo se descomprimen las claves seleccionadas, una vez por K en la evidencia.
    Bytes(&'a [Clave48]),
    /// Puntos previamente validados y autenticados por el proveedor.
    Preparadas(&'a ClavesPreparadas),
}

/// Únicas consultas externas: contexto original y registro autenticado de posesión.
///
/// Implementar este contrato obliga a autenticar el locator **y el objeto completo** (ventana,
/// clase, mensaje y contexto aplicable). Un hash o una tabla aportada por el reportero no bastan.
/// Las consultas deben ser lecturas de datos ya autenticados, sin criptografía nueva ni replay.
pub trait ProveedorContexto {
    /// Obtiene la tabla global original; nunca la tabla siguiente del mensaje.
    fn tabla_original<'a>(
        &'a self,
        objeto: &ObjetoEvidencia<'_>,
        origen: &OrigenReferencia,
    ) -> Result<TablaContexto<'a>, ErrorContexto>;

    /// PoP ya comprobada en un registro autenticado para S o claves explícitas.
    /// La curva/subgrupo/no infinito se comprueban siempre al preparar los sumandos.
    fn posesion_conocida(&self, clave: &Clave48) -> bool;
}

/// Error preciso; falta de contexto nunca se transforma en evidencia inválida.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ErrorVerificacion {
    /// Forma de la operación (incluido orden de mensajes).
    #[error("forma EA: {0}")]
    Forma(#[from] ErrorEvidenciaAgregados),
    /// Datos externos ausentes; reintentable.
    #[error("contexto no disponible para {objeto:?}")]
    ContextoNoDisponible {
        /// Objeto afectado.
        objeto: NumeroObjeto,
    },
    /// El origen no ha sido autenticado como válido.
    #[error("contexto inválido para {objeto:?}")]
    ContextoInvalido {
        /// Objeto afectado.
        objeto: NumeroObjeto,
    },
    /// Tabla vacía, demasiado grande, repetida o fuera de orden canónico.
    #[error("tabla no canónica para {objeto:?}")]
    TablaNoCanonica {
        /// Objeto afectado.
        objeto: NumeroObjeto,
    },
    /// Longitud exacta del mapa local/global.
    #[error("mapa de {objeto:?}: {obtenida} bytes, se esperaban {esperada}")]
    MapaLongitud {
        /// Objeto afectado.
        objeto: NumeroObjeto,
        /// Longitud según alcance original.
        esperada: usize,
        /// Longitud recibida.
        obtenida: usize,
    },
    /// Bit marcado fuera del alcance local/global.
    #[error("mapa fuera de tabla para {objeto:?}")]
    MapaFueraTabla {
        /// Objeto afectado.
        objeto: NumeroObjeto,
    },
    /// Una clave explícita no pertenece a la subred declarada.
    #[error("clave de otra subred en {objeto:?}")]
    ClaveOtraSubred {
        /// Objeto afectado.
        objeto: NumeroObjeto,
        /// Clave completa que no corresponde.
        clave: Clave48,
    },
    /// No se conoce una PoP autenticada; no se intenta verificarla aquí.
    #[error("posesión desconocida en {objeto:?}")]
    PosesionDesconocida {
        /// Objeto afectado.
        objeto: NumeroObjeto,
        /// Clave completa.
        clave: Clave48,
    },
    /// Ningún firmante es común, por sus bytes completos.
    #[error("intersección de firmantes vacía")]
    SinClavesComunes,
    /// Validación individual de un sumando, antes de sumar.
    #[error("clave inválida en {objeto:?}: {error}")]
    ClaveInvalida {
        /// Primer objeto que selecciona esa clave.
        objeto: NumeroObjeto,
        /// Clave completa.
        clave: Clave48,
        /// Error de curva, subgrupo o infinito.
        error: ErrorBLS,
    },
    /// Firma G2 no decodificable/validable, antes de las ecuaciones.
    #[error("firma inválida en {objeto:?}: {error}")]
    FirmaInvalida {
        /// Objeto afectado.
        objeto: NumeroObjeto,
        /// Error BLS.
        error: ErrorBLS,
    },
    /// La suma de claves válidas es infinita.
    #[error("suma infinita en {objeto:?}")]
    SumaInfinita {
        /// Objeto afectado.
        objeto: NumeroObjeto,
    },
    /// Ecuación de voto falsa (ambas se ejecutan antes de devolver este error).
    #[error("firma falsa en {objeto:?}: {error}")]
    FirmaFalsa {
        /// Primer objeto cuya ecuación falla.
        objeto: NumeroObjeto,
        /// Error BLS.
        error: ErrorBLS,
    },
}

/// Resultado estático, pendiente del hecho de cadena si las ventanas son distintas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenciaVerificada {
    /// Intersección exacta K48, estrictamente ascendente y sin repeticiones.
    pub claves_comunes: Vec<Clave48>,
    /// `true` si n1 != n2; no es un veredicto de falta entre ventanas.
    pub requiere_hecho_cadena: bool,
}

/// Perfil contable fijado por el llamante, independiente de aciertos LRU locales.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerfilCoste {
    /// Todas las claves seleccionadas cuentan D, incluso si ya hay puntos preparados.
    Frio,
    /// Referencias autenticadas con puntos preparados proporcionan garantía reutilizable.
    Caliente,
}

/// Unidades EA-R14/CUOTAS; no expresan tiempos ni imponen un presupuesto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnidadesCoste {
    /// D: K48 distintas que el perfil requiere convertir.
    pub claves_a_descomprimir: u32,
    /// A: apariciones seleccionadas; una K en ambos objetos cuenta dos.
    pub apariciones_a_sumar: u32,
    /// E: dos por evidencia, también si después falla su criptografía.
    pub ecuaciones: u32,
}

#[derive(Clone, Copy)]
struct Firmante<'a> {
    bytes: Clave48,
    preparada: Option<&'a ClavePublica>,
}

struct Resuelto<'a> {
    firmantes: Vec<Firmante<'a>>,
    exige_posesion: bool,
}

/// Cuenta sin descomprimir, sumar ni verificar firmas/PoP.
///
/// Se necesita el contexto para resolver mapas. No exige comunes ni PoP conocida: las parejas
/// criptográficamente falsas y sin comunes también consumen unidades sintácticas.
///
/// # Errores
/// Forma, contexto no disponible/inválido, tabla no canónica, mapa o subred incorrectos.
pub fn unidades_coste(
    evidencia: &EvidenciaAgregadosV3<'_>,
    proveedor: &impl ProveedorContexto,
    perfil: PerfilCoste,
) -> Result<UnidadesCoste, ErrorVerificacion> {
    let (uno, dos) = resolver_pareja(evidencia, proveedor)?;
    let mut distintas = BTreeSet::new();
    let mut preparadas = BTreeSet::new();
    for firmante in uno.firmantes.iter().chain(&dos.firmantes) {
        distintas.insert(firmante.bytes);
        if firmante.preparada.is_some() {
            preparadas.insert(firmante.bytes);
        }
    }
    let d = match perfil {
        PerfilCoste::Frio => distintas.len(),
        PerfilCoste::Caliente => distintas.difference(&preparadas).count(),
    };
    // Dos objetos acotados por MAX_CLAVES: D y A <= 131072, sin overflow de u32.
    Ok(UnidadesCoste {
        claves_a_descomprimir: d as u32,
        apariciones_a_sumar: (uno.firmantes.len() + dos.firmantes.len()) as u32,
        ecuaciones: 2,
    })
}

/// Verifica una pareja; no produce efectos sobre estado ni impone cuotas.
///
/// # Errores
/// Los de [`ErrorVerificacion`], en orden: forma y resolución de ambos objetos, PoP conocidas,
/// comunes, claves, firmas G2, sumas no infinitas y finalmente dos ecuaciones deterministas.
pub fn verificar(
    evidencia: &EvidenciaAgregadosV3<'_>,
    proveedor: &impl ProveedorContexto,
) -> Result<EvidenciaVerificada, ErrorVerificacion> {
    verificar_con_observador(evidencia, proveedor, &mut |_| {})
}

/// Instrumentación de pruebas: observa justo antes de cada ecuación real, sin sustituirla.
/// La función [`verificar`] utiliza un observador sin efectos. No se invoca por clave común.
///
/// # Errores
/// Los mismos de [`verificar`]. Los rechazos previos a ecuaciones no llaman al observador.
#[doc(hidden)]
pub fn verificar_con_observador(
    evidencia: &EvidenciaAgregadosV3<'_>,
    proveedor: &impl ProveedorContexto,
    observar: &mut impl FnMut(NumeroObjeto),
) -> Result<EvidenciaVerificada, ErrorVerificacion> {
    let (uno, dos) = resolver_pareja(evidencia, proveedor)?;
    for (objeto, resuelto) in [(NumeroObjeto::Uno, &uno), (NumeroObjeto::Dos, &dos)] {
        if resuelto.exige_posesion {
            for firmante in &resuelto.firmantes {
                if !proveedor.posesion_conocida(&firmante.bytes) {
                    return Err(ErrorVerificacion::PosesionDesconocida {
                        objeto,
                        clave: firmante.bytes,
                    });
                }
            }
        }
    }
    let conjunto1: BTreeSet<_> = uno.firmantes.iter().map(|f| f.bytes).collect();
    let conjunto2: BTreeSet<_> = dos.firmantes.iter().map(|f| f.bytes).collect();
    let comunes: Vec<_> = conjunto1.intersection(&conjunto2).copied().collect();
    if comunes.is_empty() {
        return Err(ErrorVerificacion::SinClavesComunes);
    }

    // Una unión K48 por evidencia: también reutiliza los puntos preparados entre objetos/modos.
    let mut puntos = BTreeMap::new();
    for f in uno.firmantes.iter().chain(&dos.firmantes) {
        if let Some(punto) = f.preparada {
            puntos.insert(f.bytes, *punto);
        }
    }
    for (objeto, resuelto) in [(NumeroObjeto::Uno, &uno), (NumeroObjeto::Dos, &dos)] {
        for f in &resuelto.firmantes {
            if let std::collections::btree_map::Entry::Vacant(entrada) = puntos.entry(f.bytes) {
                let punto = ClavePublica::desde_bytes(&f.bytes).map_err(|error| {
                    ErrorVerificacion::ClaveInvalida {
                        objeto,
                        clave: f.bytes,
                        error,
                    }
                })?;
                entrada.insert(punto);
            }
        }
    }
    let firma1 = firma_de(&evidencia.objeto1, NumeroObjeto::Uno)?;
    let firma2 = firma_de(&evidencia.objeto2, NumeroObjeto::Dos)?;
    let suma1 = suma_de(&uno, &puntos, NumeroObjeto::Uno)?;
    let suma2 = suma_de(&dos, &puntos, NumeroObjeto::Dos)?;
    // No hay cortocircuito por firma falsa: se evalúan ambas, una vez cada una.
    let resultado1 = ecuacion(
        &evidencia.objeto1,
        &suma1,
        &firma1,
        NumeroObjeto::Uno,
        observar,
    );
    let resultado2 = ecuacion(
        &evidencia.objeto2,
        &suma2,
        &firma2,
        NumeroObjeto::Dos,
        observar,
    );
    resultado1?;
    resultado2?;
    Ok(EvidenciaVerificada {
        claves_comunes: comunes,
        requiere_hecho_cadena: evidencia.objeto1.voto.n != evidencia.objeto2.voto.n,
    })
}

fn firma_de(
    objeto: &ObjetoEvidencia<'_>,
    numero: NumeroObjeto,
) -> Result<FirmaAgregada, ErrorVerificacion> {
    let firma = Firma::desde_bytes(&objeto.voto.firma).map_err(|error| {
        ErrorVerificacion::FirmaInvalida {
            objeto: numero,
            error,
        }
    })?;
    Ok(FirmaAgregada::desde_firma(&firma))
}

fn suma_de(
    resuelto: &Resuelto<'_>,
    puntos: &BTreeMap<Clave48, ClavePublica>,
    objeto: NumeroObjeto,
) -> Result<ClaveAgregada, ErrorVerificacion> {
    let publicas = resuelto
        .firmantes
        .iter()
        .map(|f| {
            puntos
                .get(&f.bytes)
                .ok_or(ErrorVerificacion::TablaNoCanonica { objeto })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let suma = ClaveAgregada::sumar(&publicas)
        .map_err(|error| ErrorVerificacion::FirmaFalsa { objeto, error })?;
    if suma.es_infinito() {
        return Err(ErrorVerificacion::SumaInfinita { objeto });
    }
    Ok(suma)
}

fn ecuacion(
    objeto: &ObjetoEvidencia<'_>,
    suma: &ClaveAgregada,
    firma: &FirmaAgregada,
    numero: NumeroObjeto,
    observar: &mut impl FnMut(NumeroObjeto),
) -> Result<(), ErrorVerificacion> {
    let v = objeto.voto;
    let mensaje = mensaje_voto_peso(v.n, &v.candidato, &v.h_t_siguiente, &v.raiz_estado);
    observar(numero);
    zx_bls::verificar_agregado_con_clave(suma, firma, DOMINIO_VOTO, &mensaje).map_err(|error| {
        ErrorVerificacion::FirmaFalsa {
            objeto: numero,
            error,
        }
    })
}

fn resolver_pareja<'a>(
    evidencia: &EvidenciaAgregadosV3<'_>,
    proveedor: &'a impl ProveedorContexto,
) -> Result<(Resuelto<'a>, Resuelto<'a>), ErrorVerificacion> {
    validar_forma(evidencia)?;
    let uno = resolver(&evidencia.objeto1, proveedor, NumeroObjeto::Uno)?;
    let dos = resolver(&evidencia.objeto2, proveedor, NumeroObjeto::Dos)?;
    Ok((uno, dos))
}

fn resolver<'a>(
    objeto: &ObjetoEvidencia<'_>,
    proveedor: &'a impl ProveedorContexto,
    numero: NumeroObjeto,
) -> Result<Resuelto<'a>, ErrorVerificacion> {
    match objeto.contenido {
        ContenidoObjeto::Voto { clave } => Ok(Resuelto {
            firmantes: vec![Firmante {
                bytes: clave,
                preparada: None,
            }],
            exige_posesion: true,
        }),
        ContenidoObjeto::SubredExplicita { claves, .. }
        | ContenidoObjeto::CertificadoExplicito { claves }
        | ContenidoObjeto::ActaExplicita { claves } => {
            let mut firmantes = Vec::with_capacity(claves.cantidad());
            for bytes in claves.bytes().chunks_exact(48) {
                // El tipo ClavesExplicitas garantiza chunks de longitud 48 y lista estricta.
                let clave: Clave48 = bytes
                    .try_into()
                    .map_err(|_| ErrorVerificacion::TablaNoCanonica { objeto: numero })?;
                if let ContenidoObjeto::SubredExplicita {
                    subred: declarada, ..
                } = objeto.contenido
                {
                    let real = subred(&clave, 64)
                        .map_err(|_| ErrorVerificacion::TablaNoCanonica { objeto: numero })?;
                    if real != declarada {
                        return Err(ErrorVerificacion::ClaveOtraSubred {
                            objeto: numero,
                            clave,
                        });
                    }
                }
                firmantes.push(Firmante {
                    bytes: clave,
                    preparada: None,
                });
            }
            Ok(Resuelto {
                firmantes,
                exige_posesion: true,
            })
        }
        ContenidoObjeto::SubredReferencia { origen, mapa, .. }
        | ContenidoObjeto::CertificadoReferencia { origen, mapa }
        | ContenidoObjeto::ActaReferencia { origen, mapa } => {
            let tabla = proveedor
                .tabla_original(objeto, &origen)
                .map_err(|error| match error {
                    ErrorContexto::NoDisponible => {
                        ErrorVerificacion::ContextoNoDisponible { objeto: numero }
                    }
                    ErrorContexto::Invalido => {
                        ErrorVerificacion::ContextoInvalido { objeto: numero }
                    }
                })?;
            let cantidad = match tabla {
                TablaContexto::Bytes(bytes) => bytes.len(),
                TablaContexto::Preparadas(claves) => claves.len(),
            };
            if cantidad == 0 || cantidad > MAX_CLAVES {
                return Err(ErrorVerificacion::TablaNoCanonica { objeto: numero });
            }
            let todas: Vec<_> = match tabla {
                TablaContexto::Bytes(bytes) => bytes
                    .iter()
                    .map(|bytes| Firmante {
                        bytes: *bytes,
                        preparada: None,
                    })
                    .collect(),
                TablaContexto::Preparadas(claves) => claves
                    .claves()
                    .iter()
                    .map(|clave| Firmante {
                        bytes: clave.bytes(),
                        preparada: Some(clave),
                    })
                    .collect(),
            };
            if todas.is_empty()
                || todas.len() > MAX_CLAVES
                || todas
                    .windows(2)
                    .any(|par| par.first().map(|f| f.bytes) >= par.get(1).map(|f| f.bytes))
            {
                return Err(ErrorVerificacion::TablaNoCanonica { objeto: numero });
            }
            let indices = if let ContenidoObjeto::SubredReferencia { subred, .. } = objeto.contenido
            {
                // Tabla transitoria solo de claves: ningún peso, actividad o garantía decide validez.
                let reparto_tabla = Tabla {
                    n: objeto.voto.n,
                    claves: todas
                        .iter()
                        .map(|f| Clave {
                            clave: f.bytes.to_vec(),
                            peso: 0,
                            activo: false,
                            prueba: false,
                            garantia: 0,
                        })
                        .collect(),
                };
                let reparto = Reparto::construir(&reparto_tabla, 64)
                    .map_err(|_| ErrorVerificacion::TablaNoCanonica { objeto: numero })?;
                reparto.claves_de(subred).to_vec()
            } else {
                (0..todas.len()).collect()
            };
            validar_mapa(mapa, indices.len(), numero)?;
            let firmantes = indices
                .iter()
                .enumerate()
                .filter(|(pos, _)| {
                    mapa.get(pos >> 3)
                        .is_some_and(|b| b & (1 << (pos & 7)) != 0)
                })
                .map(|(_, indice)| {
                    todas
                        .get(*indice)
                        .copied()
                        .ok_or(ErrorVerificacion::TablaNoCanonica { objeto: numero })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Resuelto {
                firmantes,
                exige_posesion: false,
            })
        }
    }
}

fn validar_mapa(mapa: &[u8], n: usize, objeto: NumeroObjeto) -> Result<(), ErrorVerificacion> {
    let esperada = n.div_ceil(8);
    if mapa.len() != esperada {
        return Err(ErrorVerificacion::MapaLongitud {
            objeto,
            esperada,
            obtenida: mapa.len(),
        });
    }
    let resto = n & 7;
    if resto != 0 && mapa.last().is_some_and(|b| b & (0xff << resto) != 0) {
        return Err(ErrorVerificacion::MapaFueraTabla { objeto });
    }
    // El vacío se rechaza por validar_forma antes de resolver cualquier contexto.
    Ok(())
}
