//! EA-WIRE-2: operación aislada `0x0C`, versión 3 (EA-R3/R4/R5/R9/R13/R14).
//!
//! No activa ninguna clase de transacción. Solo comprueba bytes y forma: las firmas, PoP,
//! reparto de subred, tablas, bits sobrantes según N y contexto son del consumidor.
//! Mapas y claves se prestan del buffer: decodificar y validar no asignan memoria.

use crate::{ClavePublica, VotoPesoEvidencia};

/// Clase propuesta; permanece desconocida para el códec de transacciones.
pub const CLASE_EVIDENCIA_AGREGADOS: u8 = 0x0c;
/// Única versión interna de este módulo.
pub const VERSION_EVIDENCIA_AGREGADOS: u8 = 3;
/// Máximo de claves por objeto, incluso para una subred sin reparto uniforme.
pub const MAX_CLAVES: usize = 65_536;
/// Máximo de bytes de un mapa de referencia.
pub const MAX_MAPA_BYTES: usize = MAX_CLAVES.div_ceil(8);
/// Contexto de elegibilidad de un agregado L, sin operación L on-chain.
pub const POSICION_SUBRED: u32 = u32::MAX;
/// Dominio propuesto del reportero: 16 bytes ASCII, distinto de `ZZKTxSigAlmacen_` de 0x0B.
/// La preimagen es literalmente `DOMINIO_REPORTERO || codificar(evidencia)`, sin testigo.
pub const DOMINIO_REPORTERO: [u8; 16] = *b"ZZKTxSigEAgV3___";

/// Errores de forma del códec puro; no son veredictos de consenso.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ErrorEvidenciaAgregados {
    /// Clase distinta de 0x0C.
    #[error("EA: clase desconocida {0:#04x}")]
    ClaseDesconocida(u8),
    /// Los bytes v2 nunca se reinterpretan como evidencia multiclave v3.
    #[error("EA: versión 2 incompatible con la versión 3")]
    Version2Incompatible,
    /// Versión interna desconocida, distinta de 3 y de la v2 incompatible.
    #[error("EA: versión distinta de 3: {0}")]
    VersionInvalida(u8),
    /// Una referencia necesita resolver su tabla original para cruzar claves completas.
    #[error("EA: claves comunes de referencia requieren tabla original")]
    TablaReferenciaNecesaria,
    /// Etiqueta fuera de S/L/C/A.
    #[error("EA: etiqueta desconocida {0}")]
    EtiquetaDesconocida(u8),
    /// Modo fuera de referencia/explicito.
    #[error("EA: modo desconocido {0}")]
    ModoDesconocido(u8),
    /// S no admite lista explícita.
    #[error("EA: voto suelto en modo explícito")]
    VotoExplicito,
    /// Longitud declarada menor que la exigida por el contenido.
    #[error("EA: longitud corta: {declarada}, mínimo/exacto {esperada}")]
    LongitudCorta {
        /// Longitud declarada en bytes.
        declarada: usize,
        /// Mínimo o longitud exacta requerida.
        esperada: usize,
    },
    /// Longitud declarada mayor que el máximo o la longitud exacta.
    #[error("EA: longitud larga: {declarada}, máximo/exacto {esperada}")]
    LongitudLarga {
        /// Longitud declarada en bytes.
        declarada: usize,
        /// Máximo o longitud exacta requerida.
        esperada: usize,
    },
    /// El buffer termina antes del campo, sin rellenarlo.
    #[error("EA: truncado: se necesitan {esperados} bytes, quedan {disponibles}")]
    Truncado {
        /// Bytes requeridos por el campo.
        esperados: usize,
        /// Bytes que quedan.
        disponibles: usize,
    },
    /// La operación completa no admite una cola.
    #[error("EA: {0} bytes sobrantes")]
    BytesSobrantes(usize),
    /// Una lista explícita debe contener al menos una clave.
    #[error("EA: m es cero")]
    NumeroClavesCero,
    /// Límite antes de recorrer o reservar claves.
    #[error("EA: demasiadas claves: {0}")]
    DemasiadasClaves(usize),
    /// Lista de bytes no divisible en claves completas de 48 B.
    #[error("EA: lista de claves con longitud no múltiplo de 48: {0}")]
    ClaveIncompleta(usize),
    /// Igualdad entre dos claves contiguas.
    #[error("EA: clave repetida")]
    ClaveRepetida,
    /// Orden lexicográfico decreciente entre claves contiguas.
    #[error("EA: claves desordenadas")]
    ClavesDesordenadas,
    /// No hay ninguna clave seleccionada en el mapa (incluye mapa de cero bytes).
    #[error("EA: mapa vacío")]
    MapaVacio,
    /// El mapa excede las 65 536 posiciones posibles.
    #[error("EA: mapa demasiado largo: {0}")]
    MapaDemasiadoLargo(usize),
    /// Subred fuera de 0..64.
    #[error("EA: subred fuera de rango: {0}")]
    SubredInvalida(u16),
    /// L en referencia exige la posición sentinela.
    #[error("EA: posición de subred no sentinela: {0}")]
    PosicionSubredInvalida(u32),
    /// C/A en referencia exige un índice real, no la posición sentinela de L.
    #[error("EA: posición de operación sentinela")]
    PosicionOperacionInvalida,
    /// Los dos M coinciden, aunque cambien firma, procedencia o clase.
    #[error("EA: mensajes iguales")]
    MensajesIguales,
    /// M1 > M2, comparando n numéricamente y luego los tres hashes por bytes.
    #[error("EA: mensajes en orden inverso")]
    MensajesInvertidos,
}

use ErrorEvidenciaAgregados as Error;

/// Claves completas ordenadas, distintas y acotadas, sin copiar el buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClavesExplicitas<'a> {
    bytes: &'a [u8],
}

impl<'a> ClavesExplicitas<'a> {
    /// Valida una lista plana de claves de 48 B; no asigna memoria.
    ///
    /// # Errores
    /// Número cero/excesivo, clave incompleta, repetida o desordenada.
    pub fn desde_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > 48 * MAX_CLAVES {
            return Err(Error::DemasiadasClaves(bytes.len().div_ceil(48)));
        }
        if !bytes.len().is_multiple_of(48) {
            return Err(Error::ClaveIncompleta(bytes.len()));
        }
        if bytes.is_empty() {
            return Err(Error::NumeroClavesCero);
        }
        let mut anterior: Option<&[u8]> = None;
        for clave in bytes.chunks_exact(48) {
            if let Some(previa) = anterior {
                match previa.cmp(clave) {
                    std::cmp::Ordering::Equal => return Err(Error::ClaveRepetida),
                    std::cmp::Ordering::Greater => return Err(Error::ClavesDesordenadas),
                    std::cmp::Ordering::Less => {}
                }
            }
            anterior = Some(clave);
        }
        Ok(Self { bytes })
    }

    /// Número de claves (1..=65 536 por construcción).
    #[must_use]
    pub fn cantidad(self) -> usize {
        self.bytes.chunks_exact(48).len()
    }

    /// Lista plana original, sin copia.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

/// Locator que deberá autenticar el consumidor con contexto original.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrigenReferencia {
    /// Tabla actual original; no es h_t_siguiente de M.
    pub h_actual: [u8; 32],
    /// Bloque de origen del contexto.
    pub bloque_origen: [u8; 32],
    /// Sentinela para L, índice real de operación para C/A.
    pub posicion: u32,
}

/// Las siete combinaciones de etiqueta/modo permitidas, sin campos opcionales en wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContenidoObjeto<'a> {
    /// S/0: M, firma y su propia clave completa de 48 B.
    Voto {
        /// Clave BLS del firmante individual, sin validar criptografía.
        clave: [u8; 48],
    },
    /// L/0: locator, subred y mapa local.
    SubredReferencia {
        /// Locator original.
        origen: OrigenReferencia,
        /// Subred menor que 64.
        subred: u16,
        /// Bits LSB; longitud y bits finales según tabla pendientes de contexto.
        mapa: &'a [u8],
    },
    /// C/0: locator y mapa global.
    CertificadoReferencia {
        /// Locator original.
        origen: OrigenReferencia,
        /// Bits LSB globales.
        mapa: &'a [u8],
    },
    /// A/0: locator y mapa global.
    ActaReferencia {
        /// Locator original.
        origen: OrigenReferencia,
        /// Bits LSB globales.
        mapa: &'a [u8],
    },
    /// L/1: subred y claves explícitas.
    SubredExplicita {
        /// Subred menor que 64; reparto hash pendiente de contexto.
        subred: u16,
        /// Claves completas, ordenadas y distintas.
        claves: ClavesExplicitas<'a>,
    },
    /// C/1: claves explícitas, sin tabla ni pesos.
    CertificadoExplicito {
        /// Claves completas, ordenadas y distintas.
        claves: ClavesExplicitas<'a>,
    },
    /// A/1: claves explícitas, sin tabla ni pesos.
    ActaExplicita {
        /// Claves completas, ordenadas y distintas.
        claves: ClavesExplicitas<'a>,
    },
}

/// Objeto S/L/C/A: se reutiliza solo la representación de bytes Mσ de 0x0B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjetoEvidencia<'a> {
    /// n, candidato, h_t_siguiente, raíz y firma (individual en S, agregada en L/C/A).
    pub voto: VotoPesoEvidencia,
    /// Clase y modo de prueba, sin validar criptografía.
    pub contenido: ContenidoObjeto<'a>,
}

/// Operación propuesta `0x0C` v3, sin testigo ni sobre de transacción.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenciaAgregadosV3<'a> {
    /// Identidad Ed25519 reportera.
    pub reportero: ClavePublica,
    /// Objeto con mensaje menor.
    pub objeto1: ObjetoEvidencia<'a>,
    /// Objeto con mensaje mayor.
    pub objeto2: ObjetoEvidencia<'a>,
}

impl ContenidoObjeto<'_> {
    fn etiqueta_modo(self) -> (u8, u8) {
        match self {
            Self::Voto { .. } => (0, 0),
            Self::SubredReferencia { .. } => (1, 0),
            Self::CertificadoReferencia { .. } => (2, 0),
            Self::ActaReferencia { .. } => (3, 0),
            Self::SubredExplicita { .. } => (1, 1),
            Self::CertificadoExplicito { .. } => (2, 1),
            Self::ActaExplicita { .. } => (3, 1),
        }
    }

    fn longitud(self) -> usize {
        match self {
            Self::Voto { .. } => 248,
            Self::SubredReferencia { mapa, .. } => 270 + mapa.len(),
            Self::CertificadoReferencia { mapa, .. } | Self::ActaReferencia { mapa, .. } => {
                268 + mapa.len()
            }
            Self::SubredExplicita { claves, .. } => 206 + claves.bytes.len(),
            Self::CertificadoExplicito { claves } | Self::ActaExplicita { claves } => {
                204 + claves.bytes.len()
            }
        }
    }

    fn validar(self) -> Result<(), Error> {
        match self {
            Self::SubredReferencia { subred, .. } | Self::SubredExplicita { subred, .. }
                if subred >= 64 =>
            {
                return Err(Error::SubredInvalida(subred));
            }
            _ => {}
        }
        match self {
            Self::SubredReferencia { origen, mapa, .. } => {
                if origen.posicion != POSICION_SUBRED {
                    return Err(Error::PosicionSubredInvalida(origen.posicion));
                }
                validar_mapa(mapa)?;
            }
            Self::CertificadoReferencia { origen, mapa }
            | Self::ActaReferencia { origen, mapa } => {
                if origen.posicion == POSICION_SUBRED {
                    return Err(Error::PosicionOperacionInvalida);
                }
                validar_mapa(mapa)?;
            }
            _ => {}
        }
        Ok(())
    }
}

fn validar_mapa(mapa: &[u8]) -> Result<(), Error> {
    if mapa.len() > MAX_MAPA_BYTES {
        return Err(Error::MapaDemasiadoLargo(mapa.len()));
    }
    if !mapa.iter().any(|b| *b != 0) {
        return Err(Error::MapaVacio);
    }
    Ok(())
}

/// Carga EA-R14: S=1, referencia=popcount, explícito=m; función pura sin reserva.
///
/// # Errores
/// Subred, locator o mapa inválidos, antes de contar bits.
pub fn carga(objeto: &ObjetoEvidencia<'_>) -> Result<u32, Error> {
    objeto.contenido.validar()?;
    Ok(match objeto.contenido {
        ContenidoObjeto::Voto { .. } => 1,
        ContenidoObjeto::SubredReferencia { mapa, .. }
        | ContenidoObjeto::CertificadoReferencia { mapa, .. }
        | ContenidoObjeto::ActaReferencia { mapa, .. } => mapa.iter().map(|b| b.count_ones()).sum(),
        ContenidoObjeto::SubredExplicita { claves, .. }
        | ContenidoObjeto::CertificadoExplicito { claves }
        | ContenidoObjeto::ActaExplicita { claves } => {
            // ClavesExplicitas tiene constructor privado y cantidad <= 65536.
            claves.cantidad() as u32
        }
    })
}

/// Intersección por los 48 bytes completos de S y objetos explícitos, en orden ascendente.
/// Recorre las listas dos veces: cuenta y luego escribe, reservando solo el resultado exacto.
/// No exige relación entre mensajes; el orden de la operación se valida en [`validar_forma`].
/// No resuelve tablas ni verifica firmas, PoP, pertenencia a subred o culpabilidad.
///
/// # Errores
/// Forma inválida de alguno de los objetos o [`ErrorEvidenciaAgregados::TablaReferenciaNecesaria`]
/// si alguno contiene un mapa de referencia. Todos se detectan antes de reservar.
pub fn claves_comunes(
    objeto1: &ObjetoEvidencia<'_>,
    objeto2: &ObjetoEvidencia<'_>,
) -> Result<Vec<[u8; 48]>, Error> {
    objeto1.contenido.validar()?;
    objeto2.contenido.validar()?;
    let uno = claves_conocidas(&objeto1.contenido)?;
    let dos = claves_conocidas(&objeto2.contenido)?;
    let mut cantidad = 0;
    recorrer_comunes(uno, dos, |_| cantidad += 1);
    let mut resultado = Vec::with_capacity(cantidad);
    recorrer_comunes(uno, dos, |bytes| {
        let mut clave = [0; 48];
        clave.copy_from_slice(bytes);
        resultado.push(clave);
    });
    Ok(resultado)
}

fn claves_conocidas<'a>(contenido: &'a ContenidoObjeto<'_>) -> Result<&'a [u8], Error> {
    match contenido {
        ContenidoObjeto::Voto { clave } => Ok(clave),
        ContenidoObjeto::SubredExplicita { claves, .. }
        | ContenidoObjeto::CertificadoExplicito { claves }
        | ContenidoObjeto::ActaExplicita { claves } => Ok(claves.bytes()),
        _ => Err(Error::TablaReferenciaNecesaria),
    }
}

fn recorrer_comunes(uno: &[u8], dos: &[u8], mut visitar: impl FnMut(&[u8])) {
    let mut izquierda = uno.chunks_exact(48);
    let mut derecha = dos.chunks_exact(48);
    let mut a = izquierda.next();
    let mut b = derecha.next();
    while let (Some(clave1), Some(clave2)) = (a, b) {
        match clave1.cmp(clave2) {
            std::cmp::Ordering::Less => a = izquierda.next(),
            std::cmp::Ordering::Greater => b = derecha.next(),
            std::cmp::Ordering::Equal => {
                visitar(clave1);
                a = izquierda.next();
                b = derecha.next();
            }
        }
    }
}

/// Valida la forma de los dos objetos y el orden estricto por M (no por firma ni tag).
///
/// # Errores
/// Subred/locator/mapa inválidos o mensajes iguales/invertidos.
pub fn validar_forma(evidencia: &EvidenciaAgregadosV3<'_>) -> Result<(), Error> {
    evidencia.objeto1.contenido.validar()?;
    evidencia.objeto2.contenido.validar()?;
    let mensaje = |v: VotoPesoEvidencia| (v.n, v.candidato, v.h_t_siguiente, v.raiz_estado);
    match mensaje(evidencia.objeto1.voto).cmp(&mensaje(evidencia.objeto2.voto)) {
        std::cmp::Ordering::Equal => Err(Error::MensajesIguales),
        std::cmp::Ordering::Greater => Err(Error::MensajesInvertidos),
        std::cmp::Ordering::Less => Ok(()),
    }
}

/// Longitud exacta de la operación, sin el sobre v6 de 80 B; no reserva memoria.
///
/// # Errores
/// Los de [`validar_forma`].
pub fn longitud_canonica(evidencia: &EvidenciaAgregadosV3<'_>) -> Result<usize, Error> {
    validar_forma(evidencia)?;
    Ok(46 + evidencia.objeto1.contenido.longitud() + evidencia.objeto2.contenido.longitud())
}

/// Codifica de forma canónica, después de validar todo y antes de la primera reserva.
///
/// # Errores
/// Los de [`validar_forma`].
pub fn codificar(evidencia: &EvidenciaAgregadosV3<'_>) -> Result<Vec<u8>, Error> {
    let longitud = longitud_canonica(evidencia)?;
    let mut out = Vec::with_capacity(longitud);
    escribir(evidencia, &mut out);
    Ok(out)
}

/// Preimagen propuesta del reportero: dominio de 16 B seguido de la operación canónica.
/// No acepta testigo, no calcula txid, ni verifica firmas ni activa reglas.
///
/// # Errores
/// Los de [`validar_forma`], antes de reservar memoria.
pub fn preimagen_reportero(evidencia: &EvidenciaAgregadosV3<'_>) -> Result<Vec<u8>, Error> {
    let longitud = longitud_canonica(evidencia)?;
    let mut out = Vec::with_capacity(16 + longitud);
    out.extend_from_slice(&DOMINIO_REPORTERO);
    escribir(evidencia, &mut out);
    Ok(out)
}

fn escribir(evidencia: &EvidenciaAgregadosV3<'_>, out: &mut Vec<u8>) {
    out.extend_from_slice(&[CLASE_EVIDENCIA_AGREGADOS, VERSION_EVIDENCIA_AGREGADOS]);
    out.extend_from_slice(evidencia.reportero.bytes());
    for objeto in [evidencia.objeto1, evidencia.objeto2] {
        let (tag, modo) = objeto.contenido.etiqueta_modo();
        out.extend_from_slice(&[tag, modo]);
        // Todos los contenidos validados son <= 270 + 48*65536 < u32::MAX.
        out.extend_from_slice(&(objeto.contenido.longitud() as u32).to_le_bytes());
        let v = objeto.voto;
        out.extend_from_slice(&v.n.to_le_bytes());
        out.extend_from_slice(&v.candidato);
        out.extend_from_slice(&v.h_t_siguiente);
        out.extend_from_slice(&v.raiz_estado);
        out.extend_from_slice(&v.firma);
        match objeto.contenido {
            ContenidoObjeto::Voto { clave } => out.extend_from_slice(&clave),
            ContenidoObjeto::SubredReferencia {
                origen,
                subred,
                mapa,
            } => {
                escribir_origen(origen, out);
                out.extend_from_slice(&subred.to_le_bytes());
                out.extend_from_slice(mapa);
            }
            ContenidoObjeto::CertificadoReferencia { origen, mapa }
            | ContenidoObjeto::ActaReferencia { origen, mapa } => {
                escribir_origen(origen, out);
                out.extend_from_slice(mapa);
            }
            ContenidoObjeto::SubredExplicita { subred, claves } => {
                out.extend_from_slice(&subred.to_le_bytes());
                escribir_claves(claves, out);
            }
            ContenidoObjeto::CertificadoExplicito { claves }
            | ContenidoObjeto::ActaExplicita { claves } => escribir_claves(claves, out),
        }
    }
}

fn escribir_origen(origen: OrigenReferencia, out: &mut Vec<u8>) {
    out.extend_from_slice(&origen.h_actual);
    out.extend_from_slice(&origen.bloque_origen);
    out.extend_from_slice(&origen.posicion.to_le_bytes());
}

fn escribir_claves(claves: ClavesExplicitas<'_>, out: &mut Vec<u8>) {
    out.extend_from_slice(&(claves.cantidad() as u32).to_le_bytes());
    out.extend_from_slice(claves.bytes);
}

struct Lector<'a> {
    resto: &'a [u8],
}

impl<'a> Lector<'a> {
    fn tomar(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (campo, resto) = self.resto.split_at_checked(n).ok_or(Error::Truncado {
            esperados: n,
            disponibles: self.resto.len(),
        })?;
        self.resto = resto;
        Ok(campo)
    }

    fn arreglo<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.tomar(N)?.try_into().map_err(|_| Error::Truncado {
            esperados: N,
            disponibles: 0,
        })
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(u8::from_le_bytes(self.arreglo()?))
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.arreglo()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.arreglo()?))
    }

    fn voto(&mut self) -> Result<VotoPesoEvidencia, Error> {
        Ok(VotoPesoEvidencia {
            n: u64::from_le_bytes(self.arreglo()?),
            candidato: self.arreglo()?,
            h_t_siguiente: self.arreglo()?,
            raiz_estado: self.arreglo()?,
            firma: self.arreglo()?,
        })
    }

    fn origen(&mut self) -> Result<OrigenReferencia, Error> {
        Ok(OrigenReferencia {
            h_actual: self.arreglo()?,
            bloque_origen: self.arreglo()?,
            posicion: self.u32()?,
        })
    }

    fn objeto(&mut self) -> Result<ObjetoEvidencia<'a>, Error> {
        let tag = self.u8()?;
        if tag > 3 {
            return Err(Error::EtiquetaDesconocida(tag));
        }
        let modo = self.u8()?;
        if modo > 1 {
            return Err(Error::ModoDesconocido(modo));
        }
        if tag == 0 && modo == 1 {
            return Err(Error::VotoExplicito);
        }
        let longitud = self.u32()? as usize;
        let fijo = match (tag, modo) {
            (0, _) => 248,
            (1, 0) => 270,
            (_, 0) => 268,
            (1, _) => 206,
            _ => 204,
        };
        let maximo = fijo
            + match (tag, modo) {
                (0, _) => 0,
                (_, 0) => MAX_MAPA_BYTES,
                _ => 48 * MAX_CLAVES,
            };
        if tag != 0 && modo == 0 && longitud > maximo {
            return Err(Error::MapaDemasiadoLargo(longitud - fijo));
        }
        comprobar_longitud(longitud, fijo, maximo)?;
        let mut payload = Lector {
            resto: self.tomar(longitud)?,
        };
        let voto = payload.voto()?;
        let contenido = if tag == 0 {
            ContenidoObjeto::Voto {
                clave: payload.arreglo()?,
            }
        } else if modo == 0 {
            let origen = payload.origen()?;
            match tag {
                1 => ContenidoObjeto::SubredReferencia {
                    origen,
                    subred: payload.u16()?,
                    mapa: payload.resto,
                },
                2 => ContenidoObjeto::CertificadoReferencia {
                    origen,
                    mapa: payload.resto,
                },
                _ => ContenidoObjeto::ActaReferencia {
                    origen,
                    mapa: payload.resto,
                },
            }
        } else {
            let subred = if tag == 1 { payload.u16()? } else { 0 };
            let m = payload.u32()? as usize;
            if m == 0 {
                return Err(Error::NumeroClavesCero);
            }
            if m > MAX_CLAVES {
                return Err(Error::DemasiadasClaves(m));
            }
            let exacta = fijo + 48 * m;
            comprobar_longitud(longitud, exacta, exacta)?;
            let claves = ClavesExplicitas::desde_bytes(payload.resto)?;
            match tag {
                1 => ContenidoObjeto::SubredExplicita { subred, claves },
                2 => ContenidoObjeto::CertificadoExplicito { claves },
                _ => ContenidoObjeto::ActaExplicita { claves },
            }
        };
        contenido.validar()?;
        Ok(ObjetoEvidencia { voto, contenido })
    }
}

fn comprobar_longitud(declarada: usize, minima: usize, maxima: usize) -> Result<(), Error> {
    if declarada < minima {
        return Err(Error::LongitudCorta {
            declarada,
            esperada: minima,
        });
    }
    if declarada > maxima {
        return Err(Error::LongitudLarga {
            declarada,
            esperada: maxima,
        });
    }
    Ok(())
}

/// Decodifica toda la operación en vistas prestadas, valida forma y exige fin del buffer.
/// No reserva memoria, ni antes ni después de inspeccionar las longitudes.
///
/// # Errores
/// Cada malformación produce la variante concreta de [`ErrorEvidenciaAgregados`].
pub fn decodificar(bytes: &[u8]) -> Result<EvidenciaAgregadosV3<'_>, Error> {
    let mut lector = Lector { resto: bytes };
    let clase = lector.u8()?;
    if clase != CLASE_EVIDENCIA_AGREGADOS {
        return Err(Error::ClaseDesconocida(clase));
    }
    let version = lector.u8()?;
    if version == 2 {
        return Err(Error::Version2Incompatible);
    }
    if version != VERSION_EVIDENCIA_AGREGADOS {
        return Err(Error::VersionInvalida(version));
    }
    let evidencia = EvidenciaAgregadosV3 {
        reportero: ClavePublica::desde_bytes(lector.arreglo()?),
        objeto1: lector.objeto()?,
        objeto2: lector.objeto()?,
    };
    if !lector.resto.is_empty() {
        return Err(Error::BytesSobrantes(lector.resto.len()));
    }
    validar_forma(&evidencia)?;
    Ok(evidencia)
}

/// Valida bytes completos sin copiarlos ni reservar memoria.
///
/// # Errores
/// Los de [`decodificar`].
pub fn validar_forma_bytes(bytes: &[u8]) -> Result<(), Error> {
    decodificar(bytes).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::DOMINIO_REPORTERO;
    use crate::hash::TAGS_FIJAS;

    #[test]
    fn dominio_reportero_distinto_de_los_23_dominios_y_del_prefijo_raiz() {
        assert!(DOMINIO_REPORTERO.is_ascii());
        assert!(
            TAGS_FIJAS
                .iter()
                .all(|tag| tag.as_bytes() != &DOMINIO_REPORTERO)
        );
        assert!(!DOMINIO_REPORTERO.starts_with(b"ZZKTxIdHash_"));
    }
}
