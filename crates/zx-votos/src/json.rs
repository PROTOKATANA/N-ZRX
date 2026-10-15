//! Parser JSON mínimo para los vectores de FV-3 (feature `vectores`).
//!
//! El esquema de los JSONL es fijo y sencillo (objetos, arreglos, cadenas, enteros, booleanos y
//! `null`); no se quiere arrastrar `serde_json` al workspace por una herramienta de evidencia. El
//! parser no hace `panic` con entradas externas: devuelve [`ErrorVotos::Json`].

use crate::error::ErrorVotos;

/// Profundidad máxima de anidamiento admitida (evita recursión sin cota).
const PROFUNDIDAD_MAXIMA: usize = 64;

/// Un valor JSON del subconjunto usado por los vectores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    /// `null`.
    Null,
    /// Booleano.
    Bool(bool),
    /// Entero (los vectores no usan coma flotante).
    Numero(i64),
    /// Cadena.
    Texto(String),
    /// Arreglo.
    Arreglo(Vec<Json>),
    /// Objeto; se conserva el orden de las claves.
    Objeto(Vec<(String, Json)>),
}

impl Json {
    /// Parsea un documento JSON completo.
    ///
    /// # Errores
    /// [`ErrorVotos::Json`] si la entrada no es JSON válido del subconjunto admitido;
    /// [`ErrorVotos::JsonProfundo`] si anida más de [`PROFUNDIDAD_MAXIMA`].
    pub fn parsear(texto: &str) -> Result<Self, ErrorVotos> {
        let mut parser = Parser {
            bytes: texto.as_bytes(),
            pos: 0,
        };
        parser.espacios();
        let valor = parser.valor(0)?;
        parser.espacios();
        if parser.pos != parser.bytes.len() {
            return Err(ErrorVotos::Json("contenido sobrante".to_string()));
        }
        Ok(valor)
    }

    /// Campo de un objeto (o `None` si `self` no es objeto o no tiene la clave).
    #[must_use]
    pub fn campo(&self, nombre: &str) -> Option<&Json> {
        match self {
            Json::Objeto(campos) => campos
                .iter()
                .find(|(clave, _)| clave == nombre)
                .map(|(_, valor)| valor),
            _ => None,
        }
    }

    /// Texto de una cadena.
    #[must_use]
    pub fn como_texto(&self) -> Option<&str> {
        match self {
            Json::Texto(texto) => Some(texto),
            _ => None,
        }
    }

    /// Entero.
    #[must_use]
    pub fn como_entero(&self) -> Option<i64> {
        match self {
            Json::Numero(numero) => Some(*numero),
            _ => None,
        }
    }

    /// Booleano.
    #[must_use]
    pub fn como_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(valor) => Some(*valor),
            _ => None,
        }
    }

    /// Arreglo.
    #[must_use]
    pub fn como_arreglo(&self) -> Option<&[Json]> {
        match self {
            Json::Arreglo(valores) => Some(valores),
            _ => None,
        }
    }
}

/// Parser recursivo con cursor sobre los bytes.
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn mirar(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn avanzar(&mut self) -> Option<u8> {
        let byte = self.mirar();
        if byte.is_some() {
            self.pos += 1;
        }
        byte
    }

    fn espacios(&mut self) {
        while matches!(self.mirar(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn valor(&mut self, profundidad: usize) -> Result<Json, ErrorVotos> {
        if profundidad > PROFUNDIDAD_MAXIMA {
            return Err(ErrorVotos::JsonProfundo);
        }
        self.espacios();
        match self.mirar() {
            Some(b'{') => self.objeto(profundidad),
            Some(b'[') => self.arreglo(profundidad),
            Some(b'"') => self.cadena().map(Json::Texto),
            Some(b't') => {
                self.literal("true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.literal("false")?;
                Ok(Json::Bool(false))
            }
            Some(b'n') => {
                self.literal("null")?;
                Ok(Json::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.numero(),
            _ => Err(ErrorVotos::Json("valor inesperado".to_string())),
        }
    }

    fn literal(&mut self, esperado: &str) -> Result<(), ErrorVotos> {
        for byte in esperado.bytes() {
            if self.avanzar() != Some(byte) {
                return Err(ErrorVotos::Json(format!("se esperaba `{esperado}`")));
            }
        }
        Ok(())
    }

    fn numero(&mut self) -> Result<Json, ErrorVotos> {
        let inicio = self.pos;
        if self.mirar() == Some(b'-') {
            self.pos += 1;
        }
        let mut digitos = 0usize;
        while matches!(self.mirar(), Some(b'0'..=b'9')) {
            self.pos += 1;
            digitos += 1;
        }
        if digitos == 0 {
            return Err(ErrorVotos::Json("numero sin digitos".to_string()));
        }
        if matches!(self.mirar(), Some(b'.' | b'e' | b'E')) {
            return Err(ErrorVotos::Json(
                "los vectores no usan coma flotante".to_string(),
            ));
        }
        let texto = self
            .bytes
            .get(inicio..self.pos)
            .ok_or_else(|| ErrorVotos::Json("numero fuera de rango".to_string()))?;
        let texto = std::str::from_utf8(texto)
            .map_err(|_| ErrorVotos::Json("numero no utf8".to_string()))?;
        texto
            .parse::<i64>()
            .map(Json::Numero)
            .map_err(|_| ErrorVotos::Json("entero fuera de i64".to_string()))
    }

    fn cadena(&mut self) -> Result<String, ErrorVotos> {
        if self.avanzar() != Some(b'"') {
            return Err(ErrorVotos::Json("se esperaba una cadena".to_string()));
        }
        let mut salida: Vec<u8> = Vec::new();
        loop {
            match self.avanzar() {
                None => return Err(ErrorVotos::Json("cadena sin cerrar".to_string())),
                Some(b'"') => break,
                Some(b'\\') => self.escape(&mut salida)?,
                Some(byte) => salida.push(byte),
            }
        }
        String::from_utf8(salida).map_err(|_| ErrorVotos::Json("cadena no utf8".to_string()))
    }

    fn escape(&mut self, salida: &mut Vec<u8>) -> Result<(), ErrorVotos> {
        match self.avanzar() {
            Some(b'"') => salida.push(b'"'),
            Some(b'\\') => salida.push(b'\\'),
            Some(b'/') => salida.push(b'/'),
            Some(b'b') => salida.push(0x08),
            Some(b'f') => salida.push(0x0c),
            Some(b'n') => salida.push(b'\n'),
            Some(b'r') => salida.push(b'\r'),
            Some(b't') => salida.push(b'\t'),
            Some(b'u') => {
                let mut codigo = 0u32;
                for _ in 0..4 {
                    let digito = self
                        .avanzar()
                        .and_then(|byte| (byte as char).to_digit(16))
                        .ok_or_else(|| ErrorVotos::Json("\\u invalido".to_string()))?;
                    codigo = codigo * 16 + digito;
                }
                let caracter = char::from_u32(codigo)
                    .ok_or_else(|| ErrorVotos::Json("\\u fuera de rango".to_string()))?;
                let mut buffer = [0u8; 4];
                salida.extend_from_slice(caracter.encode_utf8(&mut buffer).as_bytes());
            }
            _ => return Err(ErrorVotos::Json("escape invalido".to_string())),
        }
        Ok(())
    }

    fn arreglo(&mut self, profundidad: usize) -> Result<Json, ErrorVotos> {
        self.pos += 1; // '['
        let mut valores = Vec::new();
        self.espacios();
        if self.mirar() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arreglo(valores));
        }
        loop {
            valores.push(self.valor(profundidad + 1)?);
            self.espacios();
            match self.avanzar() {
                Some(b',') => {}
                Some(b']') => return Ok(Json::Arreglo(valores)),
                _ => return Err(ErrorVotos::Json("arreglo mal formado".to_string())),
            }
        }
    }

    fn objeto(&mut self, profundidad: usize) -> Result<Json, ErrorVotos> {
        self.pos += 1; // '{'
        let mut campos = Vec::new();
        self.espacios();
        if self.mirar() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Objeto(campos));
        }
        loop {
            self.espacios();
            let clave = self.cadena()?;
            self.espacios();
            if self.avanzar() != Some(b':') {
                return Err(ErrorVotos::Json("falta `:`".to_string()));
            }
            let valor = self.valor(profundidad + 1)?;
            campos.push((clave, valor));
            self.espacios();
            match self.avanzar() {
                Some(b',') => {}
                Some(b'}') => return Ok(Json::Objeto(campos)),
                _ => return Err(ErrorVotos::Json("objeto mal formado".to_string())),
            }
        }
    }
}
