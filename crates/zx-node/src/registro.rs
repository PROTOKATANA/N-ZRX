//! Registro estructurado (decisión 9; `ESCENARIOS-0.0.1.md` §1): una línea JSON por evento, con
//! reloj monotónico en nanosegundos y reloj de pared en el mismo instante.
//!
//! **No se añade `serde`/`serde_json`** (decisión del ejecutor, `PROGRESO.md`): el esquema es fijo,
//! sin anidamiento profundo, y una línea la construye [`Evento`] a mano. Cada valor de texto se
//! escapa (comillas, barra invertida y controles) antes de escribir.

use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Registro estructurado del nodo: un fichero, una línea JSON por evento.
pub struct Registro {
    archivo: Mutex<File>,
    inicio: Instant,
}

fn escapar_json(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Un evento en construcción: pares `clave: valor` en el orden en que se añaden.
pub struct Evento {
    texto: String,
    primero: bool,
}

impl Evento {
    fn nueva(tipo: &str, reloj_ns: u128, reloj_pared_ns: u128) -> Self {
        let mut texto = String::with_capacity(256);
        texto.push('{');
        texto.push_str("\"tipo\":");
        escapar_json(tipo, &mut texto);
        texto.push_str(",\"reloj_ns\":");
        texto.push_str(&reloj_ns.to_string());
        texto.push_str(",\"reloj_pared_ns\":");
        texto.push_str(&reloj_pared_ns.to_string());
        Self {
            texto,
            // Ya se escribieron `tipo`, `reloj_ns` y `reloj_pared_ns`: el próximo campo (el primero
            // que añada el llamante) necesita una coma delante. `false` aquí era el bug: producía
            // `"reloj_pared_ns":123"siguiente_campo":...` sin coma, JSON inválido.
            primero: true,
        }
    }

    fn separador(&mut self) {
        if self.primero {
            self.texto.push(',');
        }
        self.primero = true;
    }

    /// Añade un campo de texto.
    #[must_use]
    pub fn str(mut self, clave: &str, valor: &str) -> Self {
        self.separador();
        self.texto.push('"');
        self.texto.push_str(clave);
        self.texto.push_str("\":");
        escapar_json(valor, &mut self.texto);
        self
    }

    /// Añade un campo entero sin signo.
    #[must_use]
    pub fn u64(mut self, clave: &str, valor: u64) -> Self {
        self.separador();
        self.texto.push('"');
        self.texto.push_str(clave);
        self.texto.push_str("\":");
        self.texto.push_str(&valor.to_string());
        self
    }

    /// Añade un campo entero con signo.
    #[must_use]
    pub fn i64(mut self, clave: &str, valor: i64) -> Self {
        self.separador();
        self.texto.push('"');
        self.texto.push_str(clave);
        self.texto.push_str("\":");
        self.texto.push_str(&valor.to_string());
        self
    }

    /// Añade un campo booleano.
    #[must_use]
    pub fn bool(mut self, clave: &str, valor: bool) -> Self {
        self.separador();
        self.texto.push('"');
        self.texto.push_str(clave);
        self.texto.push_str("\":");
        self.texto.push_str(if valor { "true" } else { "false" });
        self
    }

    /// Añade un campo de lista de textos (p. ej. padres, como hashes hex).
    #[must_use]
    pub fn lista_str(mut self, clave: &str, valores: &[String]) -> Self {
        self.separador();
        self.texto.push('"');
        self.texto.push_str(clave);
        self.texto.push_str("\":[");
        for (i, v) in valores.iter().enumerate() {
            if i > 0 {
                self.texto.push(',');
            }
            escapar_json(v, &mut self.texto);
        }
        self.texto.push(']');
        self
    }

    fn terminar(mut self) -> String {
        self.texto.push('}');
        self.texto.push('\n');
        self.texto
    }
}

impl Registro {
    /// Abre (o crea) el fichero de registro en modo *append*.
    ///
    /// # Errores
    /// El de E/S al abrir el fichero.
    pub fn abrir(ruta: &Path) -> io::Result<Self> {
        let archivo = OpenOptions::new().create(true).append(true).open(ruta)?;
        Ok(Self {
            archivo: Mutex::new(archivo),
            inicio: Instant::now(),
        })
    }

    /// Empieza un evento nuevo con el reloj actual ya fijado.
    #[must_use]
    pub fn evento(&self, tipo: &str) -> Evento {
        let reloj_ns = self.inicio.elapsed().as_nanos();
        let reloj_pared_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Evento::nueva(tipo, reloj_ns, reloj_pared_ns)
    }

    /// Escribe el evento ya construido, con `sync` para forzarlo a disco (registro crítico).
    ///
    /// # Errores
    /// El de E/S al escribir o al forzar el volcado.
    pub fn escribir(&self, evento: Evento, sync: bool) -> io::Result<()> {
        let linea = evento.terminar();
        let mut archivo = self.archivo.lock().map_err(|_| {
            io::Error::other("registro estructurado envenenado por un fallo previo")
        })?;
        archivo.write_all(linea.as_bytes())?;
        if sync {
            archivo.sync_data()?;
        } else {
            archivo.flush()?;
        }
        Ok(())
    }
}
