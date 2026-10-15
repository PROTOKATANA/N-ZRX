//! CLI del binario `zx-node` (decisión 10).

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

/// Papel del nodo (decisión 10). En esta orden (sin red), solo `Ambos` puede alcanzar el corte por
/// sí mismo: `Minero`/`Productor` son la forma de la CLI que W06d2 (con red) necesitará para un
/// nodo que solo mina o solo produce; en un proceso aislado, uno de los dos se quedaría esperando
/// bloques que nadie le va a mandar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Papel {
    /// Solo mina PoW (no llega a producir PoST por sí solo sin red).
    Minero,
    /// Solo produce PoST (no cruza el corte por sí solo sin red).
    Productor,
    /// Mina PoW y produce PoST: el único papel autosuficiente sin red.
    Ambos,
}

zx_core::definir_red_cli! {
/// Red aceptada por la CLI. Solo las dev son válidas (decisión 2); las otras existen para que el
/// rechazo sea un valor de CLI reconocido y no un `Red` inventado.
///
/// `RL-2c`: el reloj por ticks y el segundo VDF son un perfil de **red**, no una bandera de nodo.
/// `Dev` es la red dev clásica (reloj inactivo) y `DevReloj` la red dev con reloj (reloj activo);
/// la elección entra en la identidad de red, así que nodos de perfiles distintos se desconectan.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
    pub enum RedCli
}

impl RedCli {
    /// Perfil de red de esta elección de CLI (`RL-2c`).
    ///
    /// `RL-2d`: es fallible porque el perfil con reloj valida el invariante `A ≥ F` al construirse.
    ///
    /// # Errores
    /// [`crate::perfil::ErrorPerfil`] si el perfil de reloj incumple `A ≥ F`.
    pub fn perfil_red(
        self,
    ) -> Result<crate::perfil::PerfilRedConsenso, crate::perfil::ErrorPerfil> {
        if self.reloj_activo() {
            crate::perfil::perfil_red_dev_reloj()
        } else {
            // Las redes no operativas se rechazan antes de usar el perfil, como hasta ahora.
            Ok(crate::perfil::perfil_red_dev())
        }
    }
}

/// `zx-node`: nodo de la red dev de ZEROX, sin red (`ORDEN-W06d1`).
#[derive(Parser, Debug)]
#[command(name = "zx-node", version, about)]
pub struct Cli {
    /// Directorio de datos (almacén y parcelas).
    #[arg(long, value_name = "DIR")]
    pub datos: PathBuf,

    /// Red configurada. Solo `dev` arranca (decisión 2).
    #[arg(long, value_enum, default_value_t = RedCli::POR_DEFECTO)]
    pub red: RedCli,

    /// Semilla de derivación de claves dev.
    #[arg(long, default_value_t = 1)]
    pub semilla: u64,

    /// Índices de claves a derivar, separados por comas (p. ej. `0,1,2`).
    #[arg(long, value_delimiter = ',', default_value = "0,1,2")]
    pub claves: Vec<u32>,

    /// Papel del nodo.
    #[arg(long, value_enum, default_value_t = Papel::Ambos)]
    pub papel: Papel,

    /// `N_dev`: iteraciones AES por slot.
    #[arg(long, default_value_t = 138_873_760)]
    pub n_dev: u64,

    /// `SR_dev`: rango de solución.
    #[arg(long, default_value_t = u64::MAX)]
    pub sr_dev: u64,

    /// Ruta del registro estructurado (JSON, una línea por evento).
    #[arg(long, value_name = "RUTA")]
    pub registro: PathBuf,

    /// Para el nodo tras producir/alcanzar este slot de régimen (para pruebas y mediciones).
    #[arg(long)]
    pub parada_tras_slots: Option<u64>,

    /// `ORDEN-W06d6` decisión 6: desde este slot el nodo deja de **producir**, pero sigue
    /// validando, propagando y sincronizando (a diferencia de `--parada-tras-slots`, que para el
    /// nodo entero). Solo red dev, no es consenso: sirve para el reposo antes de comparar estados
    /// entre nodos (`P-ZRX/P-MEDICION/REVISION-W07c.md`).
    #[arg(long)]
    pub dejar_de_producir_en_slot: Option<u64>,

    /// Dirección donde escuchar (`ORDEN-W06d2`). Sin esto ni `--red-marcar`, el nodo corre
    /// exactamente como en `ORDEN-W06d1`: sin red.
    #[arg(long, value_name = "MULTIADDR")]
    pub red_escuchar: Option<String>,

    /// Direcciones de pares a marcar al arrancar, repetible.
    #[arg(long = "red-marcar", value_name = "MULTIADDR")]
    pub red_marcar: Vec<String>,

    /// FV-4b-N1 · Punto de control externo (V-3 A): fichero `ZXPC1` con un certificado de
    /// finalidad y su tabla de poder. El nodo nuevo arranca la finalidad por votos desde ahí.
    #[arg(long, value_name = "ARCHIVO")]
    pub punto_control: Option<PathBuf>,

    /// FV-4b-N3 · interruptor **dev** (solo `dev`): el nodo no emite ni difunde votos. Desde AUS-1b
    /// tampoco publica revelaciones (el nodo nunca las publica), así que un nodo con esta bandera
    /// solo observa.
    #[arg(long)]
    pub sin_voto: bool,

    /// FV-4b-N3 · interruptor **dev** conservado por compatibilidad: **no tiene efecto**. AUS-1b ·
    /// B1: el nodo ya no publica nunca la revelación obligatoria de su ventana (la revelación no
    /// tiene efecto en el consenso desde AUS-1a), así que el interruptor se acepta pero no cambia
    /// nada. Nodo «en silencio» del humo.
    #[arg(long)]
    pub sin_revelacion: bool,

    /// PD-1e · E4 · activa el **modo por peso** del contrato v2 (voto A3, certificado compacto
    /// `0x09`, acta `0x0A` y evidencia `0x0B`) en lugar del sorteo de hoy. Solo red `dev` y
    /// **apagado por defecto**. Todos los nodos de una misma red deben llevarlo o ninguno: una red
    /// mezclada no encadena los certificados de los dos flujos.
    #[arg(long)]
    pub votos_peso: bool,

    /// `ORDEN-RD3c` · N1: enciende el **registro firmado de direcciones** (`ZXREG1`). **Apagado por
    /// defecto**: el nodo ni pide ni guarda entradas y responde a la petición con una página vacía.
    #[arg(long)]
    pub red_registro: bool,

    /// `ORDEN-RD3c` · N5: con el registro encendido, **no** publica la entrada propia (publicación
    /// voluntaria). Sin esta bandera, publicar va activado cuando el registro está encendido.
    #[arg(long)]
    pub red_registro_sin_publicar: bool,
}

/// `ORDEN-RD3c`: opciones de arranque del registro de direcciones.
///
/// `main.rs` (ajeno a esta orden) no reenvía la CLI a `red::arrancar_con_datos`, así que el módulo
/// de red relee aquí los argumentos del proceso. Si el proceso no es el binario `zx-node` (por
/// ejemplo, un test), la relectura falla y el registro queda **apagado** — el valor por defecto.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpcionesRegistro {
    /// ¿Enciende el registro (N1)?
    pub activo: bool,
    /// ¿Publica la entrada propia (N5)?
    pub publicar: bool,
    /// Semilla de las claves dev, para firmar la entrada propia.
    pub semilla: u64,
    /// Índices de claves dev (se usa el primero como productor).
    pub indices_claves: Vec<u32>,
}

impl OpcionesRegistro {
    /// Las opciones con el registro apagado: el valor por defecto y lo que se usa cuando no se
    /// pueden leer los argumentos del binario.
    #[must_use]
    pub fn apagado() -> Self {
        Self {
            activo: false,
            publicar: false,
            semilla: 0,
            indices_claves: Vec::new(),
        }
    }

    /// RD-4b · P5: deriva las opciones del registro de la CLI **ya parseada**. Sustituye a la
    /// relectura de los argumentos del proceso que hacía la capa de red: la bandera que ve la CLI
    /// es la que enciende el registro en la red, sin volver a mirar `argv`.
    #[must_use]
    pub fn desde(cli: &Cli) -> Self {
        Self {
            activo: cli.red_registro,
            publicar: cli.red_registro && !cli.red_registro_sin_publicar,
            semilla: cli.semilla,
            indices_claves: cli.claves.clone(),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "los tests fallan con panic por diseño")]
mod tests {
    use super::*;

    /// RD-4b · §3.3 · el arranque recibe las opciones ya parseadas: `main.rs` las deriva de `Cli` y
    /// la capa de red **no** vuelve a mirar los argumentos del proceso. La aguja se compone en
    /// tiempo de ejecución para no aparecer literalmente en este fuente.
    #[test]
    fn rd4b_main_pasa_las_opciones_sin_releer_argumentos() {
        let aguja = ["args", "_os"].concat();
        let main = include_str!("main.rs");
        assert!(
            main.contains("OpcionesRegistro::desde"),
            "main.rs no deriva las opciones del registro de la CLI"
        );
        assert!(
            !main.contains("opciones_registro()"),
            "main.rs conserva la relectura de argumentos"
        );
        let red = include_str!("red/mod.rs");
        assert!(
            !red.contains(&aguja) && !red.contains("Cli::opciones_registro"),
            "red/mod.rs vuelve a releer los argumentos del proceso"
        );
        assert!(
            !include_str!("cli.rs").contains(&aguja),
            "cli.rs conserva la relectura de argumentos"
        );
    }

    /// RD-4b · §3.3 · la bandera que ve la CLI es la que enciende el registro en la red.
    #[test]
    fn rd4b_red_y_cli_ven_la_misma_opcion() {
        let con = Cli::try_parse_from([
            "zx-node",
            "--datos",
            "/tmp/d",
            "--registro",
            "/tmp/r",
            "--red-registro",
        ])
        .unwrap();
        let o = OpcionesRegistro::desde(&con);
        assert_eq!(o.activo, con.red_registro);
        assert!(o.activo && o.publicar, "--red-registro enciende y publica");
        assert_eq!(o.semilla, con.semilla);
        assert_eq!(o.indices_claves, con.claves);

        let sin =
            Cli::try_parse_from(["zx-node", "--datos", "/tmp/d", "--registro", "/tmp/r"]).unwrap();
        let o = OpcionesRegistro::desde(&sin);
        assert!(!o.activo, "sin la bandera el registro queda apagado");
        assert!(!o.publicar);

        let publicar_off = Cli::try_parse_from([
            "zx-node",
            "--datos",
            "/tmp/d",
            "--registro",
            "/tmp/r",
            "--red-registro",
            "--red-registro-sin-publicar",
        ])
        .unwrap();
        let o = OpcionesRegistro::desde(&publicar_off);
        assert!(o.activo && !o.publicar);
    }
}
