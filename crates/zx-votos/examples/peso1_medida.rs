//! PESO-1: instrumento release, cinco repeticiones y perf activado solo en las regiones medidas.
#![forbid(unsafe_code)]
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::time::Instant;
use zx_bls::{
    ClavePublica, ClaveSecreta, ClavesPreparadas, Firma, FirmaAgregada, agregar_firmas, firmar,
};
use zx_votos::peso::{
    CertificadoPeso, mensaje_voto_peso, verificar_firma_peso, verificar_firma_peso_preparada,
    verificar_firma_peso_selectiva,
};
use zx_votos::{Clave, DOMINIO_VOTO, Tabla};

type Fallo = Box<dyn Error>;
const N: usize = 65536;
const FIRMANTES: [usize; 5] = [1, 64, 1024, 16384, N];

fn tabla(bytes: &[[u8; 48]]) -> Tabla {
    Tabla {
        n: 7,
        claves: bytes
            .iter()
            .map(|b| Clave {
                clave: b.to_vec(),
                peso: 1,
                activo: true,
                prueba: true,
                garantia: 1,
            })
            .collect(),
    }
}

fn preparar_fixture(dir: &Path, semilla: u64) -> Result<(), Fallo> {
    std::fs::create_dir_all(dir)?;
    let mut publicas = BufWriter::new(File::create(dir.join("pk.bin"))?);
    let m = mensaje_voto_peso(7, &[1; 32], &[0x31; 32], &[0x73; 32]);
    let mut firmas = Vec::with_capacity(N);
    for i in 0..N {
        let mut ikm = [0x5a; 32];
        ikm.get_mut(..8)
            .ok_or("semilla")?
            .copy_from_slice(&semilla.to_le_bytes());
        ikm.get_mut(8..16)
            .ok_or("indice")?
            .copy_from_slice(&(i as u64).to_le_bytes());
        let sk = ClaveSecreta::generar(&ikm)?;
        publicas.write_all(&sk.clave_publica().bytes())?;
        firmas.push(firmar(&sk, DOMINIO_VOTO, &m)?);
        if FIRMANTES.contains(&(i + 1)) {
            let refs = firmas.iter().collect::<Vec<_>>();
            let agregada = agregar_firmas(&refs)?;
            std::fs::write(dir.join(format!("sig-{}.bin", i + 1)), agregada.bytes())?;
        }
    }
    publicas.flush()?;
    std::fs::write(dir.join("semilla.txt"), format!("{semilla}\n"))?;
    eprintln!("fixture publica N={N} semilla={semilla}; no escalares escritos");
    Ok(())
}

fn leer_fixture(dir: &Path) -> Result<Vec<[u8; 48]>, Fallo> {
    let bytes = std::fs::read(dir.join("pk.bin"))?;
    if bytes.len() != N * 48 {
        return Err("fixture de longitud incorrecta".into());
    }
    bytes.chunks_exact(48).map(|b| Ok(b.try_into()?)).collect()
}

fn certificado(dir: &Path, cantidad: usize) -> Result<CertificadoPeso, Fallo> {
    let firma = Firma::desde_bytes(&std::fs::read(dir.join(format!("sig-{cantidad}.bin")))?)?;
    let mut mapa = vec![0; N.div_ceil(8)];
    for i in 0..cantidad {
        *mapa.get_mut(i >> 3).ok_or("mapa")? |= 1 << (i & 7);
    }
    Ok(CertificadoPeso {
        n: 7,
        candidato: [1; 32],
        h_t_siguiente: [0x31; 32],
        raiz_estado: [0x73; 32],
        firma: FirmaAgregada::desde_firma(&firma),
        mapa,
    })
}

fn puntos(tabla: &Tabla) -> Result<Vec<ClavePublica>, Fallo> {
    tabla
        .claves
        .iter()
        .map(|c| Ok(ClavePublica::desde_bytes(std::hint::black_box(&c.clave))?))
        .collect()
}

fn preparar(tabla: &Tabla) -> Result<ClavesPreparadas, Fallo> {
    Ok(ClavesPreparadas::desde_bytes(
        tabla.claves.iter().map(|c| std::hint::black_box(&c.clave)),
    )?)
}

struct Perf {
    control: File,
    ack: BufReader<File>,
}
impl Perf {
    fn abrir() -> Result<Option<Self>, Fallo> {
        let Ok(path) = std::env::var("PESO1_PERF_CTL") else {
            return Ok(None);
        };
        let ack = std::env::var("PESO1_PERF_ACK")?;
        Ok(Some(Self {
            control: OpenOptions::new().read(true).write(true).open(path)?,
            ack: BufReader::new(OpenOptions::new().read(true).write(true).open(ack)?),
        }))
    }
    fn enviar(&mut self, orden: &str) -> Result<(), Fallo> {
        writeln!(self.control, "{orden}")?;
        self.control.flush()?;
        let mut linea = String::new();
        self.ack.read_line(&mut linea)?;
        if linea.trim_matches(|c: char| c == '\0' || c.is_whitespace()) != "ack" {
            return Err(format!("acuse inesperado: {linea:?}").into());
        }
        Ok(())
    }
}

fn medir<T>(
    modo: &str,
    cantidad: usize,
    mut trabajo: impl FnMut() -> Result<T, Fallo>,
) -> Result<(), Fallo> {
    let mut perf = Perf::abrir()?;
    println!("modo,tabla,firmantes,repeticion,ns");
    for rep in 1..=5 {
        if let Some(p) = &mut perf {
            p.enviar("enable")?;
        }
        let inicio = Instant::now();
        let resultado = std::hint::black_box(trabajo()?);
        let ns = inicio.elapsed().as_nanos();
        if let Some(p) = &mut perf {
            p.enviar("disable")?;
        }
        // Como MED-EA, destruir el resultado devuelto queda fuera del cronómetro.
        // Los temporales internos de verificar_firma_peso quedan dentro.
        drop(resultado);
        println!("{modo},{N},{cantidad},{rep},{ns}");
    }
    Ok(())
}

fn entorno() -> Result<(), Fallo> {
    let cg = std::fs::read_to_string("/proc/self/cgroup")?;
    let path = cg
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or("cgroup v2")?;
    let max = std::fs::read_to_string(format!("/sys/fs/cgroup{path}/memory.max"))?;
    let swap = std::fs::read_to_string(format!("/sys/fs/cgroup{path}/memory.swap.max"))?;
    let estado = std::fs::read_to_string("/proc/self/status")?;
    let afinidad = estado
        .lines()
        .find(|l| l.starts_with("Cpus_allowed_list:"))
        .ok_or("afinidad")?;
    eprintln!(
        "cgroup={path} memory.max={} memory.swap.max={} {afinidad}",
        max.trim(),
        swap.trim()
    );
    if max.trim() != "17179869184"
        || swap.trim() != "0"
        || afinidad.split_whitespace().last() != Some("4")
    {
        return Err("limites efectivos incorrectos para medida B0b/CPU4".into());
    }
    Ok(())
}

fn main() -> Result<(), Fallo> {
    entorno()?;
    let args = std::env::args().collect::<Vec<_>>();
    let modo = args.get(1).ok_or("modo")?;
    let dir = Path::new(args.get(2).ok_or("directorio")?);
    let valor: u64 = args.get(3).ok_or("firmantes o semilla")?.parse()?;
    if modo == "fixture" {
        return preparar_fixture(dir, valor);
    }
    let cantidad = usize::try_from(valor)?;
    let bytes = leer_fixture(dir)?;
    let tabla = tabla(&bytes);
    if modo == "preparar" {
        let preparada = preparar(&tabla)?;
        eprintln!(
            "memoria puntos={} descriptor={} bytes_por_clave={} entradas={}",
            preparada.bytes_puntos(),
            std::mem::size_of::<ClavesPreparadas>(),
            std::mem::size_of::<ClavePublica>(),
            preparada.len()
        );
        drop(preparada);
        return medir(modo, N, || preparar(&tabla));
    }
    if !FIRMANTES.contains(&cantidad) {
        return Err("cantidad no prevista".into());
    }
    let cert = certificado(dir, cantidad)?;
    let sig = cert.firma.bytes();
    // Oráculo y variantes sobre la misma fixture, fuera del cronómetro.
    let keys = puntos(&tabla)?;
    let preparada = preparar(&tabla)?;
    verificar_firma_peso(&tabla, &keys, &cert)?;
    verificar_firma_peso_preparada(&tabla, &preparada, &cert)?;
    verificar_firma_peso_selectiva(&tabla, &cert)?;
    let mut cambiada = cert.clone();
    cambiada.candidato = [0xff; 32];
    assert!(verificar_firma_peso_selectiva(&tabla, &cambiada).is_err());
    eprintln!("controles mismo veredicto=OK firmantes={cantidad}");
    match modo.as_str() {
        "hoy_frio" => {
            drop(keys);
            drop(preparada);
            medir(modo, cantidad, || {
                let keys = puntos(&tabla)?;
                let firma = Firma::desde_bytes(std::hint::black_box(&sig))?;
                let cert = CertificadoPeso {
                    firma: FirmaAgregada::desde_firma(&firma),
                    ..cert.clone()
                };
                Ok(verificar_firma_peso(
                    std::hint::black_box(&tabla),
                    &keys,
                    &cert,
                )?)
            })
        }
        "selectiva_frio" => {
            drop(keys);
            drop(preparada);
            medir(modo, cantidad, || {
                let firma = Firma::desde_bytes(std::hint::black_box(&sig))?;
                let cert = CertificadoPeso {
                    firma: FirmaAgregada::desde_firma(&firma),
                    ..cert.clone()
                };
                Ok(verificar_firma_peso_selectiva(
                    std::hint::black_box(&tabla),
                    &cert,
                )?)
            })
        }
        "hoy_caliente" => {
            drop(preparada);
            medir(modo, cantidad, || {
                Ok(verificar_firma_peso(&tabla, &keys, &cert)?)
            })
        }
        "preparada" => {
            drop(keys);
            medir(modo, cantidad, || {
                Ok(verificar_firma_peso_preparada(&tabla, &preparada, &cert)?)
            })
        }
        _ => Err("modo desconocido".into()),
    }
}
