//! Pruebas de la palanca V2: la clave de un agregado por **resta de las ausentes** de la suma de su
//! subred tiene que dar exactamente el mismo resultado que sumando las presentes.
//!
//! Pruebas `resta_01`…`resta_05` de la orden A5-c-1a-5. Cubren la operación de `zx-bls`
//! ([`ClaveAgregada`]), el diferencial de veredictos contra una **referencia que suma las presentes**
//! escrita aquí, el contador de sumas por ventana, la no reutilización entre tablas y el agregado
//! sin firmantes.
#![allow(
    clippy::indexing_slicing,
    clippy::integer_division,
    reason = "test: los indices y divisores estan acotados por construccion"
)]

use std::sync::Arc;

use zx_bls::{ClaveAgregada, ErrorBLS, verificar_agregado_con_clave};
use zx_votos::agregacion::{
    Agregado, DOMINIO_SORTEO, ErrorAgregacion, GeneradorEscalares, MensajeVoto, MotivoAgregado,
    Reparto, SumasSubred, VeredictoAgregado, contador_sumas, sale_agregadora,
    verificar_lote_con_huella, verificar_lote_con_huella_y_sumas,
};
use zx_votos::agregador::{DatosVentana, ResultadoAgregado};
use zx_votos::serial::hash_bytes;
use zx_votos::ventana_raices::VentanaPorRaices;
use zx_votos::{
    Clave, ClavePublica, ClaveSecreta, DOMINIO_VOTO, Firma, FirmaAgregada, Hash, LONGITUD_HASH,
    Tabla, agregar_firmas, fast_aggregate_verify, firmar, hash_tabla, mensaje_voto_peso, verificar,
};

// ── constantes ───────────────────────────────────────────────────────────────────────────────

const N: u64 = 1;
const CANDIDATO: Hash = [0x11; LONGITUD_HASH];
const H_T: Hash = [0x22; LONGITUD_HASH];
const R1: Hash = [0x10; LONGITUD_HASH];

// ── utilidades ───────────────────────────────────────────────────────────────────────────────

/// SplitMix64: RNG determinista para las pruebas (semilla explícita, sin estado global).
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
}

impl GeneradorEscalares for SplitMix64 {
    fn escalar(&mut self) -> [u8; 16] {
        let mut escalar = [0u8; 16];
        escalar[..8].copy_from_slice(&self.siguiente().to_be_bytes());
        escalar[8..].copy_from_slice(&self.siguiente().to_be_bytes());
        escalar
    }
}

/// Par BLS determinista a partir de una semilla.
fn par_bls(semilla: u64) -> Result<(ClaveSecreta, ClavePublica), ErrorAgregacion> {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&semilla.to_le_bytes());
    ikm[8] = 0x9a;
    ikm[31] = 0x37;
    let secreta = ClaveSecreta::generar(&ikm)?;
    let publica = secreta.clave_publica();
    Ok((secreta, publica))
}

/// Mundo de prueba: tabla de claves reales, reparto, pesos y `A`.
struct Mundo {
    tabla: Tabla,
    claves: Vec<ClavePublica>,
    secretas: Vec<ClaveSecreta>,
    pesos: Vec<u128>,
    reparto: Reparto,
    huella: Hash,
    a: u32,
}

/// Construye un mundo con `num_claves` claves reales, `s` subredes, `a` agregadores y peso 1.
fn mundo_unos(num_claves: usize, s: u16, a: u32, semilla: u64) -> Result<Mundo, ErrorAgregacion> {
    let mut rng = SplitMix64(semilla);
    let mut secretas = Vec::with_capacity(num_claves);
    let mut claves = Vec::with_capacity(num_claves);
    let mut entradas = Vec::with_capacity(num_claves);
    for _ in 0..num_claves {
        let (secreta, publica) = par_bls(rng.siguiente())?;
        entradas.push(Clave {
            clave: publica.bytes().to_vec(),
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 0,
        });
        secretas.push(secreta);
        claves.push(publica);
    }
    let tabla = Tabla {
        n: 0,
        claves: entradas,
    };
    let reparto = Reparto::construir(&tabla, s)?;
    let huella = hash_tabla(&tabla);
    Ok(Mundo {
        tabla,
        claves,
        secretas,
        pesos: vec![1u128; num_claves],
        reparto,
        huella,
        a,
    })
}

/// Mensaje A3 de la raíz `R1`.
fn mensaje() -> MensajeVoto {
    MensajeVoto {
        n: N,
        candidato: CANDIDATO,
        h_t_siguiente: H_T,
        raiz_estado: R1,
    }
}

/// Bloque de datos de la ventana sobre el mundo.
fn datos_de(m: &Mundo, s: u16) -> Result<Arc<DatosVentana>, ErrorAgregacion> {
    DatosVentana::nuevo(&m.tabla, &m.claves, &m.pesos, s)
}

/// Subredes con al menos una clave.
fn subredes_no_vacias(m: &Mundo) -> Vec<u16> {
    (0..m.reparto.s())
        .filter(|sub| !m.reparto.claves_de(*sub).is_empty())
        .collect()
}

/// Lee el bit `posicion` (0-based) de un mapa.
fn bit_set(mapa: &[u8], posicion: usize) -> bool {
    mapa.get(posicion >> 3)
        .map(|byte| (byte >> (posicion & 7)) & 1 == 1)
        .unwrap_or(false)
}

/// Firma A3 de la clave global `global` sobre `mensaje`.
fn firma_de(m: &Mundo, global: usize, mensaje: MensajeVoto) -> Result<Firma, ErrorAgregacion> {
    let secreta = m
        .secretas
        .get(global)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    Ok(firmar(secreta, DOMINIO_VOTO, mensaje.mensaje().as_slice())?)
}

/// Construye un agregado con `firmantes` (posiciones en la subred) y `mensaje`, como las pruebas de
/// `ventana_raices`.
fn construir_agregado(
    m: &Mundo,
    sub: u16,
    firmantes: &[usize],
    indice_agregadora: usize,
    mensaje: MensajeVoto,
) -> Result<Agregado, ErrorAgregacion> {
    let indices_subred = m.reparto.claves_de(sub);
    let n_s = indices_subred.len();
    let mut mapa = vec![0u8; n_s.div_ceil(8)];
    let mut firmas = Vec::new();
    for &pos in firmantes {
        if let Some(byte) = mapa.get_mut(pos >> 3) {
            *byte |= 1 << (pos & 7);
        }
        let global = indices_subred
            .get(pos)
            .copied()
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        let secreta = m
            .secretas
            .get(global)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        firmas.push(firmar(secreta, DOMINIO_VOTO, mensaje.mensaje().as_slice())?);
    }
    let referencias: Vec<&Firma> = firmas.iter().collect();
    let firma_agregada = agregar_firmas(&referencias)?;
    let global_agregadora = indices_subred
        .get(indice_agregadora)
        .copied()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let secreta_agregadora = m
        .secretas
        .get(global_agregadora)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let firma_sorteo = firmar(secreta_agregadora, DOMINIO_SORTEO, &mensaje.n.to_be_bytes())?;
    Ok(Agregado {
        n: mensaje.n,
        candidato: mensaje.candidato,
        h_t_siguiente: mensaje.h_t_siguiente,
        raiz_estado: mensaje.raiz_estado,
        firma_agregada,
        huella_tabla: m.huella,
        subred: sub,
        indice_agregadora: u16::try_from(indice_agregadora)
            .map_err(|_| ErrorAgregacion::FueraDeU16)?,
        mapa_local: mapa,
        firma_sorteo,
    })
}

/// Construye un agregado con un `mapa_local` dado (y una firma agregada cualquiera válida como
/// tipo). El `indice_agregadora` se fija a 0.
fn agregado_con_mapa(
    m: &Mundo,
    sub: u16,
    mapa: &[u8],
    indice: usize,
) -> Result<Agregado, ErrorAgregacion> {
    let indices_subred = m.reparto.claves_de(sub);
    let global_agregadora = indices_subred
        .get(indice)
        .copied()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let secreta = m
        .secretas
        .get(global_agregadora)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let firma_sorteo = firmar(secreta, DOMINIO_SORTEO, &N.to_be_bytes())?;
    let firma = firma_de(m, global_agregadora, mensaje())?;
    let firma_agregada = agregar_firmas(&[&firma])?;
    Ok(Agregado {
        n: N,
        candidato: CANDIDATO,
        h_t_siguiente: H_T,
        raiz_estado: R1,
        firma_agregada,
        huella_tabla: m.huella,
        subred: sub,
        indice_agregadora: u16::try_from(indice).map_err(|_| ErrorAgregacion::FueraDeU16)?,
        mapa_local: mapa.to_vec(),
        firma_sorteo,
    })
}

/// Claves presentes en el `mapa` de la subred `sub`, en orden de subred.
fn presentes<'a>(m: &'a Mundo, sub: u16, mapa: &[u8]) -> Vec<&'a ClavePublica> {
    let indices = m.reparto.claves_de(sub);
    let mut claves = Vec::new();
    for (pos, &idx) in indices.iter().enumerate() {
        if bit_set(mapa, pos)
            && let Some(clave) = m.claves.get(idx)
        {
            claves.push(clave);
        }
    }
    claves
}

// ── 1 · clave por resta igual que por suma ───────────────────────────────────────────────────

#[test]
fn resta_01_clave_por_resta_igual_que_por_suma() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(32, 1, 64, 0xA5_0001)?;
    let sub = subredes_no_vacias(&m)[0];
    let n_s = m.reparto.claves_de(sub).len();
    let bytes = n_s.div_ceil(8);
    let sumas = SumasSubred::construir(&m.reparto, &m.claves)?;

    let mut mapas: Vec<Vec<u8>> = Vec::new();
    // (a) vacío: sin ningún bit.
    mapas.push(vec![0u8; bytes]);
    // (b) completo: todos los bits, con los sobrantes a cero.
    let mut completo = vec![0xFFu8; bytes];
    let sobrantes = n_s.rem_euclid(8);
    if sobrantes != 0
        && let Some(ultimo) = completo.last_mut()
    {
        *ultimo &= !(0xFFu8 << sobrantes);
    }
    mapas.push(completo);
    // (c) un bit: solo la posición 0.
    let mut un_bit = vec![0u8; bytes];
    if let Some(byte) = un_bit.get_mut(0) {
        *byte |= 1;
    }
    mapas.push(un_bit);
    // (d) medio: la mitad baja marcada.
    let mitad = n_s.div_ceil(2);
    let mut medio = vec![0u8; bytes];
    for pos in 0..mitad {
        if let Some(byte) = medio.get_mut(pos >> 3) {
            *byte |= 1 << (pos & 7);
        }
    }
    mapas.push(medio);
    // (e) aleatorios con semilla fija (unos casi completos y otros casi vacíos).
    let mut rng = SplitMix64(0xA5_0002);
    for _ in 0..16 {
        let mut mapa = vec![0u8; bytes];
        if rng.siguiente().is_multiple_of(2) {
            mapa.fill(0xFF);
            let faltan = (rng.siguiente() % 3) as usize;
            for _ in 0..faltan {
                let pos = (rng.siguiente() as usize) % n_s;
                if let Some(byte) = mapa.get_mut(pos >> 3) {
                    *byte &= !(1 << (pos & 7));
                }
            }
        } else {
            let cuantos = 1 + (rng.siguiente() % 3) as usize;
            for _ in 0..cuantos {
                let pos = (rng.siguiente() as usize) % n_s;
                if let Some(byte) = mapa.get_mut(pos >> 3) {
                    *byte |= 1 << (pos & 7);
                }
            }
        }
        if sobrantes != 0
            && let Some(ultimo) = mapa.last_mut()
        {
            *ultimo &= !(0xFFu8 << sobrantes);
        }
        mapas.push(mapa);
    }

    for (caso, mapa) in mapas.iter().enumerate() {
        let agregado = agregado_con_mapa(&m, sub, mapa, 0)?;
        let claves_presentes = presentes(&m, sub, mapa);
        if claves_presentes.is_empty() {
            // El mapa vacío no llega a la criptografía (la agregadora no está marcada). La suma de
            // las presentes sería la identidad: comprobamos que la resta de todas la da, y que
            // sumar una lista vacía es un error (lo que ve hoy la capa BLS).
            let todas: Vec<&ClavePublica> = m.claves.iter().collect();
            let mut total = ClaveAgregada::sumar(&todas)?;
            total.restar_varias(&todas);
            assert!(
                total.es_infinito(),
                "caso {caso}: Σ todas − Σ todas no es el infinito"
            );
            assert!(matches!(
                ClaveAgregada::sumar(&[]),
                Err(ErrorBLS::AgregacionVacia)
            ));
            assert!(
                sumas
                    .clave_de_mapa(&m.reparto, &m.claves, &agregado)
                    .is_err()
            );
            continue;
        }
        let por_resta = sumas.clave_de_mapa(&m.reparto, &m.claves, &agregado)?;
        let por_suma = ClaveAgregada::sumar(&claves_presentes)?;
        assert_eq!(
            por_resta, por_suma,
            "caso {caso}: resta y suma no coinciden"
        );
        // La suma de una sola clave coincide con `desde_clave`.
        let una = ClaveAgregada::desde_clave(claves_presentes[0]);
        assert_eq!(una, ClaveAgregada::sumar(&[claves_presentes[0]])?);
    }
    Ok(())
}

// ── 2 · veredictos iguales que la referencia que suma las presentes ──────────────────────────

/// Referencia de la prueba: reproduce el veredicto **sumando las claves presentes** con
/// `fast_aggregate_verify` (sin restar ausentes).
fn referencia_veredicto(
    m: &Mundo,
    agregado: &Agregado,
    a: u32,
) -> Result<VeredictoAgregado, ErrorAgregacion> {
    if agregado.huella_tabla != m.huella {
        return Ok(VeredictoAgregado::OtraTabla);
    }
    if agregado.subred >= m.reparto.s() {
        return Ok(VeredictoAgregado::Invalido(MotivoAgregado::Subred));
    }
    let indices = m.reparto.claves_de(agregado.subred);
    let n_s = indices.len();
    if agregado.mapa_local.len() != n_s.div_ceil(8) {
        return Ok(VeredictoAgregado::Invalido(MotivoAgregado::Forma));
    }
    let sobrantes = n_s.rem_euclid(8);
    if sobrantes != 0 {
        let mascara = 0xFFu8 << sobrantes;
        if agregado
            .mapa_local
            .last()
            .map(|ultimo| ultimo & mascara != 0)
            .unwrap_or(false)
        {
            return Ok(VeredictoAgregado::Invalido(MotivoAgregado::Forma));
        }
    }
    let posicion = agregado.indice_agregadora as usize;
    if posicion >= n_s {
        return Ok(VeredictoAgregado::Invalido(MotivoAgregado::Indice));
    }
    if !bit_set(&agregado.mapa_local, posicion) {
        return Ok(VeredictoAgregado::Invalido(
            MotivoAgregado::AgregadoraFueraDeMapa,
        ));
    }
    let huella_sorteo = hash_bytes(&agregado.firma_sorteo.bytes());
    if !sale_agregadora(&huella_sorteo, m.tabla.claves.len(), m.reparto.s(), a) {
        return Ok(VeredictoAgregado::Invalido(MotivoAgregado::SorteoNoSale));
    }
    let idx_agregadora = indices
        .get(posicion)
        .copied()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let agregadora = m
        .claves
        .get(idx_agregadora)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    if verificar(
        agregadora,
        &agregado.firma_sorteo,
        DOMINIO_SORTEO,
        &agregado.n.to_be_bytes(),
    )
    .is_err()
    {
        return Ok(VeredictoAgregado::Invalido(MotivoAgregado::FirmaSorteo));
    }
    let claves_presentes = presentes(m, agregado.subred, &agregado.mapa_local);
    let mensaje = mensaje_voto_peso(
        agregado.n,
        &agregado.candidato,
        &agregado.h_t_siguiente,
        &agregado.raiz_estado,
    );
    if fast_aggregate_verify(
        &claves_presentes,
        &agregado.firma_agregada,
        DOMINIO_VOTO,
        mensaje.as_slice(),
    )
    .is_err()
    {
        return Ok(VeredictoAgregado::Invalido(MotivoAgregado::FirmaAgregada));
    }
    Ok(VeredictoAgregado::Valido)
}

/// Mapa pseudoaleatorio para `resta_02`: casi completo, casi vacío o aleatorio.
fn mapa_aleatorio(rng: &mut SplitMix64, n_s: usize) -> Vec<u8> {
    let bytes = n_s.div_ceil(8);
    let mut mapa = vec![0u8; bytes];
    match rng.siguiente() % 4 {
        0 => {
            mapa.fill(0xFF);
            let faltan = (rng.siguiente() % 4) as usize;
            for _ in 0..faltan {
                let pos = (rng.siguiente() as usize) % n_s;
                if let Some(byte) = mapa.get_mut(pos >> 3) {
                    *byte &= !(1 << (pos & 7));
                }
            }
        }
        1 => {
            let cuantos = 1 + (rng.siguiente() % 3) as usize;
            for _ in 0..cuantos {
                let pos = (rng.siguiente() as usize) % n_s;
                if let Some(byte) = mapa.get_mut(pos >> 3) {
                    *byte |= 1 << (pos & 7);
                }
            }
        }
        _ => {
            for byte in &mut mapa {
                *byte = rng.byte();
            }
        }
    }
    // Una de cada ocho veces se dejan bits sobrantes sucios (forma inválida a propósito).
    if !rng.siguiente().is_multiple_of(8) {
        let sobrantes = n_s.rem_euclid(8);
        if sobrantes != 0
            && let Some(ultimo) = mapa.last_mut()
        {
            *ultimo &= !(0xFFu8 << sobrantes);
        }
    }
    mapa
}

/// Agregado pseudoaleatorio para `resta_02`.
fn agregado_aleatorio(m: &Mundo, rng: &mut SplitMix64) -> Result<Agregado, ErrorAgregacion> {
    let subs = subredes_no_vacias(m);
    let sub = subs[(rng.siguiente() as usize) % subs.len()];
    let indices = m.reparto.claves_de(sub);
    let n_s = indices.len();
    let mapa = mapa_aleatorio(rng, n_s);
    let marcadas: Vec<usize> = (0..n_s).filter(|pos| bit_set(&mapa, *pos)).collect();
    let mut indice = marcadas.first().copied().unwrap_or(0);
    // Una de cada diez veces, un índice fuera de rango o sobre un bit no marcado.
    if rng.siguiente().is_multiple_of(10) {
        indice = (rng.siguiente() as usize) % (n_s + 1);
    }
    let mensaje = mensaje();
    let firma_buena = !rng.siguiente().is_multiple_of(10);
    let mut firmas: Vec<Firma> = Vec::new();
    if firma_buena {
        for (pos, &idx) in indices.iter().enumerate() {
            if bit_set(&mapa, pos) {
                firmas.push(firma_de(m, idx, mensaje)?);
            }
        }
    }
    if firmas.is_empty() {
        let idx = indices.first().copied().unwrap_or(0);
        firmas.push(firma_de(
            m,
            idx,
            MensajeVoto {
                candidato: [0x77; LONGITUD_HASH],
                ..mensaje
            },
        )?);
    }
    let referencias: Vec<&Firma> = firmas.iter().collect();
    let firma_agregada = agregar_firmas(&referencias)?;
    let idx_agregadora = indices.get(indice).copied().unwrap_or(0);
    let sorteo = if rng.siguiente().is_multiple_of(20) {
        firmar(
            m.secretas
                .get(idx_agregadora)
                .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
            DOMINIO_SORTEO,
            b"sorteo de otro mensaje",
        )?
    } else {
        firmar(
            m.secretas
                .get(idx_agregadora)
                .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
            DOMINIO_SORTEO,
            &N.to_be_bytes(),
        )?
    };
    let huella = if rng.siguiente().is_multiple_of(32) {
        [0xAB; LONGITUD_HASH]
    } else {
        m.huella
    };
    Ok(Agregado {
        n: N,
        candidato: CANDIDATO,
        h_t_siguiente: H_T,
        raiz_estado: R1,
        firma_agregada,
        huella_tabla: huella,
        subred: sub,
        indice_agregadora: u16::try_from(indice).map_err(|_| ErrorAgregacion::FueraDeU16)?,
        mapa_local: mapa,
        firma_sorteo: sorteo,
    })
}

#[test]
fn resta_02_veredictos_iguales_que_antes() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(16, 3, 64, 0xA5_0003)?;
    let sumas = SumasSubred::construir(&m.reparto, &m.claves)?;
    let mut rng = SplitMix64(0xA5_0004);
    let mut vistos = 0usize;
    for lote_idx in 0..300u32 {
        let cuantos = 1 + (rng.siguiente() % 6) as usize;
        let mut lote = Vec::with_capacity(cuantos);
        for _ in 0..cuantos {
            lote.push(agregado_aleatorio(&m, &mut rng)?);
        }
        let mut generador = SplitMix64(u64::from(lote_idx) ^ 0xA5_0005);
        let nuevos = verificar_lote_con_huella_y_sumas(
            &lote,
            &m.tabla,
            &m.claves,
            &m.reparto,
            m.a,
            m.huella,
            &sumas,
            &mut generador,
        )?;
        for (k, agregado) in lote.iter().enumerate() {
            let referencia = referencia_veredicto(&m, agregado, m.a)?;
            assert_eq!(
                nuevos[k], referencia,
                "lote {lote_idx}, agregado {k}: la palanca cambió el veredicto"
            );
            if matches!(referencia, VeredictoAgregado::Valido) {
                vistos += 1;
            }
        }
        // Diferencial con la variante pública que suma las presentes.
        let mut generador_viejo = SplitMix64(u64::from(lote_idx) ^ 0xA5_0006);
        let viejos = verificar_lote_con_huella(
            &lote,
            &m.tabla,
            &m.claves,
            &m.reparto,
            m.a,
            m.huella,
            &mut generador_viejo,
        )?;
        assert_eq!(
            nuevos, viejos,
            "lote {lote_idx}: la variante con sumas difiere"
        );
    }
    assert!(vistos > 0, "la prueba no generó ningún agregado válido");
    Ok(())
}

// ── 3 · la suma de subred se calcula una vez por ventana ─────────────────────────────────────

#[test]
fn resta_03_la_suma_de_subred_se_calcula_una_vez_por_ventana()
-> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(32, 4, 64, 0xA5_0007)?;
    let subredes = subredes_no_vacias(&m).len() as u64;

    contador_sumas::reiniciar();
    let datos = datos_de(&m, 4)?;
    assert_eq!(
        contador_sumas::leer(),
        subredes,
        "debe calcularse una suma por subred no vacía al construir la ventana"
    );

    contador_sumas::reiniciar();
    // Lote de agregados casi completos (resta de ausentes) que añaden a una ventana fresca.
    let mut agregados = Vec::new();
    for sub in subredes_no_vacias(&m) {
        let n_s = m.reparto.claves_de(sub).len();
        if n_s >= 2 {
            let firmantes: Vec<usize> = (1..n_s).collect();
            agregados.push(construir_agregado(&m, sub, &firmantes, 1, mensaje())?);
        }
    }
    let mut v = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    let mut generador = SplitMix64(0xA5_0008);
    let _ = v.recibir_lote(&agregados, &mut generador)?;
    assert_eq!(
        contador_sumas::leer(),
        0,
        "recibir el lote no debe recalcular la suma de ninguna subred"
    );
    Ok(())
}

// ── 4 · otra tabla no reutiliza la suma ──────────────────────────────────────────────────────

#[test]
fn resta_04_otra_tabla_no_reutiliza_la_suma() -> Result<(), Box<dyn std::error::Error>> {
    let m_a = mundo_unos(24, 3, 64, 0xA5_0009)?;
    let m_b = mundo_unos(24, 3, 64, 0xA5_000A)?;
    // Se construyen en este orden: una caché global de sumas reutilizaría la de A en B.
    let datos_a = datos_de(&m_a, 3)?;
    let datos_b = datos_de(&m_b, 3)?;

    let sub = subredes_no_vacias(&m_b)[0];
    let suma_a = datos_a
        .sumas()
        .de_subred(sub)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let suma_b = datos_b
        .sumas()
        .de_subred(sub)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    assert_ne!(
        suma_a.bytes(),
        suma_b.bytes(),
        "las sumas de dos tablas distintas no pueden coincidir"
    );

    // Un agregado válido de B que cubre toda la subred.
    let n_s = m_b.reparto.claves_de(sub).len();
    let todos: Vec<usize> = (0..n_s).collect();
    let agregado = construir_agregado(&m_b, sub, &todos, 0, mensaje())?;

    let mut v_b = VentanaPorRaices::nuevo(Arc::clone(&datos_b), m_b.a, N, CANDIDATO, H_T);
    let mut generador = SplitMix64(0xA5_000B);
    let resultado = v_b.recibir_lote(std::slice::from_ref(&agregado), &mut generador)?;
    assert_eq!(
        resultado,
        vec![ResultadoAgregado::Aceptado],
        "la suma de la tabla B debe verificar un agregado de B"
    );

    // La firma de B no verifica contra la suma de A (la suma no se reutiliza entre tablas).
    let mensaje = mensaje_voto_peso(N, &CANDIDATO, &H_T, &R1);
    assert_eq!(
        verificar_agregado_con_clave(
            suma_a,
            &agregado.firma_agregada,
            DOMINIO_VOTO,
            mensaje.as_slice()
        ),
        Err(ErrorBLS::VerificacionFallida)
    );
    Ok(())
}

// ── 5 · el agregado sin firmantes sigue inválido ─────────────────────────────────────────────

#[test]
fn resta_05_agregado_sin_firmantes_sigue_invalido() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(16, 2, 64, 0xA5_000C)?;
    let sumas = SumasSubred::construir(&m.reparto, &m.claves)?;
    let sub = subredes_no_vacias(&m)[0];
    let n_s = m.reparto.claves_de(sub).len();
    // Mapa vacío: ningún firmante; la agregadora tampoco está marcada.
    let mapa = vec![0u8; n_s.div_ceil(8)];
    let agregado = agregado_con_mapa(&m, sub, &mapa, 0)?;
    let esperado = VeredictoAgregado::Invalido(MotivoAgregado::AgregadoraFueraDeMapa);
    assert_eq!(
        zx_votos::agregacion::veredicto_con_huella_y_sumas(
            &agregado, &m.tabla, &m.claves, &m.reparto, m.a, m.huella, &sumas,
        )?,
        esperado
    );
    let mut generador = SplitMix64(0xA5_000D);
    let lote = verificar_lote_con_huella_y_sumas(
        std::slice::from_ref(&agregado),
        &m.tabla,
        &m.claves,
        &m.reparto,
        m.a,
        m.huella,
        &sumas,
        &mut generador,
    )?;
    assert_eq!(lote, vec![esperado]);

    // La clave agregada del infinito se rechaza con el veredicto de hoy (VerificacionFallida).
    let todas: Vec<&ClavePublica> = m.claves.iter().collect();
    let mut total = ClaveAgregada::sumar(&todas)?;
    total.restar_varias(&todas);
    assert!(total.es_infinito());
    let firma = firma_de(&m, 0, mensaje())?;
    let firma_agregada = FirmaAgregada::desde_firma(&firma);
    let mensaje = mensaje_voto_peso(N, &CANDIDATO, &H_T, &R1);
    assert_eq!(
        verificar_agregado_con_clave(&total, &firma_agregada, DOMINIO_VOTO, mensaje.as_slice()),
        Err(ErrorBLS::VerificacionFallida)
    );
    Ok(())
}
