//! Pruebas de la agregación de votos por subred (pieza A5, paso (a)).
#![allow(
    clippy::indexing_slicing,
    reason = "test: los indices estan acotados por construccion"
)]

use zx_votos::agregacion::{
    Agregado, DOMINIO_SORTEO, ErrorAgregacion, GeneradorEscalares, LONGITUD_FIJA_AGREGADO,
    LONGITUD_VOTO_RED, MensajeVoto, MotivoAgregado, Reparto, VeredictoAgregado, VotoRed,
    armar_certificado, sale_agregadora, subred, veredicto, verificar_lote,
};
use zx_votos::serial::hash_bytes;
use zx_votos::{
    Clave, ClavePublica, ClaveSecreta, DOMINIO_VOTO, Firma, FirmaAgregada, Hash, LONGITUD_HASH,
    Tabla, agregar_firmas, firmar, hash_tabla, mensaje_voto_peso, verificar_firma_peso,
};

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

/// Escalar big-endian de 32 bytes con un valor pequeño.
fn escalar_pequeno(valor: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = valor;
    bytes
}

/// Mundo de prueba: tabla de claves reales, reparto y mensaje A3 comunes.
struct Mundo {
    tabla: Tabla,
    claves: Vec<ClavePublica>,
    secretas: Vec<ClaveSecreta>,
    reparto: Reparto,
    mensaje: MensajeVoto,
    huella: Hash,
    a: u32,
}

/// Construye un mundo con `num_claves` claves reales, `s` subredes y `a` agregadores.
fn mundo(num_claves: usize, s: u16, a: u32, semilla: u64) -> Result<Mundo, ErrorAgregacion> {
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
    let mensaje = MensajeVoto {
        n: 1,
        candidato: [0x11; LONGITUD_HASH],
        h_t_siguiente: [0x22; LONGITUD_HASH],
        raiz_estado: [0x33; LONGITUD_HASH],
    };
    let huella = hash_tabla(&tabla);
    Ok(Mundo {
        tabla,
        claves,
        secretas,
        reparto,
        mensaje,
        huella,
        a,
    })
}

/// Índice global, dentro de `tabla.claves`, de la clave de la posición `pos` de la subred.
fn global_de(mundo: &Mundo, subred: u16, pos: usize) -> Result<usize, ErrorAgregacion> {
    mundo
        .reparto
        .claves_de(subred)
        .get(pos)
        .copied()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)
}

/// Ubicación `(subred, posición)` de la clave global `global`.
fn ubicacion(mundo: &Mundo, global: usize) -> Result<(u16, usize), ErrorAgregacion> {
    for sub in 0..mundo.reparto.s() {
        if let Some(pos) = mundo
            .reparto
            .claves_de(sub)
            .iter()
            .position(|indice| *indice == global)
        {
            return Ok((sub, pos));
        }
    }
    Err(ErrorAgregacion::ClaveNoRegistrada)
}

/// Subredes con al menos una clave.
fn subredes_no_vacias(mundo: &Mundo) -> Vec<u16> {
    (0..mundo.reparto.s())
        .filter(|sub| !mundo.reparto.claves_de(*sub).is_empty())
        .collect()
}

/// Construye un agregado válido para `firmantes` (posiciones en la subred).
fn construir_agregado(
    mundo: &Mundo,
    subred: u16,
    firmantes: &[usize],
    indice_agregadora: usize,
) -> Result<Agregado, ErrorAgregacion> {
    let indices_subred = mundo.reparto.claves_de(subred);
    let n_s = indices_subred.len();
    let mut mapa = vec![0u8; n_s.div_ceil(8)];
    let mut firmas = Vec::new();
    for &pos in firmantes {
        if let Some(byte) = mapa.get_mut(pos >> 3) {
            *byte |= 1 << (pos & 7);
        }
        let global = global_de(mundo, subred, pos)?;
        let secreta = mundo
            .secretas
            .get(global)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        firmas.push(firmar(
            secreta,
            DOMINIO_VOTO,
            mundo.mensaje.mensaje().as_slice(),
        )?);
    }
    let referencias: Vec<&Firma> = firmas.iter().collect();
    let firma_agregada = agregar_firmas(&referencias)?;
    let global_agregadora = global_de(mundo, subred, indice_agregadora)?;
    let secreta_agregadora = mundo
        .secretas
        .get(global_agregadora)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let firma_sorteo = firmar(
        secreta_agregadora,
        DOMINIO_SORTEO,
        &mundo.mensaje.n.to_be_bytes(),
    )?;
    Ok(Agregado {
        n: mundo.mensaje.n,
        candidato: mundo.mensaje.candidato,
        h_t_siguiente: mundo.mensaje.h_t_siguiente,
        raiz_estado: mundo.mensaje.raiz_estado,
        firma_agregada,
        huella_tabla: mundo.huella,
        subred,
        indice_agregadora: u16::try_from(indice_agregadora)
            .map_err(|_| ErrorAgregacion::FueraDeU16)?,
        mapa_local: mapa,
        firma_sorteo,
    })
}

/// Firma de sorteo de una clave cualquiera que cumple (o no) la condición del A4.
fn firma_con_sorteo(
    mundo: &Mundo,
    quiere_sale: bool,
    a: u32,
    s: u16,
    semilla: u64,
) -> Result<Firma, ErrorAgregacion> {
    let mut rng = SplitMix64(semilla);
    for _ in 0..100_000 {
        let (secreta, _) = par_bls(rng.siguiente())?;
        let firma = firmar(&secreta, DOMINIO_SORTEO, &mundo.mensaje.n.to_be_bytes())?;
        let huella = hash_bytes(&firma.bytes());
        if sale_agregadora(&huella, mundo.tabla.claves.len(), s, a) == quiere_sale {
            return Ok(firma);
        }
    }
    Err(ErrorAgregacion::ClaveNoRegistrada)
}

// ── A1 · reparto ────────────────────────────────────────────────────────────────────────────

#[test]
fn agr_subred_solo_depende_de_la_clave() -> Result<(), ErrorAgregacion> {
    let mundo = mundo(32, 8, 8, 0x51)?;
    let mut distintas = 0usize;
    for clave in &mundo.claves {
        let primera = subred(&clave.bytes(), 8)?;
        let segunda = subred(&clave.bytes(), 8)?;
        assert_eq!(primera, segunda, "el reparto no es determinista");
        assert!(primera < 8, "subred fuera de rango: {primera}");
        let indices = mundo.reparto.claves_de(primera);
        let global = mundo
            .claves
            .iter()
            .position(|otra| otra.bytes() == clave.bytes())
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        assert!(
            indices.contains(&global),
            "la clave {global} no esta en su subred {primera}"
        );
        distintas += 1;
    }
    assert_eq!(distintas, mundo.claves.len());

    // La subred de una clave no cambia porque la tabla cambie: un reparto de un solo elemento la
    // coloca igual.
    let sub = subred(&mundo.claves[0].bytes(), 8)?;
    let tabla_una = Tabla {
        n: 0,
        claves: vec![mundo.tabla.claves[0].clone()],
    };
    let reparto_una = Reparto::construir(&tabla_una, 8)?;
    assert!(reparto_una.claves_de(sub).contains(&0));
    Ok(())
}

// ── A2 · voto de red ────────────────────────────────────────────────────────────────────────

#[test]
fn agr_voto_de_red_248_ida_y_vuelta() -> Result<(), ErrorAgregacion> {
    let mundo = mundo(4, 2, 4, 0x52)?;
    let secreta = mundo
        .secretas
        .first()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let firma = firmar(secreta, DOMINIO_VOTO, mundo.mensaje.mensaje().as_slice())?;
    let voto = VotoRed {
        n: mundo.mensaje.n,
        candidato: mundo.mensaje.candidato,
        h_t_siguiente: mundo.mensaje.h_t_siguiente,
        raiz_estado: mundo.mensaje.raiz_estado,
        clave: *mundo
            .claves
            .first()
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
        firma,
    };
    let bytes = voto.serializar();
    assert_eq!(bytes.len(), LONGITUD_VOTO_RED);
    assert_eq!(LONGITUD_VOTO_RED, 248);
    let vuelta = VotoRed::deserializar(&bytes)?;
    assert_eq!(vuelta, voto);
    Ok(())
}

#[test]
fn agr_voto_firma_el_mismo_a3() -> Result<(), ErrorAgregacion> {
    let mundo = mundo(4, 2, 4, 0x53)?;
    let secreta = mundo
        .secretas
        .first()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let firma = firmar(secreta, DOMINIO_VOTO, mundo.mensaje.mensaje().as_slice())?;
    let voto = VotoRed {
        n: mundo.mensaje.n,
        candidato: mundo.mensaje.candidato,
        h_t_siguiente: mundo.mensaje.h_t_siguiente,
        raiz_estado: mundo.mensaje.raiz_estado,
        clave: *mundo
            .claves
            .first()
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
        firma,
    };
    voto.verificar()?;

    let esperado = mensaje_voto_peso(
        voto.n,
        &voto.candidato,
        &voto.h_t_siguiente,
        &voto.raiz_estado,
    );
    assert_eq!(voto.mensaje(), esperado);

    let mut otro = voto;
    otro.candidato = [0x99; LONGITUD_HASH];
    assert!(
        otro.verificar().is_err(),
        "un A3 distinto MUST NOT verificar"
    );
    Ok(())
}

// ── A3 · agregado ───────────────────────────────────────────────────────────────────────────

/// Tabla de relleno con claves de 48 bytes (solo para tallas de serialización).
fn tabla_relleno(n: usize, semilla: u64) -> Tabla {
    let mut rng = SplitMix64(semilla);
    let mut claves = Vec::with_capacity(n);
    for _ in 0..n {
        let mut clave = vec![0u8; 48];
        for byte in &mut clave {
            *byte = rng.byte();
        }
        claves.push(Clave {
            clave,
            peso: 1,
            activo: true,
            prueba: false,
            garantia: 0,
        });
    }
    Tabla { n: 0, claves }
}

#[test]
fn agr_agregado_ida_y_vuelta_y_tallas() -> Result<(), ErrorAgregacion> {
    for n in [4096usize, 65536] {
        let mut tabla = tabla_relleno(n, 0x54 + n as u64);
        let (secreta, publica) = par_bls(0x54 ^ n as u64)?;
        if let Some(primera) = tabla.claves.first_mut() {
            primera.clave = publica.bytes().to_vec();
        }
        let reparto = Reparto::construir(&tabla, 64)?;
        let sub = subred(&publica.bytes(), 64)?;
        let indices = reparto.claves_de(sub);
        let pos = indices
            .iter()
            .position(|indice| *indice == 0)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        let n_s = indices.len();
        let mut mapa = vec![0u8; n_s.div_ceil(8)];
        if let Some(byte) = mapa.get_mut(pos >> 3) {
            *byte |= 1 << (pos & 7);
        }
        let mensaje = MensajeVoto {
            n: 7,
            candidato: [0x02; LONGITUD_HASH],
            h_t_siguiente: [0x03; LONGITUD_HASH],
            raiz_estado: [0x04; LONGITUD_HASH],
        };
        let firma = firmar(&secreta, DOMINIO_VOTO, mensaje.mensaje().as_slice())?;
        let firma_agregada = agregar_firmas(&[&firma])?;
        let firma_sorteo = firmar(&secreta, DOMINIO_SORTEO, &mensaje.n.to_be_bytes())?;
        let agregado = Agregado {
            n: mensaje.n,
            candidato: mensaje.candidato,
            h_t_siguiente: mensaje.h_t_siguiente,
            raiz_estado: mensaje.raiz_estado,
            firma_agregada,
            huella_tabla: hash_tabla(&tabla),
            subred: sub,
            indice_agregadora: u16::try_from(pos).map_err(|_| ErrorAgregacion::FueraDeU16)?,
            mapa_local: mapa,
            firma_sorteo,
        };
        let bytes = agregado.serializar();
        assert_eq!(bytes.len(), LONGITUD_FIJA_AGREGADO + n_s.div_ceil(8));
        assert_eq!(bytes.len(), Agregado::longitud(n_s));
        let vuelta = Agregado::deserializar(&bytes, n_s)?;
        assert_eq!(vuelta, agregado);
    }
    Ok(())
}

// ── A4 · sorteo ─────────────────────────────────────────────────────────────────────────────

#[test]
fn agr_sorteo_exacto_en_el_borde() {
    // n = 4096 = 2^12, S = 64, A = 32 -> A·S·2^256 = 2^267 y el límite es justo 2^255.
    let mut umbral = [0u8; LONGITUD_HASH];
    umbral[0] = 0x80; // 2^255: h·n = 2^267 = A·S·2^256, no es estrictamente menor.
    let mut justo_bajo = [0xffu8; LONGITUD_HASH];
    justo_bajo[0] = 0x7f; // 2^255 − 1: h·n < A·S·2^256.
    assert!(!sale_agregadora(&umbral, 4096, 64, 32));
    assert!(sale_agregadora(&justo_bajo, 4096, 64, 32));
}

#[test]
fn agr_sorteo_todas_si_a_s_mayor_que_n() {
    let cero = [0u8; LONGITUD_HASH];
    let maximo = [0xffu8; LONGITUD_HASH];
    // A·S = 32·8 = 256 ≥ 64 = n: salen todas.
    assert!(sale_agregadora(&cero, 64, 8, 32));
    assert!(sale_agregadora(&maximo, 64, 8, 32));
    // A·S = 32·2 = 64 = n: también salen todas (el umbral es estricto).
    assert!(sale_agregadora(&maximo, 64, 2, 32));
}

// ── A5 · veredicto ──────────────────────────────────────────────────────────────────────────

#[test]
fn agr_veredicto_otra_tabla_no_es_invalido() -> Result<(), ErrorAgregacion> {
    let base = mundo(16, 4, 8, 0x56)?;
    let sub = *subredes_no_vacias(&base)
        .first()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let agregado = construir_agregado(&base, sub, &[0], 0)?;
    assert_eq!(
        veredicto(&agregado, &base.tabla, &base.claves, &base.reparto, base.a)?,
        VeredictoAgregado::Valido
    );

    let otro = mundo(16, 4, 8, 0x57)?;
    assert_eq!(
        veredicto(&agregado, &otro.tabla, &otro.claves, &otro.reparto, otro.a)?,
        VeredictoAgregado::OtraTabla
    );
    Ok(())
}

#[test]
fn agr_bits_sobrantes_se_rechazan() -> Result<(), ErrorAgregacion> {
    let mundo = mundo(20, 4, 8, 0x55)?;
    let mut elegido = None;
    for sub in 0..mundo.reparto.s() {
        let n_s = mundo.reparto.claves_de(sub).len();
        if n_s > 0 && !n_s.is_multiple_of(8) {
            elegido = Some((sub, n_s));
            break;
        }
    }
    let (sub, n_s) = elegido.ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let agregado = construir_agregado(&mundo, sub, &[0], 0)?;
    assert_eq!(
        veredicto(
            &agregado,
            &mundo.tabla,
            &mundo.claves,
            &mundo.reparto,
            mundo.a
        )?,
        VeredictoAgregado::Valido
    );

    let mut malo = agregado;
    if let Some(byte) = malo.mapa_local.last_mut() {
        *byte |= 1 << (n_s & 7);
    }
    assert_eq!(
        veredicto(&malo, &mundo.tabla, &mundo.claves, &mundo.reparto, mundo.a)?,
        VeredictoAgregado::Invalido(MotivoAgregado::Forma)
    );
    Ok(())
}

#[test]
fn agr_veredicto_invalido_por_cada_motivo() -> Result<(), ErrorAgregacion> {
    let mundo = mundo(24, 4, 32, 0x58)?;
    let sub = *subredes_no_vacias(&mundo)
        .first()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let base = construir_agregado(&mundo, sub, &[0, 1], 0)?;
    let evaluar = |agregado: &Agregado, a: u32| {
        veredicto(agregado, &mundo.tabla, &mundo.claves, &mundo.reparto, a)
    };
    assert_eq!(evaluar(&base, mundo.a)?, VeredictoAgregado::Valido);

    let mut forma = base.clone();
    forma.mapa_local.push(0);
    assert_eq!(
        evaluar(&forma, mundo.a)?,
        VeredictoAgregado::Invalido(MotivoAgregado::Forma)
    );

    let mut subred_mala = base.clone();
    subred_mala.subred = mundo.reparto.s();
    assert_eq!(
        evaluar(&subred_mala, mundo.a)?,
        VeredictoAgregado::Invalido(MotivoAgregado::Subred)
    );

    let mut indice_malo = base.clone();
    indice_malo.indice_agregadora = u16::MAX;
    assert_eq!(
        evaluar(&indice_malo, mundo.a)?,
        VeredictoAgregado::Invalido(MotivoAgregado::Indice)
    );

    let mut sin_bit = base.clone();
    let posicion = base.indice_agregadora as usize;
    if let Some(byte) = sin_bit.mapa_local.get_mut(posicion >> 3) {
        *byte &= !(1 << (posicion & 7));
    }
    assert_eq!(
        evaluar(&sin_bit, mundo.a)?,
        VeredictoAgregado::Invalido(MotivoAgregado::AgregadoraFueraDeMapa)
    );

    // Sorteo que no sale: con A = 1 (A·S = 4 < 24) no salen todas.
    let mut no_sale = base.clone();
    no_sale.firma_sorteo = firma_con_sorteo(&mundo, false, 1, 4, 0x58b)?;
    assert_eq!(
        evaluar(&no_sale, 1)?,
        VeredictoAgregado::Invalido(MotivoAgregado::SorteoNoSale)
    );

    // Firma de sorteo de otra clave: con A = 64 salen todas y la firma no verifica.
    let mut firma_mala = base.clone();
    firma_mala.firma_sorteo = firma_con_sorteo(&mundo, true, 64, 4, 0x58c)?;
    assert_eq!(
        evaluar(&firma_mala, 64)?,
        VeredictoAgregado::Invalido(MotivoAgregado::FirmaSorteo)
    );

    // Firma agregada de otro mensaje: el sorteo es válido (A = 64) y la firma agregada no.
    let mut agregada_mala = base.clone();
    let secreta = mundo
        .secretas
        .first()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let otra = firmar(secreta, DOMINIO_VOTO, b"mensaje distinto")?;
    agregada_mala.firma_agregada = agregar_firmas(&[&otra])?;
    assert_eq!(
        evaluar(&agregada_mala, 64)?,
        VeredictoAgregado::Invalido(MotivoAgregado::FirmaAgregada)
    );
    Ok(())
}

// ── A6 · lotes ──────────────────────────────────────────────────────────────────────────────

#[test]
fn agr_lote_igual_que_uno_a_uno() -> Result<(), ErrorAgregacion> {
    // N = 4096, S = 32, A = 128 -> A·S = 4096 = N: todas salen.
    let mundo = mundo(4096, 32, 128, 0x60)?;
    let mut agregados = Vec::new();
    for sub in 0..mundo.reparto.s() {
        let n_s = mundo.reparto.claves_de(sub).len();
        for pos in 0..n_s.min(64) {
            agregados.push(construir_agregado(&mundo, sub, &[pos], pos)?);
        }
    }
    assert!(
        agregados.len() >= 2000,
        "ventana demasiado corta: {}",
        agregados.len()
    );

    let mut generador = SplitMix64(0x6000);
    let lote = verificar_lote(
        &agregados,
        &mundo.tabla,
        &mundo.claves,
        &mundo.reparto,
        mundo.a,
        &mut generador,
    )?;
    assert_eq!(lote.len(), agregados.len());
    for (i, agregado) in agregados.iter().enumerate() {
        let uno = veredicto(
            agregado,
            &mundo.tabla,
            &mundo.claves,
            &mundo.reparto,
            mundo.a,
        )?;
        assert_eq!(lote[i], uno, "discrepancia lote/uno-a-uno en {i}");
        assert_eq!(uno, VeredictoAgregado::Valido);
    }
    Ok(())
}

/// Mundo con las dos primeras claves fijadas a escalares pequeños para el desplazamiento compensado.
fn mundo_compensado(n: usize, s: u16, a: u32, semilla: u64) -> Result<Mundo, ErrorAgregacion> {
    let mut mundo = mundo(n, s, a, semilla)?;
    let secreta_5 = ClaveSecreta::desde_bytes(&escalar_pequeno(5))?;
    let secreta_3 = ClaveSecreta::desde_bytes(&escalar_pequeno(3))?;
    let publica_5 = secreta_5.clave_publica();
    let publica_3 = secreta_3.clave_publica();
    if let Some(entrada) = mundo.tabla.claves.get_mut(0) {
        entrada.clave = publica_5.bytes().to_vec();
    }
    if let Some(entrada) = mundo.tabla.claves.get_mut(1) {
        entrada.clave = publica_3.bytes().to_vec();
    }
    if let Some(clave) = mundo.claves.get_mut(0) {
        *clave = publica_5;
    }
    if let Some(clave) = mundo.claves.get_mut(1) {
        *clave = publica_3;
    }
    if let Some(secreta) = mundo.secretas.get_mut(0) {
        *secreta = secreta_5;
    }
    if let Some(secreta) = mundo.secretas.get_mut(1) {
        *secreta = secreta_3;
    }
    mundo.reparto = Reparto::construir(&mundo.tabla, s)?;
    mundo.huella = hash_tabla(&mundo.tabla);
    Ok(mundo)
}

#[test]
fn agr_lote_aisla_una_y_varias_firmas_malas() -> Result<(), ErrorAgregacion> {
    // A·S = 16·8 = 128 ≥ 64: todas salen.
    let mundo = mundo_compensado(64, 8, 16, 0x63)?;
    let mut agregados = Vec::new();
    let mut validos = 0usize;
    for sub in 0..mundo.reparto.s() {
        let n_s = mundo.reparto.claves_de(sub).len();
        for pos in 0..n_s {
            if validos >= 12 {
                break;
            }
            // Evita las dos claves reservadas (índices globales 0 y 1) en el tramo válido.
            let global = global_de(&mundo, sub, pos)?;
            if global <= 1 {
                continue;
            }
            agregados.push(construir_agregado(&mundo, sub, &[pos], pos)?);
            validos += 1;
        }
    }
    assert!(validos >= 12);

    // Una firma agregada mala: firma de otro mensaje.
    let (sub_mala, pos_mala) = ubicacion(&mundo, 2)?;
    let mut agregada_mala = construir_agregado(&mundo, sub_mala, &[pos_mala], pos_mala)?;
    let firma_otra = firmar(
        mundo
            .secretas
            .get(2)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
        DOMINIO_VOTO,
        b"otro mensaje",
    )?;
    agregada_mala.firma_agregada = agregar_firmas(&[&firma_otra])?;

    // Una firma de sorteo mala: firma válida de otra clave (con A = 16 salen todas).
    let (sub_sorteo, pos_sorteo) = ubicacion(&mundo, 3)?;
    let mut sorteo_malo = construir_agregado(&mundo, sub_sorteo, &[pos_sorteo], pos_sorteo)?;
    sorteo_malo.firma_sorteo = firma_con_sorteo(&mundo, true, 16, 8, 0x63a)?;

    // Par desplazado σ₁+Δ, σ₂−Δ: con suma directa compensa; con coeficientes aleatorios no.
    let mensaje = mundo.mensaje.mensaje();
    let delta = firmar(
        &ClaveSecreta::desde_bytes(&escalar_pequeno(2))?,
        DOMINIO_VOTO,
        mensaje.as_slice(),
    )?;
    let sigma_1 = firmar(
        mundo
            .secretas
            .first()
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
        DOMINIO_VOTO,
        mensaje.as_slice(),
    )?;
    let sigma_2_compensada = firmar(
        &ClaveSecreta::desde_bytes(&escalar_pequeno(1))?,
        DOMINIO_VOTO,
        mensaje.as_slice(),
    )?;

    let (sub_1, pos_1) = ubicacion(&mundo, 0)?;
    let mut desplazada_1 = construir_agregado(&mundo, sub_1, &[pos_1], pos_1)?;
    desplazada_1.firma_agregada = agregar_firmas(&[&sigma_1, &delta])?;
    let (sub_2, pos_2) = ubicacion(&mundo, 1)?;
    let mut desplazada_2 = construir_agregado(&mundo, sub_2, &[pos_2], pos_2)?;
    desplazada_2.firma_agregada = FirmaAgregada::desde_firma(&sigma_2_compensada);

    agregados.push(agregada_mala);
    agregados.push(sorteo_malo);
    agregados.push(desplazada_1);
    agregados.push(desplazada_2);

    let mut generador = SplitMix64(0x6300);
    let lote = verificar_lote(
        &agregados,
        &mundo.tabla,
        &mundo.claves,
        &mundo.reparto,
        mundo.a,
        &mut generador,
    )?;
    let total = agregados.len();
    for (i, agregado) in agregados.iter().enumerate() {
        let uno = veredicto(
            agregado,
            &mundo.tabla,
            &mundo.claves,
            &mundo.reparto,
            mundo.a,
        )?;
        assert_eq!(lote[i], uno, "discrepancia en {i}");
        if i + 4 >= total {
            assert_ne!(uno, VeredictoAgregado::Valido, "la firma mala {i} paso");
        }
    }
    Ok(())
}

// ── A7 · certificado ────────────────────────────────────────────────────────────────────────

#[test]
fn agr_certificado_de_un_agregado_por_subred_verifica() -> Result<(), Box<dyn std::error::Error>> {
    // N = 64, S = 8, A = 8 -> A·S = 64 = N: todas salen.
    let mundo = mundo(64, 8, 8, 0x61)?;
    let mut agregados = Vec::new();
    for sub in subredes_no_vacias(&mundo) {
        let n_s = mundo.reparto.claves_de(sub).len();
        let firmantes: Vec<usize> = (0..n_s.min(3)).collect();
        let indice = firmantes.last().copied().unwrap_or(0);
        agregados.push(construir_agregado(&mundo, sub, &firmantes, indice)?);
    }
    let pesos = vec![1u128; mundo.tabla.claves.len()];
    let certificado = armar_certificado(
        mundo.mensaje,
        &mundo.tabla,
        &pesos,
        &mundo.reparto,
        &agregados,
        &[],
    )?;
    verificar_firma_peso(&mundo.tabla, &mundo.claves, &certificado)?;
    Ok(())
}

#[test]
fn agr_certificado_no_cuenta_dos_veces() -> Result<(), Box<dyn std::error::Error>> {
    let mundo = mundo(128, 8, 16, 0x62)?;
    let mut elegida = None;
    for sub in subredes_no_vacias(&mundo) {
        if mundo.reparto.claves_de(sub).len() >= 4 {
            elegida = Some(sub);
            break;
        }
    }
    let sub = elegida.ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let otra = *subredes_no_vacias(&mundo)
        .iter()
        .find(|candidata| **candidata != sub)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;

    // Dos agregados solapados de la misma subred y otro de otra subred.
    let agregado_1 = construir_agregado(&mundo, sub, &[0, 1], 1)?;
    let agregado_2 = construir_agregado(&mundo, sub, &[1, 2], 0)?;
    let agregado_3 = construir_agregado(&mundo, otra, &[0], 0)?;

    // Voto suelto ya cubierto, y otro nuevo repetido.
    let cubierto = global_de(&mundo, sub, 0)?;
    let nuevo = global_de(&mundo, sub, 3)?;
    let firma_cubierta = firmar(
        mundo
            .secretas
            .get(cubierto)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
        DOMINIO_VOTO,
        mundo.mensaje.mensaje().as_slice(),
    )?;
    let firma_nueva = firmar(
        mundo
            .secretas
            .get(nuevo)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
        DOMINIO_VOTO,
        mundo.mensaje.mensaje().as_slice(),
    )?;
    let votos = vec![
        (cubierto + 1, firma_cubierta),
        (nuevo + 1, firma_nueva),
        (nuevo + 1, firma_nueva),
    ];

    let pesos = vec![1u128; mundo.tabla.claves.len()];
    let certificado = armar_certificado(
        mundo.mensaje,
        &mundo.tabla,
        &pesos,
        &mundo.reparto,
        &[agregado_1, agregado_2, agregado_3],
        &votos,
    )?;
    verificar_firma_peso(&mundo.tabla, &mundo.claves, &certificado)?;
    Ok(())
}

// ── A4 · frecuencia ─────────────────────────────────────────────────────────────────────────

#[test]
fn agr_frecuencia_del_sorteo() -> Result<(), ErrorAgregacion> {
    let n = 10_000usize;
    let s = 64u16;
    let a = 32u32;
    let probabilidad = f64::from(a) * f64::from(s) / n as f64;
    let mut generador = SplitMix64(0x0000_f7f7);
    let mut salen = 0usize;
    for _ in 0..n {
        let mut firma = [0u8; 96];
        for byte in &mut firma {
            *byte = generador.byte();
        }
        if sale_agregadora(&hash_bytes(&firma), n, s, a) {
            salen += 1;
        }
    }
    let fraccion = salen as f64 / n as f64;
    let desviacion = (probabilidad * (1.0 - probabilidad) / n as f64).sqrt();
    assert!(
        (fraccion - probabilidad).abs() < 4.0 * desviacion,
        "fraccion {fraccion} fuera de 4 sigma de {probabilidad}"
    );
    Ok(())
}
