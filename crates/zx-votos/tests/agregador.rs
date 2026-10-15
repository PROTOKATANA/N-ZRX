//! Pruebas del estado de una ventana de agregación (pieza A5, paso (c)) y de la elección por peso
//! unido (AG-R14).
#![allow(
    clippy::indexing_slicing,
    reason = "test: los indices estan acotados por construccion"
)]

use zx_votos::agregacion::{
    Agregado, DOMINIO_SORTEO, ErrorAgregacion, GeneradorEscalares, MensajeVoto, MotivoAgregado,
    Reparto, VeredictoAgregado, armar_certificado, sale_agregadora, veredicto,
    veredicto_con_huella,
};
use zx_votos::agregador::{DatosVentana, EstadoVentana, ResultadoAgregado};
use zx_votos::serial::hash_bytes;
use zx_votos::{
    Clave, ClavePublica, ClaveSecreta, DOMINIO_VOTO, Firma, Hash, LONGITUD_HASH, Tabla,
    agregar_firmas, firmantes_de_mapa, firmar, hash_tabla, verificar_firma_peso,
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

/// Mundo de prueba: tabla de claves reales, reparto, pesos y mensaje A3 comunes.
struct Mundo {
    tabla: Tabla,
    claves: Vec<ClavePublica>,
    secretas: Vec<ClaveSecreta>,
    pesos: Vec<u128>,
    reparto: Reparto,
    mensaje: MensajeVoto,
    huella: Hash,
    a: u32,
}

/// Construye un mundo con `num_claves` claves reales, `s` subredes, `a` agregadores y `pesos`.
fn mundo_pesos(
    num_claves: usize,
    s: u16,
    a: u32,
    semilla: u64,
    pesos: Vec<u128>,
) -> Result<Mundo, ErrorAgregacion> {
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
        pesos,
        reparto,
        mensaje,
        huella,
        a,
    })
}

/// Mundo con peso 1 para todas las claves.
fn mundo_unos(num_claves: usize, s: u16, a: u32, semilla: u64) -> Result<Mundo, ErrorAgregacion> {
    mundo_pesos(num_claves, s, a, semilla, vec![1u128; num_claves])
}

/// Estado de ventana sobre el mundo.
///
/// La huella y el reparto viven en el bloque compartido `DatosVentana`; el montaje cambia solo por
/// eso (V1 de A5-c-1a-2), sin tocar lo que afirma ninguna prueba.
fn estado(m: &Mundo, s: u16) -> Result<EstadoVentana, ErrorAgregacion> {
    let datos = DatosVentana::nuevo(&m.tabla, &m.claves, &m.pesos, s)?;
    Ok(EstadoVentana::nuevo(datos, m.a, m.mensaje))
}

/// Índice global, dentro de `tabla.claves`, de la posición `pos` de la subred.
fn global_de(m: &Mundo, sub: u16, pos: usize) -> Result<usize, ErrorAgregacion> {
    m.reparto
        .claves_de(sub)
        .get(pos)
        .copied()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)
}

/// Subredes con al menos una clave.
fn subredes_no_vacias(m: &Mundo) -> Vec<u16> {
    (0..m.reparto.s())
        .filter(|sub| !m.reparto.claves_de(*sub).is_empty())
        .collect()
}

/// Firma A3 de la clave global `global` sobre `mensaje`.
fn firma_de(m: &Mundo, global: usize, mensaje: MensajeVoto) -> Result<Firma, ErrorAgregacion> {
    let secreta = m
        .secretas
        .get(global)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    Ok(firmar(secreta, DOMINIO_VOTO, mensaje.mensaje().as_slice())?)
}

/// Firma A3 de una clave cualquiera sobre un mensaje distinto (para forzar `FirmaAgregada`).
fn firma_falsa(m: &Mundo) -> Result<Firma, ErrorAgregacion> {
    let secreta = m
        .secretas
        .first()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    Ok(firmar(secreta, DOMINIO_VOTO, b"mensaje falso")?)
}

/// Construye un agregado válido para `firmantes` (posiciones en la subred) y `mensaje`.
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
        let global = global_de(m, sub, pos)?;
        let secreta = m
            .secretas
            .get(global)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        firmas.push(firmar(secreta, DOMINIO_VOTO, mensaje.mensaje().as_slice())?);
    }
    let referencias: Vec<&Firma> = firmas.iter().collect();
    let firma_agregada = agregar_firmas(&referencias)?;
    let global_agregadora = global_de(m, sub, indice_agregadora)?;
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

/// Lee el bit `posicion` (0-based) de un mapa.
fn bit_set(mapa: &[u8], posicion: usize) -> bool {
    mapa.get(posicion >> 3)
        .map(|byte| (byte >> (posicion & 7)) & 1 == 1)
        .unwrap_or(false)
}

/// Peso cubierto por un mapa global.
fn peso_de_mapa_test(mapa: &[u8], pesos: &[u128]) -> u128 {
    let mut total: u128 = 0;
    for (indice, peso) in pesos.iter().enumerate() {
        if bit_set(mapa, indice) {
            total = total.saturating_add(*peso);
        }
    }
    total
}

// ── AG-R14 · elección por peso unido (IPA B-79) ─────────────────────────────────────────────

#[test]
fn agr_b79_mas_firmantes_y_menos_peso_no_gana() -> Result<(), Box<dyn std::error::Error>> {
    // Subred única (S=1): posiciones 0,1,2 honestas (pesos 10, 1, 1); 3,4 del atacante (peso 1).
    let mut m = mundo_unos(5, 1, 1, 0xB79)?;
    let g0 = global_de(&m, 0, 0)?;
    m.pesos[g0] = 10;
    // A = las tres honestas (peso 12, 3 firmantes); B = dos honestas de peso 1 y dos atacantes.
    let a_agr = construir_agregado(&m, 0, &[0, 1, 2], 0, m.mensaje)?;
    let b_agr = construir_agregado(&m, 0, &[1, 2, 3, 4], 3, m.mensaje)?;
    let certificado = armar_certificado(
        m.mensaje,
        &m.tabla,
        &m.pesos,
        &m.reparto,
        &[a_agr, b_agr],
        &[],
    )?;
    assert_eq!(
        peso_de_mapa_test(&certificado.mapa, &m.pesos),
        12,
        "debe ganar A (3 firmantes, 12 de peso), no B (4 firmantes, 4 de peso)"
    );
    assert!(bit_set(&certificado.mapa, g0));
    assert!(!bit_set(&certificado.mapa, global_de(&m, 0, 3)?));
    verificar_firma_peso(&m.tabla, &m.claves, &certificado)?;
    Ok(())
}

#[test]
fn agr_r14_la_union_con_los_sueltos_decide() -> Result<(), Box<dyn std::error::Error>> {
    // A: mapa {1,2}, agregadora 1. B: mapa {0,1}, agregadora 0. Suelto en 0.
    // Igual peso de mapa (2); A no pisa el suelto y B sí: gana A con union 3.
    let m = mundo_unos(4, 1, 1, 0xA14)?;
    let a_agr = construir_agregado(&m, 0, &[1, 2], 1, m.mensaje)?;
    let b_agr = construir_agregado(&m, 0, &[0, 1], 0, m.mensaje)?;
    let g0 = global_de(&m, 0, 0)?;
    let firma = firma_de(&m, g0, m.mensaje)?;
    let certificado = armar_certificado(
        m.mensaje,
        &m.tabla,
        &m.pesos,
        &m.reparto,
        &[a_agr, b_agr],
        &[(g0 + 1, firma)],
    )?;
    assert_eq!(peso_de_mapa_test(&certificado.mapa, &m.pesos), 3);
    assert!(bit_set(&certificado.mapa, g0));
    verificar_firma_peso(&m.tabla, &m.claves, &certificado)?;
    Ok(())
}

#[test]
fn agr_r14_el_elegido_no_pesa_menos_que_ninguno() -> Result<(), Box<dyn std::error::Error>> {
    let mensaje = MensajeVoto {
        n: 9,
        candidato: [1; LONGITUD_HASH],
        h_t_siguiente: [2; LONGITUD_HASH],
        raiz_estado: [3; LONGITUD_HASH],
    };
    let (secreta, _publica) = par_bls(0x300)?;
    let firma = firmar(&secreta, DOMINIO_VOTO, mensaje.mensaje().as_slice())?;
    let firma_agregada = agregar_firmas(&[&firma])?;

    for semilla in 0..200u64 {
        let mut rng = SplitMix64(0x3000 ^ semilla.wrapping_mul(0x9e37));
        let n = 8 + (rng.siguiente() % 17) as usize; // 8..=24
        let mut claves = Vec::with_capacity(n);
        let mut pesos = Vec::with_capacity(n);
        for _ in 0..n {
            let mut clave = [0u8; 32];
            for byte in &mut clave {
                *byte = rng.byte();
            }
            claves.push(Clave {
                clave: clave.to_vec(),
                peso: 1,
                activo: true,
                prueba: false,
                garantia: 0,
            });
            pesos.push(u128::from(rng.byte() % 8) + 1);
        }
        let tabla = Tabla { n: 0, claves };
        let huella = hash_tabla(&tabla);
        let reparto = Reparto::construir(&tabla, 1)?;
        let indices = reparto.claves_de(0);
        let n_s = indices.len();

        let mut sueltos: Vec<(usize, Firma)> = Vec::new();
        let mut suelto = vec![false; n_s];
        for (pos, &global) in indices.iter().enumerate() {
            if rng.byte().is_multiple_of(3) {
                suelto[pos] = true;
                sueltos.push((global + 1, firma));
            }
        }

        let num_agregados = 1 + (rng.siguiente() % 4) as usize;
        let mut agregados = Vec::new();
        let mut uniones: Vec<u128> = Vec::new();
        for _ in 0..num_agregados {
            let mut marcados = vec![false; n_s];
            let cuantos = 1 + (rng.siguiente() as usize % n_s.min(6));
            for _ in 0..cuantos {
                marcados[rng.siguiente() as usize % n_s] = true;
            }
            let indice = marcados
                .iter()
                .position(|marca| *marca)
                .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
            marcados[indice] = true;
            let mut mapa = vec![0u8; n_s.div_ceil(8)];
            for (pos, marca) in marcados.iter().enumerate() {
                if *marca && let Some(byte) = mapa.get_mut(pos >> 3) {
                    *byte |= 1 << (pos & 7);
                }
            }
            let mut union: u128 = 0;
            for pos in 0..n_s {
                if marcados[pos] || suelto[pos] {
                    union = union.saturating_add(pesos[indices[pos]]);
                }
            }
            uniones.push(union);
            agregados.push(Agregado {
                n: mensaje.n,
                candidato: mensaje.candidato,
                h_t_siguiente: mensaje.h_t_siguiente,
                raiz_estado: mensaje.raiz_estado,
                firma_agregada,
                huella_tabla: huella,
                subred: 0,
                indice_agregadora: u16::try_from(indice)?,
                mapa_local: mapa,
                firma_sorteo: firma,
            });
        }

        let certificado =
            armar_certificado(mensaje, &tabla, &pesos, &reparto, &agregados, &sueltos)?;
        let cubierto = peso_de_mapa_test(&certificado.mapa, &pesos);
        for (i, union) in uniones.iter().enumerate() {
            assert!(
                cubierto >= *union,
                "semilla {semilla}, agregado {i}: cubierto {cubierto} < union {union}"
            );
        }
    }
    Ok(())
}

// ── AG-R8 · un agregado por agregadora y subred ─────────────────────────────────────────────

#[test]
fn agr_r8_un_valido_por_agregadora() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(16, 2, 64, 0x481)?;
    let sub = subredes_no_vacias(&m)[0];
    let mut e = estado(&m, 2)?;
    let valido = construir_agregado(&m, sub, &[0], 0, m.mensaje)?;
    assert_eq!(e.recibir_agregado(&valido)?, ResultadoAgregado::Aceptado);
    // El segundo, aunque traiga firma inválida, es «repetido» sin gastar criptografía.
    let mut repetido = construir_agregado(&m, sub, &[0, 1], 0, m.mensaje)?;
    repetido.firma_agregada = agregar_firmas(&[&firma_falsa(&m)?])?;
    assert_eq!(e.recibir_agregado(&repetido)?, ResultadoAgregado::Repetido);
    Ok(())
}

#[test]
fn agr_r8_un_invalido_no_ocupa_la_plaza() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(16, 2, 64, 0x482)?;
    let sub = subredes_no_vacias(&m)[0];
    let mut e = estado(&m, 2)?;
    let bueno = construir_agregado(&m, sub, &[0], 0, m.mensaje)?;
    let mut malo = bueno.clone();
    malo.firma_agregada = agregar_firmas(&[&firma_falsa(&m)?])?;
    assert_eq!(
        e.recibir_agregado(&malo)?,
        ResultadoAgregado::Invalido(MotivoAgregado::FirmaAgregada)
    );
    assert_eq!(e.recibir_agregado(&bueno)?, ResultadoAgregado::Aceptado);
    Ok(())
}

#[test]
fn agr_otro_mensaje_y_otra_tabla_se_ignoran() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(16, 2, 64, 0x483)?;
    let sub = subredes_no_vacias(&m)[0];
    let mut e = estado(&m, 2)?;
    let mut otro = m.mensaje;
    otro.candidato = [0xAA; LONGITUD_HASH];
    let agr_otro = construir_agregado(&m, sub, &[0], 0, otro)?;
    assert_eq!(
        e.recibir_agregado(&agr_otro)?,
        ResultadoAgregado::OtroMensaje
    );
    let mut agr_tabla = construir_agregado(&m, sub, &[0], 0, m.mensaje)?;
    agr_tabla.huella_tabla = [0xBB; LONGITUD_HASH];
    assert_eq!(
        e.recibir_agregado(&agr_tabla)?,
        ResultadoAgregado::OtraTabla
    );
    Ok(())
}

#[test]
fn agr_orden_de_comprobaciones() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(16, 2, 64, 0x484)?;
    let sub = subredes_no_vacias(&m)[0];
    let mut e = estado(&m, 2)?;
    let mut otro = m.mensaje;
    otro.raiz_estado = [0xCC; LONGITUD_HASH];
    let mut agr = construir_agregado(&m, sub, &[0], 0, otro)?;
    agr.firma_agregada = agregar_firmas(&[&firma_falsa(&m)?])?;
    assert_eq!(e.recibir_agregado(&agr)?, ResultadoAgregado::OtroMensaje);
    Ok(())
}

// ── agregado propio ─────────────────────────────────────────────────────────────────────────

#[test]
fn agr_propio_solo_si_sale_y_una_vez() -> Result<(), Box<dyn std::error::Error>> {
    // Con a = 0 no sale ninguna; con a = 64 (A·S ≥ N) salen todas.
    let m = mundo_unos(16, 1, 0, 0x485)?;
    let mut e = estado(&m, 1)?;
    let g0 = global_de(&m, 0, 0)?;
    let firma = firma_de(&m, g0, m.mensaje)?;
    let sorteo = firmar(
        m.secretas
            .get(g0)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
        DOMINIO_SORTEO,
        &m.mensaje.n.to_be_bytes(),
    )?;
    e.registrar_suelto(g0 + 1, firma)?;
    assert!(
        e.agregado_propio(g0 + 1, &sorteo)?.is_none(),
        "con a = 0 el sorteo no sale"
    );

    let m2 = mundo_unos(16, 1, 64, 0x485)?;
    let mut e2 = estado(&m2, 1)?;
    e2.registrar_suelto(g0 + 1, firma_de(&m2, g0, m2.mensaje)?)?;
    let sorteo2 = firmar(
        m2.secretas
            .get(g0)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
        DOMINIO_SORTEO,
        &m2.mensaje.n.to_be_bytes(),
    )?;
    assert!(
        e2.agregado_propio(g0 + 1, &sorteo2)?.is_some(),
        "con a = 64 y el voto registrado debe salir"
    );
    assert!(
        e2.agregado_propio(g0 + 1, &sorteo2)?.is_none(),
        "solo una vez por clave"
    );

    let mut e3 = estado(&m2, 1)?;
    let g1 = global_de(&m2, 0, 1)?;
    let sorteo3 = firmar(
        m2.secretas
            .get(g1)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
        DOMINIO_SORTEO,
        &m2.mensaje.n.to_be_bytes(),
    )?;
    assert!(
        e3.agregado_propio(g1 + 1, &sorteo3)?.is_none(),
        "sin el voto suelto registrado no hay agregado propio"
    );
    Ok(())
}

#[test]
fn agr_propio_lleva_todos_los_sueltos_de_su_subred() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(32, 2, 64, 0x486)?;
    let mut e = estado(&m, 2)?;
    let sub0 = subredes_no_vacias(&m)[0];
    let sub1 = *subredes_no_vacias(&m)
        .iter()
        .find(|sub| **sub != sub0)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let indices0 = m.reparto.claves_de(sub0);
    let indices1 = m.reparto.claves_de(sub1);

    let cuantos0 = indices0.len().div_ceil(2);
    for (pos, &global) in indices0.iter().enumerate() {
        if pos < cuantos0 {
            e.registrar_suelto(global + 1, firma_de(&m, global, m.mensaje)?)?;
        }
    }
    for &global in indices1 {
        e.registrar_suelto(global + 1, firma_de(&m, global, m.mensaje)?)?;
    }

    let g0 = global_de(&m, sub0, 0)?;
    let sorteo = firmar(
        m.secretas
            .get(g0)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
        DOMINIO_SORTEO,
        &m.mensaje.n.to_be_bytes(),
    )?;
    let propio = e
        .agregado_propio(g0 + 1, &sorteo)?
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let marcados = firmantes_de_mapa(&propio.mapa_local);
    assert_eq!(marcados.len(), cuantos0);
    for pos in 0..indices0.len() {
        assert_eq!(marcados.contains(&(pos + 1)), pos < cuantos0);
    }
    // El agregado propio verifica: su firma es exactamente la de los sueltos marcados de su subred.
    assert_eq!(
        veredicto(&propio, &m.tabla, &m.claves, &m.reparto, m.a)?,
        VeredictoAgregado::Valido
    );
    Ok(())
}

// ── cobertura, quórum, lote y subred sin agregado ───────────────────────────────────────────

#[test]
fn agr_quorum_exacto() -> Result<(), Box<dyn std::error::Error>> {
    // N = 3, W = 3: con σ = 2 se da 3·σ = 2·W; con σ = 1 no.
    let m = mundo_unos(3, 1, 64, 0x487)?;
    let indices = m.reparto.claves_de(0);
    let mut e = estado(&m, 1)?;
    e.registrar_suelto(indices[0] + 1, firma_de(&m, indices[0], m.mensaje)?)?;
    e.registrar_suelto(indices[1] + 1, firma_de(&m, indices[1], m.mensaje)?)?;
    assert!(e.hay_quorum()?);
    let certificado = e.certificado()?.ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    verificar_firma_peso(&m.tabla, &m.claves, &certificado)?;
    assert_eq!(peso_de_mapa_test(&certificado.mapa, &m.pesos), 2);

    let mut e2 = estado(&m, 1)?;
    e2.registrar_suelto(indices[0] + 1, firma_de(&m, indices[0], m.mensaje)?)?;
    assert!(!e2.hay_quorum()?);
    assert!(e2.certificado()?.is_none());
    Ok(())
}

#[test]
fn agr_lote_igual_que_uno_a_uno() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(32, 4, 128, 0x488)?;
    let sub = subredes_no_vacias(&m)[0];
    let valido = construir_agregado(&m, sub, &[0], 0, m.mensaje)?;

    let mut agregados = vec![valido.clone(), valido.clone()];
    let mut con_firma_mala = construir_agregado(&m, sub, &[0], 0, m.mensaje)?;
    con_firma_mala.firma_agregada = agregar_firmas(&[&firma_falsa(&m)?])?;
    agregados.push(con_firma_mala);

    let mut otro = m.mensaje;
    otro.candidato = [0xDD; LONGITUD_HASH];
    agregados.push(construir_agregado(&m, sub, &[0], 0, otro)?);

    let mut de_otra_tabla = construir_agregado(&m, sub, &[1], 1, m.mensaje)?;
    de_otra_tabla.huella_tabla = [0xEE; LONGITUD_HASH];
    agregados.push(de_otra_tabla);

    let mut de_forma_mala = construir_agregado(&m, sub, &[1], 1, m.mensaje)?;
    de_forma_mala.mapa_local.push(0);
    agregados.push(de_forma_mala);

    let mut e_lote = estado(&m, 4)?;
    let mut e_uno = estado(&m, 4)?;
    let mut generador = SplitMix64(0x4880);
    let lote = e_lote.recibir_lote(&agregados, &mut generador)?;
    let mut uno = Vec::with_capacity(agregados.len());
    for agr in &agregados {
        uno.push(e_uno.recibir_agregado(agr)?);
    }
    assert_eq!(lote, uno);
    Ok(())
}

#[test]
fn agr_sin_agregado_van_los_sueltos() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(64, 2, 64, 0x489)?;
    let sub0 = subredes_no_vacias(&m)[0];
    let sub1 = *subredes_no_vacias(&m)
        .iter()
        .find(|sub| **sub != sub0)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let mut e = estado(&m, 2)?;

    // Subred 0, sin agregado: entran todos sus sueltos.
    let indices0 = m.reparto.claves_de(sub0);
    for &global in indices0 {
        e.registrar_suelto(global + 1, firma_de(&m, global, m.mensaje)?)?;
    }
    // Subred 1 con un agregado que cubre todas sus claves.
    let indices1 = m.reparto.claves_de(sub1);
    let todas: Vec<usize> = (0..indices1.len()).collect();
    let agregado = construir_agregado(&m, sub1, &todas, 0, m.mensaje)?;
    assert_eq!(e.recibir_agregado(&agregado)?, ResultadoAgregado::Aceptado);

    let certificado = e.certificado()?.ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    assert_eq!(
        peso_de_mapa_test(&certificado.mapa, &m.pesos),
        m.pesos.iter().copied().sum::<u128>()
    );
    for &global in indices0 {
        assert!(
            bit_set(&certificado.mapa, global),
            "la clave {global} de la subred sin agregado falta"
        );
    }
    verificar_firma_peso(&m.tabla, &m.claves, &certificado)?;
    Ok(())
}

// ── veredicto con huella (B1) ───────────────────────────────────────────────────────────────

/// Firma de sorteo de una clave cualquiera que cumple (o no) la condición del A4.
fn firma_con_sorteo(
    m: &Mundo,
    quiere_sale: bool,
    a: u32,
    s: u16,
    semilla: u64,
) -> Result<Firma, ErrorAgregacion> {
    let mut rng = SplitMix64(semilla);
    for _ in 0..100_000 {
        let (secreta, _) = par_bls(rng.siguiente())?;
        let firma = firmar(&secreta, DOMINIO_SORTEO, &m.mensaje.n.to_be_bytes())?;
        let huella = hash_bytes(&firma.bytes());
        if sale_agregadora(&huella, m.tabla.claves.len(), s, a) == quiere_sale {
            return Ok(firma);
        }
    }
    Err(ErrorAgregacion::ClaveNoRegistrada)
}

#[test]
fn veredicto_y_su_variante_coinciden() -> Result<(), Box<dyn std::error::Error>> {
    // N = 24, S = 4, A = 32: con A·S = 128 ≥ 24 salen todos los sorteos; `SorteoNoSale` se evalúa
    // con A = 1 (A·S = 4 < 24) y `FirmaSorteo`/`FirmaAgregada` con A = 64 (salen todos).
    let m = mundo_unos(24, 4, 32, 0x58)?;
    let sub = *subredes_no_vacias(&m)
        .iter()
        .find(|sub| m.reparto.claves_de(**sub).len() >= 2)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let base = construir_agregado(&m, sub, &[0, 1], 0, m.mensaje)?;

    let mut forma = base.clone();
    forma.mapa_local.push(0);
    let mut subred_mala = base.clone();
    subred_mala.subred = m.reparto.s();
    let mut indice_malo = base.clone();
    indice_malo.indice_agregadora = u16::MAX;
    let mut sin_bit = base.clone();
    let posicion = base.indice_agregadora as usize;
    if let Some(byte) = sin_bit.mapa_local.get_mut(posicion >> 3) {
        *byte &= !(1 << (posicion & 7));
    }
    let mut no_sale = base.clone();
    no_sale.firma_sorteo = firma_con_sorteo(&m, false, 1, 4, 0x58b)?;
    let mut firma_mala = base.clone();
    firma_mala.firma_sorteo = firma_con_sorteo(&m, true, 64, 4, 0x58c)?;
    let mut agregada_mala = base.clone();
    let secreta = m
        .secretas
        .first()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let otra = firmar(secreta, DOMINIO_VOTO, b"mensaje distinto")?;
    agregada_mala.firma_agregada = agregar_firmas(&[&otra])?;

    // (agregado, A con el que se evalúa): válido + los siete motivos.
    let casos = [
        (base, m.a),
        (forma, m.a),
        (subred_mala, m.a),
        (indice_malo, m.a),
        (sin_bit, m.a),
        (no_sale, 1),
        (firma_mala, 64),
        (agregada_mala, 64),
    ];
    let mut motivos = Vec::new();
    for (i, (agregado, a)) in casos.iter().enumerate() {
        let con_funcion = veredicto(agregado, &m.tabla, &m.claves, &m.reparto, *a)?;
        let con_variante =
            veredicto_con_huella(agregado, &m.tabla, &m.claves, &m.reparto, *a, m.huella)?;
        assert_eq!(
            con_funcion, con_variante,
            "caso {i}: veredicto y variante con huella no coinciden"
        );
        if i == 0 {
            assert_eq!(
                con_funcion,
                VeredictoAgregado::Valido,
                "el caso 0 es válido"
            );
        } else if let VeredictoAgregado::Invalido(motivo) = con_funcion {
            motivos.push(motivo);
        }
    }
    assert_eq!(motivos.len(), 7, "deben aparecer los siete motivos");
    for motivo in MotivoAgregado::TODOS {
        assert!(motivos.contains(&motivo), "falta el motivo {motivo:?}");
    }
    Ok(())
}

// ── N1–N2 (A5-c-1a-4) · no verificar ni guardar el agregado que no añade ninguna clave ──────

/// Generador que cuenta las verificaciones por lotes y los agregados que entran en ellas.
struct GeneradorCuenta {
    rng: SplitMix64,
    verificaciones: usize,
    agregados_verificados: usize,
}

impl GeneradorEscalares for GeneradorCuenta {
    fn escalar(&mut self) -> [u8; 16] {
        self.rng.escalar()
    }

    fn inicio_verificacion(&mut self) {
        self.verificaciones += 1;
    }

    fn verificacion_de_agregado(&mut self) {
        self.agregados_verificados += 1;
    }
}

fn generador_cuenta(semilla: u64) -> GeneradorCuenta {
    GeneradorCuenta {
        rng: SplitMix64(semilla),
        verificaciones: 0,
        agregados_verificados: 0,
    }
}

#[test]
fn nomejora_01_no_se_verifica_lo_que_no_anade() -> Result<(), Box<dyn std::error::Error>> {
    // S = 1, N = 128, A = 128: A·S = 128 ≥ N, todos los sorteos salen.
    let m = mundo_unos(128, 1, 128, 0x141)?;
    let sub = 0u16;
    let n_s = m.reparto.claves_de(sub).len();
    assert_eq!(n_s, 128);
    let mut e = estado(&m, 1)?;

    // Se acepta el agregado completo de la agregadora 0.
    let todas: Vec<usize> = (0..n_s).collect();
    let completo = construir_agregado(&m, sub, &todas, 0, m.mensaje)?;
    assert_eq!(e.recibir_agregado(&completo)?, ResultadoAgregado::Aceptado);
    let mapa_antes = e.mapa_constan()?;

    // Las otras 61 agregadoras con el mismo mapa: repetido sin verificar.
    let mut lote = Vec::new();
    for pos in 1..62usize {
        lote.push(construir_agregado(&m, sub, &todas, pos, m.mensaje)?);
    }
    assert_eq!(lote.len(), 61);
    let mut generador = generador_cuenta(0x1410);
    let resultados = e.recibir_lote(&lote, &mut generador)?;
    assert!(
        resultados.iter().all(|r| *r == ResultadoAgregado::Repetido),
        "todas deben ser repetido: {resultados:?}"
    );
    assert_eq!(
        generador.verificaciones, 0,
        "no debe haber verificación por lotes"
    );
    assert_eq!(
        generador.agregados_verificados, 0,
        "no debe verificarse ningún agregado"
    );
    assert_eq!(e.mapa_constan()?, mapa_antes, "el estado no debe cambiar");
    Ok(())
}

#[test]
fn nomejora_02_no_ocupa_plaza() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(32, 1, 64, 0x142)?;
    let sub = 0u16;
    let n_s = m.reparto.claves_de(sub).len();
    assert!(n_s >= 8, "la subred necesita al menos 8 claves");
    let mut e = estado(&m, 1)?;

    // Sueltos en las posiciones 0 y 5: el agregado {0,5} de la agregadora 5 no añade.
    for pos in [0usize, 5] {
        let global = global_de(&m, sub, pos)?;
        e.registrar_suelto(global + 1, firma_de(&m, global, m.mensaje)?)?;
    }
    let descartado = construir_agregado(&m, sub, &[0, 5], 5, m.mensaje)?;
    assert_eq!(
        e.recibir_agregado(&descartado)?,
        ResultadoAgregado::Repetido,
        "cubierto por sueltos: no añade y no ocupa la plaza"
    );

    // La misma agregadora entrega después otro que sí añade: se acepta.
    let bueno = construir_agregado(&m, sub, &[5, 6], 5, m.mensaje)?;
    assert_eq!(e.recibir_agregado(&bueno)?, ResultadoAgregado::Aceptado);
    Ok(())
}

#[test]
fn nomejora_03_el_que_anade_una_clave_se_verifica() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(32, 1, 64, 0x143)?;
    let sub = 0u16;
    let mut e = estado(&m, 1)?;
    let agrega = construir_agregado(&m, sub, &[3], 3, m.mensaje)?;
    let mut generador = generador_cuenta(0x1430);
    let resultados = e.recibir_lote(std::slice::from_ref(&agrega), &mut generador)?;
    assert_eq!(resultados, vec![ResultadoAgregado::Aceptado]);
    assert_eq!(
        generador.agregados_verificados, 1,
        "el que añade una clave debe verificarse"
    );
    assert!(generador.verificaciones >= 1);

    // Firma falsa: inválido y sus claves no cuentan como cubiertas.
    let mut e2 = estado(&m, 1)?;
    let mut malo = construir_agregado(&m, sub, &[4], 4, m.mensaje)?;
    malo.firma_agregada = agregar_firmas(&[&firma_falsa(&m)?])?;
    let mut generador2 = generador_cuenta(0x1431);
    let resultados2 = e2.recibir_lote(std::slice::from_ref(&malo), &mut generador2)?;
    assert_eq!(
        resultados2,
        vec![ResultadoAgregado::Invalido(MotivoAgregado::FirmaAgregada)]
    );
    assert_eq!(e2.peso_cubierto()?, 0, "un inválido no cubre ninguna clave");
    assert!(e2.mapa_constan()?.iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
fn nomejora_04_los_sueltos_cuentan() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(32, 1, 64, 0x144)?;
    let sub = 0u16;
    let n_s = m.reparto.claves_de(sub).len();
    let mut e = estado(&m, 1)?;
    for pos in 0..n_s {
        let global = global_de(&m, sub, pos)?;
        e.registrar_suelto(global + 1, firma_de(&m, global, m.mensaje)?)?;
    }
    let todas: Vec<usize> = (0..n_s).collect();
    let agregado = construir_agregado(&m, sub, &todas, 0, m.mensaje)?;
    let mut generador = generador_cuenta(0x1440);
    let resultados = e.recibir_lote(std::slice::from_ref(&agregado), &mut generador)?;
    assert_eq!(resultados, vec![ResultadoAgregado::Repetido]);
    assert_eq!(generador.verificaciones, 0);
    assert_eq!(generador.agregados_verificados, 0);
    Ok(())
}
