//! Pruebas de la ventana entera por raíces de estado (pieza A5, paso (c), segunda parte).
#![allow(
    clippy::indexing_slicing,
    reason = "test: los indices estan acotados por construccion"
)]

use std::collections::BTreeSet;
use std::sync::Arc;

use zx_votos::agregacion::{
    Agregado, DOMINIO_SORTEO, ErrorAgregacion, GeneradorEscalares, MensajeVoto, MotivoAgregado,
    Reparto, VeredictoAgregado, armar_certificado, sale_agregadora, veredicto_con_huella,
};
use zx_votos::agregador::{DatosVentana, EstadoVentana, ResultadoAgregado};
use zx_votos::serial::hash_bytes;
use zx_votos::ventana_raices::{GrupoRaiz, ResultadoSuelto, ResumenRaices, VentanaPorRaices};
use zx_votos::{
    Clave, ClavePublica, ClaveSecreta, DOMINIO_VOTO, Firma, Hash, LONGITUD_HASH, Tabla,
    agregar_firmas, firmantes_de_mapa, firmar, hash_tabla, serial_certificado_peso,
    verificar_firma_peso,
};

// ── constantes de la ventana ─────────────────────────────────────────────────────────────────

const N: u64 = 1;
const CANDIDATO: Hash = [0x11; LONGITUD_HASH];
const H_T: Hash = [0x22; LONGITUD_HASH];
const R1: Hash = [0x10; LONGITUD_HASH];
const R2: Hash = [0x20; LONGITUD_HASH];

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
    let huella = hash_tabla(&tabla);
    Ok(Mundo {
        tabla,
        claves,
        secretas,
        pesos,
        reparto,
        huella,
        a,
    })
}

/// Mundo con peso 1 para todas las claves.
fn mundo_unos(num_claves: usize, s: u16, a: u32, semilla: u64) -> Result<Mundo, ErrorAgregacion> {
    mundo_pesos(num_claves, s, a, semilla, vec![1u128; num_claves])
}

/// Mensaje A3 de una raíz con la ventana, el candidato y la tabla siguiente fijos.
fn mensaje_con(raiz: Hash) -> MensajeVoto {
    MensajeVoto {
        n: N,
        candidato: CANDIDATO,
        h_t_siguiente: H_T,
        raiz_estado: raiz,
    }
}

/// Bloque de datos de la ventana sobre el mundo.
fn datos_de(m: &Mundo, s: u16) -> Result<Arc<DatosVentana>, ErrorAgregacion> {
    DatosVentana::nuevo(&m.tabla, &m.claves, &m.pesos, s)
}

/// Ventana por raíces sobre el mundo.
fn ventana(m: &Mundo, s: u16) -> Result<VentanaPorRaices, ErrorAgregacion> {
    let datos = datos_de(m, s)?;
    Ok(VentanaPorRaices::nuevo(datos, m.a, N, CANDIDATO, H_T))
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

/// Registra un voto suelto de la clave global `global` para `raiz`, comprobando que se registra.
fn suelto_de(
    v: &mut VentanaPorRaices,
    m: &Mundo,
    global: usize,
    raiz: Hash,
) -> Result<(), ErrorAgregacion> {
    let firma = firma_de(m, global, mensaje_con(raiz))?;
    let resultado = v.registrar_suelto(global + 1, raiz, firma)?;
    assert_eq!(resultado, ResultadoSuelto::Registrado);
    Ok(())
}

// ── 1 · una raíz equivale al estado simple ───────────────────────────────────────────────────

#[test]
fn vr_una_raiz_equivale_al_estado_simple() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(24, 3, 64, 0xA001)?;
    let raiz = R1;
    let mensaje = mensaje_con(raiz);

    let datos_simple = datos_de(&m, 3)?;
    let mut simple = EstadoVentana::nuevo(datos_simple, m.a, mensaje);
    let mut v = ventana(&m, 3)?;

    let sub = subredes_no_vacias(&m)[0];
    let global_agregado = global_de(&m, sub, 0)?;
    for global in 0..24usize {
        if global == global_agregado {
            // Esta clave la cubrirá el agregado: así el agregado añade y se verifica.
            continue;
        }
        let firma = firma_de(&m, global, mensaje)?;
        simple.registrar_suelto(global + 1, firma)?;
        assert_eq!(
            v.registrar_suelto(global + 1, raiz, firma)?,
            ResultadoSuelto::Registrado
        );
    }

    let agregado = construir_agregado(&m, sub, &[0], 0, mensaje)?;
    assert_eq!(
        simple.recibir_agregado(&agregado)?,
        ResultadoAgregado::Aceptado
    );
    let mut generador = SplitMix64(0xA0010);
    let lote = v.recibir_lote(&[agregado], &mut generador)?;
    assert_eq!(lote.first().copied(), Some(ResultadoAgregado::Aceptado));

    assert!(simple.hay_quorum()?);
    assert_eq!(
        simple.peso_cubierto()?,
        v.resumen()?
            .mayor
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?
            .peso_cubierto
    );
    assert_eq!(simple.hay_quorum()?, v.grupo_ganador()?.is_some());
    assert_eq!(
        simple.mapa_constan()?,
        v.acta()?.ok_or(ErrorAgregacion::ClaveNoRegistrada)?.1
    );

    let cs = simple
        .certificado()?
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let cv = v.certificado()?.ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    assert_eq!(
        serial_certificado_peso(&cs),
        serial_certificado_peso(&cv),
        "certificado byte a byte distinto del estado simple"
    );
    verificar_firma_peso(&m.tabla, &m.claves, &cs)?;
    verificar_firma_peso(&m.tabla, &m.claves, &cv)?;
    Ok(())
}

// ── 2 · dos raíces no se mezclan ─────────────────────────────────────────────────────────────

#[test]
fn vr_dos_raices_no_se_mezclan() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(12, 2, 64, 0xA002)?;
    let mut v = ventana(&m, 2)?;

    // R1 cubre 8 claves (quórum: ⌈2·12/3⌉ = 8); R2, las 4 restantes.
    for global in 0..8usize {
        suelto_de(&mut v, &m, global, R1)?;
    }
    for global in 8..12usize {
        suelto_de(&mut v, &m, global, R2)?;
    }

    let certificado = v.certificado()?.ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    assert_eq!(certificado.raiz_estado, R1);
    for global in 0..8usize {
        assert!(
            bit_set(&certificado.mapa, global),
            "falta la clave {global} de R1"
        );
    }
    for global in 8..12usize {
        assert!(
            !bit_set(&certificado.mapa, global),
            "la clave {global} solo votó R2 y no puede estar en el certificado de R1"
        );
    }
    assert_eq!(
        v.grupo_ganador()?
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?
            .raiz,
        R1
    );
    Ok(())
}

// ── 3 · gana la que alcanza el quórum ────────────────────────────────────────────────────────

#[test]
fn vr_gana_la_que_alcanza_el_quorum() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(9, 1, 64, 0xA003)?;
    let mut v = ventana(&m, 1)?;

    // R1 se queda corta (3 claves) y R2 llega al quórum (6 de 9; umbral ⌈2·9/3⌉ = 6).
    for global in 0..3usize {
        suelto_de(&mut v, &m, global, R1)?;
    }
    for global in 3..9usize {
        suelto_de(&mut v, &m, global, R2)?;
    }

    let ganador = v
        .grupo_ganador()?
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    assert_eq!(ganador.raiz, R2);
    assert_eq!(ganador.peso_cubierto, 6);
    let certificado = v.certificado()?.ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    assert_eq!(certificado.raiz_estado, R2);
    verificar_firma_peso(&m.tabla, &m.claves, &certificado)?;
    Ok(())
}

// ── 4 · dos grupos sin quórum no certifican (la suma sí llegaría) ───────────────────────────

#[test]
fn vr_dos_grupos_sin_quorum_no_certifican() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(10, 1, 64, 0xA004)?;
    let mut v = ventana(&m, 1)?;

    // Umbral ⌈2·10/3⌉ = 7: cada grupo cubre 4; la unión, 8 (llegaría).
    for global in 0..4usize {
        suelto_de(&mut v, &m, global, R1)?;
    }
    for global in 4..8usize {
        suelto_de(&mut v, &m, global, R2)?;
    }

    assert!(v.certificado()?.is_none(), "ningún grupo llega al quórum");
    assert!(v.grupo_ganador()?.is_none());

    let resumen = v.resumen()?;
    assert_eq!(resumen.raices, 2);
    assert_eq!(
        resumen
            .mayor
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?
            .peso_cubierto,
        4
    );
    assert_eq!(
        resumen
            .segunda
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?
            .peso_cubierto,
        4
    );
    assert!(
        resumen.sin_quorum_por_division,
        "la suma de las claves distintas sí llega al quórum y el resumen debe decirlo"
    );
    Ok(())
}

// ── 5 · desempate por peso y por raíz ────────────────────────────────────────────────────────

#[test]
fn vr_desempate_por_peso_y_por_raiz() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(4, 1, 64, 0xA005)?;

    // Empate a 3: gana la raíz menor en bytes (R1 = 0x10… < R2 = 0x20…).
    let mut v = ventana(&m, 1)?;
    let a1 = construir_agregado(&m, 0, &[0, 1, 2], 0, mensaje_con(R1))?;
    let a2 = construir_agregado(&m, 0, &[0, 1, 2], 1, mensaje_con(R2))?;
    assert_eq!(v.recibir_agregado(&a1)?, ResultadoAgregado::Aceptado);
    assert_eq!(v.recibir_agregado(&a2)?, ResultadoAgregado::Aceptado);
    assert_eq!(
        v.grupo_ganador()?
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?
            .raiz,
        R1
    );

    // Distinto peso: gana R2 (4 > 3), aunque R1 sea la raíz menor.
    let mut v2 = ventana(&m, 1)?;
    let b1 = construir_agregado(&m, 0, &[0, 1, 2], 0, mensaje_con(R1))?;
    let b2 = construir_agregado(&m, 0, &[0, 1, 2, 3], 1, mensaje_con(R2))?;
    assert_eq!(v2.recibir_agregado(&b1)?, ResultadoAgregado::Aceptado);
    assert_eq!(v2.recibir_agregado(&b2)?, ResultadoAgregado::Aceptado);
    let ganador = v2
        .grupo_ganador()?
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    assert_eq!(ganador.raiz, R2);
    assert_eq!(ganador.peso_cubierto, 4);
    Ok(())
}

// ── 6 · una clave cuenta en un solo grupo ───────────────────────────────────────────────────

#[test]
fn vr_una_clave_cuenta_en_un_solo_grupo() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(3, 1, 64, 0xA006)?;
    let mut v = ventana(&m, 1)?;

    let f0 = firma_de(&m, 0, mensaje_con(R1))?;
    assert_eq!(v.registrar_suelto(1, R1, f0)?, ResultadoSuelto::Registrado);
    assert_eq!(
        v.registrar_suelto(1, R2, firma_de(&m, 0, mensaje_con(R2))?)?,
        ResultadoSuelto::OtraRaiz,
        "el segundo voto suelto con otra raíz no se añade"
    );
    assert_eq!(
        v.registrar_suelto(1, R1, f0)?,
        ResultadoSuelto::Repetido,
        "con la misma raíz es idempotente"
    );

    suelto_de(&mut v, &m, 1, R2)?;
    suelto_de(&mut v, &m, 2, R2)?;

    let resumen = v.resumen()?;
    assert_eq!(resumen.raices, 2);
    let mayor = resumen.mayor.ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    assert_eq!(mayor.raiz, R2);
    assert_eq!(mayor.peso_cubierto, 2, "R2 solo tiene las claves 1 y 2");
    let segunda = resumen.segunda.ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    assert_eq!(segunda.raiz, R1);
    assert_eq!(segunda.peso_cubierto, 1);
    Ok(())
}

// ── 7 · una agregadora, una plaza en la ventana ─────────────────────────────────────────────

#[test]
fn vr_una_agregadora_una_plaza_en_la_ventana() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(6, 1, 64, 0xA007)?;
    let mut v = ventana(&m, 1)?;

    let a1 = construir_agregado(&m, 0, &[0, 1, 2], 0, mensaje_con(R1))?;
    assert_eq!(v.recibir_agregado(&a1)?, ResultadoAgregado::Aceptado);

    // Misma plaza (subred 0, agregadora 0) con otra raíz, válida: «repetido».
    let a2 = construir_agregado(&m, 0, &[0, 1, 2], 0, mensaje_con(R2))?;
    assert_eq!(
        v.recibir_agregado(&a2)?,
        ResultadoAgregado::Repetido,
        "una agregadora ocupa una sola plaza por subred en toda la ventana"
    );
    assert_eq!(v.raices(), 1, "el repetido no crea el grupo de R2");
    assert_eq!(v.agregados_aceptados(), 1);
    Ok(())
}

// ── 8 · un agregado inválido no crea grupo ──────────────────────────────────────────────────

#[test]
fn vr_un_agregado_invalido_no_crea_grupo() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(6, 1, 64, 0xA008)?;
    let mut v = ventana(&m, 1)?;

    let mut malo = construir_agregado(&m, 0, &[0, 1], 0, mensaje_con(R2))?;
    malo.firma_agregada = agregar_firmas(&[&firma_falsa(&m)?])?;
    assert_eq!(
        v.recibir_agregado(&malo)?,
        ResultadoAgregado::Invalido(MotivoAgregado::FirmaAgregada)
    );
    assert_eq!(v.raices(), 0, "un inválido no crea grupo");
    assert_eq!(v.agregados_aceptados(), 0, "un inválido no ocupa plaza");

    let bueno = construir_agregado(&m, 0, &[0, 1], 0, mensaje_con(R2))?;
    assert_eq!(v.recibir_agregado(&bueno)?, ResultadoAgregado::Aceptado);
    assert_eq!(v.raices(), 1);
    assert_eq!(v.agregados_aceptados(), 1);
    Ok(())
}

// ── 9 · otro candidato u otra tabla siguiente se ignoran ────────────────────────────────────

#[test]
fn vr_otro_candidato_u_otra_tabla_siguiente_se_ignoran() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(6, 1, 64, 0xA009)?;
    let mut v = ventana(&m, 1)?;

    let mut otro_candidato = mensaje_con(R2);
    otro_candidato.candidato = [0x77; LONGITUD_HASH];
    let agr_candidato = construir_agregado(&m, 0, &[0], 0, otro_candidato)?;
    assert_eq!(
        v.recibir_agregado(&agr_candidato)?,
        ResultadoAgregado::OtroMensaje
    );

    let mut otra_tabla_siguiente = mensaje_con(R2);
    otra_tabla_siguiente.h_t_siguiente = [0x88; LONGITUD_HASH];
    let agr_tabla_siguiente = construir_agregado(&m, 0, &[0], 0, otra_tabla_siguiente)?;
    assert_eq!(
        v.recibir_agregado(&agr_tabla_siguiente)?,
        ResultadoAgregado::OtroMensaje
    );

    let mut otra_tabla = construir_agregado(&m, 0, &[0], 0, mensaje_con(R2))?;
    otra_tabla.huella_tabla = [0x99; LONGITUD_HASH];
    assert_eq!(
        v.recibir_agregado(&otra_tabla)?,
        ResultadoAgregado::OtraTabla
    );
    assert_eq!(v.raices(), 0);
    Ok(())
}

// ── 10 · la huella se calcula una vez ───────────────────────────────────────────────────────

#[test]
fn vr_la_huella_se_calcula_una_vez() -> Result<(), Box<dyn std::error::Error>> {
    // Demostración por construcción: `DatosVentana` es el **único** punto de la pieza que llama a
    // `hash_tabla`; los estados y la ventana comparan contra `datos.huella()` y el agregado propio
    // estampa esa misma huella. Para probarlo, se construye el bloque con una huella **distinta**
    // de `hash_tabla(tabla)`: si la pieza recalculara, el agregado propio llevaría la de la tabla.
    let m = mundo_unos(8, 1, 64, 0xA010)?;
    let falsa: Hash = [0x5A; LONGITUD_HASH];
    assert_ne!(falsa, hash_tabla(&m.tabla));

    let datos = DatosVentana::con_huella(&m.tabla, &m.claves, &m.pesos, 1, falsa)?;
    let mut v = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    let mensaje = mensaje_con(R1);
    v.registrar_suelto(1, R1, firma_de(&m, 0, mensaje)?)?;

    let secreta = m
        .secretas
        .first()
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let sorteo = firmar(secreta, DOMINIO_SORTEO, &N.to_be_bytes())?;
    let propio = v
        .agregado_propio(1, R1, &sorteo)?
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    assert_eq!(
        propio.huella_tabla, falsa,
        "el agregado propio usa la huella del bloque compartido, no una recalculada"
    );
    assert_ne!(propio.huella_tabla, hash_tabla(&m.tabla));

    // Recibir agregados no cambia la huella del bloque: sigue siendo la misma `falsa`.
    let agregado = construir_agregado(&m, 0, &[0], 0, mensaje)?;
    assert_eq!(v.recibir_agregado(&agregado)?, ResultadoAgregado::OtraTabla);
    assert_eq!(
        v.raices(),
        1,
        "el estado sigue existiendo con la misma huella"
    );
    Ok(())
}

// ── 11 · acta del grupo de más peso ─────────────────────────────────────────────────────────

#[test]
fn vr_acta_del_grupo_de_mas_peso() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(8, 1, 64, 0xA011)?;
    let mut v = ventana(&m, 1)?;

    // R1 cubre 5 claves y R2 cubre 2: sin quórum (umbral ⌈2·8/3⌉ = 6), el acta es la de más peso.
    for global in 0..5usize {
        suelto_de(&mut v, &m, global, R1)?;
    }
    for global in 5..7usize {
        suelto_de(&mut v, &m, global, R2)?;
    }

    assert!(v.grupo_ganador()?.is_none(), "ningún grupo llega al quórum");
    let (raiz, mapa) = v.acta()?.ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    assert_eq!(raiz, R1);
    for global in 0..5usize {
        assert!(
            bit_set(&mapa, global),
            "falta la clave {global} del grupo de más peso"
        );
    }
    for global in 5..8usize {
        assert!(!bit_set(&mapa, global), "la clave {global} no es de R1");
    }
    Ok(())
}

// ── 12 · el lote por raíces es idéntico a uno a uno ─────────────────────────────────────────

/// Instantánea del estado final **público** de una ventana, para comparar lote y uno a uno.
#[derive(Debug, PartialEq, Eq)]
struct Instantanea {
    raices: usize,
    aceptados: usize,
    ganador: Option<GrupoRaiz>,
    acta: Option<(Hash, Vec<u8>)>,
    certificado: Option<Vec<u8>>,
    resumen: ResumenRaices,
}

/// Estado final público de la ventana (grupos, plazas, ganador, acta, certificado y resumen).
fn instantanea(v: &VentanaPorRaices) -> Result<Instantanea, ErrorAgregacion> {
    let certificado = v.certificado()?;
    Ok(Instantanea {
        raices: v.raices(),
        aceptados: v.agregados_aceptados(),
        ganador: v.grupo_ganador()?,
        acta: v.acta()?,
        certificado: certificado.as_ref().map(serial_certificado_peso),
        resumen: v.resumen()?,
    })
}

/// Agregado válido de la plaza `(sub, pos)` para `raiz`.
fn valido_en(m: &Mundo, sub: u16, pos: usize, raiz: Hash) -> Result<Agregado, ErrorAgregacion> {
    construir_agregado(m, sub, &[pos], pos, mensaje_con(raiz))
}

/// El mismo agregado con una firma agregada que no verifica.
fn con_firma_falsa(m: &Mundo, mut agregado: Agregado) -> Result<Agregado, ErrorAgregacion> {
    agregado.firma_agregada = agregar_firmas(&[&firma_falsa(m)?])?;
    Ok(agregado)
}

#[test]
fn lote_igual_que_uno_a_uno_por_raices() -> Result<(), Box<dyn std::error::Error>> {
    // Un solo mundo (una tabla) reutilizado por los 250 lotes; los lotes son pseudoaleatorios de
    // semilla fija y mezclan válidos, firma falsa, otra tabla, otro mensaje, las dos raíces y
    // parejas de la misma agregadora (válido y válido, inválido y válido, válido e inválido).
    let m = mundo_unos(24, 2, 64, 0xBEEF)?;
    let sub0 = subredes_no_vacias(&m)[0];
    let sub1 = *subredes_no_vacias(&m)
        .get(1)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let n0 = m.reparto.claves_de(sub0).len();
    let n1 = m.reparto.claves_de(sub1).len();
    let datos = datos_de(&m, 2)?;

    // Aceptado, Repetido, Invalido, OtraTabla, OtroMensaje: el test debe ejercitar los cinco.
    let mut vistos = [false; 5];
    for semilla in 0..250u64 {
        let mut rng = SplitMix64(0xBEEF_0000 ^ semilla.wrapping_mul(0x9e37_79b9));
        let p0 = (rng.siguiente() as usize) % n0;
        let p0b = (rng.siguiente() as usize) % n0;
        let p0c = (rng.siguiente() as usize) % n0;
        let p1 = (rng.siguiente() as usize) % n1;
        let p1b = (rng.siguiente() as usize) % n1;

        let mut otro = mensaje_con(R2);
        otro.candidato = [0x77; LONGITUD_HASH];
        let mut otra_tabla = valido_en(&m, sub1, p1b, R1)?;
        otra_tabla.huella_tabla = [0x99; LONGITUD_HASH];

        let mut lote = vec![
            // válido y válido en la misma plaza (R1 y R2)
            valido_en(&m, sub0, p0, R1)?,
            valido_en(&m, sub0, p0, R2)?,
            // inválido y válido en la misma plaza
            con_firma_falsa(&m, valido_en(&m, sub0, p0b, R1)?)?,
            valido_en(&m, sub0, p0b, R1)?,
            // válido e inválido en la misma plaza
            valido_en(&m, sub1, p1, R2)?,
            con_firma_falsa(&m, valido_en(&m, sub1, p1, R2)?)?,
            // otra tabla y otro mensaje
            otra_tabla,
            construir_agregado(&m, sub1, &[p1b], p1b, otro)?,
            // plazas distintas con una firma falsa suelta
            valido_en(&m, sub0, p0c, R2)?,
            con_firma_falsa(&m, valido_en(&m, sub1, (p1 + 1) % n1, R1)?)?,
        ];
        for i in (1..lote.len()).rev() {
            let j = (rng.siguiente() as usize) % (i + 1);
            lote.swap(i, j);
        }

        let mut v_lote = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
        let mut v_uno = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
        let mut generador = SplitMix64(0x1000 ^ semilla);
        let resultados_lote = v_lote.recibir_lote(&lote, &mut generador)?;
        let mut resultados_uno = Vec::with_capacity(lote.len());
        for agregado in &lote {
            resultados_uno.push(v_uno.recibir_agregado(agregado)?);
        }
        assert_eq!(
            resultados_lote, resultados_uno,
            "semilla {semilla}: resultados por agregado distintos"
        );
        for resultado in &resultados_uno {
            match resultado {
                ResultadoAgregado::Aceptado => vistos[0] = true,
                ResultadoAgregado::Repetido => vistos[1] = true,
                ResultadoAgregado::Invalido(_) => vistos[2] = true,
                ResultadoAgregado::OtraTabla => vistos[3] = true,
                ResultadoAgregado::OtroMensaje => vistos[4] = true,
            }
        }
        assert_eq!(
            instantanea(&v_lote)?,
            instantanea(&v_uno)?,
            "semilla {semilla}: estado final distinto"
        );
    }
    assert!(
        vistos.iter().all(|visto| *visto),
        "el test debe ejercitar los cinco resultados: {vistos:?}"
    );

    // Cola determinista: varios agregados que no añaden (subconjuntos de uno anterior con plaza
    // distinta), para ejercitar el descarte por «no añade» y no solo por plaza ocupada.
    let lote = vec![
        construir_agregado(&m, sub0, &[0, 1, 2], 0, mensaje_con(R1))?,
        construir_agregado(&m, sub0, &[1, 2], 1, mensaje_con(R1))?,
        construir_agregado(&m, sub0, &[0, 2], 2, mensaje_con(R1))?,
        construir_agregado(&m, sub1, &[0, 1, 2], 0, mensaje_con(R2))?,
        construir_agregado(&m, sub1, &[1, 2], 1, mensaje_con(R2))?,
    ];
    let mut v_lote = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    let mut v_uno = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    let mut generador = SplitMix64(0xD0D0);
    let resultados_lote = v_lote.recibir_lote(&lote, &mut generador)?;
    let mut resultados_uno = Vec::with_capacity(lote.len());
    for agregado in &lote {
        resultados_uno.push(v_uno.recibir_agregado(agregado)?);
    }
    assert_eq!(
        resultados_lote, resultados_uno,
        "cola determinista: resultados por agregado distintos"
    );
    assert_eq!(
        resultados_lote,
        vec![
            ResultadoAgregado::Aceptado,
            ResultadoAgregado::Repetido,
            ResultadoAgregado::Repetido,
            ResultadoAgregado::Aceptado,
            ResultadoAgregado::Repetido,
        ],
        "la cola debe mezclar aceptado y no-añade"
    );
    assert_eq!(
        instantanea(&v_lote)?,
        instantanea(&v_uno)?,
        "cola determinista: estado final distinto"
    );
    Ok(())
}

// ── 13 · una sola verificación por lotes ────────────────────────────────────────────────────

/// Generador de escalares que cuenta las verificaciones por lotes y los agregados que entran.
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

#[test]
fn lote_una_sola_verificacion_por_lotes() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(16, 2, 64, 0xC0FE)?;
    let sub0 = subredes_no_vacias(&m)[0];
    let sub1 = *subredes_no_vacias(&m)
        .get(1)
        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
    let n0 = m.reparto.claves_de(sub0).len();
    let n1 = m.reparto.claves_de(sub1).len();

    // Un solo mensaje (R1): una sola verificación por lotes.
    let mut v = ventana(&m, 2)?;
    let mut lote = Vec::new();
    for pos in 0..n0.min(4) {
        lote.push(valido_en(&m, sub0, pos, R1)?);
    }
    let mut generador = GeneradorCuenta {
        rng: SplitMix64(0xC0FE_0000),
        verificaciones: 0,
        agregados_verificados: 0,
    };
    let resultados = v.recibir_lote(&lote, &mut generador)?;
    assert_eq!(resultados, vec![ResultadoAgregado::Aceptado; lote.len()]);
    assert_eq!(
        generador.verificaciones, 1,
        "un lote sin inválidos de un solo mensaje debe hacer una sola verificación por lotes"
    );

    // Dos mensajes (R1 y R2): una verificación por mensaje.
    let mut v2 = ventana(&m, 2)?;
    let mut lote2 = Vec::new();
    for pos in 0..n0.min(2) {
        lote2.push(valido_en(&m, sub0, pos, R1)?);
    }
    for pos in 0..n1.min(2) {
        lote2.push(valido_en(&m, sub1, pos, R2)?);
    }
    let mut generador2 = GeneradorCuenta {
        rng: SplitMix64(0xC0FE_0001),
        verificaciones: 0,
        agregados_verificados: 0,
    };
    let resultados2 = v2.recibir_lote(&lote2, &mut generador2)?;
    assert_eq!(resultados2, vec![ResultadoAgregado::Aceptado; lote2.len()]);
    assert_eq!(
        generador2.verificaciones, 2,
        "un lote sin inválidos de dos mensajes debe hacer una verificación por mensaje"
    );
    Ok(())
}

// ── 14 · la huella no se recalcula en el lote ───────────────────────────────────────────────

#[test]
fn lote_no_calcula_la_huella() -> Result<(), Box<dyn std::error::Error>> {
    let m = mundo_unos(16, 2, 64, 0xCAFE)?;
    let sub = subredes_no_vacias(&m)[0];
    let falsa: Hash = [0x5A; LONGITUD_HASH];
    assert_ne!(falsa, m.huella);
    let datos = DatosVentana::con_huella(&m.tabla, &m.claves, &m.pesos, 2, falsa)?;

    // Un agregado que lleva la huella forzada se acepta: no se recalcula `hash_tabla`.
    let mut con_falsa = construir_agregado(&m, sub, &[0], 0, mensaje_con(R1))?;
    con_falsa.huella_tabla = falsa;
    let mut v = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    let mut generador = SplitMix64(0xCAFE_0000);
    let por_lote = v.recibir_lote(std::slice::from_ref(&con_falsa), &mut generador)?;
    assert_eq!(
        por_lote,
        vec![ResultadoAgregado::Aceptado],
        "la huella forzada debe aceptarse sin recalcularla"
    );

    // Uno con la huella real es «otra tabla» contra la huella forzada.
    let con_real = construir_agregado(&m, sub, &[0], 0, mensaje_con(R1))?;
    assert_ne!(con_real.huella_tabla, falsa);
    let mut v2 = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    let otro = v2.recibir_lote(std::slice::from_ref(&con_real), &mut generador)?;
    assert_eq!(otro, vec![ResultadoAgregado::OtraTabla]);

    // La misma garantía uno a uno (la variante con huella).
    let mut v3 = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    assert_eq!(
        v3.recibir_agregado(&con_falsa)?,
        ResultadoAgregado::Aceptado
    );
    Ok(())
}

// ── 15 · cronómetro de la tabla llena (§4; prueba #[ignore], no medida limpia) ──────────────

/// Cronómetro de §4: tabla de 65 536 claves de peso igual, S = 64, A = 62; todas votan y se
/// construye el lote con los agregados de todas las agregadoras cuyo sorteo sale. Los 65 536 votos
/// sueltos solo sirven para **construir** los agregados; el nodo que los recibe es una ventana
/// fresca (el agregado es su cobertura). Con `--release` y `--nocapture`. **No** es medida limpia:
/// corre en el espacio aislado (bloque 1 en uso).
#[test]
#[ignore = "cronometro de §4: se ejecuta una sola vez con --release --ignored --nocapture"]
fn cronometro_tabla_llena() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;

    const N_CLAVES: usize = 65_536;
    const S_CLAVES: u16 = 64;
    const A_AGREGADORAS: u32 = 62;

    // ── montar la pieza: claves, mundo, votos sueltos y agregados ──
    let t_montaje = Instant::now();
    let m = mundo_unos(N_CLAVES, S_CLAVES, A_AGREGADORAS, 0xC10C)?;
    let datos = datos_de(&m, S_CLAVES)?;
    let raiz = R1;
    let mut v = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    for global in 0..N_CLAVES {
        let firma = firma_de(&m, global, mensaje_con(raiz))?;
        let _ = v.registrar_suelto(global + 1, raiz, firma)?;
    }
    let mut agregados = Vec::new();
    for sub in 0..S_CLAVES {
        let n_s = m.reparto.claves_de(sub).len();
        for pos in 0..n_s {
            let global = global_de(&m, sub, pos)?;
            let sorteo = firmar(
                m.secretas
                    .get(global)
                    .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
                DOMINIO_SORTEO,
                &N.to_be_bytes(),
            )?;
            if let Some(agregado) = v.agregado_propio(global + 1, raiz, &sorteo)? {
                agregados.push(agregado);
            }
        }
    }
    let total = agregados.len();
    let montaje = t_montaje.elapsed();

    // ── recibir el lote en una ventana fresca (sin los sueltos: el nodo recibe el agregado) ──
    let mut v_lote = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    let mut generador = GeneradorCuenta {
        rng: SplitMix64(0xC10C_0000),
        verificaciones: 0,
        agregados_verificados: 0,
    };
    let t_lote = Instant::now();
    let resultados_lote = v_lote.recibir_lote(&agregados, &mut generador)?;
    let lote = t_lote.elapsed();
    let aceptados_lote = resultados_lote
        .iter()
        .filter(|resultado| **resultado == ResultadoAgregado::Aceptado)
        .count();
    let repetidos_lote = resultados_lote
        .iter()
        .filter(|resultado| **resultado == ResultadoAgregado::Repetido)
        .count();

    // ── muestra de 200 uno a uno, en otra ventana fresca ──
    let mut v_uno = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    let muestra = total.min(200);
    let t_uno = Instant::now();
    let mut aceptados_uno = 0usize;
    for agregado in agregados.iter().take(muestra) {
        if v_uno.recibir_agregado(agregado)? == ResultadoAgregado::Aceptado {
            aceptados_uno += 1;
        }
    }
    let uno_200 = t_uno.elapsed();
    let extrapolado_ms = uno_200.as_secs_f64() * (total as f64 / muestra as f64) * 1000.0;

    // ── certificado ──
    let t_cert = Instant::now();
    let certificado = v_lote.certificado()?;
    let certificado_ms = t_cert.elapsed();

    println!("cronometro_tabla_llena: claves={N_CLAVES} S={S_CLAVES} A={A_AGREGADORAS}");
    println!("  agregadoras que salen (agregados en el lote): {total}");
    println!(
        "  aceptados por lotes: {aceptados_lote}; repetidos: {repetidos_lote}; muestra uno a uno: {aceptados_uno}/{muestra}"
    );
    println!(
        "  verificaciones_por_lotes: {}; agregados_verificados: {}",
        generador.verificaciones, generador.agregados_verificados
    );
    println!("  montaje_pieza_ms: {:.3}", montaje.as_secs_f64() * 1000.0);
    println!("  recibir_lote_ms: {:.3}", lote.as_secs_f64() * 1000.0);
    println!(
        "  uno_a_uno_muestra_200_ms: {:.3}",
        uno_200.as_secs_f64() * 1000.0
    );
    println!("  uno_a_uno_extrapolado_ms [extrapolado de la muestra de 200]: {extrapolado_ms:.3}");
    println!(
        "  certificado_ms: {:.3}; certificado_presente: {}",
        certificado_ms.as_secs_f64() * 1000.0,
        certificado.is_some()
    );
    Ok(())
}

// ── 16 · cronómetro desfavorable (§4; cada agregado añade una clave) ─────────────────────────

/// Cronómetro desfavorable de §4: igual que el anterior, pero a cada agregadora le falta una clave
/// **distinta** de su subred, de modo que cada agregado añade algo al anterior y la regla no ahorra
/// ninguna verificación. **No** es medida limpia: espacio aislado (bloque 1 en uso).
#[test]
#[ignore = "cronometro de §4: se ejecuta una sola vez con --release --ignored --nocapture"]
fn cronometro_tabla_llena_desfavorable() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;

    const N_CLAVES: usize = 65_536;
    const S_CLAVES: u16 = 64;
    const A_AGREGADORAS: u32 = 62;

    // ── montar la pieza ──
    let t_montaje = Instant::now();
    let m = mundo_unos(N_CLAVES, S_CLAVES, A_AGREGADORAS, 0xC10D)?;
    let datos = datos_de(&m, S_CLAVES)?;
    let raiz = R1;
    // Firmas A3 de todas las claves (no se registran como sueltos en la ventana que recibe).
    let mut firmas: Vec<Firma> = Vec::with_capacity(N_CLAVES);
    for global in 0..N_CLAVES {
        firmas.push(firma_de(&m, global, mensaje_con(raiz))?);
    }
    // Un agregado por agregadora cuyo sorteo sale: mapa = todas las claves de la subred menos una
    // clave distinta por agregadora (y distinta de la agregadora, para que su bit esté marcado).
    let mut agregados: Vec<Agregado> = Vec::new();
    for sub in 0..S_CLAVES {
        let indices = m.reparto.claves_de(sub);
        let n_s = indices.len();
        if n_s == 0 {
            continue;
        }
        let mut faltantes: BTreeSet<usize> = BTreeSet::new();
        for pos in 0..n_s {
            let global = global_de(&m, sub, pos)?;
            let secreta = m
                .secretas
                .get(global)
                .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
            let sorteo = firmar(secreta, DOMINIO_SORTEO, &N.to_be_bytes())?;
            let huella = hash_bytes(&sorteo.bytes());
            if !sale_agregadora(&huella, N_CLAVES, S_CLAVES, A_AGREGADORAS) {
                continue;
            }
            let mut falta = None;
            for candidata in 0..n_s {
                if candidata != pos && !faltantes.contains(&candidata) {
                    falta = Some(candidata);
                    break;
                }
            }
            let Some(falta) = falta else {
                continue;
            };
            faltantes.insert(falta);
            let mut mapa = vec![0u8; n_s.div_ceil(8)];
            let mut firmas_agregado: Vec<Firma> = Vec::new();
            for (p, &idx_global) in indices.iter().enumerate() {
                if p == falta {
                    continue;
                }
                if let Some(byte) = mapa.get_mut(p >> 3) {
                    *byte |= 1 << (p & 7);
                }
                firmas_agregado.push(
                    *firmas
                        .get(idx_global)
                        .ok_or(ErrorAgregacion::ClaveNoRegistrada)?,
                );
            }
            let referencias: Vec<&Firma> = firmas_agregado.iter().collect();
            let firma_agregada = agregar_firmas(&referencias)?;
            agregados.push(Agregado {
                n: N,
                candidato: CANDIDATO,
                h_t_siguiente: H_T,
                raiz_estado: raiz,
                firma_agregada,
                huella_tabla: m.huella,
                subred: sub,
                indice_agregadora: u16::try_from(pos).map_err(|_| ErrorAgregacion::FueraDeU16)?,
                mapa_local: mapa,
                firma_sorteo: sorteo,
            });
        }
    }
    let total = agregados.len();
    let montaje = t_montaje.elapsed();

    // ── recibir el lote en una ventana fresca ──
    let mut v_lote = VentanaPorRaices::nuevo(Arc::clone(&datos), m.a, N, CANDIDATO, H_T);
    let mut generador = GeneradorCuenta {
        rng: SplitMix64(0xC10D_0000),
        verificaciones: 0,
        agregados_verificados: 0,
    };
    let t_lote = Instant::now();
    let resultados = v_lote.recibir_lote(&agregados, &mut generador)?;
    let lote = t_lote.elapsed();
    let aceptados = resultados
        .iter()
        .filter(|r| **r == ResultadoAgregado::Aceptado)
        .count();
    let repetidos = resultados
        .iter()
        .filter(|r| **r == ResultadoAgregado::Repetido)
        .count();

    println!(
        "cronometro_tabla_llena_desfavorable: claves={N_CLAVES} S={S_CLAVES} A={A_AGREGADORAS}"
    );
    println!("  agregados en el lote: {total}");
    println!("  aceptados: {aceptados}; repetidos: {repetidos}");
    println!(
        "  verificaciones_por_lotes: {}; agregados_verificados: {}",
        generador.verificaciones, generador.agregados_verificados
    );
    println!("  montaje_pieza_ms: {:.3}", montaje.as_secs_f64() * 1000.0);
    println!("  recibir_lote_ms: {:.3}", lote.as_secs_f64() * 1000.0);
    Ok(())
}

// ── 17 · la cobertura no cambia con la regla de «no añade» (N4, prueba 5) ────────────────────

/// Cobertura de referencia **sin** la regla de «no añade»: para cada raíz, todos sus agregados
/// válidos y sus sueltos, con `armar_certificado` (misma elección AG-R14). Devuelve
/// `(raíz, peso, mapa)` ordenado por peso descendente y raíz ascendente.
fn referencia_sin_regla(
    m: &Mundo,
    agregados: &[Agregado],
    sueltos: &[(usize, Hash)],
) -> Result<Vec<(Hash, u128, Vec<u8>)>, ErrorAgregacion> {
    let mut esperado = Vec::new();
    for raiz in [R1, R2] {
        let validos: Vec<Agregado> = agregados
            .iter()
            .filter(|agregado| agregado.raiz_estado == raiz)
            .filter(|agregado| {
                matches!(
                    veredicto_con_huella(agregado, &m.tabla, &m.claves, &m.reparto, m.a, m.huella),
                    Ok(VeredictoAgregado::Valido)
                )
            })
            .cloned()
            .collect();
        let mut sueltos_raiz: Vec<(usize, Firma)> = Vec::new();
        for (posicion, raiz_suelto) in sueltos {
            if *raiz_suelto == raiz {
                sueltos_raiz.push((*posicion, firma_de(m, *posicion - 1, mensaje_con(raiz))?));
            }
        }
        if validos.is_empty() && sueltos_raiz.is_empty() {
            continue;
        }
        let certificado = armar_certificado(
            mensaje_con(raiz),
            &m.tabla,
            &m.pesos,
            &m.reparto,
            &validos,
            &sueltos_raiz,
        )?;
        let peso = firmantes_de_mapa(&certificado.mapa).len() as u128;
        esperado.push((raiz, peso, certificado.mapa));
    }
    esperado.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Ok(esperado)
}

#[test]
fn nomejora_05_la_cobertura_no_cambia() -> Result<(), Box<dyn std::error::Error>> {
    // A·S = 64·3 = 192 ≥ N = 48: todos los sorteos salen.
    let m = mundo_unos(48, 3, 64, 0x505)?;
    let s = m.reparto.s();
    let total = m.pesos.iter().copied().sum::<u128>();

    for semilla in 0..300u64 {
        let mut rng = SplitMix64(0x5050 ^ semilla.wrapping_mul(0x9e37_79b9));

        // Agregados con plazas distintas (subred, índice) para que la plaza no los descarte.
        let mut agregados: Vec<Agregado> = Vec::new();
        let mut plazas: BTreeSet<(u16, u16)> = BTreeSet::new();
        let objetivo = 2 + (rng.siguiente() % 8) as usize;
        let mut intentos = 0;
        while agregados.len() < objetivo && intentos < 300 {
            intentos += 1;
            let sub = (rng.siguiente() % u64::from(s)) as u16;
            let n_s = m.reparto.claves_de(sub).len();
            if n_s == 0 {
                continue;
            }
            let pos = (rng.siguiente() as usize) % n_s;
            if !plazas.insert((sub, pos as u16)) {
                continue;
            }
            let mut marcados = vec![pos];
            let extra = (rng.siguiente() % 4) as usize;
            for _ in 0..extra {
                let p = (rng.siguiente() as usize) % n_s;
                if !marcados.contains(&p) {
                    marcados.push(p);
                }
            }
            let raiz = [R1, R2][(rng.siguiente() % 2) as usize];
            let mut agregado = construir_agregado(&m, sub, &marcados, pos, mensaje_con(raiz))?;
            if rng.siguiente().is_multiple_of(5) {
                agregado.firma_agregada = agregar_firmas(&[&firma_falsa(&m)?])?;
            }
            agregados.push(agregado);
        }

        // Sueltos únicos (una clave, un grupo) y con las dos raíces presentes.
        let mut sueltos: Vec<(usize, Hash)> = Vec::new();
        let mut claves: BTreeSet<usize> = BTreeSet::new();
        let cuantos = (rng.siguiente() % 6) as usize;
        for _ in 0..cuantos {
            let global = (rng.siguiente() as usize) % m.tabla.claves.len();
            if !claves.insert(global) {
                continue;
            }
            sueltos.push((global + 1, [R1, R2][(rng.siguiente() % 2) as usize]));
        }
        for (raiz, global) in [(R1, 0usize), (R2, m.tabla.claves.len() - 1)] {
            if claves.insert(global) {
                sueltos.push((global + 1, raiz));
            }
        }

        // Regla: la ventana por raíces, en un solo lote.
        let mut v = ventana(&m, s)?;
        for (posicion, raiz) in &sueltos {
            let firma = firma_de(&m, *posicion - 1, mensaje_con(*raiz))?;
            let _ = v.registrar_suelto(*posicion, *raiz, firma)?;
        }
        let mut generador = SplitMix64(0x5050 ^ semilla);
        let _ = v.recibir_lote(&agregados, &mut generador)?;

        // Referencia sin la regla.
        let esperado = referencia_sin_regla(&m, &agregados, &sueltos)?;
        let resumen = v.resumen()?;
        assert_eq!(
            resumen.mayor.map(|g| (g.raiz, g.peso_cubierto)),
            esperado.first().map(|(raiz, peso, _)| (*raiz, *peso)),
            "semilla {semilla}: grupo de más peso distinto"
        );
        assert_eq!(
            resumen.segunda.map(|g| (g.raiz, g.peso_cubierto)),
            esperado.get(1).map(|(raiz, peso, _)| (*raiz, *peso)),
            "semilla {semilla}: segundo grupo distinto"
        );
        let acta = v.acta()?;
        assert_eq!(
            acta,
            esperado
                .first()
                .map(|(raiz, _, mapa)| (*raiz, mapa.clone())),
            "semilla {semilla}: mapa del acta distinto"
        );

        // Ganador (con quórum) y certificado.
        let ganador_ref = esperado
            .iter()
            .find(|(_, peso, _)| 3 * peso >= 2 * total)
            .map(|(raiz, peso, _)| (*raiz, *peso));
        assert_eq!(
            v.grupo_ganador()?.map(|g| (g.raiz, g.peso_cubierto)),
            ganador_ref,
            "semilla {semilla}: ganador distinto"
        );
        if let Some(certificado) = v.certificado()? {
            verificar_firma_peso(&m.tabla, &m.claves, &certificado)?;
            let (_, _, mapa_ref) = esperado
                .iter()
                .find(|(raiz, _, _)| *raiz == certificado.raiz_estado)
                .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
            assert_eq!(
                &certificado.mapa, mapa_ref,
                "semilla {semilla}: certificado distinto"
            );
            assert_eq!(
                firmantes_de_mapa(&certificado.mapa),
                firmantes_de_mapa(mapa_ref),
                "semilla {semilla}: firmantes distintos"
            );
        }
    }
    Ok(())
}
