//! Verificación por lotes con escalares dados (`zx_bls::verificar_lote_con_escalares`).
#![allow(
    clippy::indexing_slicing,
    reason = "test: los indices estan acotados por construccion"
)]

use zx_bls::{
    ClavePublica, ClaveSecreta, ErrorBLS, Firma, LONGITUD_ESCALAR_LOTE, agregar_firmas, firmar,
    verificar_lote_con_escalares,
};

/// Dominio de prueba de la API (la separación de dominios de ZEROX exige uno no vacío).
const DOMINIO: &[u8] = b"ZX-PRUEBA-LOTE";

/// Material de clave determinista.
fn semilla(indice: usize) -> [u8; 32] {
    let mut ikm = [0u8; 32];
    let bytes = (indice as u64).to_le_bytes();
    for (destino, origen) in ikm.iter_mut().zip(bytes.iter()) {
        *destino = *origen;
    }
    if let Some(byte) = ikm.get_mut(8) {
        *byte = 0x77;
    }
    ikm
}

/// Escalar big-endian de 32 bytes con un valor pequeño.
fn escalar_pequeno(valor: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    if let Some(ultimo) = bytes.last_mut() {
        *ultimo = valor;
    }
    bytes
}

fn claves(n: usize) -> Result<Vec<(ClaveSecreta, ClavePublica)>, ErrorBLS> {
    (0..n)
        .map(|indice| {
            let secreta = ClaveSecreta::generar(&semilla(indice))?;
            let publica = secreta.clave_publica();
            Ok((secreta, publica))
        })
        .collect()
}

#[test]
fn lote_valido_pasa_con_cualquier_escalar() -> Result<(), Box<dyn std::error::Error>> {
    let pares = claves(4)?;
    let publicas: Vec<ClavePublica> = pares.iter().map(|(_, publica)| *publica).collect();
    let mensaje = b"mismo mensaje del lote";
    let firmas: Vec<Firma> = pares
        .iter()
        .map(|(secreta, _)| firmar(secreta, DOMINIO, mensaje))
        .collect::<Result<_, _>>()?;
    let refs_publicas: Vec<&ClavePublica> = publicas.iter().collect();
    let refs_firmas: Vec<&Firma> = firmas.iter().collect();

    let escalares: Vec<[u8; LONGITUD_ESCALAR_LOTE]> = (0..publicas.len())
        .map(|indice| [indice as u8 + 1; LONGITUD_ESCALAR_LOTE])
        .collect();
    verificar_lote_con_escalares(&refs_publicas, &refs_firmas, &escalares, DOMINIO, mensaje)?;
    Ok(())
}

#[test]
fn una_firma_ajena_falla() -> Result<(), Box<dyn std::error::Error>> {
    let pares = claves(3)?;
    let publicas: Vec<ClavePublica> = pares.iter().map(|(_, publica)| *publica).collect();
    let mensaje = b"mismo mensaje del lote";
    let mut firmas: Vec<Firma> = pares
        .iter()
        .map(|(secreta, _)| firmar(secreta, DOMINIO, mensaje))
        .collect::<Result<_, _>>()?;
    // La firma 1 es de otra clave.
    let otra = ClaveSecreta::generar(&semilla(99))?;
    firmas[1] = firmar(&otra, DOMINIO, mensaje)?;
    let refs_publicas: Vec<&ClavePublica> = publicas.iter().collect();
    let refs_firmas: Vec<&Firma> = firmas.iter().collect();
    let escalares = vec![[0x5a; LONGITUD_ESCALAR_LOTE]; publicas.len()];

    assert_eq!(
        verificar_lote_con_escalares(&refs_publicas, &refs_firmas, &escalares, DOMINIO, mensaje),
        Err(ErrorBLS::VerificacionFallida)
    );
    Ok(())
}

/// Un desplazamiento compensado pasa solo si los escalares coinciden: es la propiedad de seguridad.
#[test]
fn el_desplazamiento_compensado_solo_pasa_con_escalares_iguales()
-> Result<(), Box<dyn std::error::Error>> {
    let mensaje = b"mismo mensaje del lote";
    let secreta_1 = ClaveSecreta::generar(&semilla(50))?;
    let publica_1 = secreta_1.clave_publica();
    let publica_2 = ClaveSecreta::desde_bytes(&escalar_pequeno(3))?.clave_publica();

    let sigma_1 = firmar(&secreta_1, DOMINIO, mensaje)?;
    let delta = firmar(
        &ClaveSecreta::desde_bytes(&escalar_pequeno(2))?,
        DOMINIO,
        mensaje,
    )?;
    let sigma_1_prima = Firma::desde_bytes(&agregar_firmas(&[&sigma_1, &delta])?.bytes())?;
    let sigma_2_prima = firmar(
        &ClaveSecreta::desde_bytes(&escalar_pequeno(1))?,
        DOMINIO,
        mensaje,
    )?;

    let publicas = [publica_1, publica_2];
    let firmas = [sigma_1_prima, sigma_2_prima];
    let refs_publicas: Vec<&ClavePublica> = publicas.iter().collect();
    let refs_firmas: Vec<&Firma> = firmas.iter().collect();

    let iguales = [[0x11; LONGITUD_ESCALAR_LOTE], [0x11; LONGITUD_ESCALAR_LOTE]];
    verificar_lote_con_escalares(&refs_publicas, &refs_firmas, &iguales, DOMINIO, mensaje)?;

    let distintos = [[0x11; LONGITUD_ESCALAR_LOTE], [0x22; LONGITUD_ESCALAR_LOTE]];
    assert_eq!(
        verificar_lote_con_escalares(&refs_publicas, &refs_firmas, &distintos, DOMINIO, mensaje),
        Err(ErrorBLS::VerificacionFallida)
    );
    Ok(())
}

#[test]
fn longitudes_incompatibles_y_lote_vacio_se_rechazan() -> Result<(), Box<dyn std::error::Error>> {
    let pares = claves(2)?;
    let publicas: Vec<ClavePublica> = pares.iter().map(|(_, publica)| *publica).collect();
    let mensaje = b"mismo mensaje del lote";
    let firmas: Vec<Firma> = pares
        .iter()
        .map(|(secreta, _)| firmar(secreta, DOMINIO, mensaje))
        .collect::<Result<_, _>>()?;
    let refs_publicas: Vec<&ClavePublica> = publicas.iter().collect();
    let refs_firmas: Vec<&Firma> = firmas.iter().collect();
    let un_escalar = [[0u8; LONGITUD_ESCALAR_LOTE]];

    assert_eq!(
        verificar_lote_con_escalares(&refs_publicas, &refs_firmas, &un_escalar, DOMINIO, mensaje),
        Err(ErrorBLS::LongitudesLoteIncompatibles {
            claves: 2,
            firmas: 2,
            escalares: 1,
        })
    );
    assert_eq!(
        verificar_lote_con_escalares(&[], &[], &[], DOMINIO, mensaje),
        Err(ErrorBLS::AgregacionVacia)
    );
    Ok(())
}

/// Invariante que permite al lote **no** revalidar cada punto: un punto de la curva fuera del
/// subgrupo de orden primo **no** se puede materializar como `Firma` ni como `ClavePublica`, así
/// que [`verificar_lote_con_escalares`] no recibe nunca un punto fuera del subgrupo.
///
/// Los bytes son los vectores oficiales `ethereum/bls12-381-tests`
/// (`deserialization_fails_not_in_G1.json` / `deserialization_fails_not_in_G2.json`): puntos que
/// pasan la comprobación de curva y fallan la de subgrupo.
#[test]
fn un_punto_fuera_de_subgrupo_no_entra_en_los_tipos() {
    // 48 bytes: punto de G1 en la curva pero fuera del subgrupo.
    let g1 = hex::decode(
        "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap_or_default();
    // 96 bytes: punto de G2 en la curva pero fuera del subgrupo.
    let g2 = hex::decode(
        "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap_or_default();

    let error_clave = ClavePublica::desde_bytes(&g1).err();
    let error_firma = Firma::desde_bytes(&g2).err();
    assert!(
        matches!(error_clave, Some(ErrorBLS::ClaveInvalida { motivo }) if motivo.contains("subgrupo")),
        "un punto de G1 fuera del subgrupo MUST NOT convertirse en ClavePublica: {error_clave:?}"
    );
    assert!(
        matches!(error_firma, Some(ErrorBLS::FirmaInvalida { motivo }) if motivo.contains("subgrupo")),
        "un punto de G2 fuera del subgrupo MUST NOT convertirse en Firma: {error_firma:?}"
    );
}
