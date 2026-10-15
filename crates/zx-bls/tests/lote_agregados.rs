//! Lote de **agregados** con escalares dados (`zx_bls::verificar_lote_de_agregados_con_escalares`).

use zx_bls::{
    AgregadoLote, ClavePublica, ClaveSecreta, ErrorBLS, FirmaAgregada, LONGITUD_ESCALAR_LOTE,
    agregar_firmas, firmar, verificar_lote_de_agregados_con_escalares,
};

/// Dominio de prueba de la API (la separación de dominios de ZEROX exige uno no vacío).
const DOMINIO: &[u8] = b"ZX-PRUEBA-LOTE-AGREGADOS";
/// Mensaje común del lote.
const MENSAJE: &[u8] = b"mismo mensaje de todos los agregados";

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

/// Un agregado válido: `n` claves y la suma de sus firmas individuales.
fn agregado_valido(
    indice_base: usize,
    n: usize,
) -> Result<(Vec<ClavePublica>, FirmaAgregada), Box<dyn std::error::Error>> {
    let mut publicas = Vec::with_capacity(n);
    let mut firmas = Vec::with_capacity(n);
    for i in 0..n {
        let secreta = ClaveSecreta::generar(&semilla(indice_base + i))?;
        publicas.push(secreta.clave_publica());
        firmas.push(firmar(&secreta, DOMINIO, MENSAJE)?);
    }
    let refs: Vec<&zx_bls::Firma> = firmas.iter().collect();
    Ok((publicas, agregar_firmas(&refs)?))
}

#[test]
fn lote_de_agregados_valido_pasa_con_cualquier_escalar() -> Result<(), Box<dyn std::error::Error>> {
    let (publicas_0, firma_0) = agregado_valido(0, 2)?;
    let (publicas_1, firma_1) = agregado_valido(10, 3)?;
    let (publicas_2, firma_2) = agregado_valido(20, 1)?;

    let refs_0: Vec<&ClavePublica> = publicas_0.iter().collect();
    let refs_1: Vec<&ClavePublica> = publicas_1.iter().collect();
    let refs_2: Vec<&ClavePublica> = publicas_2.iter().collect();
    let agregados = [
        AgregadoLote {
            claves: &refs_0,
            firma: &firma_0,
        },
        AgregadoLote {
            claves: &refs_1,
            firma: &firma_1,
        },
        AgregadoLote {
            claves: &refs_2,
            firma: &firma_2,
        },
    ];
    let escalares = [
        [0x01; LONGITUD_ESCALAR_LOTE],
        [0x02; LONGITUD_ESCALAR_LOTE],
        [0x03; LONGITUD_ESCALAR_LOTE],
    ];
    verificar_lote_de_agregados_con_escalares(&agregados, &escalares, DOMINIO, MENSAJE)?;
    Ok(())
}

/// Un desplazamiento compensado **entre dos agregados** pasa solo si los escalares coinciden: es la
/// propiedad que impide que un lote sin coeficientes (suma directa) acepte el par `σ₁+Δ`, `σ₂−Δ`.
#[test]
fn desplazamiento_compensado_entre_agregados() -> Result<(), Box<dyn std::error::Error>> {
    let secreta_1 = ClaveSecreta::generar(&semilla(50))?;
    let publica_1 = secreta_1.clave_publica();
    let publica_2 = ClaveSecreta::desde_bytes(&escalar_pequeno(3))?.clave_publica();

    let sigma_1 = firmar(&secreta_1, DOMINIO, MENSAJE)?;
    let delta = firmar(
        &ClaveSecreta::desde_bytes(&escalar_pequeno(2))?,
        DOMINIO,
        MENSAJE,
    )?;
    let sigma_1_prima = agregar_firmas(&[&sigma_1, &delta])?;
    let sigma_2_prima = firmar(
        &ClaveSecreta::desde_bytes(&escalar_pequeno(1))?,
        DOMINIO,
        MENSAJE,
    )?;
    let sigma_2_agregada = FirmaAgregada::desde_firma(&sigma_2_prima);

    let claves_1 = [publica_1];
    let claves_2 = [publica_2];
    let refs_1: Vec<&ClavePublica> = claves_1.iter().collect();
    let refs_2: Vec<&ClavePublica> = claves_2.iter().collect();
    let agregados = [
        AgregadoLote {
            claves: &refs_1,
            firma: &sigma_1_prima,
        },
        AgregadoLote {
            claves: &refs_2,
            firma: &sigma_2_agregada,
        },
    ];

    let iguales = [[0x11; LONGITUD_ESCALAR_LOTE], [0x11; LONGITUD_ESCALAR_LOTE]];
    verificar_lote_de_agregados_con_escalares(&agregados, &iguales, DOMINIO, MENSAJE)?;

    let distintos = [[0x11; LONGITUD_ESCALAR_LOTE], [0x22; LONGITUD_ESCALAR_LOTE]];
    assert_eq!(
        verificar_lote_de_agregados_con_escalares(&agregados, &distintos, DOMINIO, MENSAJE),
        Err(ErrorBLS::VerificacionFallida)
    );
    Ok(())
}

#[test]
fn longitudes_incompatibles_y_lote_vacio_se_rechazan() -> Result<(), Box<dyn std::error::Error>> {
    let (publicas, firma) = agregado_valido(0, 1)?;
    let refs: Vec<&ClavePublica> = publicas.iter().collect();
    let agregados = [AgregadoLote {
        claves: &refs,
        firma: &firma,
    }];
    let un_escalar = [[0u8; LONGITUD_ESCALAR_LOTE]];
    let sin_escalares: [[u8; LONGITUD_ESCALAR_LOTE]; 0] = [];
    let sin_agregados: [AgregadoLote<'_>; 0] = [];

    assert_eq!(
        verificar_lote_de_agregados_con_escalares(&agregados, &sin_escalares, DOMINIO, MENSAJE),
        Err(ErrorBLS::LongitudesLoteIncompatibles {
            claves: 1,
            firmas: 1,
            escalares: 0,
        })
    );
    assert_eq!(
        verificar_lote_de_agregados_con_escalares(&sin_agregados, &sin_escalares, DOMINIO, MENSAJE),
        Err(ErrorBLS::AgregacionVacia)
    );

    let vacio: [&ClavePublica; 0] = [];
    let agregado_vacio = [AgregadoLote {
        claves: &vacio,
        firma: &firma,
    }];
    assert_eq!(
        verificar_lote_de_agregados_con_escalares(&agregado_vacio, &un_escalar, DOMINIO, MENSAJE),
        Err(ErrorBLS::AgregacionVacia)
    );
    Ok(())
}
