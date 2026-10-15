//! PESO-1: diferencial determinista frente al verificador existente y su preparación completa.
use zx_bls::{ClavePublica, ClaveSecreta, ClavesPreparadas, ErrorBLS, FirmaAgregada, firmar};
use zx_votos::peso::{
    CertificadoPeso, construir_certificado, mensaje_voto_peso, verificar_firma_peso,
    verificar_firma_peso_preparada, verificar_firma_peso_selectiva,
};
use zx_votos::{Clave, DOMINIO_VOTO, ErrorVotos, Tabla};

type Fallo = Box<dyn std::error::Error>;
const SEMILLA: u64 = 0x5045_534f_0000_0001;
const TAMANOS: &[usize] = &[
    1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511,
    512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096,
];

fn siguiente(estado: &mut u64) -> u64 {
    *estado = estado.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *estado;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn secreta(indice: u64) -> Result<ClaveSecreta, ErrorBLS> {
    let mut ikm = [0x5a; 32];
    ikm.get_mut(..8)
        .ok_or(ErrorBLS::SemillaCorta(0))?
        .copy_from_slice(&SEMILLA.to_le_bytes());
    ikm.get_mut(8..16)
        .ok_or(ErrorBLS::SemillaCorta(0))?
        .copy_from_slice(&indice.to_le_bytes());
    ClaveSecreta::generar(&ikm)
}

fn tabla(publicas: &[ClavePublica]) -> Tabla {
    Tabla {
        n: 7,
        claves: publicas
            .iter()
            .enumerate()
            .map(|(i, pk)| Clave {
                clave: pk.bytes().to_vec(),
                peso: (i as u64 % 3) + 1,
                activo: !i.is_multiple_of(5),
                prueba: i.is_multiple_of(2),
                garantia: 1,
            })
            .collect(),
    }
}

fn preparadas(tabla: &Tabla) -> Result<ClavesPreparadas, ErrorBLS> {
    ClavesPreparadas::desde_bytes(tabla.claves.iter().map(|c| &c.clave))
}

/// El mismo helper completo que consensus::claves_bls_de_tabla, antes de verificar el mapa.
fn hoy_desde_bytes(tabla: &Tabla, cert: &CertificadoPeso) -> Result<(), ErrorVotos> {
    let claves = tabla
        .claves
        .iter()
        .map(|c| ClavePublica::desde_bytes_con_memoria(&c.clave))
        .collect::<Result<Vec<_>, _>>()?;
    verificar_firma_peso(tabla, &claves, cert)
}

fn comparar(
    tabla: &Tabla,
    claves: &[ClavePublica],
    preparadas: &ClavesPreparadas,
    cert: &CertificadoPeso,
    esperado: Result<(), ErrorVotos>,
) {
    assert_eq!(
        verificar_firma_peso(tabla, claves, cert),
        esperado,
        "oraculo N={}",
        claves.len()
    );
    assert_eq!(
        verificar_firma_peso_selectiva(tabla, cert),
        esperado,
        "selectiva N={}",
        claves.len()
    );
    assert_eq!(
        verificar_firma_peso_preparada(tabla, preparadas, cert),
        esperado,
        "preparada N={}",
        claves.len()
    );
}

#[test]
fn peso1_bateria_semilla_fija_1_a_4096() -> Result<(), Fallo> {
    let secretas = (0..4096).map(secreta).collect::<Result<Vec<_>, _>>()?;
    let todas = secretas
        .iter()
        .map(ClaveSecreta::clave_publica)
        .collect::<Vec<_>>();
    let ajena = secreta(99999)?;
    let mut rng = SEMILLA;
    let mut comprobaciones = 0;
    for &n in TAMANOS {
        let claves = todas.get(..n).ok_or("N")?;
        let tabla = tabla(claves);
        let preparadas = preparadas(&tabla)?;
        assert_eq!(preparadas.claves(), claves);
        for mensaje in 0..2u8 {
            let candidato = [mensaje + 1; 32];
            let h = [0x31; 32];
            let raiz = [0x73; 32];
            let m = mensaje_voto_peso(7, &candidato, &h, &raiz);
            let firmas = secretas
                .get(..n)
                .ok_or("N")?
                .iter()
                .map(|sk| firmar(sk, DOMINIO_VOTO, &m))
                .collect::<Result<Vec<_>, _>>()?;
            let ajena = FirmaAgregada::desde_firma(&firmar(&ajena, DOMINIO_VOTO, &m)?);
            // Permutación determinista: ni claves ni mapas dependen de RNG de sistema.
            let mut orden = (0..n).map(|i| (siguiente(&mut rng), i)).collect::<Vec<_>>();
            orden.sort_unstable();
            for cantidad in [1, n.div_ceil(2), n] {
                let votos = orden
                    .iter()
                    .take(cantidad)
                    .map(|(_, i)| Ok((i + 1, *firmas.get(*i).ok_or("firma")?)))
                    .collect::<Result<Vec<_>, Fallo>>()?;
                let cert = construir_certificado(7, candidato, h, raiz, &tabla, &votos)?;
                comparar(&tabla, claves, &preparadas, &cert, Ok(()));
                comprobaciones += 1;
                for campo in 0..4 {
                    let mut falso = cert.clone();
                    match campo {
                        0 => falso.n += 1,
                        1 => falso.candidato = [0xfe; 32],
                        2 => falso.h_t_siguiente = [0xfe; 32],
                        _ => falso.raiz_estado = [0xfe; 32],
                    }
                    comparar(
                        &tabla,
                        claves,
                        &preparadas,
                        &falso,
                        Err(ErrorVotos::Bls(ErrorBLS::VerificacionFallida)),
                    );
                    comprobaciones += 1;
                }
                let mut falso = cert.clone();
                falso.firma = ajena;
                comparar(
                    &tabla,
                    claves,
                    &preparadas,
                    &falso,
                    Err(ErrorVotos::Bls(ErrorBLS::VerificacionFallida)),
                );
                comprobaciones += 1;
                if cantidad > 1 {
                    falso.firma = construir_certificado(
                        7,
                        candidato,
                        h,
                        raiz,
                        &tabla,
                        votos.get(..cantidad - 1).ok_or("subconjunto")?,
                    )?
                    .firma;
                    comparar(
                        &tabla,
                        claves,
                        &preparadas,
                        &falso,
                        Err(ErrorVotos::Bls(ErrorBLS::VerificacionFallida)),
                    );
                    comprobaciones += 1;
                }
            }
        }
    }
    eprintln!(
        "PESO1 semilla={SEMILLA:#x} tablas={} mensajes=2 densidades=1/mitad/todos casos={comprobaciones} verificadores=3",
        TAMANOS.len()
    );
    Ok(())
}

#[test]
fn peso1_errores_y_precedencia_sobre_tablas_validas() -> Result<(), Fallo> {
    for n in [0usize, 1, 7, 8, 9, 4096] {
        let claves = (0..n)
            .map(|i| Ok(secreta(i as u64)?.clave_publica()))
            .collect::<Result<Vec<_>, ErrorBLS>>()?;
        let tabla = tabla(&claves);
        let preparada = preparadas(&tabla)?;
        let m = mensaje_voto_peso(7, &[1; 32], &[2; 32], &[3; 32]);
        let firma = FirmaAgregada::desde_firma(&firmar(&secreta(0)?, DOMINIO_VOTO, &m)?);
        let mut cert = CertificadoPeso {
            n: 7,
            candidato: [1; 32],
            h_t_siguiente: [2; 32],
            raiz_estado: [3; 32],
            firma,
            mapa: vec![0; n.div_ceil(8)],
        };
        comparar(
            &tabla,
            &claves,
            &preparada,
            &cert,
            Err(ErrorVotos::Bls(ErrorBLS::AgregacionVacia)),
        );
        cert.mapa.push(0xff);
        comparar(
            &tabla,
            &claves,
            &preparada,
            &cert,
            Err(ErrorVotos::LongitudInesperada {
                esperado: n.div_ceil(8),
                obtenido: n.div_ceil(8) + 1,
            }),
        );
        cert.mapa.pop();
        if n > 0 && !n.is_multiple_of(8) {
            *cert.mapa.last_mut().ok_or("mapa")? |= 0x80;
            comparar(
                &tabla,
                &claves,
                &preparada,
                &cert,
                Err(ErrorVotos::ClaveNoRegistrada),
            );
        }
        let vacia = ClavesPreparadas::desde_bytes(std::iter::empty::<&[u8]>())?;
        if n > 0 {
            assert_eq!(
                verificar_firma_peso_preparada(&tabla, &vacia, &cert),
                verificar_firma_peso(&tabla, &[], &cert)
            );
            assert_eq!(
                verificar_firma_peso_preparada(&tabla, &vacia, &cert),
                Err(ErrorVotos::LongitudesIncompatibles {
                    claves: 0,
                    plazas: n
                })
            );
        }
    }
    Ok(())
}

#[test]
fn peso1_suma_infinita_mismo_error() -> Result<(), Fallo> {
    let pk = secreta(0)?.clave_publica();
    let mut negada = pk.bytes();
    *negada.first_mut().ok_or("clave")? ^= 0x20;
    let claves = [pk, ClavePublica::desde_bytes(&negada)?];
    let tabla = tabla(&claves);
    let preparada = preparadas(&tabla)?;
    let m = mensaje_voto_peso(7, &[1; 32], &[2; 32], &[3; 32]);
    let firma = firmar(&secreta(0)?, DOMINIO_VOTO, &m)?;
    let cert = CertificadoPeso {
        n: 7,
        candidato: [1; 32],
        h_t_siguiente: [2; 32],
        raiz_estado: [3; 32],
        firma: FirmaAgregada::desde_firma(&firma),
        mapa: vec![3],
    };
    comparar(
        &tabla,
        &claves,
        &preparada,
        &cert,
        Err(ErrorVotos::Bls(ErrorBLS::VerificacionFallida)),
    );
    Ok(())
}

#[test]
fn peso1_clave_invalida_no_firmante_y_precedencia() -> Result<(), Fallo> {
    let pk = secreta(0)?.clave_publica();
    let valida = tabla(&[pk, secreta(1)?.clave_publica()]);
    let m = mensaje_voto_peso(7, &[1; 32], &[2; 32], &[3; 32]);
    let cert = construir_certificado(
        7,
        [1; 32],
        [2; 32],
        [3; 32],
        &valida,
        &[(1, firmar(&secreta(0)?, DOMINIO_VOTO, &m)?)],
    )?;
    let subgrupo = hex::decode(
        "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )?;
    let mut infinito = vec![0; 48];
    *infinito.first_mut().ok_or("infinito")? = 0xc0;
    for bytes in [vec![0; 47], vec![0; 48], infinito, subgrupo] {
        let mut invalida = valida.clone();
        invalida.claves.get_mut(1).ok_or("clave")?.clave = bytes.clone();
        let error = ClavePublica::desde_bytes(&bytes)
            .err()
            .ok_or("debe ser invalida")?;
        assert_eq!(
            hoy_desde_bytes(&invalida, &cert),
            Err(ErrorVotos::Bls(error.clone()))
        );
        assert_eq!(preparadas(&invalida).err(), Some(error.clone()));
        verificar_firma_peso_selectiva(&invalida, &cert)?;
        let mut firmado = cert.clone();
        firmado.mapa = vec![3];
        assert_eq!(
            verificar_firma_peso_selectiva(&invalida, &firmado),
            Err(ErrorVotos::Bls(error.clone()))
        );
        let mut fuera = cert.clone();
        fuera.mapa = vec![0x81];
        assert_eq!(
            hoy_desde_bytes(&invalida, &fuera),
            Err(ErrorVotos::Bls(error.clone()))
        );
        assert_eq!(
            verificar_firma_peso_selectiva(&invalida, &fuera),
            Err(ErrorVotos::ClaveNoRegistrada)
        );
        let mut vacio = cert.clone();
        vacio.mapa.fill(0);
        assert_eq!(
            hoy_desde_bytes(&invalida, &vacio),
            Err(ErrorVotos::Bls(error.clone()))
        );
        assert_eq!(
            verificar_firma_peso_selectiva(&invalida, &vacio),
            Err(ErrorVotos::Bls(ErrorBLS::AgregacionVacia))
        );
        vacio.mapa.push(0);
        assert_eq!(
            hoy_desde_bytes(&invalida, &vacio),
            Err(ErrorVotos::Bls(error))
        );
        assert_eq!(
            verificar_firma_peso_selectiva(&invalida, &vacio),
            Err(ErrorVotos::LongitudInesperada {
                esperado: 1,
                obtenido: 2
            })
        );
    }
    Ok(())
}

/// Fixture producida por zx-bls::clave::pruebas_peso1_subgrupo: pk_a+Q y pk_b-Q,
/// ambas fuera del subgrupo. Su suma es pk_a+pk_b: validar solo la suma sería insuficiente.
#[test]
fn peso1_firmantes_fuera_subgrupo_con_torsion_cancelada_se_rechazan() -> Result<(), Fallo> {
    let mut tabla = tabla(&[
        ClaveSecreta::generar(&[0x61; 32])?.clave_publica(),
        ClaveSecreta::generar(&[0x62; 32])?.clave_publica(),
    ]);
    let m = mensaje_voto_peso(7, &[1; 32], &[2; 32], &[3; 32]);
    let cert = construir_certificado(
        7,
        [1; 32],
        [2; 32],
        [3; 32],
        &tabla,
        &[
            (
                1,
                firmar(&ClaveSecreta::generar(&[0x61; 32])?, DOMINIO_VOTO, &m)?,
            ),
            (
                2,
                firmar(&ClaveSecreta::generar(&[0x62; 32])?, DOMINIO_VOTO, &m)?,
            ),
        ],
    )?;
    for (clave, hex) in tabla.claves.iter_mut().zip([
        "931192eb3aafbd3a4ba776147132a606ba94e8a514d80852d2baf8017169433e1725d90339d74a9dca0a5489bd7d83c8",
        "81740d0b015b7566a810bb52cd483fc5a588b521fa7398bf826871e9ce42760892f247913ed3e5d512c1d529678f8724",
    ]) { clave.clave = hex::decode(hex)?; }
    let esperado = Err(ErrorVotos::Bls(ErrorBLS::ClaveInvalida {
        motivo: "el punto no esta en el subgrupo",
    }));
    assert_eq!(verificar_firma_peso_selectiva(&tabla, &cert), esperado);
    assert_eq!(hoy_desde_bytes(&tabla, &cert), esperado);
    assert_eq!(
        preparadas(&tabla).err(),
        Some(ErrorBLS::ClaveInvalida {
            motivo: "el punto no esta en el subgrupo"
        })
    );
    Ok(())
}
