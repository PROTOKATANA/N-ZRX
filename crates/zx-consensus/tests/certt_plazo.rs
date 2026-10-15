//! CERT-T: frontera inclusiva en aplicación estricta, fusión, rearranque y repetición.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "fixtures deterministas y aserciones de pruebas"
)]
use ed25519_zebra::SigningKey;
use zx_consensus::sectores::{ClaveVoto, Etapa, ParametrosSector, RegistroSector, SectorId};
use zx_consensus::transicion::votos::{
    W_REVEAL_SLOTS_VOTOS, apertura_ventana, aplicar_certificado_peso_con_undo,
    calendario_rearranque, cierre_ventana, derivar_tabla_sin_base_con_undo,
    tomar_instantaneas_rearranque_con_undo,
};
use zx_consensus::transicion::{
    BloqueTransicion, ErrorTransicion, Estado, Fase, Garantia, HechosCabecera, ParametrosEvidencia,
    ParametrosTransicion, Punto, aplicar_con_undo, aplicar_fusion, deshacer,
};
use zx_core::{Amount, BlockHash, ClavePublica, Digest, ExtensionTx, OperacionAlmacenamiento, Tx};
use zx_votos::{Clave, ClaveSecreta, DOMINIO_VOTO, Tabla};
type Error = Box<dyn std::error::Error>;
fn hash(i: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([i; 32]))
}
fn ed() -> ClavePublica {
    ClavePublica::desde_bytes(SigningKey::from([7; 32]).verification_key().into())
}
fn params() -> ParametrosTransicion {
    ParametrosTransicion {
        h_dep: 0,
        m_cb: 1,
        m_dep: 1,
        h_corte_min: 0,
        w_min: primitive_types::U256::zero(),
        s_min: Amount::CERO,
        q: Amount::CERO,
        k_min: 0,
        max_tx_bytes: 300_000,
        max_cuerpo_bloque_bytes: 320_000,
        m_res_slots: 1,
        m_dep_slots: 1,
        m_rec_slots: 1,
        r_slots: 600,
        f_slots: Some(600),
        subsidio_pow: |_| Amount::CERO,
        subsidio_post: |_| Amount::CERO,
    }
}
fn escenario(n: u64, con_base: bool) -> Result<(Estado, ClaveSecreta), Error> {
    let sk = ClaveSecreta::generar(&[9; 32])?;
    let mut estado = Estado::inicial();
    estado.fase = Fase::PoST;
    estado.parametros_sector = ParametrosSector::dev();
    estado.claves_voto.insert(
        ed(),
        ClaveVoto {
            clave_bls: sk.clave_publica().bytes(),
            prueba_posesion: zx_votos::probar_posesion(&sk).bytes(),
        },
    );
    let mut garantia = Garantia::nueva();
    garantia.activo = Amount::nuevo(1_000_000)?;
    estado.garantias.insert(ed(), garantia);
    let id = SectorId {
        clave: ed(),
        sector_index: 0,
        version: 0,
    };
    estado.sectores.insert(
        id,
        RegistroSector {
            id,
            r2: [0; 4],
            history_size: 1,
            etapa: Etapa::Activo,
            alta_slot: 0,
            renovacion_slot: 10_000,
            retiro_slot: -1,
            fianza: estado.parametros_sector.q_sec,
            aud_apertura: -1,
            aud_contestada: -1,
        },
    );
    let (mut estado, _) = derivar_tabla_sin_base_con_undo(&estado, apertura_ventana(n));
    let h = estado.cola_tablas_voto.last().ok_or("cola vacía")?.1;
    if con_base {
        estado.finalidad_votos = Some(hash(1));
        estado.finalidad_votos_n = 0;
        estado.finalidad_votos_h_t = Some(h);
        estado
            .tablas_voto
            .insert(0, estado.tablas_voto_contenido[&h].clone());
        estado.liquidacion_voto_hasta = Some(0);
    }
    Ok((estado, sk))
}
fn certificado(
    estado: &Estado,
    sk: &ClaveSecreta,
    n: u64,
) -> Result<OperacionAlmacenamiento, Error> {
    let h_siguiente = estado.cola_tablas_voto.last().ok_or("cola vacía")?.1;
    let h = if let Some(cal) =
        calendario_rearranque(&estado.parametros_sector, estado.finalidad_votos_n)
        && let Some(j) = cal.ciclo_de_apertura(apertura_ventana(n))
        && let Some(h) = estado.tabla_ciclo_rearranque.get(&j)
    {
        *h
    } else {
        estado.finalidad_votos_h_t.unwrap_or(h_siguiente)
    };
    let tabla = Tabla {
        n,
        claves: estado.tablas_voto_contenido[&h]
            .iter()
            .map(|c| Clave {
                clave: c.clave_bls.to_vec(),
                peso: c.peso,
                activo: c.activo,
                prueba: c.prueba,
                garantia: c.garantia,
            })
            .collect(),
    };
    let candidato = *hash(2).as_bytes();
    let raiz = [0xC7; 32];
    let firma = zx_votos::firmar(
        sk,
        DOMINIO_VOTO,
        &zx_votos::mensaje_voto_peso(n, &candidato, &h_siguiente, &raiz),
    )?;
    let cert =
        zx_votos::construir_certificado(n, candidato, h_siguiente, raiz, &tabla, &[(1, firma)])?;
    Ok(OperacionAlmacenamiento::CertificadoPeso {
        clave: ed(),
        bytes: zx_votos::serial_certificado_peso(&cert),
    })
}
fn bloque(op: OperacionAlmacenamiento, slot: u64) -> BloqueTransicion {
    let tx = Tx {
        version: 6,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::PruebaAlmacenamiento { operacion: op },
    };
    let firma = SigningKey::from([7; 32]).sign(&zx_core::mensaje_almacenamiento(&tx, 0));
    BloqueTransicion::nuevo(
        HechosCabecera::PoST {
            hash: hash(3),
            padre: hash(1),
            slot,
            productor: ed(),
            peso: 1,
            prueba_valida: true,
            requisito_declarado: 0,
        },
        vec![(tx, vec![<[u8; 64]>::from(firma).to_vec()])],
    )
}
fn limite(n: u64) -> u64 {
    cierre_ventana(n).saturating_add(W_REVEAL_SLOTS_VOTOS)
}

#[test]
fn certt_invariancia_bloques_dentro_del_plazo() -> Result<(), Error> {
    for con_base in [false, true] {
        let (mut estado, sk) = escenario(2, con_base)?;
        for n in 2..=12 {
            let slot = apertura_ventana(n);
            let op = certificado(&estado, &sk, n)?;
            let b = bloque(op, slot);
            let (estricto, undo) =
                aplicar_con_undo(&estado, &b, &params(), 0, &ParametrosEvidencia::inactiva())?;
            assert_eq!(deshacer(&estricto, &undo), estado);
            let (fusion, undo, descartes) = aplicar_fusion(
                &estado,
                &b,
                Punto::Slot(slot),
                &params(),
                0,
                &ParametrosEvidencia::inactiva(),
            )?;
            assert!(descartes.is_empty());
            assert_eq!(deshacer(&fusion, &undo), estado);
            assert_eq!(estricto.raiz_estado, Some([0xC7; 32]));
            assert_eq!(fusion.raiz_estado, estricto.raiz_estado);
            println!("CERTT_ESTADO {con_base} {n} estricto {estricto:?}");
            println!("CERTT_ESTADO {con_base} {n} fusion {fusion:?}");
            estado = estricto;
        }
    }
    Ok(())
}

#[test]
fn certt_frontera_normal_con_y_sin_base() -> Result<(), Error> {
    for con_base in [false, true] {
        let n = 2;
        let (estado, sk) = escenario(n, con_base)?;
        let op = certificado(&estado, &sk, n)?;
        let (admitido, undo, r) =
            aplicar_certificado_peso_con_undo(&estado, &op, i64::try_from(limite(n))?);
        r?;
        assert_eq!(admitido.finalidad_votos_n, n);
        assert_eq!(deshacer(&admitido, &undo), estado);
        let b = bloque(op.clone(), limite(n));
        let (admitido, undo) =
            aplicar_con_undo(&estado, &b, &params(), 0, &ParametrosEvidencia::inactiva())?;
        assert_eq!(admitido.finalidad_votos_n, n);
        assert_eq!(deshacer(&admitido, &undo), estado);
        let (rechazado, undo, r) =
            aplicar_certificado_peso_con_undo(&estado, &op, i64::try_from(limite(n) + 1)?);
        assert_eq!(r, Err(ErrorTransicion::ErrCertificadoPlazo));
        assert_eq!(rechazado, estado);
        assert_eq!(deshacer(&rechazado, &undo), estado);
        let b = bloque(op, limite(n) + 1);
        assert_eq!(
            aplicar_con_undo(&estado, &b, &params(), 0, &ParametrosEvidencia::inactiva()),
            Err(ErrorTransicion::ErrCertificadoPlazo)
        );
    }
    Ok(())
}

#[test]
fn certt_frontera_fusion_usa_punto_aplicacion() -> Result<(), Error> {
    for con_base in [false, true] {
        let n = 2;
        let (estado, sk) = escenario(n, con_base)?;
        let op = certificado(&estado, &sk, n)?;
        // El bloque nació a tiempo: el plazo se decide en el punto donde se fusiona.
        let b = bloque(op, apertura_ventana(n));
        let (admitido, undo, descartes) = aplicar_fusion(
            &estado,
            &b,
            Punto::Slot(limite(n)),
            &params(),
            0,
            &ParametrosEvidencia::inactiva(),
        )?;
        assert!(descartes.is_empty());
        assert_eq!(admitido.finalidad_votos_n, n);
        assert_eq!(deshacer(&admitido, &undo), estado);
        let (rechazado, undo, descartes) = aplicar_fusion(
            &estado,
            &b,
            Punto::Slot(limite(n) + 1),
            &params(),
            0,
            &ParametrosEvidencia::inactiva(),
        )?;
        assert_eq!(descartes.len(), 1);
        assert_eq!(descartes[0].indice, 0);
        assert_eq!(descartes[0].motivo, ErrorTransicion::ErrCertificadoPlazo);
        assert_eq!(rechazado.finalidad_votos, estado.finalidad_votos);
        assert_eq!(rechazado.raiz_estado, estado.raiz_estado);
        assert_eq!(deshacer(&rechazado, &undo), estado);
    }
    Ok(())
}

#[test]
fn certt_repetido_dentro_y_fuera_normal_y_fusion() -> Result<(), Error> {
    let n = 2;
    let (estado, sk) = escenario(n, false)?;
    let op = certificado(&estado, &sk, n)?;
    let (estado, _, r) =
        aplicar_certificado_peso_con_undo(&estado, &op, i64::try_from(apertura_ventana(n))?);
    r?;
    let (repetido, _, r) =
        aplicar_certificado_peso_con_undo(&estado, &op, i64::try_from(limite(n))?);
    r?;
    assert_eq!(repetido, estado);
    let (rechazado, _, r) =
        aplicar_certificado_peso_con_undo(&estado, &op, i64::try_from(limite(n) + 1)?);
    assert_eq!(r, Err(ErrorTransicion::ErrCertificadoPlazo));
    assert_eq!(rechazado, estado);
    let b = bloque(op.clone(), apertura_ventana(n));
    for (slot, vencido) in [(limite(n), false), (limite(n) + 1, true)] {
        let estricto = aplicar_con_undo(
            &estado,
            &bloque(op.clone(), slot),
            &params(),
            0,
            &ParametrosEvidencia::inactiva(),
        );
        if vencido {
            assert_eq!(estricto, Err(ErrorTransicion::ErrCertificadoPlazo));
        } else {
            let (post, undo) = estricto?;
            assert_eq!(post.finalidad_votos, estado.finalidad_votos);
            assert_eq!(post.raiz_estado, estado.raiz_estado);
            assert_eq!(deshacer(&post, &undo), estado);
        }
        let (post, undo, descartes) = aplicar_fusion(
            &estado,
            &b,
            Punto::Slot(slot),
            &params(),
            0,
            &ParametrosEvidencia::inactiva(),
        )?;
        assert_eq!(descartes.len(), usize::from(vencido));
        if vencido {
            assert_eq!(descartes[0].motivo, ErrorTransicion::ErrCertificadoPlazo);
        }
        assert_eq!(post.finalidad_votos, estado.finalidad_votos);
        assert_eq!(post.raiz_estado, estado.raiz_estado);
        assert_eq!(deshacer(&post, &undo), estado);
    }
    Ok(())
}

#[test]
fn certt_rearranque_dentro_y_fuera_normal_y_fusion() -> Result<(), Error> {
    let (estado, sk) = escenario(0, true)?;
    let cal = calendario_rearranque(&estado.parametros_sector, 0).ok_or("sin calendario")?;
    let (estado, _) = tomar_instantaneas_rearranque_con_undo(&estado, cal.referencia(0) + 1);
    let n = cal
        .inicio(0)
        .div_ceil(zx_consensus::transicion::votos::T_INST_VOTOS);
    let (estado, _) = derivar_tabla_sin_base_con_undo(&estado, apertura_ventana(n));
    let op = certificado(&estado, &sk, n)?;
    let (admitido, _, r) =
        aplicar_certificado_peso_con_undo(&estado, &op, i64::try_from(limite(n))?);
    r?;
    assert_eq!(admitido.finalidad_votos_n, n);
    assert!(admitido.tabla_ciclo_rearranque.is_empty());
    let b = bloque(op.clone(), apertura_ventana(n));
    let (admitido, undo) = aplicar_con_undo(
        &estado,
        &bloque(op.clone(), apertura_ventana(n) + 1),
        &params(),
        0,
        &ParametrosEvidencia::inactiva(),
    )?;
    assert_eq!(admitido.finalidad_votos_n, n);
    assert_eq!(deshacer(&admitido, &undo), estado);
    assert_eq!(
        aplicar_con_undo(
            &estado,
            &bloque(op.clone(), limite(n) + 1),
            &params(),
            0,
            &ParametrosEvidencia::inactiva(),
        ),
        Err(ErrorTransicion::ErrCertificadoPlazo)
    );
    let (admitido, undo, descartes) = aplicar_fusion(
        &estado,
        &b,
        Punto::Slot(apertura_ventana(n) + 1),
        &params(),
        0,
        &ParametrosEvidencia::inactiva(),
    )?;
    assert!(descartes.is_empty());
    assert_eq!(admitido.finalidad_votos_n, n);
    assert_eq!(deshacer(&admitido, &undo), estado);
    let (rechazado, _, r) =
        aplicar_certificado_peso_con_undo(&estado, &op, i64::try_from(limite(n) + 1)?);
    assert_eq!(r, Err(ErrorTransicion::ErrCertificadoPlazo));
    assert_eq!(rechazado, estado);
    let (rechazado, undo, descartes) = aplicar_fusion(
        &estado,
        &b,
        Punto::Slot(limite(n) + 1),
        &params(),
        0,
        &ParametrosEvidencia::inactiva(),
    )?;
    assert_eq!(descartes.len(), 1);
    assert_eq!(descartes[0].motivo, ErrorTransicion::ErrCertificadoPlazo);
    assert_eq!(rechazado.finalidad_votos, estado.finalidad_votos);
    assert_eq!(deshacer(&rechazado, &undo), estado);
    Ok(())
}

#[test]
fn certt_plazo_precede_conflicto_retroceso_y_tabla() -> Result<(), Error> {
    let (mut estado, sk) = escenario(2, false)?;
    let op = certificado(&estado, &sk, 2)?;
    estado.finalidad_votos_n = 3;
    estado.finalidad_votos_h_t = Some([0; 32]);
    let (_, _, r) = aplicar_certificado_peso_con_undo(&estado, &op, i64::try_from(limite(2) + 1)?);
    assert_eq!(r, Err(ErrorTransicion::ErrCertificadoPlazo));
    let (_, _, r) =
        aplicar_certificado_peso_con_undo(&estado, &op, i64::try_from(apertura_ventana(2) - 1)?);
    assert_eq!(r, Err(ErrorTransicion::ErrCertificadoVentanaFutura));
    assert_eq!(
        ErrorTransicion::ErrCertificadoPlazo.nombre_t01(),
        "ErrCertificadoPlazo"
    );
    assert_eq!(
        ErrorTransicion::ErrCertificadoPlazo.to_string(),
        "ErrCertificadoPlazo"
    );
    Ok(())
}

#[test]
fn certt_suma_saturada_ventanas_enormes() -> Result<(), Error> {
    for n in [
        u64::MAX,
        u64::MAX.div_euclid(2),
        (u64::MAX - W_REVEAL_SLOTS_VOTOS).div_euclid(2),
    ] {
        assert_eq!(limite(n), u64::MAX);
        let (estado, sk) = escenario(2, false)?;
        let op = certificado(&estado, &sk, n)?;
        let (post, _, r) = aplicar_certificado_peso_con_undo(&estado, &op, i64::MAX);
        assert_eq!(r, Err(ErrorTransicion::ErrCertificadoVentanaFutura));
        assert_eq!(post, estado);
        // El adaptador i64 convierte -1 a u64::MAX: cubre la suma saturada sin fabricar
        // un slot de cadena (que no puede representar este punto). La siguiente guarda
        // del contrato puede rechazar, pero nunca el plazo por desbordamiento.
        let (_, _, r) = aplicar_certificado_peso_con_undo(&estado, &op, -1);
        assert_ne!(r, Err(ErrorTransicion::ErrCertificadoPlazo));
    }
    Ok(())
}
