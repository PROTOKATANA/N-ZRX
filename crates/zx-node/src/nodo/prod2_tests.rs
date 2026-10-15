// PROD-2: estos tests comparten los fixtures del armado real CAR-PROD.
mod prod2 {
    use super::*;
    use zx_consensus::transicion::ErrorTransicion;
    use zx_post::productor_regimen::{CuerpoProductor, ErrorRegimen, preparar_regimen_para_ensayo};

    fn candidata_real(nodo: &Nodo, desde: u64) -> (BloqueDag, u64) {
        candidata_de_clave(nodo, &nodo.claves[0], desde)
    }

    fn candidata_de_clave(nodo: &Nodo, c: &ClaveDev, desde: u64) -> (BloqueDag, u64) {
        let parcela = abrir_o_crear_parcela(&nodo.dir_datos, c, &nodo.historia)
            .expect("fixture PROD-2 válido");
        let fuente = FuenteTransicion {
            parcela: &parcela,
            historia: &nodo.historia,
        };
        let terminal = nodo.cadena.terminal().expect("fixture PROD-2 válido");
        let padres = padres_de_regimen(&nodo.cadena).expect("fixture PROD-2 válido");
        let mut servicio =
            ServicioPot::nuevo(terminal, nodo.n_dev, 512).expect("fixture PROD-2 válido");
        let padres_vec: Vec<_> = std::iter::once(padres.seleccionado())
            .chain(padres.extras().iter().copied())
            .collect();
        let max_slot = padres_vec
            .iter()
            .filter_map(|p| nodo.cadena.bloque(p).and_then(BloqueCadena::slot))
            .max()
            .unwrap_or(0);
        servicio
            .avanzar_hasta(max_slot)
            .expect("fixture PROD-2 válido");
        for p in padres_vec {
            if let Some(s) = nodo.cadena.bloque(&p).and_then(BloqueCadena::slot) {
                servicio
                    .registrar_validado(p, s)
                    .expect("fixture PROD-2 válido");
            }
        }
        let params = ParametrosProductor {
            n_dev: nodo.n_dev,
            sr_dev: nodo.sr_dev_actual,
            max_slots: 150,
            consensus_branch_id: nodo.cbid,
            timestamp: 1,
            i_iter: 0,
            importe_coinbase: perfil::subsidio_post(0),
        };
        for slot in desde..desde + 64 {
            match preparar_regimen_para_ensayo(
                padres,
                slot,
                &mut servicio,
                &fuente,
                &c.sk,
                &params,
                CuerpoProductor::vacio(),
            ) {
                Ok(b) => {
                    let distancia = zx_poas::verificar_solucion_poas(
                        &b.cabecera.sol,
                        b.cabecera.slot,
                        b.cabecera.pot_output,
                        b.cabecera.rango_solucion,
                        &nodo.historia.params_pieza(),
                    )
                    .expect("fixture PROD-2 válido");
                    return (b, distancia);
                }
                Err(ErrorRegimen::SinSolucion { .. }) => {}
                Err(e) => panic!("preparación real: {e}"),
            }
        }
        panic!("no hubo solución real dentro de 64 slots");
    }

    fn con_cuerpo(base: &BloqueDag, pares: Vec<TxTestigos>) -> BloqueDag {
        let mut todas = vec![(base.txs()[0].clone(), base.testigos()[0].clone())];
        todas.extend(pares);
        recomponer_candidata_post(base, todas).expect("fixture PROD-2 válido")
    }

    fn huella_cola(nodo: &Nodo) -> Vec<u8> {
        let m = nodo.mempool.lock().expect("fixture PROD-2 válido");
        let mut salida = Vec::new();
        for (tx, tst) in m.seleccionar(u64::MAX, 42) {
            zx_core::wire::tx_a_bytes(&mut salida, &tx, &tst);
        }
        salida
    }

    fn huella_motor(nodo: &Nodo) -> String {
        let m = nodo.motor_votos.as_ref().expect("fixture PROD-2 válido");
        format!(
            "{:?}|{:?}",
            m.certificados_peso(),
            m.ultimo_certificado_peso()
        )
    }

    pub(super) fn depurar_dgacta(nodo: &Nodo, cuerpo: Vec<TxTestigos>) -> (Vec<TxTestigos>, u64) {
        let (base, distancia) = candidata_real(nodo, 14);
        let dep = depurar_candidata_post(
            &nodo.cadena,
            &con_cuerpo(&base, cuerpo),
            distancia,
            nodo.params.max_cuerpo_bloque_bytes,
        )
        .expect("fixture PROD-2 válido");
        assert_eq!(dep.retiradas.len(), 1);
        assert_eq!(dep.retiradas[0].motivo, ErrorTransicion::ErrActaRepetida);
        assert!(!dep.respaldo);
        (
            dep.candidata
                .txs()
                .iter()
                .cloned()
                .zip(dep.candidata.testigos().iter().cloned())
                .skip(1)
                .collect(),
            dep.candidata.cabecera.slot,
        )
    }

    fn pago(estado: &mut EstadoTransicion, id: u8, salida: i64) -> TxTestigos {
        let c = ClaveDev::derivar(1, 0);
        let op = OutPoint {
            prev_txid: TxId::from_digest(Digest::from_bytes([id; 32])),
            prev_index: 0,
        };
        estado.utxo.insert(
            op,
            EntradaUtxo {
                valor: Amount::nuevo(100).expect("fixture PROD-2 válido"),
                lock: Lock::PubKey { pubkey: c.pk },
                origen: Origen::Tx,
                creada: Punto::Altura(0),
            },
        );
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                outpoint: op,
                sequence: 0,
            }],
            outputs: vec![TxOut {
                value: Amount::nuevo(salida).expect("fixture PROD-2 válido"),
                lock: Lock::PubKey { pubkey: c.pk },
            }],
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Ninguna,
        };
        let digest = zx_core::sighash(
            &tx,
            &[SpentOutput {
                value: Amount::nuevo(100).expect("fixture PROD-2 válido"),
                lock: Lock::PubKey { pubkey: c.pk },
            }],
            HashType::All,
            0,
            zx_core::CBID_RED_DEV,
        )
        .expect("fixture PROD-2 válido");
        let firma: [u8; 64] = c.sk.sign(digest.as_bytes()).into();
        (tx, vec![firma.to_vec()])
    }

    fn aleatorio(semilla: &mut u64) -> u64 {
        *semilla ^= *semilla << 13;
        *semilla ^= *semilla >> 7;
        *semilla ^= *semilla << 17;
        *semilla
    }

    fn relleno_al_tope(estado: &mut EstadoTransicion) -> Vec<TxTestigos> {
        let c = ClaveDev::derivar(1, 0);
        let coinbase = tx_coinbase_post(c.pk, perfil::SUBSIDIO_POST_BREK, 2);
        let presupuesto = perfil::MAX_CUERPO_BLOQUE_BYTES - bytes(&(coinbase, Vec::new()));
        let mut pares = relleno(estado);
        let anteriores: u64 = pares.iter().take(3).map(bytes).sum();
        let ultimo = pares.last_mut().expect("fixture PROD-2 válido");
        for salida in &mut ultimo.0.outputs {
            salida.lock = Lock::PubKey { pubkey: c.pk };
        }
        while anteriores + bytes(ultimo) <= presupuesto {
            ultimo.0.outputs.push(TxOut {
                value: Amount::nuevo(1).expect("fixture PROD-2 válido"),
                lock: Lock::PubKey { pubkey: c.pk },
            });
        }
        ultimo.0.outputs.pop().expect("fixture PROD-2 válido");
        let mut hueco = presupuesto - anteriores - bytes(ultimo);
        if !hueco.is_multiple_of(2) {
            ultimo.0.outputs.pop().expect("fixture PROD-2 válido");
            hueco = presupuesto - anteriores - bytes(ultimo);
        }
        for salida in ultimo
            .0
            .outputs
            .iter_mut()
            .take(usize::try_from(hueco.div_euclid(2)).expect("fixture PROD-2 válido"))
        {
            salida.lock = Lock::multisig(1, vec![c.pk]).expect("fixture PROD-2 válido");
        }
        let valor =
            Amount::nuevo(i64::try_from(ultimo.0.outputs.len()).expect("fixture PROD-2 válido"))
                .expect("fixture PROD-2 válido");
        estado
            .utxo
            .get_mut(&ultimo.0.inputs[0].outpoint)
            .expect("fixture PROD-2 válido")
            .valor = valor;
        let digest = zx_core::sighash(
            &ultimo.0,
            &[SpentOutput {
                value: valor,
                lock: Lock::PubKey { pubkey: c.pk },
            }],
            HashType::All,
            0,
            zx_core::CBID_RED_DEV,
        )
        .expect("fixture PROD-2 válido");
        let firma: [u8; 64] = c.sk.sign(digest.as_bytes()).into();
        ultimo.1 = vec![firma.to_vec()];
        assert_eq!(pares.iter().map(bytes).sum::<u64>(), presupuesto);
        assert!(pares.iter().all(|p| bytes(p) <= perfil::MAX_TX_BYTES));
        pares
    }

    #[test]
    fn prod2_cuerpo_en_el_tope_sigue_en_el_tope_tras_ensayar() {
        let dir = tempfile::tempdir().expect("fixture PROD-2 válido");
        let mut estado = estado_inicial(3);
        let pagos = relleno_al_tope(&mut estado);
        let nodo = nodo(dir.path(), estado);
        let (base, distancia) = candidata_real(&nodo, 2);
        let candidata = con_cuerpo(&base, pagos);
        let dep = depurar_candidata_post(
            &nodo.cadena,
            &candidata,
            distancia,
            nodo.params.max_cuerpo_bloque_bytes,
        )
        .expect("fixture PROD-2 válido");
        assert!(dep.retiradas.is_empty());
        assert_eq!(dep.bytes_finales, nodo.params.max_cuerpo_bloque_bytes);
        assert_eq!(dep.candidata.txs(), candidata.txs());
    }

    #[test]
    #[ignore = "medida release con 1024 claves bajo candado exclusivo y perf"]
    fn prod2_coste_release_tabla_1024() {
        if cfg!(debug_assertions) {
            panic!("la medida exige release");
        }
        assert_eq!(
            std::env::var("PROD2_MEDIR").expect("fixture PROD-2 válido"),
            "1"
        );
        let dir = tempfile::tempdir().expect("fixture PROD-2 válido");
        let mut estado = estado_inicial(1024);
        let pagos = relleno_al_tope(&mut estado);
        let nodo = nodo(dir.path(), estado);
        let (vacio, distancia) = candidata_real(&nodo, 2);
        let lleno = con_cuerpo(&vacio, pagos);
        assert_eq!(
            tabla_peso_para_bloque(
                nodo.cadena
                    .estado_post(&hash_u32(31))
                    .expect("fixture PROD-2 válido"),
                vacio.cabecera.slot,
                0
            )
            .claves
            .len(),
            1024
        );
        for (nombre, candidata) in [("vacio", vacio), ("lleno", lleno)] {
            let ensayo = || {
                let dep = depurar_candidata_post(
                    &nodo.cadena,
                    &candidata,
                    distancia,
                    nodo.params.max_cuerpo_bloque_bytes,
                )
                .expect("fixture PROD-2 válido");
                // Incluye la puerta final de firmar_post_ensayado, excluye eventos y sello.
                let (_, d) = nodo
                    .cadena
                    .ensayar_post(
                        &post_de_candidata(&dep.candidata, distancia)
                            .expect("fixture PROD-2 válido"),
                    )
                    .expect("fixture PROD-2 válido");
                assert!(d.is_empty());
                assert!(dep.retiradas.is_empty());
                dep
            };
            let comprobacion = ensayo();
            if nombre == "lleno" {
                assert_eq!(
                    comprobacion.bytes_finales,
                    nodo.params.max_cuerpo_bloque_bytes
                );
            }
            let mut tiempos = [0_u128; 5];
            for (rep, tiempo) in tiempos.iter_mut().enumerate() {
                let inicio = Instant::now();
                let resultado = std::hint::black_box(ensayo());
                *tiempo = inicio.elapsed().as_nanos();
                println!(
                    "PROD2_MEDIDA cuerpo={nombre} rep={rep} ns={tiempo} claves=1024 bytes={} vueltas={} perfil=release ensayos=3",
                    resultado.bytes_finales, resultado.vueltas
                );
            }
            tiempos.sort_unstable();
            println!(
                "PROD2_RESUMEN cuerpo={nombre} min_ns={} mediana_ns={} max_ns={} replicas=5",
                tiempos[0], tiempos[2], tiempos[4]
            );
        }
    }

    #[test]
    fn prod2_propiedad_candidatas_reales_mezcladas_y_control_rojo() {
        const SEMILLA: u64 = 0x5052_4f44_3200_0001;
        let dir = tempfile::tempdir().expect("fixture PROD-2 válido");
        let mut est = estado_inicial(3);
        let p1 = pago(&mut est, 0xA0, 90);
        let p2 = pago(&mut est, 0xA1, 90);
        let conflicto = pago(&mut est, 0xA0, 80);
        let mut mala = pago(&mut est, 0xA2, 90);
        mala.1[0][0] ^= 1;
        let mut nodo = nodo(dir.path(), est);
        let cert = certificado(&mut nodo);
        let reportero = nodo.claves[0].clone();
        let cbid = nodo.cbid;
        aplicar_cuerpo(
            &mut nodo,
            32,
            2,
            vec![crate::votos::tx_certificado_peso(
                &cert,
                reportero.pk,
                &reportero.sk,
                cbid,
            )],
        )
        .expect("fixture PROD-2 válido");
        let mut motor = dgacta::motor_abierto(&nodo, cert.clone(), true);
        let acta = motor
            .cerrar()
            .expect("fixture PROD-2 válido")
            .acta_peso
            .expect("fixture PROD-2 válido");
        let otro = ClaveDev::derivar(1, 2);
        let a1 = crate::votos::tx_acta_presencia(&acta, reportero.pk, &reportero.sk, nodo.cbid);
        let a2 = crate::votos::tx_acta_presencia(&acta, otro.pk, &otro.sk, nodo.cbid);
        let viejo = crate::votos::tx_certificado_peso(&cert, otro.pk, &otro.sk, nodo.cbid);
        // Certificado real posterior: el n=0 del candidato pasa a estar superado.
        let base_cert = nodo
            .cadena
            .estado_post(&hash_u32(32))
            .expect("fixture PROD-2 válido");
        let tabla = tabla_peso_para_bloque(base_cert, 4, 1);
        let sk_cert = crate::votos::clave_voto_dev(1, 0).expect("fixture PROD-2 válido");
        let pos = tabla
            .claves
            .iter()
            .position(|c| c.clave.as_slice() == sk_cert.clave_publica().bytes())
            .expect("fixture PROD-2 válido");
        let siguiente = base_cert
            .cola_tablas_voto
            .last()
            .expect("fixture PROD-2 válido")
            .1;
        let firma_cert = zx_votos::firmar(
            &sk_cert,
            zx_votos::DOMINIO_VOTO,
            &zx_votos::mensaje_voto_peso(1, hash_u32(31).as_bytes(), &siguiente, &[0; 32]),
        )
        .expect("fixture PROD-2 válido");
        let nuevo = zx_votos::construir_certificado(
            1,
            *hash_u32(31).as_bytes(),
            siguiente,
            [0; 32],
            &tabla,
            &[(pos + 1, firma_cert)],
        )
        .expect("fixture PROD-2 válido");
        aplicar_cuerpo(
            &mut nodo,
            33,
            4,
            vec![crate::votos::tx_certificado_peso(
                &nuevo,
                reportero.pk,
                &reportero.sk,
                cbid,
            )],
        )
        .expect("fixture PROD-2 válido");
        assert!(
            nodo.cadena
                .descartes(&hash_u32(33))
                .expect("fixture PROD-2 válido")
                .is_empty()
        );
        assert_eq!(
            nodo.cadena
                .estado_post(&hash_u32(33))
                .expect("fixture PROD-2 válido")
                .finalidad_votos_n,
            1
        );
        let voto_sk = crate::votos::clave_voto_dev(1, 0).expect("fixture PROD-2 válido");
        let payload = crate::votos::VotoPropioPayload {
            n: 0,
            candidato: cert.candidato,
            h_t_siguiente: cert.h_t_siguiente,
            raiz_estado: cert.raiz_estado,
            clave_bls: voto_sk.clave_publica().bytes(),
            firma: zx_votos::firmar(
                &voto_sk,
                zx_votos::DOMINIO_VOTO,
                &zx_votos::mensaje_voto_peso(
                    0,
                    &cert.candidato,
                    &cert.h_t_siguiente,
                    &cert.raiz_estado,
                ),
            )
            .expect("fixture PROD-2 válido")
            .bytes(),
        };
        let contado =
            crate::votos::tx_voto_propio(&payload, reportero.pk, &reportero.sk, nodo.cbid);
        // Cola y pendientes reales: selección y ensayo no pueden consumirlos.
        let base_cola = nodo
            .cadena
            .estado_post(&hash_u32(33))
            .expect("fixture PROD-2 válido")
            .clone();
        refrescar_cola(&mut nodo, base_cola);
        nodo.mempool
            .lock()
            .expect("fixture PROD-2 válido")
            .admitir(
                None,
                p1.0.clone(),
                p1.1.clone(),
                Instant::now(),
                Punto::Slot(14),
            )
            .expect("fixture PROD-2 válido");
        nodo.encolar_v6_con_firmantes(
            a1.0.clone(),
            a1.1.clone(),
            true,
            vec![ClaveDev::derivar(1, 1).pk],
            1,
        );
        nodo.encolar_v6_con_firmantes(
            a2.0.clone(),
            a2.1.clone(),
            true,
            vec![ClaveDev::derivar(1, 1).pk],
            1,
        );
        let armado_real = armar(&mut nodo, 14);
        assert!(armado_real.iter().any(|p| p.0 == p1.0));
        let (plantilla, distancia) = candidata_real(&nodo, 14);
        let estado_antes = nodo.resumen_estado_actual();
        let cola_antes = huella_cola(&nodo);
        let motor_antes = huella_motor(&nodo);
        let pendientes_antes: Vec<_> = nodo
            .v6_pendientes
            .iter()
            .map(|p| txid(&p.tx, nodo.cbid))
            .collect();
        let registro = RegistroFirmante::nueva(dir.path().join("firmante-propiedad"))
            .expect("fixture PROD-2 válido");
        let mut firmante = Firmante::nuevo(&registro);
        let mut rng = SEMILLA;
        let mut rojos = 0;
        for caso in 0..64 {
            let mut pares = vec![
                p1.clone(),
                p2.clone(),
                conflicto.clone(),
                p1.clone(),
                a1.clone(),
                a1.clone(),
                a2.clone(),
                contado.clone(),
                mala.clone(),
                viejo.clone(),
            ];
            for i in (1..pares.len()).rev() {
                let j = usize::try_from(
                    aleatorio(&mut rng) % u64::try_from(i + 1).expect("fixture PROD-2 válido"),
                )
                .expect("fixture PROD-2 válido");
                pares.swap(i, j);
            }
            let candidata = con_cuerpo(&plantilla, pares);
            let (_, desc_raw) = nodo
                .cadena
                .ensayar_post(
                    &post_de_candidata(&candidata, distancia).expect("fixture PROD-2 válido"),
                )
                .expect("fixture PROD-2 válido");
            if std::env::var("PROD2_CONTROL_ROJO").is_ok_and(|v| v == "1") {
                assert!(
                    desc_raw.is_empty(),
                    "control rojo: el cuerpo sin ensayo tiene descartes"
                );
            }
            assert!(!desc_raw.is_empty()); // Control rojo, sin depurar.
            assert!(
                desc_raw
                    .iter()
                    .any(|d| d.motivo == ErrorTransicion::ErrFinalidadRetrocede)
            );
            rojos += 1;
            let aceptadas: Vec<_> = candidata
                .txs()
                .iter()
                .enumerate()
                .filter(|(i, _)| !desc_raw.iter().any(|d| d.indice == *i))
                .map(|(_, tx)| txid(tx, nodo.cbid))
                .collect();
            let dep = depurar_candidata_post(
                &nodo.cadena,
                &candidata,
                distancia,
                nodo.params.max_cuerpo_bloque_bytes,
            )
            .expect("fixture PROD-2 válido");
            assert!(dep.vueltas <= candidata.txs().len());
            assert!(!dep.respaldo);
            for id in aceptadas {
                assert!(
                    dep.candidata
                        .txs()
                        .iter()
                        .any(|tx| txid(tx, nodo.cbid) == id),
                    "válida perdida: caso={caso}"
                );
            }
            let registro_caso = RegistroFirmante::nueva(dir.path().join(format!("firma-{caso}")))
                .expect("fixture PROD-2 válido");
            let mut f = Firmante::nuevo(&registro_caso);
            let ProductoFirmado::Bloque(b, _) = nodo
                .firmar_post_ensayado(&candidata, distancia, &reportero.sk, &mut f)
                .expect("fixture PROD-2 válido")
            else {
                panic!("abstención");
            };
            b.cabecera.verificar_sello().expect("fixture PROD-2 válido");
            assert_eq!(
                b.cabecera.body_commitment,
                zx_core::body_commitment(b.txs(), b.testigos(), nodo.cbid)
                    .expect("fixture PROD-2 válido")
            );
            assert_eq!(
                b.cabecera.merkle_root,
                zx_core::preimage::block::merkle_root(
                    &b.txs()
                        .iter()
                        .map(|tx| txid(tx, nodo.cbid))
                        .collect::<Vec<_>>()
                )
            );
            let mut cadena = nodo.cadena.clone();
            let post = post_de_candidata(&b, distancia).expect("fixture PROD-2 válido");
            let hash = post.hash;
            cadena
                .admitir(BloqueCadena::Post(post))
                .expect("fixture PROD-2 válido");
            assert!(
                cadena
                    .descartes(&hash)
                    .expect("fixture PROD-2 válido")
                    .is_empty()
            );
        }
        // El callback fallido no alcanza el firmante ni ocupa la identidad/slot.
        let fracaso = zx_post::productor_regimen::firmar_regimen_tras_ensayo(
            plantilla.clone(),
            &reportero.sk,
            &mut firmante,
            |_| -> ResultadoNodo<()> { Err(ErrorNodo::Otro("control de ensayo fallido".into())) },
        );
        assert!(fracaso.is_err());
        let ProductoFirmado::Bloque(_, _) = nodo
            .firmar_post_ensayado(&plantilla, distancia, &reportero.sk, &mut firmante)
            .expect("fixture PROD-2 válido")
        else {
            panic!("el ensayo fallido consumió la identidad");
        };
        assert_eq!(estado_antes, nodo.resumen_estado_actual());
        assert_eq!(cola_antes, huella_cola(&nodo));
        assert_eq!(motor_antes, huella_motor(&nodo));
        assert_eq!(
            pendientes_antes,
            nodo.v6_pendientes
                .iter()
                .map(|p| txid(&p.tx, nodo.cbid))
                .collect::<Vec<_>>()
        );
        assert!(!huella_cola(&nodo).is_empty());
        assert_eq!(armar(&mut nodo, 14).len(), armado_real.len());
        println!(
            "PROD2 semilla={SEMILLA:#x} casos=64 rojos={rojos} firmados_descartes=0 poas_real=true conservación=true"
        );
    }

    #[test]
    fn prod2_evidencia_fuera_de_plazo_y_forma_permanente_salen_sin_mutar_origen() {
        let dir = tempfile::tempdir().expect("fixture PROD-2 válido");
        let mut est = estado_inicial(3);
        let valida = pago(&mut est, 0xA8, 90);
        let mut nodo = nodo(dir.path(), est);
        aplicar_cuerpo(&mut nodo, 35, 300, Vec::new()).expect("fixture PROD-2 válido");
        let (base, distancia) = candidata_real(&nodo, 302);
        let ev = evidencia();
        let mut forma = ev.clone();
        forma.outputs.push(TxOut {
            value: Amount::nuevo(1).expect("fixture PROD-2 válido"),
            lock: Lock::PubKey {
                pubkey: nodo.claves[0].pk,
            },
        });
        let candidata = con_cuerpo(
            &base,
            vec![valida.clone(), (ev, Vec::new()), (forma, Vec::new())],
        );
        let antes = nodo.resumen_estado_actual();
        let dep = depurar_candidata_post(
            &nodo.cadena,
            &candidata,
            distancia,
            nodo.params.max_cuerpo_bloque_bytes,
        )
        .expect("fixture PROD-2 válido");
        assert_eq!(dep.retiradas.len(), 2);
        assert!(
            dep.retiradas
                .iter()
                .any(|r| r.motivo == ErrorTransicion::ErrEvidenciaTardia)
        );
        assert!(
            dep.retiradas
                .iter()
                .any(|r| matches!(r.motivo, ErrorTransicion::ErrForma(_)))
        );
        assert!(dep.candidata.txs().contains(&valida.0));
        let (_, desc) = nodo
            .cadena
            .ensayar_post(
                &post_de_candidata(&dep.candidata, distancia).expect("fixture PROD-2 válido"),
            )
            .expect("fixture PROD-2 válido");
        assert!(desc.is_empty());
        assert_eq!(antes, nodo.resumen_estado_actual());
    }

    #[test]
    fn prod2_el_mergeset_real_descarta_lo_que_la_base_cacheada_acepta() {
        let dir = tempfile::tempdir().expect("fixture PROD-2 válido");
        let mut est = estado_inicial(3);
        let gastada = pago(&mut est, 0xB1, 90);
        let valida = pago(&mut est, 0xB2, 90);
        let mut nodo = nodo(dir.path(), est);
        let pk = nodo.claves[0].pk;
        let coinbase = |slot| {
            (
                tx_coinbase_post(pk, perfil::SUBSIDIO_POST_BREK, slot),
                Vec::new(),
            )
        };
        nodo.cadena
            .admitir(post_con_txs(
                40,
                vec![hash_u32(31)],
                2,
                u64::MAX,
                pk,
                vec![coinbase(2)],
            ))
            .expect("fixture PROD-2 válido");
        nodo.cadena
            .admitir(post_con_txs(
                42,
                vec![hash_u32(40)],
                3,
                u64::MAX,
                pk,
                vec![coinbase(3)],
            ))
            .expect("fixture PROD-2 válido");
        nodo.cadena
            .admitir(post_con_txs(
                41,
                vec![hash_u32(31)],
                2,
                u64::MAX,
                pk,
                vec![coinbase(2), gastada.clone()],
            ))
            .expect("fixture PROD-2 válido");
        let padres = padres_de_regimen(&nodo.cadena).expect("fixture PROD-2 válido");
        assert_eq!(padres.seleccionado(), hash_u32(42));
        assert!(padres.extras().contains(&hash_u32(41)));
        let cache = nodo
            .cadena
            .estado_post(&padres.seleccionado())
            .expect("fixture PROD-2 válido")
            .clone();
        assert!(cache.utxo.contains_key(&gastada.0.inputs[0].outpoint));
        refrescar_cola(&mut nodo, cache);
        nodo.mempool
            .lock()
            .expect("fixture PROD-2 válido")
            .admitir(
                None,
                gastada.0.clone(),
                gastada.1.clone(),
                Instant::now(),
                Punto::Slot(4),
            )
            .expect("fixture PROD-2 válido");
        let cola_antes = huella_cola(&nodo);
        let (base, distancia) = candidata_real(&nodo, 4);
        let candidata = con_cuerpo(&base, vec![gastada.clone(), valida.clone()]);
        let (_, rojo) = nodo
            .cadena
            .ensayar_post(&post_de_candidata(&candidata, distancia).expect("fixture PROD-2 válido"))
            .expect("fixture PROD-2 válido");
        assert!(
            rojo.iter().any(|d| d.txid == txid(&gastada.0, nodo.cbid)
                && d.motivo == ErrorTransicion::ErrDobleGasto)
        );
        let dep = depurar_candidata_post(
            &nodo.cadena,
            &candidata,
            distancia,
            nodo.params.max_cuerpo_bloque_bytes,
        )
        .expect("fixture PROD-2 válido");
        assert!(!dep.candidata.txs().contains(&gastada.0));
        assert!(dep.candidata.txs().contains(&valida.0));
        assert_eq!(cola_antes, huella_cola(&nodo));
        let registro = RegistroFirmante::nueva(dir.path().join("firma-mergeset"))
            .expect("fixture PROD-2 válido");
        let mut firmante = Firmante::nuevo(&registro);
        let ProductoFirmado::Bloque(b, _) = nodo
            .firmar_post_ensayado(&candidata, distancia, &nodo.claves[0].sk, &mut firmante)
            .expect("fixture PROD-2 válido")
        else {
            panic!("abstención");
        };
        let p = post_de_candidata(&b, distancia).expect("fixture PROD-2 válido");
        let hash = p.hash;
        let mut copia = nodo.cadena.clone();
        copia
            .admitir(BloqueCadena::Post(p))
            .expect("fixture PROD-2 válido");
        assert!(
            copia
                .descartes(&hash)
                .expect("fixture PROD-2 válido")
                .is_empty()
        );
    }

    #[test]
    fn prod2_la_coinbase_y_el_credito_son_del_productor_real_que_no_es_la_primera_clave() {
        let dir = tempfile::tempdir().expect("fixture PROD-2 válido");
        let nodo = nodo(dir.path(), estado_inicial(3));
        let real = ClaveDev::derivar(1, 2);
        assert_ne!(real.pk, nodo.claves[0].pk);
        let (base, distancia) = candidata_de_clave(&nodo, &real, 2);
        assert_eq!(base.cabecera.sol.public_key, real.pk);
        let candidata = con_cuerpo(&base, vec![(evidencia(), Vec::new())]);
        let dep = depurar_candidata_post(
            &nodo.cadena,
            &candidata,
            distancia,
            nodo.params.max_cuerpo_bloque_bytes,
        )
        .expect("fixture PROD-2 válido");
        assert!(dep.retiradas.is_empty());
        assert!(
            matches!(dep.candidata.txs()[0].extension, ExtensionTx::CoinbasePost { clave, .. } if clave == real.pk)
        );
        let (estado, descartes) = nodo
            .cadena
            .ensayar_post(
                &post_de_candidata(&dep.candidata, distancia).expect("fixture PROD-2 válido"),
            )
            .expect("fixture PROD-2 válido");
        assert!(descartes.is_empty());
        let anterior = nodo
            .cadena
            .estado_post(&hash_u32(31))
            .expect("fixture PROD-2 válido");
        assert!(
            estado.garantias[&real.pk].creditos.len() > anterior.garantias[&real.pk].creditos.len()
        );
        assert_eq!(
            estado.garantias[&nodo.claves[0].pk].creditos,
            anterior.garantias[&nodo.claves[0].pk].creditos
        );
        let registro = RegistroFirmante::nueva(dir.path().join("firma-identidad-real"))
            .expect("fixture PROD-2 válido");
        let mut firmante = Firmante::nuevo(&registro);
        let ProductoFirmado::Bloque(b, _) = nodo
            .firmar_post_ensayado(&candidata, distancia, &real.sk, &mut firmante)
            .expect("fixture PROD-2 válido")
        else {
            panic!("abstención");
        };
        b.cabecera.verificar_sello().expect("fixture PROD-2 válido");
        assert_eq!(b.cabecera.sol.public_key, real.pk);
        let post = post_de_candidata(&b, distancia).expect("fixture PROD-2 válido");
        let hash = post.hash;
        let mut copia = nodo.cadena.clone();
        copia
            .admitir(BloqueCadena::Post(post))
            .expect("fixture PROD-2 válido");
        assert!(
            copia
                .descartes(&hash)
                .expect("fixture PROD-2 válido")
                .is_empty()
        );
    }

    /// PROD-3a · E3 y E5: para las mismas candidatas reales de
    /// `prod2_propiedad_candidatas_reales_mezcladas_y_control_rojo` (claves, PoAS y PoT reales),
    /// el ensayo nuevo contra O2 (admisión en una copia) y, tras firmar, la admisión del bloque
    /// firmado en una copia del original reproduce estado y descartes del ensayo (identificador).
    #[test]
    fn prod3a_equivalencia_y_identificador_candidatas_reales() {
        const SEMILLA: u64 = 0x5052_4f44_3200_0001;
        let dir = tempfile::tempdir().expect("fixture PROD-3a válido");
        let mut est = estado_inicial(3);
        let p1 = pago(&mut est, 0xA0, 90);
        let p2 = pago(&mut est, 0xA1, 90);
        let conflicto = pago(&mut est, 0xA0, 80);
        let mut mala = pago(&mut est, 0xA2, 90);
        mala.1[0][0] ^= 1;
        let mut nodo = nodo(dir.path(), est);
        let cert = certificado(&mut nodo);
        let reportero = nodo.claves[0].clone();
        let cbid = nodo.cbid;
        aplicar_cuerpo(
            &mut nodo,
            32,
            2,
            vec![crate::votos::tx_certificado_peso(
                &cert,
                reportero.pk,
                &reportero.sk,
                cbid,
            )],
        )
        .expect("fixture PROD-3a válido");
        let mut motor = dgacta::motor_abierto(&nodo, cert.clone(), true);
        let acta = motor
            .cerrar()
            .expect("fixture PROD-3a válido")
            .acta_peso
            .expect("fixture PROD-3a válido");
        let otro = ClaveDev::derivar(1, 2);
        let a1 = crate::votos::tx_acta_presencia(&acta, reportero.pk, &reportero.sk, nodo.cbid);
        let a2 = crate::votos::tx_acta_presencia(&acta, otro.pk, &otro.sk, nodo.cbid);
        let viejo = crate::votos::tx_certificado_peso(&cert, otro.pk, &otro.sk, nodo.cbid);
        let base_cert = nodo
            .cadena
            .estado_post(&hash_u32(32))
            .expect("fixture PROD-3a válido");
        let tabla = tabla_peso_para_bloque(base_cert, 4, 1);
        let sk_cert = crate::votos::clave_voto_dev(1, 0).expect("fixture PROD-3a válido");
        let pos = tabla
            .claves
            .iter()
            .position(|c| c.clave.as_slice() == sk_cert.clave_publica().bytes())
            .expect("fixture PROD-3a válido");
        let siguiente = base_cert
            .cola_tablas_voto
            .last()
            .expect("fixture PROD-3a válido")
            .1;
        let firma_cert = zx_votos::firmar(
            &sk_cert,
            zx_votos::DOMINIO_VOTO,
            &zx_votos::mensaje_voto_peso(1, hash_u32(31).as_bytes(), &siguiente, &[0; 32]),
        )
        .expect("fixture PROD-3a válido");
        let nuevo = zx_votos::construir_certificado(
            1,
            *hash_u32(31).as_bytes(),
            siguiente,
            [0; 32],
            &tabla,
            &[(pos + 1, firma_cert)],
        )
        .expect("fixture PROD-3a válido");
        aplicar_cuerpo(
            &mut nodo,
            33,
            4,
            vec![crate::votos::tx_certificado_peso(
                &nuevo,
                reportero.pk,
                &reportero.sk,
                cbid,
            )],
        )
        .expect("fixture PROD-3a válido");
        let voto_sk = crate::votos::clave_voto_dev(1, 0).expect("fixture PROD-3a válido");
        let payload = crate::votos::VotoPropioPayload {
            n: 0,
            candidato: cert.candidato,
            h_t_siguiente: cert.h_t_siguiente,
            raiz_estado: cert.raiz_estado,
            clave_bls: voto_sk.clave_publica().bytes(),
            firma: zx_votos::firmar(
                &voto_sk,
                zx_votos::DOMINIO_VOTO,
                &zx_votos::mensaje_voto_peso(
                    0,
                    &cert.candidato,
                    &cert.h_t_siguiente,
                    &cert.raiz_estado,
                ),
            )
            .expect("fixture PROD-3a válido")
            .bytes(),
        };
        let contado =
            crate::votos::tx_voto_propio(&payload, reportero.pk, &reportero.sk, nodo.cbid);
        let base_cola = nodo
            .cadena
            .estado_post(&hash_u32(33))
            .expect("fixture PROD-3a válido")
            .clone();
        refrescar_cola(&mut nodo, base_cola);
        nodo.mempool
            .lock()
            .expect("fixture PROD-3a válido")
            .admitir(
                None,
                p1.0.clone(),
                p1.1.clone(),
                Instant::now(),
                Punto::Slot(14),
            )
            .expect("fixture PROD-3a válido");
        nodo.encolar_v6_con_firmantes(
            a1.0.clone(),
            a1.1.clone(),
            true,
            vec![ClaveDev::derivar(1, 1).pk],
            1,
        );
        nodo.encolar_v6_con_firmantes(
            a2.0.clone(),
            a2.1.clone(),
            true,
            vec![ClaveDev::derivar(1, 1).pk],
            1,
        );
        let _ = armar(&mut nodo, 14);
        let (plantilla, distancia) = candidata_real(&nodo, 14);
        let mut rng = SEMILLA;
        let mut casos = 0usize;
        let mut con_descartes = 0usize;
        for caso in 0..64 {
            let mut pares = vec![
                p1.clone(),
                p2.clone(),
                conflicto.clone(),
                p1.clone(),
                a1.clone(),
                a1.clone(),
                a2.clone(),
                contado.clone(),
                mala.clone(),
                viejo.clone(),
            ];
            for i in (1..pares.len()).rev() {
                let j = usize::try_from(
                    aleatorio(&mut rng) % u64::try_from(i + 1).expect("fixture PROD-3a válido"),
                )
                .expect("fixture PROD-3a válido");
                pares.swap(i, j);
            }
            let candidata = con_cuerpo(&plantilla, pares);
            let post_sin = post_de_candidata(&candidata, distancia)
                .expect("fixture PROD-3a válido");
            let hash_sin = post_sin.hash;
            let (estado_ensayo, descartes_ensayo) = nodo
                .cadena
                .ensayar_post(&post_sin)
                .expect("fixture PROD-3a válido");
            if !descartes_ensayo.is_empty() {
                con_descartes += 1;
            }
            // E3 · O2: admisión pública en una copia.
            let mut copia = nodo.cadena.clone();
            copia
                .admitir(BloqueCadena::Post(post_sin))
                .expect("fixture PROD-3a válido");
            assert_eq!(
                copia.estado_post(&hash_sin),
                Some(&estado_ensayo),
                "E3: estado difiere de O2 (caso {caso})"
            );
            assert_eq!(
                copia.descartes(&hash_sin).unwrap_or(&[]),
                descartes_ensayo.as_slice(),
                "E3: descartes difieren de O2 (caso {caso})"
            );
            // E5 · identificador: la candidata que se firma es la **depurada**
            // (`firmar_post_ensayado` vuelve a depurar); se ensaya sin sello y se admite el bloque
            // firmado en una copia del original.
            let dep = depurar_candidata_post(
                &nodo.cadena,
                &candidata,
                distancia,
                nodo.params.max_cuerpo_bloque_bytes,
            )
            .expect("fixture PROD-3a válido");
            let post_dep = post_de_candidata(&dep.candidata, distancia)
                .expect("fixture PROD-3a válido");
            let (estado_dep, descartes_dep) = nodo
                .cadena
                .ensayar_post(&post_dep)
                .expect("fixture PROD-3a válido");
            assert!(
                descartes_dep.is_empty(),
                "E5: la candidata depurada sigue con descartes (caso {caso})"
            );
            let registro_caso =
                RegistroFirmante::nueva(dir.path().join(format!("prod3a-firma-{caso}")))
                    .expect("fixture PROD-3a válido");
            let mut f = Firmante::nuevo(&registro_caso);
            let ProductoFirmado::Bloque(b, _) = nodo
                .firmar_post_ensayado(&candidata, distancia, &reportero.sk, &mut f)
                .expect("fixture PROD-3a válido")
            else {
                panic!("abstención");
            };
            let post_firmado =
                post_de_candidata(&b, distancia).expect("fixture PROD-3a válido");
            let hash_firmado = post_firmado.hash;
            let mut original = nodo.cadena.clone();
            original
                .admitir(BloqueCadena::Post(post_firmado))
                .expect("fixture PROD-3a válido");
            assert_eq!(
                original.estado_post(&hash_firmado),
                Some(&estado_dep),
                "E5: estado del bloque firmado difiere del ensayo (caso {caso})"
            );
            assert_eq!(
                original.descartes(&hash_firmado).unwrap_or(&[]),
                descartes_dep.as_slice(),
                "E5: descartes del bloque firmado difieren del ensayo (caso {caso})"
            );
            casos += 1;
        }
        assert_eq!(casos, 64);
        // E3 · PROD-3a-2: afirmar (no solo decir) que hay candidatas sin sello con descartes.
        assert!(
            con_descartes > 0,
            "E3: ninguna de las 64 candidatas sin sello tiene descartes"
        );
        println!(
            "PROD3A_CANDIDATAS casos={casos} con_descartes={con_descartes} o2_igual=true identificador_igual=true"
        );
    }

    /// PROD-3a · E6b: coste en `zx-node` con la tabla de 1 024 claves, alternando
    /// `cadena.clone()` sola, el ensayo nuevo y O2 (cuerpo vacío y lleno). Release e `#[ignore]`.
    #[test]
    #[ignore = "medida release de E6b (zx-node); se corre aparte"]
    fn prod3a_coste_release_tabla_1024() {
        if cfg!(debug_assertions) {
            panic!("la medida exige release");
        }
        assert_eq!(
            std::env::var("PROD3A_MEDIR").expect("fixture PROD-3a válido"),
            "1"
        );
        let dir = tempfile::tempdir().expect("fixture PROD-3a válido");
        let mut estado = estado_inicial(1024);
        let pagos = relleno_al_tope(&mut estado);
        let nodo = nodo(dir.path(), estado);
        let (vacio, distancia) = candidata_real(&nodo, 2);
        let lleno = con_cuerpo(&vacio, pagos);
        for (nombre, candidata) in [("vacio", vacio), ("lleno", lleno)] {
            let post =
                post_de_candidata(&candidata, distancia).expect("fixture PROD-3a válido");
            let _ = nodo.cadena.clone();
            let _ = nodo
                .cadena
                .ensayar_post(&post)
                .expect("fixture PROD-3a válido");
            let mut t_clone = [0_u128; 5];
            let mut t_nuevo = [0_u128; 5];
            let mut t_o2 = [0_u128; 5];
            for rep in 0..5 {
                let i = Instant::now();
                let _ = std::hint::black_box(nodo.cadena.clone());
                t_clone[rep] = i.elapsed().as_nanos();
                let i = Instant::now();
                let _ = std::hint::black_box(
                    nodo.cadena
                        .ensayar_post(&post)
                        .expect("fixture PROD-3a válido"),
                );
                t_nuevo[rep] = i.elapsed().as_nanos();
                let i = Instant::now();
                let mut copia = nodo.cadena.clone();
                copia
                    .admitir(BloqueCadena::Post(post.clone()))
                    .expect("fixture PROD-3a válido");
                let _ = std::hint::black_box(copia);
                t_o2[rep] = i.elapsed().as_nanos();
            }
            for v in [&mut t_clone, &mut t_nuevo, &mut t_o2] {
                v.sort_unstable();
            }
            println!(
                "PROD3A_COSTE_NODO cuerpo={nombre} clone_ns={}/{}/{} nuevo_ns={}/{}/{} o2_ns={}/{}/{} perfil=release",
                t_clone[0], t_clone[2], t_clone[4],
                t_nuevo[0], t_nuevo[2], t_nuevo[4],
                t_o2[0], t_o2[2], t_o2[4]
            );
        }
    }
}
