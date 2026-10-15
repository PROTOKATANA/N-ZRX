//! Regresión RI-3a #2 (`ORDEN-W06d6` decisión 4; `P-ZRX/P-REVISION-CODIGO/REVISION-RI-3a.md`
//! hallazgo 2).
//!
//! Antes de corregir (confirmado; el test original de reproducción, ejecutado tal cual contra la
//! base en `deepseek/W06d6/logs/RI-3a-antes.log`), `leer_acotado` reservaba `MAX_RESPUESTA_BYTES +
//! 1` de golpe, antes de leer un solo byte, y unos pocos pares silenciosos (menos que
//! `MAX_STREAMS_SYNC`) bastaban para agotar el presupuesto agregado (256 MiB) y denegar a un par
//! honesto cuya respuesta ya estaba completa.
//!
//! Después de corregir, la reserva es incremental, en trozos de [`TROZO_LECTURA_BYTES`]. Un par
//! silencioso que nunca escribe solo retiene un trozo (64 KiB), no la respuesta entera.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::integer_division,
    reason = "el test falla con panic por diseño; la división entera es deliberada (orden de magnitud)"
)]

use std::time::Duration;

use futures::AsyncWriteExt;
use futures_ringbuf::Endpoint;
use libp2p::StreamProtocol;
use libp2p::request_response::Codec;

use zx_core::digest::{BlockHash, Digest};
use zx_core::red::Red;
use zx_p2p::codec::{TROZO_LECTURA_BYTES, ZxCodec, respuesta_a_bytes};
use zx_p2p::limites::MAX_RESPUESTA_BYTES;
use zx_p2p::mensaje::{Estado, Fase, PuntaPow, Respuesta};
use zx_p2p::presupuesto::{PRESUPUESTO_BYTES, Presupuesto};

fn proto() -> StreamProtocol {
    StreamProtocol::new("/zx-dev/1")
}

fn h(n: u8) -> BlockHash {
    BlockHash::from_digest(Digest::from_bytes([n; 32]))
}

fn estado_minimo() -> Estado {
    Estado {
        hash_genesis: h(0),
        red: Red::Dev,
        fase: Fase::Pow,
        punta_pow: PuntaPow {
            hash: h(1),
            altura: 0,
            trabajo_acumulado: [0; 32],
        },
        terminal: None,
        puntas_post: vec![],
        blue_work_virtual: [0; 32],
        longitud_registro: 0,
    }
}

/// **Regresión.** El mismo escenario que el hallazgo (`MAX_STREAMS_SYNC` pares silenciosos, menos
/// streams que el propio tope por conexión): con la reserva incremental, retienen `streams ×
/// TROZO_LECTURA_BYTES`, muy por debajo del presupuesto total, y un par honesto **sí** recibe su
/// respuesta.
#[tokio::test]
async fn muchos_pares_silenciosos_ya_no_agotan_el_presupuesto() {
    let presupuesto = Presupuesto::nuevo(PRESUPUESTO_BYTES);

    // El mismo número de streams silenciosos que agotaba el presupuesto entero antes de corregir:
    // por debajo de `MAX_STREAMS_SYNC`, para que sea "un solo par", no varios.
    let costo_por_lectura_antes = MAX_RESPUESTA_BYTES + 1;
    let cabida_antes = (PRESUPUESTO_BYTES as u64) / costo_por_lectura_antes;
    assert!(
        cabida_antes >= 1 && cabida_antes < zx_p2p::limites::MAX_STREAMS_SYNC as u64,
        "cabida_antes = {cabida_antes}: MUST caber por debajo de MAX_STREAMS_SYNC"
    );

    let mut silencio = Vec::new();
    let mut tareas = Vec::new();
    for _ in 0..cabida_antes {
        let (a, mut b) = Endpoint::pair(4096, 4096);
        silencio.push(a);
        let p = presupuesto.clone();
        tareas.push(tokio::spawn(async move {
            let mut codec = ZxCodec::con_presupuesto(p);
            let _ = codec.read_response(&proto(), &mut b).await;
        }));
    }

    // Tiempo de sobra para que cada tarea haga su primera reserva (un trozo) y se quede esperando
    // datos que nunca llegan.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let reservado_antes_de_corregir = cabida_antes as usize * (costo_por_lectura_antes as usize);
    let reservado_ahora = presupuesto.en_vuelo();
    assert!(
        reservado_ahora <= cabida_antes as usize * TROZO_LECTURA_BYTES,
        "cada par silencioso MUST retener como mucho un trozo ({TROZO_LECTURA_BYTES} B), no toda \
         la respuesta: reservado = {reservado_ahora} B"
    );
    assert!(
        reservado_ahora < reservado_antes_de_corregir / 100,
        "la reserva incremental MUST quitar por lo menos dos órdenes de magnitud frente al \
         {reservado_antes_de_corregir} B que se reservaba antes de corregir; reservado ahora: \
         {reservado_ahora} B"
    );

    // Y sigue habiendo presupuesto de sobra para un par honesto: su respuesta, ya completa, se lee
    // sin que el presupuesto lo deniegue.
    let (mut a_honesto, mut b_honesto) = Endpoint::pair(4096, 4096);
    let bytes = respuesta_a_bytes(&Respuesta::Estado(estado_minimo()));
    a_honesto.write_all(&bytes).await.unwrap();
    a_honesto.close().await.unwrap();

    let mut codec_honesto = ZxCodec::con_presupuesto(presupuesto.clone());
    let leida = codec_honesto
        .read_response(&proto(), &mut b_honesto)
        .await
        .expect("un par honesto MUST poder leerse: queda presupuesto de sobra");
    assert_eq!(leida, Respuesta::Estado(estado_minimo()));

    eprintln!(
        "RI-3a (corregido): {cabida_antes} pares silenciosos retienen {reservado_ahora} B (antes: \
         {reservado_antes_de_corregir} B); el par honesto SÍ recibió su respuesta"
    );

    for t in tareas {
        t.abort();
    }
}
