//! EA-WIRE-2: formato puro 0x0C v3 y frontera intacta del códec de transacciones.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "aserciones de pruebas sobre datos controlados"
)]

use zx_core::error::EncodingError;
use zx_core::{ClasePruebaAlmacenamiento, ErrorCodecAlmacenamiento, OperacionAlmacenamiento};

#[test]
fn ea_transacciones_siguen_rechazando_0c_como_en_la_base() {
    // Vector mínimo v6: cabecera, entradas/salidas vacías y clase 0x0C.
    let bytes = hex::decode("06000000000000000000000000000c").unwrap();
    assert!(matches!(
        zx_core::wire::tx_desde_bytes(&bytes),
        Err(EncodingError::OperacionAlmacenamientoInvalida(
            ErrorCodecAlmacenamiento::DiscriminanteInvalido(0x0c)
        ))
    ));
    assert_eq!(ClasePruebaAlmacenamiento::desde_byte(0x0c), None);
    assert_eq!(
        OperacionAlmacenamiento::desde_canonica(&[0x0c]),
        Err(ErrorCodecAlmacenamiento::DiscriminanteInvalido(0x0c))
    );
}
const HEX_S: &str = concat!(
    "070000000000000011111111111111111111111111111111111111111111111111111111111111112222222222222222",
    "222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333",
    "333333333333333344444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "4444444444444444",
    "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
);

const HEX_L_REF: &str = concat!(
    "070000000000000011111111111111111111111111111111111111111111111111111111111111112222222222222222",
    "222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333",
    "333333333333333344444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444466666666666666666666666666666666666666666666666666666666666666667777777777777777",
    "777777777777777777777777777777777777777777777777ffffffff030005",
);

const HEX_C_REF: &str = concat!(
    "070000000000000011111111111111111111111111111111111111111111111111111111111111112222222222222222",
    "222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333",
    "333333333333333344444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444466666666666666666666666666666666666666666666666666666666666666667777777777777777",
    "7777777777777777777777777777777777777777777777770900000005",
);

const HEX_A_REF: &str = concat!(
    "070000000000000011111111111111111111111111111111111111111111111111111111111111112222222222222222",
    "222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333",
    "333333333333333344444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444466666666666666666666666666666666666666666666666666666666666666667777777777777777",
    "7777777777777777777777777777777777777777777777770900000005",
);

const HEX_L_EXP: &str = concat!(
    "070000000000000011111111111111111111111111111111111111111111111111111111111111112222222222222222",
    "222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333",
    "333333333333333344444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444403000100000055555555555555555555555555555555555555555555555555555555555555555555",
    "5555555555555555555555555555",
);

const HEX_C_EXP: &str = concat!(
    "070000000000000011111111111111111111111111111111111111111111111111111111111111112222222222222222",
    "222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333",
    "333333333333333344444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444401000000555555555555555555555555555555555555555555555555555555555555555555555555",
    "555555555555555555555555",
);

const HEX_A_EXP: &str = concat!(
    "070000000000000011111111111111111111111111111111111111111111111111111111111111112222222222222222",
    "222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333",
    "333333333333333344444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
    "444444444444444401000000555555555555555555555555555555555555555555555555555555555555555555555555",
    "555555555555555555555555",
);
use zx_core::evidencia_agregados::{
    ClavesExplicitas, ContenidoObjeto, DOMINIO_REPORTERO, ErrorEvidenciaAgregados as Error,
    EvidenciaAgregadosV3, MAX_CLAVES, MAX_MAPA_BYTES, ObjetoEvidencia, OrigenReferencia,
    POSICION_SUBRED, carga, claves_comunes, codificar, decodificar, longitud_canonica,
    preimagen_reportero, validar_forma, validar_forma_bytes,
};
use zx_core::{ClavePublica, VotoPesoEvidencia};

const MAPA: &[u8] = &[5];
const CLAVE: &[u8] = &[0x55; 48];
const S: ContenidoObjeto<'static> = ContenidoObjeto::Voto { clave: [0x99; 48] };

fn voto(n: u64) -> VotoPesoEvidencia {
    VotoPesoEvidencia {
        n,
        candidato: [0x11; 32],
        h_t_siguiente: [0x22; 32],
        raiz_estado: [0x33; 32],
        firma: [0x44; 96],
    }
}

fn origen(posicion: u32) -> OrigenReferencia {
    OrigenReferencia {
        h_actual: [0x66; 32],
        bloque_origen: [0x77; 32],
        posicion,
    }
}

fn contenidos<'a>(mapa: &'a [u8], claves: ClavesExplicitas<'a>) -> [ContenidoObjeto<'a>; 7] {
    [
        S,
        ContenidoObjeto::SubredReferencia {
            origen: origen(POSICION_SUBRED),
            subred: 3,
            mapa,
        },
        ContenidoObjeto::CertificadoReferencia {
            origen: origen(9),
            mapa,
        },
        ContenidoObjeto::ActaReferencia {
            origen: origen(9),
            mapa,
        },
        ContenidoObjeto::SubredExplicita { subred: 3, claves },
        ContenidoObjeto::CertificadoExplicito { claves },
        ContenidoObjeto::ActaExplicita { claves },
    ]
}

fn evidencia<'a>(uno: ContenidoObjeto<'a>, dos: ContenidoObjeto<'a>) -> EvidenciaAgregadosV3<'a> {
    EvidenciaAgregadosV3 {
        reportero: ClavePublica::desde_bytes([0x88; 32]),
        objeto1: ObjetoEvidencia {
            voto: voto(7),
            contenido: uno,
        },
        objeto2: ObjetoEvidencia {
            voto: voto(8),
            contenido: dos,
        },
    }
}

fn clases() -> [ContenidoObjeto<'static>; 7] {
    contenidos(MAPA, ClavesExplicitas::desde_bytes(CLAVE).unwrap())
}

fn bytes_s() -> Vec<u8> {
    codificar(&evidencia(S, S)).unwrap()
}

fn cambiar_u32(bytes: &mut [u8], offset: usize, valor: u32) {
    bytes[offset..offset + 4].copy_from_slice(&valor.to_le_bytes());
}

// Instrumenta solo el hilo actual. Las aserciones y la preparación ocurren con el contador apagado.
#[allow(
    unsafe_code,
    reason = "instrumentación aislada de GlobalAlloc, delegada a System; no producto"
)]
mod asignaciones {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static ACTIVO: Cell<bool> = const { Cell::new(false) };
        static LLAMADAS: Cell<usize> = const { Cell::new(0) };
        static BYTES: Cell<usize> = const { Cell::new(0) };
    }

    pub struct Espia;

    fn contar(bytes: usize) {
        let _ = ACTIVO.try_with(|activo| {
            if activo.get() {
                let _ = LLAMADAS.try_with(|n| n.set(n.get() + 1));
                let _ = BYTES.try_with(|n| n.set(n.get() + bytes));
            }
        });
    }

    // SAFETY: cada operación se delega tal cual en `System`; `contar` solo actualiza contadores
    // `thread_local` de tipo `Cell` y no reserva memoria, así que no hay reentrada en el asignador.
    unsafe impl GlobalAlloc for Espia {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            contar(layout.size());
            // SAFETY: quien llama cumple el contrato de `GlobalAlloc`; la reserva se
            // delega tal cual en `System`.
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            contar(layout.size());
            // SAFETY: quien llama cumple el contrato de `GlobalAlloc`; la reserva se
            // delega tal cual en `System`.
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            contar(size);
            // SAFETY: puntero, `Layout` y tamaño nuevo cumplen el contrato de
            // `GlobalAlloc::realloc`; la reserva la hizo `System`, que es quien la amplía.
            unsafe { System.realloc(ptr, layout, size) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: el puntero y su `Layout` vienen de una reserva que hizo `System`
            // a través de este asignador.
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    pub fn contar_llamadas<T>(f: impl FnOnce() -> T) -> (T, usize) {
        let (valor, llamadas, _) = contar_reservas(f);
        (valor, llamadas)
    }

    pub fn contar_reservas<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
        LLAMADAS.with(|n| n.set(0));
        BYTES.with(|n| n.set(0));
        ACTIVO.with(|a| a.set(true));
        let valor = f();
        ACTIVO.with(|a| a.set(false));
        (valor, LLAMADAS.with(Cell::get), BYTES.with(Cell::get))
    }
}

#[global_allocator]
static ASIGNADOR: asignaciones::Espia = asignaciones::Espia;

fn rechaza(bytes: &[u8], esperado: Error) {
    let (resultado, reservas) = asignaciones::contar_llamadas(|| decodificar(bytes));
    assert_eq!(resultado, Err(esperado));
    assert_eq!(reservas, 0, "decodificador reservó al rechazar");
    let (resultado, reservas) = asignaciones::contar_llamadas(|| validar_forma_bytes(bytes));
    assert_eq!(resultado, Err(esperado));
    assert_eq!(reservas, 0, "validador reservó al rechazar");
}

#[test]
fn ea_49_parejas_y_modos_ida_vuelta_determinista() {
    for uno in clases() {
        for dos in clases() {
            let mut ea = evidencia(uno, dos);
            for misma_ventana in [false, true] {
                if misma_ventana {
                    ea.objeto2.voto.n = 7;
                    ea.objeto2.voto.raiz_estado = [0x34; 32];
                }
                let bytes = codificar(&ea).unwrap();
                assert_eq!(longitud_canonica(&ea), Ok(bytes.len()));
                assert_eq!(codificar(&ea).unwrap(), bytes);
                let (decoded, reservas) = asignaciones::contar_llamadas(|| decodificar(&bytes));
                assert_eq!(reservas, 0);
                assert_eq!(decoded, Ok(ea));
                assert_eq!(codificar(&decoded.unwrap()).unwrap(), bytes);
            }
        }
    }
}

#[test]
fn ea_vectores_hex_independientes_de_las_siete_formas() {
    let payloads = [
        HEX_S, HEX_L_REF, HEX_C_REF, HEX_A_REF, HEX_L_EXP, HEX_C_EXP, HEX_A_EXP,
    ];
    let tags_modos = [(0, 0), (1, 0), (2, 0), (3, 0), (1, 1), (2, 1), (3, 1)];
    for ((contenido, hex_payload), (tag, modo)) in
        clases().into_iter().zip(payloads).zip(tags_modos)
    {
        let ea = evidencia(contenido, contenido);
        let mut esperado = hex::decode("0c03").unwrap();
        esperado.extend_from_slice(&[0x88; 32]);
        let payload = hex::decode(hex_payload).unwrap();
        for n in [7_u64, 8] {
            esperado.extend_from_slice(&[tag, modo]);
            esperado.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            let mut p = payload.clone();
            p[..8].copy_from_slice(&n.to_le_bytes());
            esperado.extend_from_slice(&p);
        }
        assert_eq!(codificar(&ea).unwrap(), esperado);
        assert_eq!(decodificar(&esperado).unwrap(), ea);
    }
}

#[test]
fn ea_tabla_tamanos_referencia_seis_familias() {
    // Fórmulas independientes de EA-R4 v3, ya con los 80 B del sobre tx.
    let c = clases();
    let casos = [
        (0, 0, 622),
        (0, 1, 645),
        (0, 2, 643),
        (1, 1, 668),
        (1, 2, 666),
        (2, 3, 664),
    ];
    for (a, b, total) in casos {
        assert_eq!(codificar(&evidencia(c[a], c[b])).unwrap().len() + 80, total);
    }
}

#[test]
fn ea_tabla_tamanos_explicitos_seis_familias() {
    let c = clases();
    let casos = [
        (0, 0, 622),
        (0, 4, 628),
        (0, 5, 626),
        (4, 4, 634),
        (4, 5, 632),
        (5, 6, 630),
    ];
    for (a, b, total) in casos {
        assert_eq!(codificar(&evidencia(c[a], c[b])).unwrap().len() + 80, total);
    }
}

fn claves_ordenadas(m: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(48 * m);
    for i in 0..m {
        bytes.extend_from_slice(&(i as u32).to_be_bytes());
        bytes.extend_from_slice(&[0; 44]);
    }
    bytes
}

#[test]
fn ea_maximos_referencia_17050_y_17046() {
    let mapa = [0xff; MAX_MAPA_BYTES];
    let c = contenidos(&mapa, ClavesExplicitas::desde_bytes(CLAVE).unwrap());
    for (indice, total) in [(1, 17050), (2, 17046), (3, 17046)] {
        let ea = evidencia(c[indice], c[indice]);
        let bytes = codificar(&ea).unwrap();
        assert_eq!(bytes.len() + 80, total);
        assert_eq!(carga(&ea.objeto1), Ok(65536));
        assert_eq!(decodificar(&bytes).unwrap(), ea);
    }
}

#[test]
fn ea_1024_claves_dos_subredes_98842_y_maximo_65536() {
    for (m, totales) in [(1024, [98842, 98838]), (MAX_CLAVES, [6291994, 6291990])] {
        let claves = claves_ordenadas(m);
        let c = contenidos(MAPA, ClavesExplicitas::desde_bytes(&claves).unwrap());
        for (indice, total) in [(4, totales[0]), (5, totales[1]), (6, totales[1])] {
            let ea = evidencia(c[indice], c[indice]);
            let bytes = codificar(&ea).unwrap();
            assert_eq!(bytes.len() + 80, total);
            assert_eq!(carga(&ea.objeto1), Ok(m as u32));
            let (decoded, reservas) = asignaciones::contar_llamadas(|| decodificar(&bytes));
            assert_eq!(reservas, 0);
            assert_eq!(decoded, Ok(ea));
            assert_eq!(codificar(&decoded.unwrap()).unwrap(), bytes);
        }
    }
}

#[test]
fn ea_carga_popcount_y_m_sin_inferir_pesos() {
    let mapa = [0b1000_0001, 0b0101_1010];
    let claves = claves_ordenadas(3);
    let c = contenidos(&mapa, ClavesExplicitas::desde_bytes(&claves).unwrap());
    for (contenido, esperada) in c.into_iter().zip([1, 6, 6, 6, 3, 3, 3]) {
        assert_eq!(
            carga(&ObjetoEvidencia {
                voto: voto(7),
                contenido
            }),
            Ok(esperada)
        );
    }
}

#[test]
fn ea_preimagen_dominio_propio_y_canonica_sin_testigo() {
    assert_eq!(&DOMINIO_REPORTERO, b"ZZKTxSigEAgV3___");
    assert_ne!(&DOMINIO_REPORTERO, b"ZZKTxSigEAgV2___");
    assert_ne!(&DOMINIO_REPORTERO, b"ZZKTxSigAlmacen_");
    for contenido in clases() {
        let ea = evidencia(contenido, S);
        let p = preimagen_reportero(&ea).unwrap();
        assert_eq!(&p[..16], &DOMINIO_REPORTERO);
        assert_eq!(&p[16..], codificar(&ea).unwrap());
        let mut distinta = ea;
        distinta.reportero = ClavePublica::desde_bytes([0x87; 32]);
        assert_ne!(p, preimagen_reportero(&distinta).unwrap());
    }
}

#[test]
fn ea_clase_version_etiqueta_modo_y_voto_explicito() {
    for (offset, valor, error) in [
        (0, 0x0b, Error::ClaseDesconocida(0x0b)),
        (1, 1, Error::VersionInvalida(1)),
        (34, 4, Error::EtiquetaDesconocida(4)),
        (35, 2, Error::ModoDesconocido(2)),
        (35, 1, Error::VotoExplicito),
    ] {
        let mut bytes = bytes_s();
        bytes[offset] = valor;
        rechaza(&bytes, error);
    }
    for version in [0, 4, 255] {
        let mut b = bytes_s();
        b[1] = version;
        rechaza(&b, Error::VersionInvalida(version));
    }
}

#[test]
fn ea_longitudes_corta_larga_y_u32_max_sin_reserva() {
    for (len, error) in [
        (
            247,
            Error::LongitudCorta {
                declarada: 247,
                esperada: 248,
            },
        ),
        (
            249,
            Error::LongitudLarga {
                declarada: 249,
                esperada: 248,
            },
        ),
        (
            u32::MAX,
            Error::LongitudLarga {
                declarada: u32::MAX as usize,
                esperada: 248,
            },
        ),
    ] {
        let mut bytes = bytes_s();
        cambiar_u32(&mut bytes, 36, len);
        rechaza(&bytes, error);
    }
    // Segundo objeto adversarial: ni siquiera la lectura válida del primero reserva.
    let mut bytes = bytes_s();
    cambiar_u32(&mut bytes, 290, u32::MAX);
    rechaza(
        &bytes,
        Error::LongitudLarga {
            declarada: u32::MAX as usize,
            esperada: 248,
        },
    );
}

#[test]
fn ea_longitud_declarada_no_coincide_con_m() {
    for contenido in [clases()[4], clases()[5], clases()[6]] {
        let ea = evidencia(contenido, S);
        let original = codificar(&ea).unwrap();
        let fijo = if matches!(contenido, ContenidoObjeto::SubredExplicita { .. }) {
            206
        } else {
            204
        };
        let m_offset = 40 + fijo - 4;
        let mut bytes = original.clone();
        cambiar_u32(&mut bytes, m_offset, 2);
        rechaza(
            &bytes,
            Error::LongitudCorta {
                declarada: fijo + 48,
                esperada: fijo + 96,
            },
        );
        let mut bytes = original;
        cambiar_u32(&mut bytes, 36, (fijo + 49) as u32);
        bytes.insert(40 + fijo + 48, 0);
        rechaza(
            &bytes,
            Error::LongitudLarga {
                declarada: fijo + 49,
                esperada: fijo + 48,
            },
        );
    }
}

#[test]
fn ea_m_cero_65537_y_u32_max_antes_de_reserva() {
    for contenido in [clases()[4], clases()[5], clases()[6]] {
        let fijo = if matches!(contenido, ContenidoObjeto::SubredExplicita { .. }) {
            206
        } else {
            204
        };
        for (m, error) in [
            (0, Error::NumeroClavesCero),
            (65537, Error::DemasiadasClaves(65537)),
            (u32::MAX, Error::DemasiadasClaves(u32::MAX as usize)),
        ] {
            let mut bytes = codificar(&evidencia(contenido, S)).unwrap();
            cambiar_u32(&mut bytes, 40 + fijo - 4, m);
            rechaza(&bytes, error);
        }
    }
}

#[test]
fn ea_claves_repetidas_y_desordenadas_rechazadas_sin_reserva() {
    let buenas = claves_ordenadas(2);
    let c = contenidos(MAPA, ClavesExplicitas::desde_bytes(&buenas).unwrap());
    for contenido in [c[4], c[5], c[6]] {
        let fijo = if matches!(contenido, ContenidoObjeto::SubredExplicita { .. }) {
            206
        } else {
            204
        };
        let original = codificar(&evidencia(contenido, S)).unwrap();
        let mut repetidas = original.clone();
        repetidas[40 + fijo + 48..40 + fijo + 96].copy_from_slice(&buenas[..48]);
        rechaza(&repetidas, Error::ClaveRepetida);
        let mut inversas = original;
        inversas[40 + fijo..40 + fijo + 48].copy_from_slice(&buenas[48..]);
        inversas[40 + fijo + 48..40 + fijo + 96].copy_from_slice(&buenas[..48]);
        rechaza(&inversas, Error::ClavesDesordenadas);
    }
}

#[test]
fn ea_constructor_claves_rechaza_longitud_y_numero() {
    assert_eq!(
        ClavesExplicitas::desde_bytes(&[]),
        Err(Error::NumeroClavesCero)
    );
    assert_eq!(
        ClavesExplicitas::desde_bytes(&[0; 47]),
        Err(Error::ClaveIncompleta(47))
    );
    let demasiadas = vec![0; 48 * 65537];
    let (resultado, reservas) =
        asignaciones::contar_llamadas(|| ClavesExplicitas::desde_bytes(&demasiadas));
    assert_eq!(resultado, Err(Error::DemasiadasClaves(65537)));
    assert_eq!(reservas, 0);
}

#[test]
fn ea_subred_64_referencia_y_explicita() {
    for (indice, offset) in [(1, 40 + 268), (4, 40 + 200)] {
        let mut bytes = codificar(&evidencia(clases()[indice], S)).unwrap();
        bytes[offset..offset + 2].copy_from_slice(&64_u16.to_le_bytes());
        rechaza(&bytes, Error::SubredInvalida(64));
    }
}

#[test]
fn ea_mapa_vacio_y_cero_y_sobredimensionado() {
    for indice in [1, 2, 3] {
        let c = clases()[indice];
        let fijo = if indice == 1 { 270 } else { 268 };
        let original = codificar(&evidencia(c, S)).unwrap();
        let mut cero = original.clone();
        cero[40 + fijo] = 0;
        rechaza(&cero, Error::MapaVacio);
        let mut vacio = original;
        cambiar_u32(&mut vacio, 36, fijo as u32);
        vacio.remove(40 + fijo);
        rechaza(&vacio, Error::MapaVacio);
        let mut largo = codificar(&evidencia(clases()[indice], S)).unwrap();
        cambiar_u32(&mut largo, 36, (fijo + MAX_MAPA_BYTES + 1) as u32);
        // La longitud basta para rechazar: ni siquiera exige esos bytes en el buffer.
        rechaza(&largo, Error::MapaDemasiadoLargo(MAX_MAPA_BYTES + 1));
        let mapa = vec![1; MAX_MAPA_BYTES + 1];
        let c = contenidos(&mapa, ClavesExplicitas::desde_bytes(CLAVE).unwrap());
        let ea = evidencia(c[indice], S);
        assert_eq!(
            validar_forma(&ea),
            Err(Error::MapaDemasiadoLargo(MAX_MAPA_BYTES + 1))
        );
        let (resultado, reservas) = asignaciones::contar_llamadas(|| codificar(&ea));
        assert_eq!(
            resultado,
            Err(Error::MapaDemasiadoLargo(MAX_MAPA_BYTES + 1))
        );
        assert_eq!(reservas, 0);
    }
}

#[test]
fn ea_locators_con_posicion_invalida() {
    let mut b = codificar(&evidencia(clases()[1], S)).unwrap();
    cambiar_u32(&mut b, 40 + 264, 9);
    rechaza(&b, Error::PosicionSubredInvalida(9));
    for indice in [2, 3] {
        let mut b = codificar(&evidencia(clases()[indice], S)).unwrap();
        cambiar_u32(&mut b, 40 + 264, u32::MAX);
        rechaza(&b, Error::PosicionOperacionInvalida);
    }
}

#[test]
fn ea_mensajes_iguales_e_inversos_firmas_y_tags_no_cuentan() {
    for uno in clases() {
        for dos in clases() {
            let mut ea = evidencia(uno, dos);
            let mut bytes = codificar(&ea).unwrap();
            let segundo = 40 + longitud_canonica(&evidencia(uno, S)).unwrap() - 46 - 248;
            // segundo apunta al marco 2; payload empieza seis bytes después.
            bytes[segundo + 6..segundo + 14].copy_from_slice(&7_u64.to_le_bytes());
            rechaza(&bytes, Error::MensajesIguales);
            ea.objeto2.voto.n = 6;
            let mut inversos = codificar(&evidencia(uno, dos)).unwrap();
            inversos[segundo + 6..segundo + 14].copy_from_slice(&6_u64.to_le_bytes());
            rechaza(&inversos, Error::MensajesInvertidos);
            assert_eq!(codificar(&ea), Err(Error::MensajesInvertidos));
            ea.objeto2.voto.n = 7;
            ea.objeto2.voto.firma = [0xaa; 96];
            assert_eq!(validar_forma(&ea), Err(Error::MensajesIguales));
        }
    }
}

#[test]
fn ea_orden_por_cada_campo_y_n_numerico() {
    let mut ea = evidencia(S, S);
    ea.objeto1.voto.n = 255;
    ea.objeto2.voto.n = 256;
    assert!(codificar(&ea).is_ok()); // Little-endian del wire no determina el orden.
    ea.objeto2.voto.n = 255;
    for campo in 0..3 {
        ea.objeto2.voto = ea.objeto1.voto;
        match campo {
            0 => ea.objeto2.voto.candidato = [0x12; 32],
            1 => ea.objeto2.voto.h_t_siguiente = [0x23; 32],
            _ => ea.objeto2.voto.raiz_estado = [0x34; 32],
        }
        assert!(validar_forma(&ea).is_ok());
        std::mem::swap(&mut ea.objeto1, &mut ea.objeto2);
        assert_eq!(validar_forma(&ea), Err(Error::MensajesInvertidos));
        std::mem::swap(&mut ea.objeto1, &mut ea.objeto2);
    }
}

#[test]
fn ea_todos_los_prefijos_truncados_y_bytes_sobrantes() {
    for contenido in clases() {
        let bytes = codificar(&evidencia(contenido, contenido)).unwrap();
        for longitud in 0..bytes.len() {
            let (resultado, reservas) =
                asignaciones::contar_llamadas(|| decodificar(&bytes[..longitud]));
            assert!(matches!(resultado, Err(Error::Truncado { .. })));
            assert_eq!(reservas, 0);
        }
        let mut sobrantes = bytes;
        sobrantes.push(0);
        rechaza(&sobrantes, Error::BytesSobrantes(1));
    }
}

#[test]
fn ea_campo_sin_contexto_y_sin_criptografia_se_expone_sin_inventar() {
    // No conoce N: el último byte conserva bits altos y cero final; tampoco valida firmas.
    let mapa = [0x80, 0];
    let contenido = ContenidoObjeto::CertificadoReferencia {
        origen: origen(9),
        mapa: &mapa,
    };
    let mut ea = evidencia(contenido, S);
    ea.objeto1.voto.firma = [0; 96];
    let bytes = codificar(&ea).unwrap();
    let decoded = decodificar(&bytes).unwrap();
    assert_eq!(decoded.objeto1.contenido, contenido);
    assert_eq!(carga(&decoded.objeto1), Ok(1));
    if let ContenidoObjeto::CertificadoReferencia { mapa: prestado, .. } = decoded.objeto1.contenido
    {
        assert_eq!(prestado.as_ptr(), bytes[40 + 268..].as_ptr());
    }
}

#[test]
fn ea_operacion_completa_sigue_rechazada_por_parser_tx() {
    for contenido in clases() {
        let bytes = codificar(&evidencia(contenido, contenido)).unwrap();
        let mut tx = hex::decode("0600000000000000000000000000").unwrap();
        tx.extend_from_slice(&bytes);
        tx.extend_from_slice(&[1, 64]);
        tx.extend_from_slice(&[0; 64]);
        assert!(matches!(
            zx_core::wire::tx_desde_bytes(&tx),
            Err(EncodingError::OperacionAlmacenamientoInvalida(
                ErrorCodecAlmacenamiento::DiscriminanteInvalido(0x0c)
            ))
        ));
    }
}

#[test]
fn ea_v2_incompatible_antes_de_leer_cabecera_y_sin_reserva() {
    // Wire v2 completo e independiente: K exterior y S de 200 B, sin K interna.
    let mut antigua = hex::decode("0c02").unwrap();
    antigua.extend_from_slice(&[0x88; 32]);
    antigua.extend_from_slice(&[0x99; 48]);
    let mut payload = hex::decode(HEX_S).unwrap();
    payload.truncate(200);
    for n in [7_u64, 8] {
        antigua.extend_from_slice(&[0, 0]);
        antigua.extend_from_slice(&200_u32.to_le_bytes());
        payload[..8].copy_from_slice(&n.to_le_bytes());
        antigua.extend_from_slice(&payload);
    }
    assert_eq!(antigua.len(), 494);
    rechaza(&antigua, Error::Version2Incompatible);
    rechaza(&[0x0c, 2], Error::Version2Incompatible);
    let mut v3_con_version_antigua = bytes_s();
    v3_con_version_antigua[1] = 2;
    rechaza(&v3_con_version_antigua, Error::Version2Incompatible);
}

#[test]
fn ea_v3_cinco_tamanos_del_contrato() {
    let ss = evidencia(S, S);
    assert_eq!(longitud_canonica(&ss).unwrap() - 2 * 248 + 80, 126);
    assert_eq!(codificar(&ss).unwrap().len() + 80, 622);
    let mapa = [0xff; MAX_MAPA_BYTES];
    let claves = claves_ordenadas(1024);
    let c = contenidos(&mapa, ClavesExplicitas::desde_bytes(&claves).unwrap());
    for (a, b, total) in [
        (2, 2, 17046),
        (2, 3, 17046),
        (3, 3, 17046),
        (1, 1, 17050),
        (4, 4, 98842),
    ] {
        let ea = evidencia(c[a], c[b]);
        assert_eq!(longitud_canonica(&ea).unwrap() + 80, total);
        let bytes = codificar(&ea).unwrap();
        assert_eq!(bytes.len() + 80, total);
        assert_eq!(decodificar(&bytes), Ok(ea));
    }
}

fn objeto(contenido: ContenidoObjeto<'_>) -> ObjetoEvidencia<'_> {
    ObjetoEvidencia {
        voto: voto(7),
        contenido,
    }
}

fn explicitos(claves: ClavesExplicitas<'_>) -> [ContenidoObjeto<'_>; 3] {
    [
        ContenidoObjeto::SubredExplicita { subred: 3, claves },
        ContenidoObjeto::CertificadoExplicito { claves },
        ContenidoObjeto::ActaExplicita { claves },
    ]
}

fn comunes_comprobadas(uno: ContenidoObjeto<'_>, dos: ContenidoObjeto<'_>, esperado: &[[u8; 48]]) {
    let a = objeto(uno);
    let b = objeto(dos);
    let (resultado, llamadas, bytes) = asignaciones::contar_reservas(|| claves_comunes(&a, &b));
    let resultado = resultado.unwrap();
    assert_eq!(resultado, esperado);
    assert_eq!(resultado.capacity(), esperado.len());
    assert_eq!(llamadas, usize::from(!esperado.is_empty()));
    assert_eq!(bytes, 48 * esperado.len());
}

fn claves_seleccionadas(indices: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(48 * indices.len());
    for i in indices {
        bytes.extend_from_slice(&i.to_be_bytes());
        bytes.extend_from_slice(&[0; 44]);
    }
    bytes
}

#[test]
fn ea_comunes_nueve_parejas_explicitas_disjuntas_una_todas() {
    for (a, b) in [
        (&[1, 3][..], &[2, 4][..]),
        (&[1, 2, 4][..], &[0, 2, 3][..]),
        (&[0, 2, 4][..], &[0, 2, 4][..]),
    ] {
        let uno = claves_seleccionadas(a);
        let dos = claves_seleccionadas(b);
        // Oráculo pequeño deliberadamente distinto de la fusión: búsqueda exhaustiva K48.
        let esperado: Vec<[u8; 48]> = uno
            .chunks_exact(48)
            .filter(|k| dos.chunks_exact(48).any(|otra| *k == otra))
            .map(|k| k.try_into().unwrap())
            .collect();
        for c1 in explicitos(ClavesExplicitas::desde_bytes(&uno).unwrap()) {
            for c2 in explicitos(ClavesExplicitas::desde_bytes(&dos).unwrap()) {
                comunes_comprobadas(c1, c2, &esperado);
                comunes_comprobadas(c2, c1, &esperado);
            }
        }
    }
}

#[test]
fn ea_comunes_nueve_parejas_explicitas_65536_solo_reserva_resultado() {
    let bytes = claves_ordenadas(MAX_CLAVES);
    let claves = ClavesExplicitas::desde_bytes(&bytes).unwrap();
    let esperado: Vec<[u8; 48]> = bytes
        .chunks_exact(48)
        .map(|k| k.try_into().unwrap())
        .collect();
    for uno in explicitos(claves) {
        for dos in explicitos(claves) {
            comunes_comprobadas(uno, dos, &esperado);
        }
    }
}

#[test]
fn ea_comunes_voto_voto_clave_igual_y_distinta_por_48_bytes() {
    let mut otra = [0x99; 48];
    otra[47] = 0x98;
    comunes_comprobadas(S, S, &[[0x99; 48]]);
    comunes_comprobadas(S, ContenidoObjeto::Voto { clave: otra }, &[]);
    comunes_comprobadas(ContenidoObjeto::Voto { clave: otra }, S, &[]);
    let ea = evidencia(S, ContenidoObjeto::Voto { clave: otra });
    let bytes = codificar(&ea).unwrap();
    assert_eq!(bytes.len(), 542);
    assert_eq!(decodificar(&bytes), Ok(ea));
    assert_eq!(carga(&ea.objeto1), Ok(1));
    assert_eq!(carga(&ea.objeto2), Ok(1));
    assert_ne!(
        preimagen_reportero(&ea).unwrap(),
        preimagen_reportero(&evidencia(S, S)).unwrap()
    );
    let mut mismos_mensajes = ea;
    mismos_mensajes.objeto2.voto = mismos_mensajes.objeto1.voto;
    assert_eq!(validar_forma(&mismos_mensajes), Err(Error::MensajesIguales));
}

#[test]
fn ea_comunes_voto_con_tres_explicitos_en_ambos_ordenes() {
    let bytes = claves_seleccionadas(&[1, 2, 4]);
    let claves = ClavesExplicitas::desde_bytes(&bytes).unwrap();
    for indice in [0_u32, 1, 2, 3, 4, 5] {
        let mut clave = [0; 48];
        clave[..4].copy_from_slice(&indice.to_be_bytes());
        let s = ContenidoObjeto::Voto { clave };
        let esperado = if [1, 2, 4].contains(&indice) {
            vec![clave]
        } else {
            vec![]
        };
        for c in explicitos(claves) {
            comunes_comprobadas(s, c, &esperado);
            comunes_comprobadas(c, s, &esperado);
        }
    }
}

#[test]
fn ea_comunes_explicitos_comparan_tambien_ultimo_byte() {
    let mut uno = [[7; 48]; 2];
    uno[0][47] = 1;
    uno[1][47] = 3;
    let mut dos = [[7; 48]; 2];
    dos[0][47] = 2;
    dos[1][47] = 3;
    let bytes1 = uno.concat();
    let bytes2 = dos.concat();
    for a in explicitos(ClavesExplicitas::desde_bytes(&bytes1).unwrap()) {
        for b in explicitos(ClavesExplicitas::desde_bytes(&bytes2).unwrap()) {
            comunes_comprobadas(a, b, &[uno[1]]);
        }
    }
}

#[test]
fn ea_comunes_referencias_exigen_tabla_sin_reserva_ni_inferir_posiciones() {
    for uno in clases() {
        for dos in clases() {
            if !matches!(
                uno,
                ContenidoObjeto::SubredReferencia { .. }
                    | ContenidoObjeto::CertificadoReferencia { .. }
                    | ContenidoObjeto::ActaReferencia { .. }
            ) && !matches!(
                dos,
                ContenidoObjeto::SubredReferencia { .. }
                    | ContenidoObjeto::CertificadoReferencia { .. }
                    | ContenidoObjeto::ActaReferencia { .. }
            ) {
                continue;
            }
            let a = objeto(uno);
            let b = objeto(dos);
            let (resultado, llamadas, bytes) =
                asignaciones::contar_reservas(|| claves_comunes(&a, &b));
            assert_eq!(resultado, Err(Error::TablaReferenciaNecesaria));
            assert_eq!((llamadas, bytes), (0, 0));
        }
    }
}

#[test]
fn ea_comunes_validan_ambos_objetos_antes_de_reservar() {
    let claves = ClavesExplicitas::desde_bytes(CLAVE).unwrap();
    for (contenido, error) in [
        (
            ContenidoObjeto::SubredExplicita { subred: 64, claves },
            Error::SubredInvalida(64),
        ),
        (
            ContenidoObjeto::CertificadoReferencia {
                origen: origen(9),
                mapa: &[],
            },
            Error::MapaVacio,
        ),
    ] {
        for (uno, dos) in [(S, contenido), (contenido, S)] {
            let a = objeto(uno);
            let b = objeto(dos);
            let (resultado, llamadas, bytes) =
                asignaciones::contar_reservas(|| claves_comunes(&a, &b));
            assert_eq!(resultado, Err(error));
            assert_eq!((llamadas, bytes), (0, 0));
        }
    }
}
