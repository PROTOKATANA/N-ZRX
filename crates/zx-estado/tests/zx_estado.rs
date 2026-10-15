//! Pruebas del crate `zx-estado` (nombres fijos de `P-ZRX/P-004/ORDEN-RE1C.md` §3).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "las pruebas fallan con panic por diseño"
)]

use zx_estado::{
    Almacen, AlmacenEnMemoria, Cambio, Camino, CaminoSha3, Estado, Prueba, SplitMix64,
    TAMANO_MAXIMO_PRUEBA, Terminal, hash_valor, verificar,
};

/// Familia A de las pruebas (`utxo`).
const FAM_A: u8 = 0x01;
/// Familia B de las pruebas (`garantias`).
const FAM_B: u8 = 0x02;

fn nuevo() -> Estado<AlmacenEnMemoria> {
    Estado::nuevo(AlmacenEnMemoria::nuevo(), CaminoSha3)
}

fn clave(i: usize) -> Vec<u8> {
    format!("clave-{i:08}").into_bytes()
}

fn valor(i: usize) -> Vec<u8> {
    format!("valor-{i:08}").into_bytes()
}

fn base(m: usize) -> Vec<Cambio> {
    (0..m)
        .map(|i| Cambio::poner(FAM_A, clave(i), valor(i)))
        .collect()
}

/// Función de camino de prueba: los 7 primeros bytes de la clave.
///
/// Permite forzar colisiones de 56 bits y cadenas de profundidad máxima sin depender de encontrar
/// una colisión real de SHA3.
#[derive(Clone, Copy)]
struct CaminoDirecto;

impl Camino for CaminoDirecto {
    fn camino(&self, _familia: u8, clave: &[u8]) -> [u8; 7] {
        let mut p = [0u8; 7];
        for (destino, origen) in p.iter_mut().zip(clave.iter()) {
            *destino = *origen;
        }
        p
    }
}

fn nuevo_directo() -> Estado<AlmacenEnMemoria, CaminoDirecto> {
    Estado::nuevo(AlmacenEnMemoria::nuevo(), CaminoDirecto)
}

#[test]
fn raiz_determinista() {
    let cambios = base(64);
    let mut e1 = nuevo();
    let mut e2 = nuevo();
    let r1 = e1.aplicar(&cambios, 1).unwrap();
    let r2 = e2.aplicar(&cambios, 1).unwrap();
    assert_eq!(r1, r2);
    let h_escalares = hash_valor(b"escalares-de-prueba");
    assert_eq!(
        e1.raiz_estado(&h_escalares).unwrap(),
        e2.raiz_estado(&h_escalares).unwrap()
    );
}

#[test]
fn raiz_sensible_a_cada_entrada_y_familia() {
    // Cambiar el valor de cada entrada cambia la raíz.
    for i in 0..24usize {
        let mut estado = nuevo();
        estado.aplicar(&base(24), 1).unwrap();
        let antes = estado.raiz_familia(FAM_A).unwrap();
        estado
            .aplicar(&[Cambio::poner(FAM_A, clave(i), valor(i + 1_000))], 1)
            .unwrap();
        let despues = estado.raiz_familia(FAM_A).unwrap();
        assert_ne!(antes, despues, "cambiar la entrada {i} no cambió la raíz");
    }

    // Cambiar la familia (misma clave y valor) cambia la raíz de estado.
    let h_escalares = hash_valor(b"escalares-de-prueba");
    let mut en_a = nuevo();
    en_a.aplicar(&[Cambio::poner(FAM_A, clave(1), valor(1))], 1)
        .unwrap();
    let mut en_b = nuevo();
    en_b.aplicar(&[Cambio::poner(FAM_B, clave(1), valor(1))], 1)
        .unwrap();
    let ra = en_a.raiz_estado(&h_escalares).unwrap();
    let rb = en_b.raiz_estado(&h_escalares).unwrap();
    assert_ne!(ra, rb, "la misma entrada en otra familia no cambió la raíz");
}

#[test]
fn lote_igual_que_uno_a_uno() {
    let mut por_lote = nuevo();
    let mut uno_a_uno = nuevo();
    por_lote.aplicar(&base(40), 1).unwrap();
    uno_a_uno.aplicar(&base(40), 1).unwrap();

    let mut lote = vec![
        Cambio::poner(FAM_A, clave(3), valor(300)),
        Cambio::poner(FAM_B, clave(3), valor(303)),
        Cambio::borrar(FAM_A, clave(7)),
        Cambio::poner(FAM_A, clave(7), valor(700)),
        Cambio::poner(FAM_A, clave(99), valor(999)),
        Cambio::borrar(FAM_B, clave(20)),
        Cambio::poner(FAM_A, clave(3), valor(301)),
    ];
    lote.push(Cambio::borrar(FAM_A, clave(99)));

    let normalizado = zx_estado::normalizar(&lote, &CaminoSha3);
    let r_lote = por_lote.aplicar(&lote, 1).unwrap();
    for cambio in &normalizado {
        uno_a_uno.aplicar(std::slice::from_ref(cambio), 1).unwrap();
    }
    assert_eq!(r_lote, uno_a_uno.raices().unwrap());
    assert_eq!(
        por_lote.raiz_estado(&hash_valor(b"e")).unwrap(),
        uno_a_uno.raiz_estado(&hash_valor(b"e")).unwrap()
    );
}

#[test]
fn lote_igual_que_reconstruir() {
    let mut estado = nuevo();
    estado.aplicar(&base(80), 1).unwrap();
    let lote = vec![
        Cambio::poner(FAM_A, clave(5), valor(500)),
        Cambio::poner(FAM_A, clave(120), valor(1_200)),
        Cambio::borrar(FAM_A, clave(9)),
        Cambio::borrar(FAM_A, clave(10)),
        Cambio::poner(FAM_A, clave(11), valor(1_100)),
    ];
    let raices = estado.aplicar(&lote, 1).unwrap();
    let raiz = raices.first().unwrap().1;
    assert_eq!(estado.reconstruir_familia(FAM_A).unwrap(), raiz);
}

#[test]
fn orden_de_entrada_del_lote_no_importa() {
    let mut e1 = nuevo();
    let mut e2 = nuevo();
    e1.aplicar(&base(50), 1).unwrap();
    e2.aplicar(&base(50), 1).unwrap();

    let mut lote = vec![
        Cambio::poner(FAM_A, clave(4), valor(400)),
        Cambio::borrar(FAM_A, clave(1)),
        Cambio::poner(FAM_A, clave(8), valor(800)),
        Cambio::poner(FAM_A, clave(60), valor(600)),
    ];
    let r1 = e1.aplicar(&lote, 1).unwrap();
    lote.reverse();
    let r2 = e2.aplicar(&lote, 1).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn clave_repetida_vale_la_ultima() {
    let mut por_lista = nuevo();
    let mut solo_ultima = nuevo();
    por_lista.aplicar(&base(30), 1).unwrap();
    solo_ultima.aplicar(&base(30), 1).unwrap();

    let lote = vec![
        Cambio::poner(FAM_A, clave(2), valor(201)),
        Cambio::poner(FAM_A, clave(2), valor(202)),
        Cambio::poner(FAM_A, clave(2), valor(203)),
    ];
    let normalizado = zx_estado::normalizar(&lote, &CaminoSha3);
    assert_eq!(normalizado.len(), 1);
    assert_eq!(normalizado.first().unwrap().valor, Some(valor(203)));

    let r1 = por_lista.aplicar(&lote, 1).unwrap();
    let r2 = solo_ultima
        .aplicar(&[Cambio::poner(FAM_A, clave(2), valor(203))], 1)
        .unwrap();
    assert_eq!(r1, r2);
    assert_eq!(
        por_lista.almacen().hoja(FAM_A, &clave(2)).unwrap(),
        Some(hash_valor(&valor(203)))
    );
}

#[test]
fn borrar_y_reinsertar_devuelve_la_raiz() {
    let mut estado = nuevo();
    estado.aplicar(&base(40), 1).unwrap();
    let raiz = estado.raiz_familia(FAM_A).unwrap();

    let borrados: Vec<Cambio> = (0..10).map(|i| Cambio::borrar(FAM_A, clave(i))).collect();
    estado.aplicar(&borrados, 1).unwrap();
    assert_ne!(estado.raiz_familia(FAM_A).unwrap(), raiz);

    let reinsertados: Vec<Cambio> = (0..10)
        .map(|i| Cambio::poner(FAM_A, clave(i), valor(i)))
        .collect();
    estado.aplicar(&reinsertados, 1).unwrap();
    assert_eq!(estado.raiz_familia(FAM_A).unwrap(), raiz);

    // Borrar todo y reinsertar todo vuelve exactamente a la raíz inicial.
    let todos: Vec<Cambio> = (0..40).map(|i| Cambio::borrar(FAM_A, clave(i))).collect();
    estado.aplicar(&todos, 1).unwrap();
    assert_eq!(estado.raiz_familia(FAM_A).unwrap(), zx_estado::hash_vacio());
    estado.aplicar(&base(40), 1).unwrap();
    assert_eq!(estado.raiz_familia(FAM_A).unwrap(), raiz);
}

#[test]
fn lote_con_hilos_da_la_misma_raiz() {
    let mut un_hilo = nuevo();
    let mut ocho_hilos = nuevo();
    un_hilo.aplicar(&base(60), 1).unwrap();
    ocho_hilos.aplicar(&base(60), 1).unwrap();

    // Lote desordenado y con una clave repetida: la última debe ganar en ambos caminos.
    let lote = vec![
        Cambio::poner(FAM_A, clave(5), valor(500)),
        Cambio::borrar(FAM_A, clave(2)),
        Cambio::poner(FAM_A, clave(9), valor(900)),
        Cambio::poner(FAM_B, clave(5), valor(550)),
        Cambio::poner(FAM_A, clave(5), valor(501)),
        Cambio::poner(FAM_A, clave(70), valor(700)),
        Cambio::poner(FAM_A, clave(5), valor(502)),
    ];
    let r1 = un_hilo.aplicar(&lote, 1).unwrap();
    let r8 = ocho_hilos.aplicar(&lote, 8).unwrap();
    assert_eq!(r1, r8);
    // Y la clave repetida queda con la última ocurrencia del lote (502 en FAM_A).
    let normalizado = zx_estado::normalizar(&lote, &CaminoSha3);
    let en_fam_a: Vec<&Cambio> = normalizado
        .iter()
        .filter(|c| c.familia == FAM_A && c.clave == clave(5))
        .collect();
    assert_eq!(en_fam_a.len(), 1);
    assert_eq!(en_fam_a.first().unwrap().valor, Some(valor(502)));
}

#[test]
fn prueba_de_pertenencia_verifica() {
    let mut estado = nuevo();
    estado.aplicar(&base(100), 1).unwrap();
    let raiz = estado.raiz_familia(FAM_A).unwrap();
    for i in [0usize, 1, 17, 50, 99] {
        let prueba = estado.prueba(FAM_A, &clave(i)).unwrap();
        assert!(
            estado.verificar(&raiz, FAM_A, &clave(i), Some(&valor(i)), &prueba),
            "pertenencia {i}"
        );
        // El valor equivocado no verifica.
        assert!(!estado.verificar(&raiz, FAM_A, &clave(i), Some(b"otro"), &prueba));
    }
}

#[test]
fn prueba_de_no_pertenencia_verifica() {
    let mut estado = nuevo();
    estado.aplicar(&base(100), 1).unwrap();
    let raiz = estado.raiz_familia(FAM_A).unwrap();

    // Clave ausente en una familia con árbol.
    let prueba = estado.prueba(FAM_A, b"clave-que-no-esta").unwrap();
    assert!(estado.verificar(&raiz, FAM_A, b"clave-que-no-esta", None, &prueba));
    // Una clave presente no puede probar ausencia.
    assert!(!estado.verificar(
        &raiz,
        FAM_A,
        &clave(3),
        None,
        &estado.prueba(FAM_A, &clave(3)).unwrap()
    ));

    // Clave ausente en una familia vacía.
    let vacia = estado.raiz_familia(FAM_B).unwrap();
    let prueba_vacia = estado.prueba(FAM_B, b"lo-que-sea").unwrap();
    assert!(estado.verificar(&vacia, FAM_B, b"lo-que-sea", None, &prueba_vacia));

    // La comprobación directa del módulo coincide.
    assert!(verificar(
        &CaminoSha3,
        &raiz,
        FAM_A,
        b"clave-que-no-esta",
        None,
        &estado.prueba(FAM_A, b"clave-que-no-esta").unwrap()
    ));
}

fn alterar_bit(bytes: &mut [u8], indice: usize) {
    if let Some(b) = bytes.get_mut(indice) {
        *b ^= 0x01;
    }
}

#[test]
fn prueba_alterada_no_verifica() {
    let mut estado = nuevo();
    estado.aplicar(&base(100), 1).unwrap();
    let raiz = estado.raiz_familia(FAM_A).unwrap();
    let k = clave(7);
    let v = valor(7);
    let prueba = estado.prueba(FAM_A, &k).unwrap();
    assert!(estado.verificar(&raiz, FAM_A, &k, Some(&v), &prueba));

    // Un bit en la familia.
    let mut p = prueba.clone();
    p.familia ^= 0x01;
    assert!(
        !estado.verificar(&raiz, FAM_A, &k, Some(&v), &p),
        "familia alterada verifica"
    );

    // Un bit en la clave.
    let mut p = prueba.clone();
    alterar_bit(&mut p.clave, 0);
    assert!(
        !estado.verificar(&raiz, FAM_A, &k, Some(&v), &p),
        "clave alterada verifica"
    );

    // Un bit en cada hermano del camino.
    for i in 0..prueba.camino.len() {
        let mut p = prueba.clone();
        if let Some(sib) = p.camino.get_mut(i) {
            alterar_bit(sib, 0);
        }
        assert!(
            !estado.verificar(&raiz, FAM_A, &k, Some(&v), &p),
            "hermano {i} alterado verifica"
        );
    }

    // Un bit en cada profundidad de bifurcación.
    for i in 0..prueba.split_depths.len() {
        let mut p = prueba.clone();
        if let Some(split) = p.split_depths.get_mut(i) {
            *split ^= 0x01;
        }
        assert!(
            !estado.verificar(&raiz, FAM_A, &k, Some(&v), &p),
            "split {i} alterado verifica"
        );
    }

    // Un bit en el `h_valor` del terminal.
    let mut p = prueba.clone();
    if let Terminal::Hoja(entradas) = &mut p.terminal
        && let Some((_, hv)) = entradas
            .iter_mut()
            .find(|(c, _)| c.as_slice() == k.as_slice())
    {
        alterar_bit(hv, 0);
    }
    assert!(
        !estado.verificar(&raiz, FAM_A, &k, Some(&v), &p),
        "h_valor alterado verifica"
    );

    // Un bit en la clave del terminal.
    let mut p = prueba.clone();
    if let Terminal::Hoja(entradas) = &mut p.terminal
        && let Some((c, _)) = entradas.first_mut()
    {
        alterar_bit(c, 0);
    }
    assert!(
        !estado.verificar(&raiz, FAM_A, &k, Some(&v), &p),
        "clave del terminal alterada verifica"
    );

    // Terminal vacío para una pertenencia.
    let mut p = prueba.clone();
    p.terminal = Terminal::Vacio;
    assert!(
        !estado.verificar(&raiz, FAM_A, &k, Some(&v), &p),
        "terminal vacío verifica pertenencia"
    );

    // Terminal de hoja para una no pertenencia (la clave no está en la lista).
    let mut p = estado.prueba(FAM_A, b"ausente").unwrap();
    if let Terminal::Hoja(entradas) = &mut p.terminal {
        entradas.push((k.clone(), hash_valor(&v)));
    }
    assert!(
        !estado.verificar(&raiz, FAM_A, b"ausente", None, &p),
        "hoja con la clave verifica ausencia"
    );
}

#[test]
fn prueba_contra_otra_raiz_no_verifica() {
    let mut e1 = nuevo();
    let mut e2 = nuevo();
    e1.aplicar(&base(50), 1).unwrap();
    e2.aplicar(&base(50), 1).unwrap();
    e2.aplicar(&[Cambio::poner(FAM_A, clave(1), valor(9_999))], 1)
        .unwrap();

    let raiz1 = e1.raiz_familia(FAM_A).unwrap();
    let raiz2 = e2.raiz_familia(FAM_A).unwrap();
    assert_ne!(raiz1, raiz2);
    let prueba = e1.prueba(FAM_A, &clave(1)).unwrap();
    assert!(e1.verificar(&raiz1, FAM_A, &clave(1), Some(&valor(1)), &prueba));
    assert!(!e2.verificar(&raiz2, FAM_A, &clave(1), Some(&valor(1)), &prueba));
    assert!(!e1.verificar(&raiz2, FAM_A, &clave(1), Some(&valor(1)), &prueba));
}

#[test]
fn tamano_maximo_de_prueba() {
    // Caterpillar de 57 caminos: el camino de la clave base tiene 56 bifurcaciones.
    let mut estado = nuevo_directo();
    let base_key = vec![0u8; 8];
    let mut cambios = vec![Cambio::poner(FAM_A, base_key.clone(), vec![0])];
    for i in 0u16..56 {
        let mut k = vec![0u8; 8];
        let byte = usize::from(i >> 3);
        if let Some(b) = k.get_mut(byte) {
            *b |= 1u8 << (7 - (i & 7));
        }
        if let Some(marca) = k.get_mut(7) {
            *marca = u8::try_from(i).unwrap_or(0);
        }
        cambios.push(Cambio::poner(FAM_A, k, vec![u8::try_from(i).unwrap_or(0)]));
    }
    estado.aplicar(&cambios, 1).unwrap();
    let raiz = estado.raiz_familia(FAM_A).unwrap();
    let prueba = estado.prueba(FAM_A, &base_key).unwrap();
    assert_eq!(prueba.camino.len(), 56, "profundidad del peor caso");
    let tamano = prueba.tamano().unwrap();
    assert!(
        tamano <= TAMANO_MAXIMO_PRUEBA,
        "prueba de {tamano} B supera el máximo de {TAMANO_MAXIMO_PRUEBA} B"
    );
    assert!(estado.verificar(&raiz, FAM_A, &base_key, Some(&[0u8]), &prueba));

    // Una prueba típica (no adversarial) es bastante menor.
    let mut tipico = nuevo();
    tipico.aplicar(&base(1_000), 1).unwrap();
    let raiz_t = tipico.raiz_familia(FAM_A).unwrap();
    let prueba_t = tipico.prueba(FAM_A, &clave(3)).unwrap();
    assert!(prueba_t.camino.len() < 56);
    assert!(prueba_t.tamano().unwrap() < TAMANO_MAXIMO_PRUEBA);
    assert!(tipico.verificar(&raiz_t, FAM_A, &clave(3), Some(&valor(3)), &prueba_t));
}

#[test]
fn colision_de_camino_no_pierde_datos() {
    // Dos claves distintas con los mismos 7 primeros bytes (misma ruta de 56 bits).
    let mut estado = nuevo_directo();
    let k1 = vec![0u8; 32];
    let mut k2 = vec![0u8; 32];
    if let Some(b) = k2.get_mut(20) {
        *b = 0xAB;
    }
    let v1 = b"valor-1".to_vec();
    let v2 = b"valor-2".to_vec();
    estado
        .aplicar(
            &[
                Cambio::poner(FAM_A, k1.clone(), v1.clone()),
                Cambio::poner(FAM_A, k2.clone(), v2.clone()),
            ],
            1,
        )
        .unwrap();
    let raiz = estado.raiz_familia(FAM_A).unwrap();

    let p1 = estado.prueba(FAM_A, &k1).unwrap();
    let p2 = estado.prueba(FAM_A, &k2).unwrap();
    assert!(estado.verificar(&raiz, FAM_A, &k1, Some(&v1), &p1));
    assert!(estado.verificar(&raiz, FAM_A, &k2, Some(&v2), &p2));
    // Las dos entradas viven en la misma hoja (lista de colisión).
    match (&p1.terminal, &p2.terminal) {
        (Terminal::Hoja(a), Terminal::Hoja(b)) => {
            assert_eq!(a.len(), 2, "la lista de colisión debe tener dos entradas");
            assert_eq!(b.len(), 2);
        }
        otro => panic!("terminal inesperado: {otro:?}"),
    }

    // Borrar una no pierde ni mezcla la otra.
    estado
        .aplicar(&[Cambio::borrar(FAM_A, k1.clone())], 1)
        .unwrap();
    let raiz2 = estado.raiz_familia(FAM_A).unwrap();
    assert_ne!(raiz, raiz2);
    let p2b = estado.prueba(FAM_A, &k2).unwrap();
    assert!(estado.verificar(&raiz2, FAM_A, &k2, Some(&v2), &p2b));
    let p1b = estado.prueba(FAM_A, &k1).unwrap();
    assert!(estado.verificar(&raiz2, FAM_A, &k1, None, &p1b));

    // Actualizar una no cambia el valor de la otra.
    estado
        .aplicar(&[Cambio::poner(FAM_A, k1.clone(), b"valor-3".to_vec())], 1)
        .unwrap();
    let raiz3 = estado.raiz_familia(FAM_A).unwrap();
    let p2c = estado.prueba(FAM_A, &k2).unwrap();
    assert!(estado.verificar(&raiz3, FAM_A, &k2, Some(&v2), &p2c));
    let p1c = estado.prueba(FAM_A, &k1).unwrap();
    assert!(estado.verificar(&raiz3, FAM_A, &k1, Some(b"valor-3"), &p1c));

    // Borrar la última deja el árbol vacío.
    estado.aplicar(&[Cambio::borrar(FAM_A, k2)], 1).unwrap();
    estado.aplicar(&[Cambio::borrar(FAM_A, k1)], 1).unwrap();
    assert_eq!(estado.raiz_familia(FAM_A).unwrap(), zx_estado::hash_vacio());
}

#[cfg(feature = "rocksdb")]
#[test]
fn memoria_y_rocksdb_dan_la_misma_raiz() {
    use zx_estado::AlmacenRocks;

    let dir = tempfile::tempdir().unwrap();
    let rocks = AlmacenRocks::abrir(dir.path(), false).unwrap();
    let mut en_memoria = nuevo();
    let mut en_disco = Estado::nuevo(rocks, CaminoSha3);

    let mut lote = base(80);
    lote.push(Cambio::poner(FAM_B, clave(1), valor(1)));
    lote.push(Cambio::borrar(FAM_A, clave(4)));
    lote.push(Cambio::poner(FAM_A, clave(4), valor(404)));

    let rm = en_memoria.aplicar(&lote, 1).unwrap();
    let rd = en_disco.aplicar(&lote, 1).unwrap();
    assert_eq!(rm, rd);
    let h_escalares = hash_valor(b"escalares-de-prueba");
    assert_eq!(
        en_memoria.raiz_estado(&h_escalares).unwrap(),
        en_disco.raiz_estado(&h_escalares).unwrap()
    );

    // La prueba del almacén en disco verifica contra la misma raíz.
    let raiz = rd.first().unwrap().1;
    let prueba = en_disco.prueba(FAM_A, &clave(3)).unwrap();
    assert!(en_disco.verificar(&raiz, FAM_A, &clave(3), Some(&valor(3)), &prueba));

    // Y sobrevive al cierre y reapertura.
    en_disco.almacen_mut().sincronizar().unwrap();
    drop(en_disco);
    let rocks2 = AlmacenRocks::abrir(dir.path(), false).unwrap();
    let reabierto = Estado::nuevo(rocks2, CaminoSha3);
    assert_eq!(reabierto.raiz_familia(FAM_A).unwrap(), raiz);
    assert_eq!(reabierto.reconstruir_familia(FAM_A).unwrap(), raiz);
    assert_eq!(
        reabierto.raiz_estado(&h_escalares).unwrap(),
        en_memoria.raiz_estado(&h_escalares).unwrap()
    );
}

#[test]
fn propiedad_lote_reconstruir() {
    const SECUENCIAS: u64 = 1_000;
    const BASE: usize = 16;
    for secuencia in 0..SECUENCIAS {
        let mut rng = SplitMix64::nuevo(0x5EED_0000 ^ secuencia);
        let mut estado = nuevo();
        let claves: Vec<Vec<u8>> = (0..BASE).map(|_| rng.bytes32().to_vec()).collect();
        let inicial: Vec<Cambio> = claves
            .iter()
            .map(|k| Cambio::poner(FAM_A, k.clone(), rng.bytes32().to_vec()))
            .collect();
        estado.aplicar(&inicial, 1).unwrap();

        let mut lote: Vec<Cambio> = Vec::with_capacity(20);
        for _ in 0..20 {
            match rng.hasta(10) {
                0..=6 => {
                    let k = if rng.hasta(2) == 0 {
                        claves
                            .get(usize::try_from(rng.hasta(BASE as u64)).unwrap_or(0))
                            .cloned()
                            .unwrap_or_default()
                    } else {
                        rng.bytes32().to_vec()
                    };
                    lote.push(Cambio::poner(FAM_A, k, rng.bytes32().to_vec()));
                }
                7..=8 => {
                    let k = claves
                        .get(usize::try_from(rng.hasta(BASE as u64)).unwrap_or(0))
                        .cloned()
                        .unwrap_or_default();
                    lote.push(Cambio::borrar(FAM_A, k));
                }
                _ => {
                    // Clave repetida: vale la última.
                    let k = lote.last().map(|c| c.clave.clone()).unwrap_or_default();
                    lote.push(Cambio::poner(FAM_A, k, rng.bytes32().to_vec()));
                }
            }
        }
        estado.aplicar(&lote, 1).unwrap();
        let raiz = estado.raiz_familia(FAM_A).unwrap();
        let reconstruida = estado.reconstruir_familia(FAM_A).unwrap();
        assert_eq!(raiz, reconstruida, "secuencia {secuencia}");
    }
}

/// Comprueba que `Prueba` es serializable a bytes y que el tipo público está completo.
#[test]
fn prueba_codifica_y_el_tipo_es_publico() {
    let mut estado = nuevo();
    estado.aplicar(&base(8), 1).unwrap();
    let mut prueba: Prueba = estado.prueba(FAM_A, &clave(1)).unwrap();
    let bytes = prueba.codificar().unwrap();
    assert!(!bytes.is_empty());
    prueba.familia = FAM_B;
    assert_ne!(prueba.familia, FAM_A);
}
