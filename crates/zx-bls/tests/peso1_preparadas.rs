//! PESO-1: construcción validada, orden, persistencia y memoria de puntos.
use zx_bls::{ClavePublica, ClaveSecreta, ClavesPreparadas, ErrorBLS};

#[test]
fn peso1_preparadas_conservan_orden_bytes_y_no_toman_prestamo() -> Result<(), ErrorBLS> {
    let bytes = (0..16u8)
        .map(|i| Ok(ClaveSecreta::generar(&[i + 1; 32])?.clave_publica().bytes()))
        .collect::<Result<Vec<_>, ErrorBLS>>()?;
    let preparada = ClavesPreparadas::desde_bytes(&bytes)?;
    let vuelta = preparada
        .claves()
        .iter()
        .map(ClavePublica::bytes)
        .collect::<Vec<_>>();
    assert_eq!(vuelta, bytes);
    assert_eq!(preparada.len(), 16);
    assert!(!preparada.is_empty());
    assert_eq!(
        preparada.bytes_puntos(),
        16 * std::mem::size_of::<ClavePublica>()
    );
    drop(bytes);
    assert_eq!(
        preparada
            .claves()
            .iter()
            .map(ClavePublica::bytes)
            .collect::<Vec<_>>(),
        vuelta
    );
    let vacia = ClavesPreparadas::desde_bytes(std::iter::empty::<&[u8]>())?;
    assert!(vacia.is_empty());
    assert_eq!(vacia.bytes_puntos(), 0);
    Ok(())
}

#[test]
fn peso1_preparadas_rechazan_toda_entrada_invalida() -> Result<(), Box<dyn std::error::Error>> {
    let valida = ClaveSecreta::generar(&[0x51; 32])?.clave_publica().bytes();
    let subgrupo = hex::decode(
        "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )?;
    let mut infinito = vec![0; 48];
    if let Some(byte) = infinito.first_mut() {
        *byte = 0xc0;
    }
    for invalida in [
        vec![],
        vec![0; 47],
        vec![0; 48],
        vec![0; 49],
        infinito,
        subgrupo,
    ] {
        let esperado = ClavePublica::desde_bytes(&invalida).err();
        assert!(esperado.is_some());
        for bytes in [
            [invalida.as_slice(), &valida],
            [&valida, invalida.as_slice()],
        ] {
            assert_eq!(ClavesPreparadas::desde_bytes(bytes).err(), esperado);
        }
    }
    Ok(())
}
