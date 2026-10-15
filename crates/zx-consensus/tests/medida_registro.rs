//! SR-1-2 · medida del coste del registro de sectores (PK-13).
//!
//! Mide, con un allocator contador, los bytes **por entrada** de
//! `BTreeMap<SectorId, RegistroSector>` en el estado, y los bytes en **disco** de la operación de
//! alta (preimagen canónica) y de la transacción v5 completa. Extrapola a 10 000 granjeros con
//! ≈ 3 725 sectores de 1 GiB cada uno. No depende de red: es una medida de estructura de datos.

#![expect(
    unsafe_code,
    reason = "el allocator contador es la única forma de medir la asignación real del BTreeMap"
)]
#![expect(
    clippy::expect_used,
    reason = "medida de test: falla con panic por diseño"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::atomic::{AtomicUsize, Ordering};

use zx_consensus::sectores::{NO_HAY, RegistroSector, SectorId, clave_de};
use zx_core::{Amount, ExtensionTx, OperacionSector, Tx};

struct Contador;

static BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: delega en `System`; solo suma al contador atómico.
unsafe impl GlobalAlloc for Contador {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        BYTES.fetch_add(l.size(), Ordering::Relaxed);
        // SAFETY: quien llama cumple el contrato de `GlobalAlloc`; la reserva se
        // delega tal cual en `System`.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: el puntero y su `Layout` vienen de una reserva que hizo `System`
        // a través de este asignador.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if n > l.size() {
            BYTES.fetch_add(n - l.size(), Ordering::Relaxed);
        }
        // SAFETY: puntero, `Layout` y tamaño nuevo cumplen el contrato de
        // `GlobalAlloc::realloc`; la reserva la hizo `System`, que es quien la amplía.
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static ALLOC: Contador = Contador;

fn registro(i: u64) -> RegistroSector {
    RegistroSector {
        id: SectorId {
            clave: clave_de((i & 0xff) as u8),
            sector_index: (i & 0xffff) as u16,
            version: (i >> 16) as u32,
        },
        r2: [i; 4],
        history_size: 1 << 20,
        etapa: zx_consensus::sectores::Etapa::Activo,
        alta_slot: 1,
        renovacion_slot: 2,
        retiro_slot: NO_HAY,
        fianza: 10,
        aud_apertura: NO_HAY,
        aud_contestada: NO_HAY,
    }
}

fn bytes_por_entrada(n: usize) -> f64 {
    BYTES.store(0, Ordering::SeqCst);
    let mut m: BTreeMap<SectorId, RegistroSector> = BTreeMap::new();
    for i in 0..n as u64 {
        let r = registro(i);
        m.insert(r.id, r);
    }
    let asignados = BYTES.load(Ordering::SeqCst);
    // `m` sigue vivo: no se libera nada de lo contado.
    assert_eq!(m.len(), n);
    asignados as f64 / n as f64
}

#[test]
fn mide_registro_y_extrapola_pk13() {
    let n = 200_000usize;
    let por_entrada = bytes_por_entrada(n);
    let solo_valor = size_of::<RegistroSector>() + size_of::<SectorId>();
    // Preimagen canónica del alta y wire de la transacción v5 completa.
    let alta = OperacionSector::Alta {
        clave: clave_de(1),
        sector_index: 0,
        version: 0,
        r2: [7u8; 32],
        history_size: 1 << 20,
    };
    let canonicos = alta.longitud_canonica().expect("cabe en el tope");
    let tx = Tx {
        version: 5,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        expiry_height: 0,
        extension: ExtensionTx::Sector {
            operacion: alta.clone(),
        },
    };
    let testigos = vec![vec![0u8; 64]];
    let mut buf = Vec::new();
    zx_core::wire::tx_a_bytes(&mut buf, &tx, &testigos);
    let wire_tx = buf.len();
    let _ = Amount::CERO;

    // 10 000 granjeros × 3 725 sectores de 1 GiB (PK-13).
    let sectores = 10_000u64 * 3_725;
    let mib = 1024.0 * 1024.0;
    println!("=== SR-1-2 · medida del registro de sectores (PK-13) ===");
    println!("n entradas medidas             = {n}");
    println!(
        "size_of<RegistroSector>        = {} B",
        size_of::<RegistroSector>()
    );
    println!(
        "size_of<SectorId>              = {} B",
        size_of::<SectorId>()
    );
    println!("suma de campos K+V             = {solo_valor} B");
    println!("BTreeMap: bytes asignados/entrada = {por_entrada:.3} B");
    println!("operación Alta canónica        = {canonicos} B");
    println!("tx v5 completa (wire, 1 testigo)= {wire_tx} B");
    println!("sectores totales (PK-13)       = {sectores}");
    println!(
        "estado BTreeMap                = {:.3} GiB",
        por_entrada * sectores as f64 / (1024.0 * mib)
    );
    println!(
        "disco solo operación canónica  = {:.3} GiB",
        canonicos as f64 * sectores as f64 / (1024.0 * mib)
    );
    println!(
        "disco tx v5 completa           = {:.3} GiB",
        wire_tx as f64 * sectores as f64 / (1024.0 * mib)
    );
    assert!(por_entrada >= solo_valor as f64);
    assert!(por_entrada < 4.0 * solo_valor as f64);
}
