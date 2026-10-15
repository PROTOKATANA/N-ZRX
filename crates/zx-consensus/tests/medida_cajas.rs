//! `SR-G2b` · V6 · medida del estado de las cajas (memoria y disco) frente a SR-1-2.
//!
//! Mide con un allocator contador:
//! - `size_of<RegistroCaja>` y `size_of<Ocupante>`;
//! - bytes asignados por entrada de `BTreeMap<CajaId, RegistroCaja>` (cajas de 16 huecos);
//! - bytes asignados por entrada de `BTreeMap<SectorId, RegistroSector>` (baseline de SR-1-2);
//! - las operaciones nuevas `CerrarCaja`/`RetirarCaja` en disco (preimagen canónica).
//!
//! La conclusión honesta (`PROGRESO.md` §1, D-2): la caja **añade** un índice compacto porque el
//! estado conserva el registro por sector; el factor 15,38× de SR-G2a solo se alcanza cuando el
//! ciclo de vida se **deriva** del hueco (trabajo abierto). Aquí se mide el coste real.

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
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use zx_consensus::cajas::{CAPACIDAD_MAX, CajaId, HUECO_LIBRE, Ocupante, RegistroCaja};
use zx_consensus::sectores::{Etapa, NO_HAY, RegistroSector, SectorId, clave_de};
use zx_core::OperacionSector;

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

/// El contador es global: los dos tests de este binario deben medir **en serie**.
static CERROJO: Mutex<()> = Mutex::new(());

fn caja(i: u64) -> RegistroCaja {
    let mut huecos = [HUECO_LIBRE; CAPACIDAD_MAX];
    for (j, h) in huecos.iter_mut().enumerate() {
        *h = Ocupante {
            sector_index: (i as u16).wrapping_add(j as u16),
            version: 0,
            ocupado: true,
        };
    }
    RegistroCaja {
        id: CajaId {
            clave: clave_de((i & 0xff) as u8),
            seq: (i >> 8) as u32,
        },
        raiz: [i; 4],
        n: CAPACIDAD_MAX as u8,
        ocupacion: u16::MAX,
        estado_hueco: 0xAAAA_AAAA,
        history_size: 1 << 20,
        etapa: zx_consensus::cajas::EtapaCaja::Cerrada,
        alta_slot: 1,
        ultima_alta_slot: 1,
        cierre_slot: 2,
        renovacion_slot: 2,
        retiro_slot: NO_HAY,
        fianza: 16 * 140,
        huecos,
    }
}

fn sector(i: u64) -> RegistroSector {
    RegistroSector {
        id: SectorId {
            clave: clave_de((i & 0xff) as u8),
            sector_index: (i & 0xffff) as u16,
            version: (i >> 16) as u32,
        },
        r2: [i; 4],
        history_size: 1 << 20,
        etapa: Etapa::Activo,
        alta_slot: 1,
        renovacion_slot: 2,
        retiro_slot: NO_HAY,
        fianza: 140,
        aud_apertura: NO_HAY,
        aud_contestada: NO_HAY,
    }
}

fn bytes_cajas(n: usize) -> f64 {
    BYTES.store(0, Ordering::SeqCst);
    let mut m: BTreeMap<CajaId, RegistroCaja> = BTreeMap::new();
    for i in 0..n as u64 {
        let c = caja(i);
        m.insert(c.id, c);
    }
    let a = BYTES.load(Ordering::SeqCst);
    assert_eq!(m.len(), n);
    a as f64 / n as f64
}

fn bytes_sectores(n: usize) -> f64 {
    BYTES.store(0, Ordering::SeqCst);
    let mut m: BTreeMap<SectorId, RegistroSector> = BTreeMap::new();
    for i in 0..n as u64 {
        let r = sector(i);
        m.insert(r.id, r);
    }
    let a = BYTES.load(Ordering::SeqCst);
    assert_eq!(m.len(), n);
    a as f64 / n as f64
}

#[test]
fn mide_cajas_y_extrapola() {
    let _g = CERROJO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let n = 20_000usize;
    let por_caja = bytes_cajas(n);
    let por_sector_base = bytes_sectores(n * CAPACIDAD_MAX);
    let solo_valor_caja = size_of::<RegistroCaja>();
    let solo_valor_ocup = size_of::<Ocupante>();
    let solo_valor_sector = size_of::<RegistroSector>() + size_of::<SectorId>();

    let cerrar = OperacionSector::CerrarCaja {
        clave: clave_de(1),
        seq: 1,
    }
    .longitud_canonica()
    .expect("cabe");
    let retirar = OperacionSector::RetirarCaja {
        clave: clave_de(1),
        seq: 1,
    }
    .longitud_canonica()
    .expect("cabe");

    // PK-13: 10 000 granjeros × 3 725 sectores = 37 250 000; cajas = 10 000 × ⌈3725/16⌉.
    let sectores = 10_000u64 * 3_725;
    let cajas = 10_000u64 * 3_725usize.div_ceil(CAPACIDAD_MAX) as u64;
    let mib = 1024.0 * 1024.0;
    let sector_en_caja = por_caja / CAPACIDAD_MAX as f64;
    let total_por_sector = por_sector_base + sector_en_caja;

    println!("=== SR-G2b · V6 · medida real del estado de las cajas ===");
    println!("n cajas medidas               = {n}");
    println!("size_of<RegistroCaja>         = {solo_valor_caja} B");
    println!("size_of<Ocupante>             = {solo_valor_ocup} B");
    println!("suma K+V del sector baseline  = {solo_valor_sector} B");
    println!("BTreeMap<caja>: bytes/caja    = {por_caja:.3} B");
    println!("BTreeMap<sector>: bytes/sector= {por_sector_base:.3} B");
    println!("caja / 16 = bytes/sector      = {sector_en_caja:.3} B");
    println!("total por sector (sector+caja)= {total_por_sector:.3} B");
    println!(
        "factor estado (baseline+extra)/baseline = {:.3}×",
        total_por_sector / por_sector_base
    );
    println!("entrada canónica propuesta    = 132 B (SR-G2a, derivado)");
    println!("operación CerrarCaja canónica = {cerrar} B");
    println!("operación RetirarCaja canónica= {retirar} B");
    println!("sectores totales (PK-13)      = {sectores}");
    println!("cajas totales (PK-13)         = {cajas}");
    println!(
        "estado sectores (PK-13)       = {:.3} GiB",
        por_sector_base * sectores as f64 / (1024.0 * mib)
    );
    println!(
        "estado cajas (PK-13)          = {:.3} GiB",
        por_caja * cajas as f64 / (1024.0 * mib)
    );
    println!(
        "disco operaciones de caja     = {:.3} GiB",
        (cerrar + retirar) as f64 * cajas as f64 / (1024.0 * mib)
    );

    assert!(solo_valor_caja >= 132, "la entrada debe cubrir los 132 B");
    assert!(por_caja >= solo_valor_caja as f64);
    assert!(por_sector_base >= solo_valor_sector as f64);
}

/// **PT-3bc (f)** · la compactación se mide **en el mismo arnés y con el mismo `n`**: el mismo
/// número de sectores, una vez como `BTreeMap<SectorId, RegistroSector>` (registro de `main`) y otra
/// como `BTreeMap<CajaId, RegistroCaja>` con `CAPACIDAD_MAX` huecos por caja. Es la medida de D-06
/// (`REVISION-SZ2.md`: la base no es única; se juzga con esta).
#[test]
#[expect(
    clippy::integer_division,
    reason = "n es múltiplo exacto de CAPACIDAD_MAX; el assert lo comprueba"
)]
fn mide_compactacion_mismo_n() {
    let _g = CERROJO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let sectores = 160_000usize;
    let cajas = sectores / CAPACIDAD_MAX;
    assert_eq!(cajas * CAPACIDAD_MAX, sectores, "n exacto, sin resto");

    let por_sector_base = bytes_sectores(sectores);
    let por_caja = bytes_cajas(cajas);
    let compacto_por_sector = por_caja / CAPACIDAD_MAX as f64;
    let factor = por_sector_base / compacto_por_sector;
    let mib = 1024.0 * 1024.0;

    println!("=== PT-3bc · (f) compactación a mismo n ===");
    println!("sectores (n)                  = {sectores}");
    println!("cajas (n/16)                  = {cajas}");
    println!("main: bytes/sector            = {por_sector_base:.3} B");
    println!("compacto: bytes/caja          = {por_caja:.3} B");
    println!("compacto: bytes/sector        = {compacto_por_sector:.3} B");
    println!("factor compacto/main          = {factor:.3}×");
    println!(
        "estado main (n)               = {:.3} GiB",
        por_sector_base * sectores as f64 / mib
    );
    println!(
        "estado compacto (n)           = {:.3} GiB",
        por_caja * cajas as f64 / mib
    );

    // Si el r2 y el ciclo de vida por sector se guardaran dentro de la caja, se sumarían ≥32 B por
    // sector y el factor caería por debajo de 8× (ver `PROGRESO.md` §A.2). Esta medida mide la
    // representación compacta tal y como la define el diseño: `Ocupante` de 8 B.
    assert!(
        factor >= 8.0,
        "D-06: el registro compacto debe ocupar ≥ 8× menos (dio {factor:.3}×)"
    );
}
