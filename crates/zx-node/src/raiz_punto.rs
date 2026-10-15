//! La raíz de estado del punto de cada época, calculada en segundo plano.
//!
//! Pieza pura de A1-D2a (`P-ZRX/P-004/ORDEN-A1D2A.md`, con las reglas de
//! `P-ZRX/P-004/ADOPCION-A1-PASO-D2.md`): traduce una ventana a la época de la raíz que le toca,
//! calcula el tope de slot del bloque punto de una época y guarda por época la raíz de su punto,
//! calculada **en un hilo aparte y sin bloquear nunca** a quien la pide. Nadie la cablea todavía:
//! eso es A1-D2b.
//!
//! - [`epoca_de_raiz`] y [`tope_de_punto`] son la aritmética del contrato (P2 y P3).
//! - [`RaicesPunto`] es el almacén (P4): `solicitar`, `recoger`, `raiz`, `pendiente` y `podar`.
//!   Un único hilo trabajador garantiza **como mucho un cálculo a la vez** (P6), y las
//!   solicitudes que llegan mientras hay uno en curso esperan en una cola cuyo tamaño nunca
//!   supera el número de épocas vivas (a lo sumo una por época, `podar` mediante; P6).
//! - La función que calcula se **inyecta** en [`RaicesPunto::nuevo`] (P7); en producción es
//!   `zx_estado::canon::raiz_de_estado`.
//! - Ninguna operación espera a un hilo y ninguna usa `unwrap`, `expect` ni `panic` fuera de
//!   pruebas (P5).

use std::collections::{HashMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use zx_consensus::transicion::Estado;
use zx_core::BlockHash;
use zx_estado::Hash32;

/// Ventanas por época para la raíz de estado (P1).
///
/// Valor **provisional**, fijado por el orquestador (`P-ZRX/P-004/REVISION-ER2.md`): `E = 128`.
pub const EPOCA_RAIZ_VENTANAS: u64 = 128;

/// Épocas de retraso entre el punto y la raíz que lo firma (P1).
///
/// Valor **provisional**, fijado por el orquestador (`P-ZRX/P-004/REVISION-ER2.md`): `d = 2`.
pub const RETRASO_RAIZ_EPOCAS: u64 = 2;

/// Época cuya raíz firma la ventana `n` (P2): `⌊n / E⌋ − d`.
///
/// Devuelve `None` en las `d` primeras épocas, cuando la resta no cabe en `u64`.
#[must_use]
#[expect(
    clippy::integer_division,
    reason = "la regla de consenso es división entera; el coma flotante está prohibido (LINEO §5.3)"
)]
pub const fn epoca_de_raiz(n: u64) -> Option<u64> {
    (n / EPOCA_RAIZ_VENTANAS).checked_sub(RETRASO_RAIZ_EPOCAS)
}

/// Tope de slot del punto de la época `e` (P3): `e · E · t_inst − lag`.
///
/// Es la regla del candidato de voto aplicada a la primera ventana de la época; el bloque lo
/// busca el nodo con `Cadena::candidato_por_slot`. Devuelve `None` si el producto desborda `u64`
/// o si el tope quedaría por debajo de cero.
#[must_use]
pub const fn tope_de_punto(e: u64, t_inst: u64, lag: u64) -> Option<u64> {
    match e.checked_mul(EPOCA_RAIZ_VENTANAS) {
        Some(base) => match base.checked_mul(t_inst) {
            Some(v) => v.checked_sub(lag),
            None => None,
        },
        None => None,
    }
}

/// Resultado que el hilo trabajador manda al almacén.
struct Resultado {
    epoca: u64,
    punto: BlockHash,
    raiz: Option<Hash32>,
}

/// Estado de una época en el almacén (P4).
enum EstadoEpoca {
    /// Hay un cálculo en curso o en cola para esta época.
    Calculando,
    /// La raíz está lista.
    Lista(Hash32),
}

/// Entrada guardada por época: su punto y el estado del cálculo.
struct Entrada {
    punto: BlockHash,
    estado: EstadoEpoca,
}

/// Un cálculo pendiente en la cola del trabajador.
struct Trabajo {
    epoca: u64,
    punto: BlockHash,
    estado: Estado,
}

/// Interior compartido entre el almacén y su hilo trabajador.
struct Interior {
    epocas: HashMap<u64, Entrada>,
    cola: VecDeque<Trabajo>,
    cerrado: bool,
}

/// Almacén de raíces de estado por época, calculadas en segundo plano (P4).
///
/// Se construye con la función que calcula (P7) y **nunca bloquea** a quien lo usa (P5): todas
/// las operaciones vuelven en el acto. La cola interna no usa ninguna capacidad literal: al
/// guardar a lo sumo un trabajo por época, su longitud nunca supera el número de épocas vivas
/// que `podar` deja.
pub struct RaicesPunto {
    interior: Arc<Mutex<Interior>>,
    despertar: Arc<Condvar>,
    resultados: Receiver<Resultado>,
    trabajador: Option<JoinHandle<()>>,
}

impl RaicesPunto {
    /// Crea el almacén con la función que calcula la raíz (P7).
    ///
    /// `calculadora` se llama **siempre desde el hilo trabajador**, nunca desde el hilo que
    /// construye; en producción es `zx_estado::canon::raiz_de_estado`. Si el sistema no deja
    /// crear el hilo, el almacén queda inerte: `solicitar` no guarda nada y `raiz` siempre da
    /// `None`.
    #[must_use]
    pub fn nuevo<F, E>(calculadora: F) -> Self
    where
        F: Fn(&Estado) -> Result<Hash32, E> + Send + 'static,
        E: 'static,
    {
        let interior = Arc::new(Mutex::new(Interior {
            epocas: HashMap::new(),
            cola: VecDeque::new(),
            cerrado: false,
        }));
        let despertar = Arc::new(Condvar::new());
        let (envio, resultados) = mpsc::channel::<Resultado>();
        let interior_t = Arc::clone(&interior);
        let despertar_t = Arc::clone(&despertar);
        let trabajador = thread::Builder::new()
            .name("raiz-punto".to_owned())
            .spawn(move || bucle_trabajador(calculadora, &interior_t, &despertar_t, &envio))
            .ok();
        if trabajador.is_none() {
            interior.lock().unwrap_or_else(|e| e.into_inner()).cerrado = true;
        }
        Self {
            interior,
            despertar,
            resultados,
            trabajador,
        }
    }

    /// Solicita la raíz de `epoca` para el punto `punto` y vuelve en el acto (P4.1).
    ///
    /// Si ya hay algo para esa época **con ese mismo punto**, no hace nada; si lo hay con **otro**
    /// punto, lo descarta. `estado` entra por valor: el llamante lo clona.
    pub fn solicitar(&self, epoca: u64, punto: BlockHash, estado: Estado) {
        let mut guard = self.interior.lock().unwrap_or_else(|e| e.into_inner());
        if guard.cerrado {
            return;
        }
        if guard
            .epocas
            .get(&epoca)
            .is_some_and(|entrada| entrada.punto == punto)
        {
            return;
        }
        guard.epocas.remove(&epoca);
        guard.cola.retain(|trabajo| trabajo.epoca != epoca);
        guard.epocas.insert(
            epoca,
            Entrada {
                punto,
                estado: EstadoEpoca::Calculando,
            },
        );
        guard.cola.push_back(Trabajo {
            epoca,
            punto,
            estado,
        });
        drop(guard);
        self.despertar.notify_one();
    }

    /// Incorpora los cálculos terminados, sin bloquear (P4.2).
    ///
    /// Un resultado cuyo punto ya no es el guardado para su época **se tira**. Un cálculo que
    /// devuelve error, o que el hilo no pudo completar, deja la época libre (sin raíz y sin
    /// «calculando»), de modo que se puede volver a solicitar (P5).
    pub fn recoger(&self) {
        while let Ok(resultado) = self.resultados.try_recv() {
            self.incorporar(resultado);
        }
    }

    /// La raíz de `epoca` **solo si** está lista y el punto guardado es `punto` (P4.3).
    #[must_use]
    pub fn raiz(&self, epoca: u64, punto: &BlockHash) -> Option<Hash32> {
        let guard = self.interior.lock().unwrap_or_else(|e| e.into_inner());
        match guard.epocas.get(&epoca) {
            Some(entrada) if entrada.punto == *punto => match &entrada.estado {
                EstadoEpoca::Lista(raiz) => Some(*raiz),
                EstadoEpoca::Calculando => None,
            },
            _ => None,
        }
    }

    /// ¿Hay un cálculo en curso o en cola para `epoca` y `punto`? (P4.4).
    #[must_use]
    pub fn pendiente(&self, epoca: u64, punto: &BlockHash) -> bool {
        let guard = self.interior.lock().unwrap_or_else(|e| e.into_inner());
        guard.epocas.get(&epoca).is_some_and(|entrada| {
            entrada.punto == *punto && matches!(&entrada.estado, EstadoEpoca::Calculando)
        })
    }

    /// Olvida las épocas anteriores a `epoca_minima` (P4.5).
    pub fn podar(&self, epoca_minima: u64) {
        let mut guard = self.interior.lock().unwrap_or_else(|e| e.into_inner());
        guard.epocas.retain(|epoca, _| *epoca >= epoca_minima);
        guard.cola.retain(|trabajo| trabajo.epoca >= epoca_minima);
    }

    /// Incorpora un resultado si su época sigue esperando ese mismo punto.
    fn incorporar(&self, resultado: Resultado) {
        let mut guard = self.interior.lock().unwrap_or_else(|e| e.into_inner());
        let sigue = guard.epocas.get(&resultado.epoca).is_some_and(|entrada| {
            entrada.punto == resultado.punto && matches!(&entrada.estado, EstadoEpoca::Calculando)
        });
        if !sigue {
            return;
        }
        match resultado.raiz {
            Some(raiz) => {
                if let Some(entrada) = guard.epocas.get_mut(&resultado.epoca) {
                    entrada.estado = EstadoEpoca::Lista(raiz);
                }
            }
            None => {
                guard.epocas.remove(&resultado.epoca);
            }
        }
    }
}

impl Drop for RaicesPunto {
    fn drop(&mut self) {
        {
            let mut guard = self.interior.lock().unwrap_or_else(|e| e.into_inner());
            guard.cerrado = true;
            guard.cola.clear();
        }
        self.despertar.notify_all();
        if let Some(trabajador) = self.trabajador.take() {
            let _ = trabajador.join();
        }
    }
}

/// Extrae el siguiente trabajo de la cola; `None` si el almacén se cerró (P5).
fn siguiente(interior: &Mutex<Interior>, despertar: &Condvar) -> Option<Trabajo> {
    let mut guard = interior.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if guard.cerrado {
            return None;
        }
        if let Some(trabajo) = guard.cola.pop_front() {
            return Some(trabajo);
        }
        guard = despertar.wait(guard).unwrap_or_else(|e| e.into_inner());
    }
}

/// ¿Sigue ese trabajo esperando en el almacén? (no fue descartado por otro punto ni podado).
fn sigue_vivo(interior: &Mutex<Interior>, trabajo: &Trabajo) -> bool {
    let guard = interior.lock().unwrap_or_else(|e| e.into_inner());
    guard.epocas.get(&trabajo.epoca).is_some_and(|entrada| {
        entrada.punto == trabajo.punto && matches!(&entrada.estado, EstadoEpoca::Calculando)
    })
}

/// Bucle del hilo trabajador: un cálculo a la vez, en el orden en que se solicitaron (P6).
///
/// Un `Err` de la calculadora o un `panic` suyo se traducen en «sin raíz»: el almacén retira la
/// época y se puede volver a solicitar (P5), sin que el hilo muera.
fn bucle_trabajador<F, E>(
    calculadora: F,
    interior: &Mutex<Interior>,
    despertar: &Condvar,
    envio: &Sender<Resultado>,
) where
    F: Fn(&Estado) -> Result<Hash32, E>,
{
    loop {
        let Some(trabajo) = siguiente(interior, despertar) else {
            return;
        };
        if !sigue_vivo(interior, &trabajo) {
            continue;
        }
        let raiz = catch_unwind(AssertUnwindSafe(|| calculadora(&trabajo.estado)))
            .ok()
            .and_then(|resultado| resultado.ok());
        let _ = envio.send(Resultado {
            epoca: trabajo.epoca,
            punto: trabajo.punto,
            raiz,
        });
    }
}

#[cfg(test)]
mod pruebas {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::mutex_atomic,
        reason = "pruebas: el fallo es un panic por diseño"
    )]

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use zx_consensus::transicion::Estado;
    use zx_core::{BlockHash, Digest};
    use zx_estado::canon::raiz_de_estado;

    use super::{RaicesPunto, epoca_de_raiz, tope_de_punto};

    /// Error propio de las pruebas: el almacén solo distingue éxito de fallo.
    #[derive(Debug)]
    struct ErrorFalso;

    fn punto(n: u8) -> BlockHash {
        BlockHash::from_digest(Digest::from_bytes([n; 32]))
    }

    fn estado_con(altura: u32) -> Estado {
        let mut estado = Estado::inicial();
        estado.altura = altura;
        estado
    }

    /// Sondea `recoger` hasta que la raíz esté lista o se agote el margen.
    fn esperar_raiz(almacen: &RaicesPunto, epoca: u64, punto: &BlockHash) -> Option<[u8; 32]> {
        for _ in 0..2_000_000u32 {
            almacen.recoger();
            if let Some(raiz) = almacen.raiz(epoca, punto) {
                return Some(raiz);
            }
            std::thread::yield_now();
        }
        None
    }

    #[test]
    fn punto_01_epoca_de_raiz() {
        // Las ventanas de las dos primeras épocas no tienen raíz.
        for ventana in [0u64, 1, 127, 128, 129, 255] {
            assert_eq!(epoca_de_raiz(ventana), None, "ventana {ventana}");
        }
        // La primera ventana de la tercera época ya es la época 0.
        assert_eq!(epoca_de_raiz(256), Some(0));
        // El borde de cada época.
        assert_eq!(epoca_de_raiz(383), Some(0));
        assert_eq!(epoca_de_raiz(384), Some(1));
        assert_eq!(epoca_de_raiz(511), Some(1));
        assert_eq!(epoca_de_raiz(512), Some(2));
        assert_eq!(epoca_de_raiz(640), Some(3));
    }

    #[test]
    fn punto_02_tope_de_punto() {
        assert_eq!(tope_de_punto(0, 10, 0), Some(0));
        assert_eq!(tope_de_punto(1, 10, 3), Some(1277));
        assert_eq!(tope_de_punto(2, 3, 5), Some(763));
        // La época 0 con `lag > 0` queda por debajo de cero.
        assert_eq!(tope_de_punto(0, 10, 1), None);
        // Desbordamiento del producto (2^57 · 128 = 2^64).
        assert_eq!(tope_de_punto(u64::MAX, u64::MAX, 0), None);
        assert_eq!(tope_de_punto(1u64 << 57, 1, 0), None);
    }

    #[test]
    fn punto_03_raiz_lista_tras_calcular() {
        let estado = estado_con(7);
        let esperada = raiz_de_estado(&estado).expect("la raíz real debe calcularse");
        let almacen = RaicesPunto::nuevo(raiz_de_estado);
        let p = punto(1);
        almacen.solicitar(0, p, estado.clone());
        assert_eq!(esperar_raiz(&almacen, 0, &p), Some(esperada));
        assert_eq!(
            raiz_de_estado(&estado).expect("la raíz real debe calcularse"),
            esperada
        );
    }

    #[test]
    fn punto_04_solicitar_no_bloquea() {
        let senal = Arc::new((Mutex::new(false), Condvar::new()));
        let senal_calc = Arc::clone(&senal);
        let almacen = RaicesPunto::nuevo(move |_estado: &Estado| {
            let (candado, aviso) = &*senal_calc;
            let mut listo = candado.lock().unwrap_or_else(|e| e.into_inner());
            while !*listo {
                let (guard, espera) = aviso
                    .wait_timeout(listo, Duration::from_secs(10))
                    .unwrap_or_else(|e| e.into_inner());
                listo = guard;
                if espera.timed_out() {
                    break;
                }
            }
            Ok::<[u8; 32], ErrorFalso>([0xAA; 32])
        });
        let p = punto(2);
        almacen.solicitar(0, p, estado_con(0));
        // `solicitar` volvió aunque el cálculo siga bloqueado.
        assert!(almacen.raiz(0, &p).is_none());
        assert!(almacen.pendiente(0, &p));
        // Al soltar la señal, `recoger` incorpora la raíz.
        {
            let (candado, aviso) = &*senal;
            let mut listo = candado.lock().unwrap_or_else(|e| e.into_inner());
            *listo = true;
            aviso.notify_all();
        }
        assert_eq!(esperar_raiz(&almacen, 0, &p), Some([0xAA; 32]));
    }

    #[test]
    fn punto_05_si_el_punto_cambia_se_descarta() {
        let llamadas = Arc::new(AtomicUsize::new(0));
        let senal = Arc::new((Mutex::new(false), Condvar::new()));
        let llamadas_calc = Arc::clone(&llamadas);
        let senal_calc = Arc::clone(&senal);
        let almacen = RaicesPunto::nuevo(move |_estado: &Estado| {
            let n = llamadas_calc.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                let (candado, aviso) = &*senal_calc;
                let mut listo = candado.lock().unwrap_or_else(|e| e.into_inner());
                while !*listo {
                    listo = aviso.wait(listo).unwrap_or_else(|e| e.into_inner());
                }
            }
            Ok::<[u8; 32], ErrorFalso>([u8::try_from(n).unwrap_or(0); 32])
        });
        let a = punto(0xA0);
        let b = punto(0xB0);
        almacen.solicitar(0, a, estado_con(1));
        // Espera a que el cálculo de A haya empezado (y quede bloqueado).
        for _ in 0..2_000_000u32 {
            if llamadas.load(Ordering::SeqCst) == 1 {
                break;
            }
            std::thread::yield_now();
        }
        assert_eq!(llamadas.load(Ordering::SeqCst), 1);
        // El segundo punto descarta el primero, aunque su cálculo esté en curso.
        almacen.solicitar(0, b, estado_con(2));
        {
            let (candado, aviso) = &*senal;
            let mut listo = candado.lock().unwrap_or_else(|e| e.into_inner());
            *listo = true;
            aviso.notify_all();
        }
        assert_eq!(esperar_raiz(&almacen, 0, &b), Some([1u8; 32]));
        // El resultado de A no aparece nunca, ni para A ni para B.
        assert!(almacen.raiz(0, &a).is_none());
        assert_eq!(llamadas.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn punto_06_idempotente() {
        let llamadas = Arc::new(AtomicUsize::new(0));
        let llamadas_calc = Arc::clone(&llamadas);
        let almacen = RaicesPunto::nuevo(move |_estado: &Estado| {
            llamadas_calc.fetch_add(1, Ordering::SeqCst);
            Ok::<[u8; 32], ErrorFalso>([0x55; 32])
        });
        let p = punto(3);
        almacen.solicitar(0, p, estado_con(1));
        almacen.solicitar(0, p, estado_con(2));
        assert_eq!(esperar_raiz(&almacen, 0, &p), Some([0x55; 32]));
        assert_eq!(llamadas.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn punto_07_un_error_no_envenena() {
        let llamadas = Arc::new(AtomicUsize::new(0));
        let llamadas_calc = Arc::clone(&llamadas);
        let almacen = RaicesPunto::nuevo(move |_estado: &Estado| {
            let n = llamadas_calc.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Err(ErrorFalso)
            } else {
                Ok::<[u8; 32], ErrorFalso>([0x77; 32])
            }
        });
        let p = punto(4);
        almacen.solicitar(0, p, estado_con(1));
        // El error deja la época libre: sin raíz y sin «calculando».
        for _ in 0..2_000_000u32 {
            almacen.recoger();
            if !almacen.pendiente(0, &p) {
                break;
            }
            std::thread::yield_now();
        }
        assert!(!almacen.pendiente(0, &p), "la época debe quedar libre");
        assert!(almacen.raiz(0, &p).is_none());
        // Una segunda solicitud sí calcula la raíz.
        almacen.solicitar(0, p, estado_con(1));
        assert_eq!(esperar_raiz(&almacen, 0, &p), Some([0x77; 32]));
        assert_eq!(llamadas.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn punto_08_uno_a_la_vez_y_en_orden() {
        let activos = Arc::new(AtomicUsize::new(0));
        let maximo = Arc::new(AtomicUsize::new(0));
        let orden = Arc::new(Mutex::new(Vec::<u32>::new()));
        let activos_calc = Arc::clone(&activos);
        let maximo_calc = Arc::clone(&maximo);
        let orden_calc = Arc::clone(&orden);
        let almacen = RaicesPunto::nuevo(move |estado: &Estado| {
            let ahora = activos_calc.fetch_add(1, Ordering::SeqCst) + 1;
            maximo_calc.fetch_max(ahora, Ordering::SeqCst);
            orden_calc
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(estado.altura);
            std::thread::sleep(Duration::from_millis(10));
            activos_calc.fetch_sub(1, Ordering::SeqCst);
            Ok::<[u8; 32], ErrorFalso>([u8::try_from(estado.altura).unwrap_or(0); 32])
        });
        let p0 = punto(10);
        let p1 = punto(11);
        let p2 = punto(12);
        almacen.solicitar(0, p0, estado_con(0));
        almacen.solicitar(1, p1, estado_con(1));
        almacen.solicitar(2, p2, estado_con(2));
        assert!(esperar_raiz(&almacen, 0, &p0).is_some());
        assert!(esperar_raiz(&almacen, 1, &p1).is_some());
        assert!(esperar_raiz(&almacen, 2, &p2).is_some());
        assert_eq!(maximo.load(Ordering::SeqCst), 1, "dos cálculos a la vez");
        assert_eq!(
            *orden.lock().unwrap_or_else(|e| e.into_inner()),
            vec![0u32, 1, 2]
        );
    }

    #[test]
    fn punto_09_poda() {
        let vistas = Arc::new(Mutex::new(Vec::<u32>::new()));
        let senal = Arc::new((Mutex::new(false), Condvar::new()));
        let vistas_calc = Arc::clone(&vistas);
        let senal_calc = Arc::clone(&senal);
        let almacen = RaicesPunto::nuevo(move |estado: &Estado| {
            vistas_calc
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(estado.altura);
            if estado.altura == 10 {
                let (candado, aviso) = &*senal_calc;
                let mut listo = candado.lock().unwrap_or_else(|e| e.into_inner());
                while !*listo {
                    listo = aviso.wait(listo).unwrap_or_else(|e| e.into_inner());
                }
            }
            Ok::<[u8; 32], ErrorFalso>([u8::try_from(estado.altura).unwrap_or(0); 32])
        });
        let reciente = punto(20);
        let viejo = punto(3);
        almacen.solicitar(10, reciente, estado_con(10));
        almacen.solicitar(3, viejo, estado_con(3));
        // El trabajador ya tomó la época 10 y la tiene bloqueada; la 3 sigue en cola.
        for _ in 0..2_000_000u32 {
            if vistas
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&10)
            {
                break;
            }
            std::thread::yield_now();
        }
        almacen.podar(5);
        assert!(almacen.raiz(3, &viejo).is_none());
        assert!(!almacen.pendiente(3, &viejo));
        {
            let (candado, aviso) = &*senal;
            let mut listo = candado.lock().unwrap_or_else(|e| e.into_inner());
            *listo = true;
            aviso.notify_all();
        }
        assert!(esperar_raiz(&almacen, 10, &reciente).is_some());
        let calculadas = vistas.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(calculadas.contains(&10));
        assert!(
            !calculadas.contains(&3),
            "la época podada no debe calcularse: {calculadas:?}"
        );
    }
}
