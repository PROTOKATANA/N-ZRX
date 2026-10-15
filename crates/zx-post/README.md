# `zx-post`

PoT puro, núcleo de verificación de un rango PoT, puerta conjunta de una cabecera PoST, contexto de
transición dev PoW → PoST (marcador S1), verificación de la justificación PoT del wire, productor
del bloque de transición (W05b2), servicio PoT local y productor PoST **en régimen** con varios
padres (W05b3). Es el crate D-P14 y depende solo de `zx-core`, `zx-pot`, `zx-dag` y `zx-poas` (más
las primitivas externas de Autonomys que ya usaba el verificador).

## Módulos

- `pot`: operaciones **puras** del PoT —proyección de `N(s)`, conversión wire↔primitiva,
  `verificar_slot_aes`, `semilla_siguiente` y `semilla_genesis`—. El reto y su aleatoriedad se
  reutilizan de `zx_poas::reto` (no se duplican).
- `pot_rango`: núcleo de `C-POT-08` (dos fases con el sello entre ellas), con los tres estados
  `PotValido` / `PotInvalido` / `PotPendiente`, la caché contextual y el presupuesto.
- `cabecera_conjunta`: puerta conjunta; mismo orden `C-POT-08` que el código antiguo, con padres por
  `zx_dag::comprobar_padres_contextual`, rango por `zx_dag::RangoSolucionValidado` y PoAS por
  `zx_poas::verificar_solucion_poas`. Devuelve `Comprobada(HechosPost)` / `Invalida` / `Pendiente`.
- `contexto_transicion`: instancia dev de D-P09…D-P11 (`f_0`, S1, sin inyecciones, `D = 0`,
  `N_dev` y `SR_dev` por parámetro, `es_terminal(h) ⟺ h = T`). Etiquetada **dev** (marcador S1).
  Desde W05b3, dos registros validados del mismo slot con **salidas distintas** son error explícito
  (H2 de RI-1b), no un `or_insert` silencioso.
- `justificacion`: decodifica y verifica los portadores del wire con `pot_rango`; sustituye el
  `IntegracionPotPendiente` perpetuo del código antiguo.
- `productor`: calcula el PoT slot a slot desde S1, audita la parcela por una fuente inyectada
  (`FuenteSoluciones`), ensambla la cabecera y la coinbase v3, firma y devuelve el `BloqueDag`
  (bloque de transición, hijo único de `T`).
- `servicio_pot`: **servicio PoT local** (lógica pura, sin hilos propios). Arranca de S1, avanza un
  slot por llamada con `N_dev`, guarda salidas y portadores de una ventana acotada y configurable
  (error explícito fuera de ella) e implementa `InstantaneaPot` para verificar cabeceras ajenas. El
  pasado validado se declara con `registrar_validado` (no se inventa).
- `productor_regimen`: **productor en régimen**. Recibe los padres ya elegidos (`PadresDag`, ≤ 15),
  el slot objetivo, el `ServicioPot`, la fuente, la clave, los parámetros dev y el cuerpo (sin la
  coinbase) y devuelve el bloque con justificación de `(slot(sp), slot(B)]`, sellado y con coinbase
  v3 del slot correcto. Rechaza `slot ≤ slot(sp)` y rangos `> MAX_BUNDLES_POT = 150`.

## Lo que este crate NO hace

No admite bloques, no inserta en GHOSTDAG, no aplica UTXO, no comprueba cuerpo ni coinbase fuera de
la forma dev, no elige `SR` desde el pasado, no controla altura ni rama DAG y no publica. Un
`Comprobada` solo acredita las pruebas locales contra los contextos recibidos. La procedencia causal
del `past(B)` sigue siendo una precondición del llamante. `producir_en_regimen` **no elige padres ni
decide si la clave tiene garantía**: eso es del nodo (`zx-cadena`).
