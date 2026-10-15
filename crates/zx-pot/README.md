# zx-pot

Primitiva **Proof of Time AES de Autonomys** portada a Rust estable y adoptada como crate del
workspace de ZEROX. Verifica **un slot**: dada `(semilla, N, PotCheckpoints)`, decide si la
cadena AES128 secuencial los reproduce. **No declara válido un bloque** ni conoce flujo, caché,
reto, sello ni estado.

## Procedencia

- **Origen:** `subspace-proof-of-time` (Autonomys / Subspace), `subspace` @ `f8842d0`,
  licencia **0BSD**. El port reproduce su AES sin reimplementar ninguna primitiva.
- **Vectores:** `tests/vectores-nightly.txt` son 32 vectores **diferenciales** byte a byte,
  generados ejecutando el **crate original sin modificar** bajo `nightly-2026-05-03`. El test
  `tests/diferencial.rs` los reproduce exactamente; se comprobó por mutación que alterar un byte
  de un vector hace fallar el test.
- **Prototipo de origen:** `prototipos/pot-estable`, conservado sin cambios. Este crate es su
  incorporación al workspace, no una reescritura.

## Qué se copió y qué no

Copiados **literalmente** desde `prototipos/pot-estable`:

| Archivo | Contenido |
|---|---|
| `src/aes.rs` | `create`, `verify_sequential` y la variante genérica |
| `src/aes/x86_64.rs` | AES-NI, VAES/AVX2, VAES/AVX-512 y expansión de claves |
| `src/aes/aarch64.rs` | AES de ARM, tal cual lo dejó el prototipo |
| `src/tipos.rs` | newtypes de 16 B y el `PotCheckpoints` de 8 salidas |
| `tests/vectores-nightly.txt` | los 32 vectores diferenciales |

Diferencias respecto del prototipo, todas documentadas:

1. **Nombre del crate:** `pot-estable` → `zx-pot`. Los tests referencian `zx_pot`.
2. **Atributos de lint** en `src/lib.rs` (no en el AES), con su motivo, para convivir con los
   lints del workspace sin reformular el código copiado.
3. **Aviso sobre `aarch64`:** el prototipo sustituyó `portable_simd` solo en `x86_64.rs`; su
   `aarch64.rs` sigue usando `core::simd` (inestable) y el gate de nightly se retiró de
   `lib.rs`. En esta máquina `x86_64` la ruta ARM no se compila ni se ha verificado; se conserva
   intacta, sin tocar, y **no se presenta como probada**.

## Qué no hace

- No implementa el flujo del slot, la inyección de entropía, el encadenado slot a slot
  (`C-POT-01`) ni la derivación del reto (`C-POT-03`).
- No tiene los tres estados, la caché contextual ni el orden de validación de §7.1.2
  (`C-POT-06`…`C-POT-08`): el adaptador puro entre el wire y esta primitiva vive en
  `zx-consensus` y no está cableado a `zx-node`.
- No declara válido un bloque PoST. `zx-core::wire_dag::verificar_justificacion_pot` sigue
  devolviendo `IntegracionPotPendiente`.

## Comprobación

```bash
cargo test -p zx-pot --offline --locked
```

El contrato de la primitiva está en `SPEC.md` `C-POT-02`; el dominio de `N(s)` que el
verificador debe proyectar antes de llamarla, en `C-POT-04`.
