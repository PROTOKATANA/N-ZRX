# Vectores CAVP del NIST — SHA3-256

Copiados al repo desde `/tmp` el 2026-09-04. **`/tmp` es efímero: estos archivos son la fuente de
verdad de la conformidad de nuestra función hash y no pueden vivir fuera del control de versiones.**

Origen: NIST CAVP, *SHA-3 byte test vectors* y *bit test vectors*.
Cabecera de los archivos: `CAVS 19.0`, generados 2016-01-28.

## Qué aplica a ZEROX

| Archivo | Vectores | ¿Aplica? |
|---|---|---|
| `SHA3_256ShortMsg.rsp` | 137 | ✅ **Sí** — byte-oriented, mensajes de 0 a 1088 bits |
| `SHA3_256LongMsg.rsp` | 100 | ✅ **Sí** — byte-oriented, mensajes largos |
| `SHA3_256Monte.rsp` | Monte Carlo | ✅ **Sí** — 100 000 iteraciones encadenadas |
| `SHA3_256ShortMsg_bitoriented.rsp` | 1089 | ⚠️ **No aplica** — ver abajo |

**Total aplicable: 237 vectores** byte-oriented, más el Monte Carlo.

### Por qué el bit-oriented no aplica

`SPEC.md` C-ENC-01 y toda la codificación canónica trabajan en **bytes completos**. ZEROX nunca
hashea un mensaje de longitud no múltiplo de 8 bits. Se conserva el archivo por completitud y por si
hiciera falta para una auditoría externa, pero **un fallo ahí no es un fallo de ZEROX**.

### Sobre la cifra "860" de `research/sha3-kernel-audit.md`

Los 860 del informe son las **cuatro variantes** de SHA-3 byte-oriented sumadas:

```
SHA3-224: 245  ·  SHA3-256: 237  ·  SHA3-384: 205  ·  SHA3-512: 173   =  860
```

ZEROX solo usa **SHA3-256**, así que su puerta de CI son **237 + Monte**, no 860. No es una
discrepancia del informe: es que el informe auditó el kernel completo, y nosotros solo necesitamos
una variante.

## Formato

```
Len = 0                      ← longitud en BITS, no en bytes
Msg = 00                     ← ⚠️ con Len = 0 el mensaje es VACÍO, no el byte 0x00
MD  = a7ffc6f8bf1ed766...    ← digest esperado
```

El primer vector es el ancla de cordura conocida: `SHA3-256("")` =
`a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`.

Si esa línea no pasa, no sigas: es SHA3-256 FIPS 202 mal implementado. El valor equivalente para
Keccak-256 (el legacy con byte de dominio `0x01`) es
`c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` — si te sale ese, has
implementado Keccak, no SHA-3. Es exactamente el hallazgo H-001.
