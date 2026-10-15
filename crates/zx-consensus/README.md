# `zx-consensus` — motor PoW de la fase de arranque

Crate **nuevo** de la red dev de 0.0.1 (órdenes D-P05 y D-T01). Implementa, **parametrizado por
red** en lugar de con constantes:

- el retarget **LWMA-1** (`C-DIFF-01…08`) con aritmética `U512` y solvetimes monótonos;
- la **selección por mayor trabajo acumulado** con desempate determinista por menor `block_hash`
  (`C-FORK-03`, `C-FORK-04`);
- las reglas de **timestamp** (`C-TS-01`, `C-TS-03`, `C-TS-05`);
- el **génesis constructivo** (`C-GEN-01…07`) para dev, mainnet y testnet;
- el **verificador de cabecera PoW** con `bits`, `hash_pow < target`, altura y padre;
- un **minero CPU de desarrollo**.

El `block_hash` de la cabecera es **siempre** `SHA3-256("ZZKBlkHeader____" ‖ cabecera)`. El
`hash_pow` es lo que se compara con el target y vive detrás de `trait AlgoritmoPow`; la única
implementación es `Sha3Dev`, un **parámetro de desarrollo** — el algoritmo de producción está
abierto (IPA A-12).

## Alcance

Entra: `dificultad`, `fork_choice`, `timestamps`, `activacion`, `genesis`, verificador y minero.
**No** entra: GHOSTDAG, PoT, PoAS, firmante, emisión, validación de transacciones, cuerpo de bloque
ni la transición PoW → PoST (TRN-04/TRN-05 son de W03/W05). Este crate no decide la profundidad de
reorganización de la fase PoW.
