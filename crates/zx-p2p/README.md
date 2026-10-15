# zx-p2p

Transporte libp2p, descubrimiento, gossip de bloques híbridos, codificación y límites de recursos.

Contiene implementación y tests. La red transporta datos; la validación y el estado se coordinan
en `zx-node`. En 0.0.1 la difusión lleva el **bloque completo** por dos temas (`pow` y `post`) y el
protocolo de sincronización es `/zx-dev/1`. El relé compacto (BIP 152) **no se porta** en 0.0.1.

Frontera de dependencias: `zx-p2p → {zx-core}`. `zx-core` aporta los tipos puros (cabeceras,
transacciones, `Red`); este crate **no** ve consenso, almacén ni mempool. La CI
`frontera-crates.sh` lo comprueba.
