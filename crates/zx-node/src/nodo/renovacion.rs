//! Pieza S (MAP-1): renovación de los sectores propios.
//!
//! Métodos y elementos movidos tal cual de `nodo.rs` (solo cambia la visibilidad).

use super::{
    ClaveDev, ErrorNodo, Etapa, ExtensionTx, HistoriaGenesis, Nodo, ParcelaDisco, Path, PathBuf,
    PublicKey, ResultadoNodo, SectorId, Tx, hex, plotear_sector_en_disco,
};

#[cfg(test)]
use super::ESTADO_VIRTUAL_RENOVACION;

/// RN-1 · S2/S3 · renovación **en vuelo** de una clave propia: la operación `Renovar` que el nodo ya
/// construyó y admitió en su mempool y que todavía no ha visto aplicada en el estado seleccionado.
///
/// Se guarda una por clave (S2: una operación de sector propia en vuelo por clave). El `sector_index`
/// y la `version` localizan el `SectorId` exacto; `renovacion_slot_previo` es el valor que tenía el
/// sector cuando se envió, de modo que basta ver uno **posterior** para darla por aplicada (S3).
#[derive(Clone, Copy)]
pub(super) struct RenovacionEnVuelo {
    /// Índice del sector que se renueva.
    sector_index: u16,
    /// Versión del sector renovado (para localizar su `SectorId`).
    version: u32,
    /// `renovacion_slot` del sector cuando se construyó la renovación (valor anterior).
    renovacion_slot_previo: i64,
    /// Slot del reloj de votos en que se intentó por última vez.
    slot_envio: u64,
    /// `true` si el último intento lo **rechazó** la mempool: se reintenta tras `m_sec` (S2/S3), no
    /// tras `m_sec · 4`.
    rechazada: bool,
}

fn ruta_parcela(dir_datos: &Path, indice: u32) -> PathBuf {
    dir_datos.join(format!("parcela-{indice}.plot"))
}

/// Índice de sector determinista por índice de clave (D2: distinto de cero para ejercitar offset).
fn indice_sector_de(indice_clave: u32) -> u16 {
    u16::try_from(indice_clave % 1000).unwrap_or(0) + 1
}

const PIEZAS_POR_SECTOR: u16 = zx_poas::protocolo_dev::PIEZAS_POR_SECTOR_DEV;

/// Abre o crea la parcela de una clave (D2).
pub(super) fn abrir_o_crear_parcela(
    dir_datos: &Path,
    clave: &ClaveDev,
    historia: &HistoriaGenesis,
) -> ResultadoNodo<ParcelaDisco> {
    let ruta = ruta_parcela(dir_datos, clave.indice);
    let public_key = PublicKey::from(*clave.pk.bytes());
    if !ruta.exists() {
        plotear_sector_en_disco(
            &ruta,
            &public_key,
            indice_sector_de(clave.indice),
            PIEZAS_POR_SECTOR,
            historia.historial(),
            historia.protocolo(),
            historia.erasure_coding(),
        )
        .map_err(ErrorNodo::Farmer)?;
    }
    ParcelaDisco::abrir(&ruta, &public_key).map_err(ErrorNodo::Farmer)
}

impl Nodo {
    /// RN-1 · S2 · construye la transacción `Renovar` de un sector propio, la admite en la mempool y
    /// la difunde por el mismo camino que las demás transacciones propias. Deja `tx_admitida`/
    /// `tx_rechazada` (S5) y, si se admite, `renovacion_enviada` con el `renovacion_slot` anterior.
    fn enviar_renovacion(
        &mut self,
        clave: zx_core::ClavePublica,
        sector_index: u16,
        version: u32,
        renovacion_slot_previo: i64,
        slot: u64,
    ) {
        let Some(clave_dev) = self.claves.iter().find(|c| c.pk == clave).cloned() else {
            return;
        };
        let tx = Tx {
            version: 5,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            expiry_height: 0,
            extension: ExtensionTx::Sector {
                operacion: zx_core::OperacionSector::Renovar {
                    clave,
                    sector_index,
                },
            },
        };
        let firma: [u8; 64] = clave_dev
            .sk
            .sign(&zx_core::mensaje_sector(&tx, self.cbid))
            .into();
        let testigos = vec![firma.to_vec()];
        let mut buf = Vec::new();
        zx_core::wire::tx_a_bytes(&mut buf, &tx, &testigos);
        match self.admitir_tx_en_mempool(tx, testigos, "propia") {
            Ok(crate::mempool::Admision::Admitida) => {
                let _ = self.difundir_tx_si_hay_red(&buf);
                let evento = self
                    .registro
                    .evento("renovacion_enviada")
                    .str("clave", &hex(clave.bytes()))
                    .u64("sector", u64::from(sector_index))
                    .i64("renovacion_slot", renovacion_slot_previo);
                let _ = self.registro.escribir(evento, false);
                self.renovaciones_propias.insert(
                    clave,
                    RenovacionEnVuelo {
                        sector_index,
                        version,
                        renovacion_slot_previo,
                        slot_envio: slot,
                        rechazada: false,
                    },
                );
            }
            Ok(_) => {
                // Ya estaba en la mempool (duplicada): no se reenvía ni se reemite el evento.
                self.renovaciones_propias
                    .entry(clave)
                    .or_insert(RenovacionEnVuelo {
                        sector_index,
                        version,
                        renovacion_slot_previo,
                        slot_envio: slot,
                        rechazada: false,
                    });
            }
            Err(_) => {
                // Rechazo registrado por `admitir_tx_en_mempool`; se reintenta tras `m_sec` (S2/S3).
                self.renovaciones_propias.insert(
                    clave,
                    RenovacionEnVuelo {
                        sector_index,
                        version,
                        renovacion_slot_previo,
                        slot_envio: slot,
                        rechazada: true,
                    },
                );
            }
        }
    }

    /// RN-1 · S1/S2/S3/S4 · mantiene vivos los sectores **propios activos** del estado seleccionado.
    ///
    /// - **S1:** renueva cuando `slot ≥ renovacion_slot + t_cad / 2`, todo de `parametros_sector`.
    /// - **S2:** como mucho **una** operación de sector propia en vuelo por clave; si una clave tiene
    ///   varios sectores que renovar, primero el de `renovacion_slot` más antiguo; no reenvía antes
    ///   de `m_sec`.
    /// - **S3:** da la renovación por hecha al ver un `renovacion_slot` posterior; si pasan
    ///   `m_sec · 4` slots sin aplicarse, la reconstruye y la reenvía.
    /// - **S4:** no toca sectores ajenos ni inactivos y no da de alta; corre con o sin `--sin-voto`.
    pub(super) fn renovar_sectores_propios(&mut self, slot: u64) {
        #[cfg(test)]
        ESTADO_VIRTUAL_RENOVACION.with(|c| c.set(c.get().saturating_add(1)));
        let Ok(estado) = self.cadena.estado_virtual() else {
            return;
        };
        let p = estado.parametros_sector;
        let m_sec = p.m_sec.max(1);
        let umbral_mitad = p.t_cad.div_euclid(2);
        let slot_i64 = i64::try_from(slot).unwrap_or(i64::MAX);

        // 1) Renovaciones en vuelo: ¿aplicadas? ¿por reenviar (S3)?
        let en_vuelo: Vec<zx_core::ClavePublica> =
            self.renovaciones_propias.keys().copied().collect();
        for clave in en_vuelo {
            let Some(pend) = self.renovaciones_propias.get(&clave).cloned() else {
                continue;
            };
            let id = SectorId {
                clave,
                sector_index: pend.sector_index,
                version: pend.version,
            };
            if let Some(r) = estado.sectores.get(&id)
                && r.renovacion_slot > pend.renovacion_slot_previo
            {
                let evento = self
                    .registro
                    .evento("renovacion_aplicada")
                    .str("clave", &hex(clave.bytes()))
                    .u64("sector", u64::from(pend.sector_index))
                    .i64("renovacion_slot", r.renovacion_slot);
                let _ = self.registro.escribir(evento, false);
                self.renovaciones_propias.remove(&clave);
                continue;
            }
            let espera = if pend.rechazada {
                m_sec
            } else {
                m_sec.saturating_mul(4)
            };
            let objetivo = pend
                .slot_envio
                .saturating_add(u64::try_from(espera).unwrap_or(u64::MAX));
            if slot >= objetivo {
                self.enviar_renovacion(
                    clave,
                    pend.sector_index,
                    pend.version,
                    pend.renovacion_slot_previo,
                    slot,
                );
            }
        }

        // 2) Nuevas renovaciones para cada clave propia sin ninguna en vuelo.
        let propias: Vec<zx_core::ClavePublica> = self.claves.iter().map(|c| c.pk).collect();
        for clave in propias {
            if self.renovaciones_propias.contains_key(&clave) {
                continue;
            }
            let mut mejor: Option<(i64, u16, u32)> = None;
            for (id, r) in &estado.sectores {
                if id.clave != clave || r.etapa != Etapa::Activo {
                    continue;
                }
                // Un sector que ya pasó `renovacion_slot + t_cad` está caducado de hecho aunque el
                // último bloque aplicado no lo haya materializado: no se renueva (S1/S4).
                if slot_i64 >= r.renovacion_slot.saturating_add(p.t_cad) {
                    continue;
                }
                let necesita = slot_i64 >= r.renovacion_slot.saturating_add(umbral_mitad);
                if !necesita {
                    continue;
                }
                if mejor.is_none_or(|(rs, _, _)| r.renovacion_slot < rs) {
                    mejor = Some((r.renovacion_slot, id.sector_index, id.version));
                }
            }
            if let Some((previo, sector_index, version)) = mejor {
                self.enviar_renovacion(clave, sector_index, version, previo, slot);
            }
        }
    }

    /// RN-1 · S1 · evalúa la renovación **una vez por cambio de slot** (no en cada vuelta del bucle).
    pub(super) fn renovar_si_cambia_slot(&mut self, slot: u64) {
        if self.ultimo_slot_renovacion == Some(slot) {
            return;
        }
        self.ultimo_slot_renovacion = Some(slot);
        self.renovar_sectores_propios(slot);
    }
}
