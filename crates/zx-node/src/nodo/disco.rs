//! Pieza D (MAP-1): disco: arranque, repetición y reinicio.
//!
//! Métodos y elementos movidos tal cual de `nodo.rs` (solo cambia la visibilidad).

use super::{
    Almacen, Arc, BlockHash, BlockHeader, BloqueAdmitido, BloqueCadena, BloqueRed,
    BloqueTransicion, ErrorNodo, ErrorRepeticion, Familia, HechosCabecera, Instant, Nodo, PathBuf,
    RegistroFirmante, ResultadoNodo, ServicioPot, Tx, bloque_dag_desde_bytes, cuerpo_desde_bytes,
    perfil,
};

impl Nodo {
    pub(super) fn arranque_limpio(
        &mut self,
        cabecera_genesis: BlockHeader,
        tx_genesis: Tx,
    ) -> ResultadoNodo<()> {
        let testigos_genesis: Vec<Vec<Vec<u8>>> = vec![Vec::new()];
        // `ORDEN-W06d6` decisión 1: instantánea para el registro de admisión de la vista de red,
        // construida antes de que `tx_genesis` se consuma más abajo.
        let para_vista_genesis = BloqueRed::Pow {
            cabecera: cabecera_genesis,
            txs: vec![tx_genesis.clone()],
            testigos: testigos_genesis.clone(),
        };
        self.cadena
            .admitir(BloqueCadena::Pow(BloqueTransicion::nuevo(
                HechosCabecera::Genesis {
                    hash: cabecera_genesis.block_hash(),
                },
                vec![(
                    tx_genesis.clone(),
                    testigos_genesis.first().cloned().unwrap_or_default(),
                )],
            )))
            .map_err(|m| ErrorNodo::BloquePropioRechazado {
                hash: cabecera_genesis.block_hash(),
                motivo: m.nombre().to_string(),
                // Interno: el génesis dev es una constante fija (W04); un rechazo aquí es siempre
                // un bug de construcción, nunca una carrera (no hay nada concurrente todavía).
                clasificacion: crate::rechazo::ClasificacionRechazo::Interno,
            })?;
        self.emitir_violaciones_finalidad()?;
        let admitido = BloqueAdmitido::pow(&cabecera_genesis, &[tx_genesis], &testigos_genesis);
        self.almacen.admitir(&admitido, true)?;
        self.headers_pow
            .insert(cabecera_genesis.block_hash(), cabecera_genesis);
        self.historial_pow.push(cabecera_genesis);
        // `ORDEN-W06d3`, hallazgo en vivo (`PROGRESO.md`): en un arranque limpio (a diferencia de
        // un reinicio, que sí pasa por `admitir_pow_interno`) nada más registraba el génesis en
        // `VistaRed::cabeceras_pow`; el primer bloque real quedaba como "hueco de altura" para
        // siempre y el localizador de sincronización nunca llegaba a funcionar. `Self::historial_pow`
        // es la fuente de verdad; `fijar_cabeceras_pow` la copia entera a la vista.
        self.vista_red.fijar_cabeceras_pow(&self.historial_pow);
        // `ORDEN-W06d6` decisión 1: el registro de admisión de la vista tiene que empezar en el
        // génesis, igual que el registro real de `zx-storage` (`registrar_pow` no se llama aquí,
        // así que sin esto el cuerpo y la entrada de registro del génesis nunca existirían en la
        // vista de red).
        self.vista_red.registrar_genesis_pow(para_vista_genesis);
        // `ORDEN-SL4b2` decisión 2 (FIR-12): arranque limpio ⇒ `Registro::nueva`, sin historia y
        // sin abstención — el directorio de datos lo creó este mismo proceso, así que no hay nada
        // que perder.
        self.abrir_registro_firmante_limpio()?;
        Ok(())
    }

    /// Ruta del registro durable del firmante seguro (decisión 2): un fichero por nodo, compartido
    /// entre todas sus claves (la identidad RAT-1 ya incluye `public_key`, FIR-02).
    fn ruta_registro_firmante(&self) -> PathBuf {
        self.dir_datos.join("firmante.registro")
    }

    /// `ORDEN-SL4b2` decisión 2, FIR-12: alta atómica sin historia. Solo válido en un arranque
    /// **limpio** (directorio de datos creado por este proceso): una identidad que ya existía y
    /// perdió su registro usa [`Self::abrir_registro_firmante_tras_reinicio`], nunca esta ruta.
    fn abrir_registro_firmante_limpio(&mut self) -> ResultadoNodo<()> {
        let ruta = self.ruta_registro_firmante();
        let registro = RegistroFirmante::nueva(ruta).map_err(|e| {
            ErrorNodo::Otro(format!(
                "firmante: no se pudo crear el registro nuevo (arranque limpio): {e}"
            ))
        })?;
        self.registro_firmante = Some(Arc::new(registro));
        Ok(())
    }

    /// `ORDEN-SL4b2` decisión 2: en todo reinicio, `Registro::abrir(ruta, slot_actual, 150)` con
    /// `slot_actual = máx(slot más alto de los bloques del almacén, slot PoT reconstruido)`. Se
    /// llama al final de [`Self::reiniciar`], cuando `self.cadena` y
    /// `self.servicios_verificacion` ya reflejan toda la historia repetida.
    fn abrir_registro_firmante_tras_reinicio(&mut self) -> ResultadoNodo<()> {
        let slot_bloques = self
            .cadena
            .bloques_post()
            .iter()
            .map(|b| b.slot)
            .max()
            .unwrap_or(0);
        let slot_pot = self
            .cadena
            .terminal()
            .and_then(|t| self.servicios_verificacion.get(&t))
            .map(ServicioPot::slot_actual)
            .unwrap_or(0);
        let slot_actual = slot_bloques.max(slot_pot);
        let ruta = self.ruta_registro_firmante();
        let registro =
            RegistroFirmante::abrir(ruta, slot_actual, perfil::S_MAX_SLOTS).map_err(|e| {
                ErrorNodo::Otro(format!(
                    "firmante: no se pudo abrir el registro tras el reinicio (slot_actual \
                     {slot_actual}): {e}"
                ))
            })?;
        self.registro_firmante = Some(Arc::new(registro));
        Ok(())
    }

    /// D-N03′: repite el registro de admisión sobre una `Cadena` fresca, sin re-verificar cabeceras,
    /// y reconstruye el `ServicioPot` de verificación desde las cabeceras almacenadas (decisión 7).
    pub(super) fn reiniciar(&mut self, longitud: u64) -> ResultadoNodo<()> {
        let inicio = Instant::now();

        // `Almacen::repetir` toma un `FnMut` que aquí no puede pedir prestado `self` entero (ya
        // presta `self.almacen`): se recogen primero los pares crudos (el almacén ya comprobó su
        // integridad al abrir) y se procesan después, uno a uno, con acceso normal a `self`.
        let mut crudos: Vec<(BlockHash, Vec<u8>)> = Vec::new();
        let resultado: Result<(), ErrorRepeticion<std::convert::Infallible>> =
            self.almacen.repetir(&mut |hash, valor| {
                crudos.push((hash, valor.to_vec()));
                Ok(())
            });
        resultado.map_err(|e| match e {
            ErrorRepeticion::Almacen(se) => ErrorNodo::Almacen(se),
            ErrorRepeticion::Destino(ne) => match ne {},
        })?;

        let mut indice = 0u64;
        for (hash, valor) in &crudos {
            self.repetir_uno(*hash, valor, indice)?;
            indice = indice.saturating_add(1);
        }

        if indice != longitud {
            return Err(ErrorNodo::Otro(format!(
                "la repetición procesó {indice} entradas, se esperaban {longitud}"
            )));
        }
        // `ORDEN-SL4b2` decisión 2: se abre **después** de repetir, cuando `self.cadena` y
        // `self.servicios_verificacion` ya reflejan toda la historia (necesarios para calcular
        // `slot_actual`).
        self.abrir_registro_firmante_tras_reinicio()?;
        // `ORDEN-W07d` decisión 1: el resumen del estado virtual **después** de repetir todo el
        // almacén, más la punta, el conteo de bloques y el compendio de todos los admitidos. El
        // resumen usa la misma función que `cambio_punta`; el compendio, el registro persistido
        // completo (PoW y PoST).
        let (punta, resumen, n_bloques_dag, compendio, n_sectores, finalidad_votos_n, _, _, _, _) =
            self.campos_estado_final()?;
        self.registro.escribir(
            self.registro
                .evento("reinicio_completo")
                .u64("bloques_repetidos", indice)
                .u64("duracion_ns", inicio.elapsed().as_nanos() as u64)
                .str("punta", &punta)
                .str("resumen_estado", &resumen)
                .u64("n_bloques_dag", n_bloques_dag)
                .u64("n_sectores", n_sectores)
                .u64("finalidad_votos_n", finalidad_votos_n)
                .str("compendio_bloques", &compendio),
            true,
        )?;
        Ok(())
    }

    fn repetir_uno(&mut self, hash: BlockHash, valor: &[u8], indice: u64) -> Result<(), ErrorNodo> {
        let bloque =
            BloqueAdmitido::desde_almacen(valor).map_err(|e| ErrorNodo::RepeticionFallida {
                indice,
                hash,
                motivo: e.to_string(),
            })?;
        match bloque.familia() {
            Familia::Pow => {
                let (cuerpo, _) = cuerpo_desde_bytes(bloque.canonicos()).map_err(|e| {
                    ErrorNodo::RepeticionFallida {
                        indice,
                        hash,
                        motivo: e.to_string(),
                    }
                })?;
                let (cabecera, txs, testigos) = cuerpo;
                self.admitir_pow_interno(cabecera, txs, testigos, indice, false, false)
            }
            Familia::Post => {
                let (bloque_dag, _) = bloque_dag_desde_bytes(bloque.canonicos()).map_err(|e| {
                    ErrorNodo::RepeticionFallida {
                        indice,
                        hash,
                        motivo: e.to_string(),
                    }
                })?;
                self.admitir_post_interno(bloque_dag, indice, false)
            }
        }
    }
}
