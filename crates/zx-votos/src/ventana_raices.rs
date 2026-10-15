//! Ventana entera por **raíces de estado** (pieza A5, paso (c), segunda parte).
//!
//! [`VentanaPorRaices`] lleva **una** ventana (`n`), **una** tabla, **un** candidato y **una** tabla
//! siguiente, y dentro mantiene **un [`EstadoVentana`] por raíz de estado**, creado al llegar el
//! primer voto suelto o el primer agregado **válido** de esa raíz. Es la pieza que el motor
//! necesita para certificar la raíz que alcanza el quórum cuando los votos de una ventana traen
//! raíces distintas (reglas M3 y M5 de `ORDEN-A1D1-2.md`).
//!
//! Reglas propias de la ventana, además de las de A5-c-1a dentro de cada raíz:
//!
//! - **Una clave cuenta en un solo grupo:** el segundo voto suelto de una clave con otra raíz no se
//!   añade ([`VentanaPorRaices::registrar_suelto`] devuelve [`ResultadoSuelto::OtraRaiz`]).
//! - **Una agregadora ocupa una sola plaza por subred en toda la ventana**, sea cual sea la raíz:
//!   su segundo agregado válido con otra raíz es [`ResultadoAgregado::Repetido`]. Un agregado
//!   inválido no crea grupo ni ocupa plaza.
//! - **El grupo ganador** es el que alcanza el quórum; si lo alcanzaran dos, el de más peso
//!   cubierto y, a igualdad, el de raíz menor en bytes. Sin quórum en ninguno, no hay ganador.
//! - **El certificado** del ganador solo lleva firmas de **su** raíz; pasa `verificar_firma_peso`.
//! - **El acta** es el mapa de quienes constan en el grupo de **más peso** (mismo desempate), con
//!   su raíz.
//!
//! **Cota de memoria (V3).** La tabla tiene `N` claves, de modo que hay **como mucho `N` plazas**
//! `(subred, indice_agregadora)` y por tanto **`agregados_aceptados() ≤ N`**. Cada grupo se crea con
//! un voto suelto (a lo sumo `N`, porque cada clave cuenta una vez) o con un agregado aceptado (a lo
//! sumo `N`), así que **`raices() ≤ N + N = 2·N`**. La orden pedía «no más grupos que claves»; esa
//! cota literal no se sigue de sus propias reglas (véase `PROGRESO.md`, definición 4), y aquí se
//! expone la cota que sí se sigue de la construcción.
//!
//! Nadie llama todavía a esta pieza: no se toca `zx-node`, `zx-p2p` ni `zx-consensus`.

use std::collections::BTreeMap;
use std::sync::Arc;

use zx_bls::Firma;

use crate::agregacion::{
    Agregado, ErrorAgregacion, GeneradorEscalares, MensajeVoto, MotivoAgregado, VeredictoAgregado,
    verificar_lote_con_huella_y_sumas,
};
use crate::agregador::{
    DatosVentana, EstadoVentana, ResultadoAgregado, motivo_forma, no_anade, peso_de_mapa,
};
use crate::peso::{CertificadoPeso, quorum_peso};
use crate::tipos::Hash;

/// Resultado de registrar un voto suelto en la ventana por raíces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultadoSuelto {
    /// La clave no estaba en ningún grupo: se añadió al grupo de su raíz.
    Registrado,
    /// La clave ya estaba registrada **con esa misma raíz**: se conserva la primera firma.
    Repetido,
    /// La clave ya estaba registrada **con otra raíz**: no se añade (una clave, un grupo).
    OtraRaiz,
}

/// Grupo de una raíz con su peso cubierto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrupoRaiz {
    /// Raíz de estado del grupo.
    pub raiz: Hash,
    /// Peso cubierto `C` del grupo (elección AG-R14).
    pub peso_cubierto: u128,
}

/// Resumen de una ventana por raíces para el aviso de discrepancia.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumenRaices {
    /// Número de raíces (grupos) con estado en la ventana.
    pub raices: usize,
    /// Grupo de más peso (mismo desempate que el ganador), si hay alguno.
    pub mayor: Option<GrupoRaiz>,
    /// Segundo grupo de más peso, si hay al menos dos.
    pub segunda: Option<GrupoRaiz>,
    /// `true` si ningún grupo alcanza el quórum pero la **unión** de las claves distintas de todos
    /// los grupos sí lo alcanzaría.
    pub sin_quorum_por_division: bool,
}

/// Ventana entera con **un estado por raíz de estado**.
///
/// Comparte un único [`DatosVentana`] (tabla, claves, pesos, reparto y huella) entre todos los
/// estados; construir un grupo nuevo no vuelve a hashear la tabla.
pub struct VentanaPorRaices {
    datos: Arc<DatosVentana>,
    a: u32,
    n: u64,
    candidato: Hash,
    h_t_siguiente: Hash,
    /// Un estado por raíz de estado.
    estados: BTreeMap<Hash, EstadoVentana>,
    /// Clave (posición 1-based) → raíz que la registró como voto suelto.
    raiz_por_clave: BTreeMap<usize, Hash>,
    /// Plaza `(subred, indice_agregadora)` → raíz del agregado válido que la ocupa.
    plazas: BTreeMap<(u16, u16), Hash>,
}

impl VentanaPorRaices {
    /// Construye la ventana para una tabla (`datos`), `a = A`, la instancia `n`, el candidato y la
    /// tabla siguiente. La raíz de cada grupo se fija al crear su estado.
    #[must_use]
    pub fn nuevo(
        datos: Arc<DatosVentana>,
        a: u32,
        n: u64,
        candidato: Hash,
        h_t_siguiente: Hash,
    ) -> Self {
        Self {
            datos,
            a,
            n,
            candidato,
            h_t_siguiente,
            estados: BTreeMap::new(),
            raiz_por_clave: BTreeMap::new(),
            plazas: BTreeMap::new(),
        }
    }

    /// Número de raíces (grupos) con estado: `≤ N + N`, con `N` claves en la tabla (V3).
    #[must_use]
    pub fn raices(&self) -> usize {
        self.estados.len()
    }

    /// Número de agregados válidos aceptados: `≤ N`, con `N` claves en la tabla (V3).
    #[must_use]
    pub fn agregados_aceptados(&self) -> usize {
        self.plazas.len()
    }

    /// Mensaje A3 de una raíz con la ventana, el candidato y la tabla siguiente de la pieza.
    fn mensaje(&self, raiz: &Hash) -> MensajeVoto {
        MensajeVoto {
            n: self.n,
            candidato: self.candidato,
            h_t_siguiente: self.h_t_siguiente,
            raiz_estado: *raiz,
        }
    }

    /// `true` si el agregado trae la ventana, el candidato y la tabla siguiente de la pieza.
    fn es_de_la_pieza(&self, agregado: &Agregado) -> bool {
        self.n == agregado.n
            && self.candidato == agregado.candidato
            && self.h_t_siguiente == agregado.h_t_siguiente
    }

    /// N1 dentro de la ventana por raíces: `true` si `agregado` no añade ninguna clave a lo que el
    /// estado de **su raíz** ya tiene (más los `extras` seleccionados del mismo lote y raíz).
    fn no_anade_con(&self, agregado: &Agregado, extras: &[Agregado]) -> bool {
        let misma_raiz = extras
            .iter()
            .filter(|extra| extra.raiz_estado == agregado.raiz_estado);
        match self.estados.get(&agregado.raiz_estado) {
            Some(estado) => no_anade(
                self.datos.reparto(),
                agregado,
                |posicion| estado.es_suelto(posicion),
                estado.aceptados_valores().chain(misma_raiz),
            ),
            None => no_anade(self.datos.reparto(), agregado, |_| false, misma_raiz),
        }
    }

    /// Registra un voto suelto **ya verificado** en la posición **1-based** `posicion`, para la raíz
    /// `raiz`.
    ///
    /// Una clave cuenta en un solo grupo: si ya está registrada con otra raíz no se añade y el
    /// resultado es [`ResultadoSuelto::OtraRaiz`]; con la misma raíz es idempotente
    /// ([`ResultadoSuelto::Repetido`], se conserva la primera firma). El grupo de `raiz` se crea al
    /// llegar su primer voto suelto. La firma no se verifica aquí: el llamador la verificó.
    ///
    /// # Errores
    /// [`ErrorAgregacion::ClaveNoRegistrada`] si `posicion` cae fuera de `1..=N`.
    pub fn registrar_suelto(
        &mut self,
        posicion: usize,
        raiz: Hash,
        firma: Firma,
    ) -> Result<ResultadoSuelto, ErrorAgregacion> {
        let n = self.datos.tabla().claves.len();
        if posicion == 0 || posicion > n {
            return Err(ErrorAgregacion::ClaveNoRegistrada);
        }
        match self.raiz_por_clave.get(&posicion) {
            Some(propia) if *propia == raiz => {
                if let Some(estado) = self.estados.get_mut(&raiz) {
                    estado.registrar_suelto(posicion, firma)?;
                }
                Ok(ResultadoSuelto::Repetido)
            }
            Some(_) => Ok(ResultadoSuelto::OtraRaiz),
            None => {
                let datos = Arc::clone(&self.datos);
                let a = self.a;
                let mensaje = self.mensaje(&raiz);
                let estado = self
                    .estados
                    .entry(raiz)
                    .or_insert_with(|| EstadoVentana::nuevo(datos, a, mensaje));
                estado.registrar_suelto(posicion, firma)?;
                self.raiz_por_clave.insert(posicion, raiz);
                Ok(ResultadoSuelto::Registrado)
            }
        }
    }

    /// Recibe un agregado y dice qué pasó.
    ///
    /// Comprueba, en este orden y **antes** de cualquier firma: ventana/candidato/tabla siguiente →
    /// huella de tabla → forma → plaza global. Después lo entrega al estado de **su raíz** con las
    /// reglas de A5-c-1a. Una agregadora ocupa **una sola plaza por subred en toda la ventana**,
    /// sea cual sea la raíz: su segundo agregado válido con otra raíz es
    /// [`ResultadoAgregado::Repetido`]. Un agregado inválido **no** crea grupo ni ocupa plaza.
    ///
    /// # Errores
    /// El de BLS en la verificación del agregado, si la forma es válida.
    pub fn recibir_agregado(
        &mut self,
        agregado: &Agregado,
    ) -> Result<ResultadoAgregado, ErrorAgregacion> {
        if !self.es_de_la_pieza(agregado) {
            return Ok(ResultadoAgregado::OtroMensaje);
        }
        if agregado.huella_tabla != self.datos.huella() {
            return Ok(ResultadoAgregado::OtraTabla);
        }
        if let Some(motivo) = motivo_forma(self.datos.reparto(), agregado) {
            return Ok(ResultadoAgregado::Invalido(motivo));
        }
        let plaza = (agregado.subred, agregado.indice_agregadora);
        if self.plazas.contains_key(&plaza) {
            return Ok(ResultadoAgregado::Repetido);
        }

        let raiz = agregado.raiz_estado;
        let resultado = if self.estados.contains_key(&raiz) {
            let estado = self
                .estados
                .get_mut(&raiz)
                .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
            estado.recibir_agregado(agregado)?
        } else {
            let datos = Arc::clone(&self.datos);
            let a = self.a;
            let mensaje = self.mensaje(&raiz);
            let mut estado = EstadoVentana::nuevo(datos, a, mensaje);
            let resultado = estado.recibir_agregado(agregado)?;
            if resultado == ResultadoAgregado::Aceptado {
                self.estados.insert(raiz, estado);
            }
            resultado
        };
        if resultado == ResultadoAgregado::Aceptado {
            self.plazas.insert(plaza, raiz);
        }
        Ok(resultado)
    }

    /// Recibe un lote con el **mismo** resultado por agregado que [`Self::recibir_agregado`] uno a
    /// uno, sin verificar los agregados que no añaden ninguna clave (N2, N5).
    ///
    /// (a) clasifica cada agregado **sin** criptografía (ventana/candidato/tabla siguiente, huella,
    /// forma, plaza global y **no añade** contra lo ya aceptado antes del lote); (b) recorre los
    /// pendientes **en orden** y verifica por lotes los que añaden, con la cobertura optimista del
    /// propio lote por raíz; (c) aplica en orden el veredicto real, acepta los válidos que añaden y
    /// descarta como [`ResultadoAgregado::Repetido`] los que ya no añaden. Una agregadora ocupa una
    /// sola plaza por subred en toda la ventana. Nunca se acepta un agregado sin verificar; se puede
    /// verificar de más.
    ///
    /// # Errores
    /// El de BLS en la verificación por lotes.
    pub fn recibir_lote(
        &mut self,
        agregados: &[Agregado],
        generador: &mut impl GeneradorEscalares,
    ) -> Result<Vec<ResultadoAgregado>, ErrorAgregacion> {
        let mut resultados: Vec<Option<ResultadoAgregado>> = vec![None; agregados.len()];
        let mut pendientes: Vec<usize> = Vec::new();

        // (a) clasificación sin criptografía y descarte de lo que no añade.
        for (i, agregado) in agregados.iter().enumerate() {
            let resultado = if !self.es_de_la_pieza(agregado) {
                Some(ResultadoAgregado::OtroMensaje)
            } else if agregado.huella_tabla != self.datos.huella() {
                Some(ResultadoAgregado::OtraTabla)
            } else if let Some(motivo) = motivo_forma(self.datos.reparto(), agregado) {
                Some(ResultadoAgregado::Invalido(motivo))
            } else if self
                .plazas
                .contains_key(&(agregado.subred, agregado.indice_agregadora))
                || self.no_anade_con(agregado, &[])
            {
                Some(ResultadoAgregado::Repetido)
            } else {
                pendientes.push(i);
                None
            };
            if let Some(slot) = resultados.get_mut(i) {
                *slot = resultado;
            }
        }

        // (b)+(c) procesa los pendientes en orden, verificando por lotes los que añaden.
        let mut pos = 0usize;
        while pos < pendientes.len() {
            let Some(indice) = pendientes.get(pos).copied() else {
                break;
            };
            let Some(agregado) = agregados.get(indice) else {
                pos += 1;
                continue;
            };
            let plaza = (agregado.subred, agregado.indice_agregadora);
            if self.plazas.contains_key(&plaza) || self.no_anade_con(agregado, &[]) {
                if let Some(slot) = resultados.get_mut(indice) {
                    *slot = Some(ResultadoAgregado::Repetido);
                }
                pos += 1;
                continue;
            }

            // Selección optimista: pendientes que añaden contando ya los seleccionados.
            let mut seleccion: Vec<usize> = Vec::new();
            let mut extras: Vec<Agregado> = Vec::new();
            for (j, indice_siguiente) in pendientes.iter().enumerate().skip(pos) {
                let Some(siguiente) = agregados.get(*indice_siguiente) else {
                    continue;
                };
                if self
                    .plazas
                    .contains_key(&(siguiente.subred, siguiente.indice_agregadora))
                {
                    continue;
                }
                if !self.no_anade_con(siguiente, &extras) {
                    seleccion.push(j);
                    extras.push(siguiente.clone());
                }
            }
            let Some(ultimo) = seleccion.last().copied() else {
                pos += 1;
                continue;
            };

            let lote: Vec<Agregado> = seleccion
                .iter()
                .filter_map(|j| pendientes.get(*j).and_then(|k| agregados.get(*k)).cloned())
                .collect();
            let veredictos = verificar_lote_con_huella_y_sumas(
                &lote,
                self.datos.tabla(),
                self.datos.claves(),
                self.datos.reparto(),
                self.a,
                self.datos.huella(),
                self.datos.sumas(),
                generador,
            )?;

            // (c) aplica en orden desde `pos` hasta el último verificado.
            let mut k = 0usize;
            for (j, indice_final) in pendientes.iter().enumerate().take(ultimo + 1).skip(pos) {
                let Some(agregado) = agregados.get(*indice_final) else {
                    continue;
                };
                let plaza = (agregado.subred, agregado.indice_agregadora);
                let veredicto = if seleccion.get(k).copied() == Some(j) {
                    let actual = veredictos.get(k).copied();
                    k += 1;
                    actual
                } else {
                    None
                };
                let resultado = if self.plazas.contains_key(&plaza)
                    || self.no_anade_con(agregado, &[])
                {
                    ResultadoAgregado::Repetido
                } else if let Some(veredicto) = veredicto {
                    match veredicto {
                        VeredictoAgregado::Valido => {
                            self.aceptar_verificado(agregado);
                            ResultadoAgregado::Aceptado
                        }
                        VeredictoAgregado::Invalido(motivo) => ResultadoAgregado::Invalido(motivo),
                        VeredictoAgregado::OtraTabla => ResultadoAgregado::OtraTabla,
                    }
                } else {
                    // No se seleccionó (dominado de forma optimista): se verifica ahora, solo.
                    let uno = [agregado.clone()];
                    let veredictos_uno = verificar_lote_con_huella_y_sumas(
                        &uno,
                        self.datos.tabla(),
                        self.datos.claves(),
                        self.datos.reparto(),
                        self.a,
                        self.datos.huella(),
                        self.datos.sumas(),
                        generador,
                    )?;
                    match veredictos_uno.first().copied() {
                        Some(VeredictoAgregado::Valido) => {
                            self.aceptar_verificado(agregado);
                            ResultadoAgregado::Aceptado
                        }
                        Some(VeredictoAgregado::Invalido(motivo)) => {
                            ResultadoAgregado::Invalido(motivo)
                        }
                        Some(VeredictoAgregado::OtraTabla) => ResultadoAgregado::OtraTabla,
                        None => ResultadoAgregado::Invalido(MotivoAgregado::Forma),
                    }
                };
                if let Some(slot) = resultados.get_mut(*indice_final) {
                    *slot = Some(resultado);
                }
            }
            pos = ultimo + 1;
        }

        Ok(resultados
            .into_iter()
            .map(|resultado| {
                resultado.unwrap_or(ResultadoAgregado::Invalido(MotivoAgregado::Forma))
            })
            .collect())
    }

    /// Acepta un agregado **ya verificado** por la verificación por lotes de [`Self::recibir_lote`]:
    /// crea el grupo de su raíz si no existe, lo inserta y ocupa su plaza global. No verifica ni
    /// reclasifica (el llamador garantiza el veredicto `Valido` y la plaza libre).
    fn aceptar_verificado(&mut self, agregado: &Agregado) {
        let raiz = agregado.raiz_estado;
        if !self.estados.contains_key(&raiz) {
            let datos = Arc::clone(&self.datos);
            let a = self.a;
            let mensaje = self.mensaje(&raiz);
            self.estados
                .insert(raiz, EstadoVentana::nuevo(datos, a, mensaje));
        }
        if let Some(estado) = self.estados.get_mut(&raiz) {
            estado.aceptar_verificado(agregado);
        }
        self.plazas
            .insert((agregado.subred, agregado.indice_agregadora), raiz);
    }

    /// Devuelve el agregado propio de la clave en la posición **1-based** `posicion`, **para la raíz
    /// indicada**, dada su firma de sorteo.
    ///
    /// Si la raíz no tiene grupo (no hubo voto suelto ni agregado válido), devuelve `None`. Si lo
    /// tiene, aplica las reglas de A5-c-1a dentro de ese grupo.
    ///
    /// # Errores
    /// [`ErrorAgregacion::ClaveNoRegistrada`] si la posición no está en `1..=N`; el de BLS al
    /// agregar las firmas.
    pub fn agregado_propio(
        &mut self,
        posicion: usize,
        raiz: Hash,
        firma_sorteo: &Firma,
    ) -> Result<Option<Agregado>, ErrorAgregacion> {
        let n = self.datos.tabla().claves.len();
        if posicion == 0 || posicion > n {
            return Err(ErrorAgregacion::ClaveNoRegistrada);
        }
        match self.estados.get_mut(&raiz) {
            Some(estado) => estado.agregado_propio(posicion, firma_sorteo),
            None => Ok(None),
        }
    }

    /// Grupo ganador: el grupo que alcanza el quórum; a igualdad, más peso cubierto y, a igualdad,
    /// raíz menor en bytes. `None` si ningún grupo alcanza el quórum.
    ///
    /// # Errores
    /// El de [`EstadoVentana::hay_quorum`].
    pub fn grupo_ganador(&self) -> Result<Option<GrupoRaiz>, ErrorAgregacion> {
        let mut mejor: Option<GrupoRaiz> = None;
        for (raiz, estado) in &self.estados {
            if !estado.hay_quorum()? {
                continue;
            }
            let candidato = GrupoRaiz {
                raiz: *raiz,
                peso_cubierto: estado.peso_cubierto()?,
            };
            let es_mejor = match mejor {
                None => true,
                Some(previo) => {
                    candidato.peso_cubierto > previo.peso_cubierto
                        || (candidato.peso_cubierto == previo.peso_cubierto
                            && candidato.raiz < previo.raiz)
                }
            };
            if es_mejor {
                mejor = Some(candidato);
            }
        }
        Ok(mejor)
    }

    /// Grupo de **más peso** con el mismo desempate que el ganador, tenga o no quórum. Es el grupo
    /// del acta. `None` si no hay grupos.
    ///
    /// # Errores
    /// El de [`EstadoVentana::peso_cubierto`].
    fn grupo_mas_peso(&self) -> Result<Option<GrupoRaiz>, ErrorAgregacion> {
        let mut mejor: Option<GrupoRaiz> = None;
        for (raiz, estado) in &self.estados {
            let candidato = GrupoRaiz {
                raiz: *raiz,
                peso_cubierto: estado.peso_cubierto()?,
            };
            let es_mejor = match mejor {
                None => true,
                Some(previo) => {
                    candidato.peso_cubierto > previo.peso_cubierto
                        || (candidato.peso_cubierto == previo.peso_cubierto
                            && candidato.raiz < previo.raiz)
                }
            };
            if es_mejor {
                mejor = Some(candidato);
            }
        }
        Ok(mejor)
    }

    /// Certificado del grupo ganador, o `None` si ningún grupo alcanza el quórum.
    ///
    /// Solo lleva firmas de **su** raíz (cada [`EstadoVentana`] tiene los votos de una sola raíz) y
    /// pasa [`crate::peso::verificar_firma_peso`] contra la tabla y sus claves.
    ///
    /// # Errores
    /// El de BLS al agregar firmas.
    pub fn certificado(&self) -> Result<Option<CertificadoPeso>, ErrorAgregacion> {
        let Some(ganador) = self.grupo_ganador()? else {
            return Ok(None);
        };
        let estado = self
            .estados
            .get(&ganador.raiz)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        estado.certificado()
    }

    /// Mapa de quienes constan en el grupo de **más peso** (mismo desempate que el ganador) y su
    /// raíz, para el acta. `None` si no hay grupos.
    ///
    /// # Errores
    /// El de [`EstadoVentana::mapa_constan`].
    pub fn acta(&self) -> Result<Option<(Hash, Vec<u8>)>, ErrorAgregacion> {
        let Some(mayor) = self.grupo_mas_peso()? else {
            return Ok(None);
        };
        let estado = self
            .estados
            .get(&mayor.raiz)
            .ok_or(ErrorAgregacion::ClaveNoRegistrada)?;
        Ok(Some((mayor.raiz, estado.mapa_constan()?)))
    }

    /// Unión (OR) de los mapas de quienes constan de **todos** los grupos, o `None` sin grupos.
    ///
    /// Es la «suma de las claves distintas» que solo usa el resumen para detectar la división del
    /// quórum. No se usa para certificar: un certificado mezclaría raíces.
    fn union_mapa(&self) -> Result<Option<Vec<u8>>, ErrorAgregacion> {
        let mut union: Option<Vec<u8>> = None;
        for estado in self.estados.values() {
            let mapa = estado.mapa_constan()?;
            match union.as_mut() {
                None => union = Some(mapa),
                Some(acumulado) => {
                    for (indice, byte) in mapa.iter().enumerate() {
                        if let Some(slot) = acumulado.get_mut(indice) {
                            *slot |= *byte;
                        }
                    }
                }
            }
        }
        Ok(union)
    }

    /// `true` si la **unión** de las claves distintas de todos los grupos alcanza el quórum.
    fn union_tiene_quorum(&self) -> Result<bool, ErrorAgregacion> {
        match self.union_mapa()? {
            Some(mapa) => Ok(quorum_peso(
                peso_de_mapa(&mapa, self.datos.pesos()),
                self.datos.peso_total(),
            )),
            None => Ok(false),
        }
    }

    /// Resumen para el aviso de discrepancia: número de raíces, las **dos de más peso** con su peso
    /// cubierto, y si ningún grupo llega al quórum pero la **unión de las claves distintas** de
    /// todos los grupos sí.
    ///
    /// # Errores
    /// El de [`EstadoVentana::peso_cubierto`] y [`EstadoVentana::mapa_constan`].
    pub fn resumen(&self) -> Result<ResumenRaices, ErrorAgregacion> {
        let mut grupos: Vec<GrupoRaiz> = Vec::with_capacity(self.estados.len());
        for (raiz, estado) in &self.estados {
            grupos.push(GrupoRaiz {
                raiz: *raiz,
                peso_cubierto: estado.peso_cubierto()?,
            });
        }
        grupos.sort_by(|a, b| {
            b.peso_cubierto
                .cmp(&a.peso_cubierto)
                .then_with(|| a.raiz.cmp(&b.raiz))
        });
        let mayor = grupos.first().copied();
        let segunda = grupos.get(1).copied();

        let sin_quorum_por_division = if self.grupo_ganador()?.is_some() {
            false
        } else {
            self.union_tiene_quorum()?
        };

        Ok(ResumenRaices {
            raices: self.estados.len(),
            mayor,
            segunda,
            sin_quorum_por_division,
        })
    }
}
