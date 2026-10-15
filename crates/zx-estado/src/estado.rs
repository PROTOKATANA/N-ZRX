//! Estado: el árbol por familia, la raíz combinada y la fachada de lote y pruebas.

use crate::almacen::{Almacen, reconstruir_familia};
use crate::camino::{Camino, CaminoSha3};
use crate::error::Error;
use crate::hash::{Hash32, raiz_estado};
use crate::lote::{self, Cambio};
use crate::prueba::{self, Prueba};

/// Árbol de estado genérico sobre un almacén `A` y una función de camino `C`.
///
/// No conoce `Estado` de consenso ni depende de `zx-consensus`/`zx-node`: familia, clave y valor
/// son bytes.
pub struct Estado<A: Almacen, C: Camino = CaminoSha3> {
    almacen: A,
    camino: C,
}

impl<A: Almacen, C: Camino> Estado<A, C> {
    /// Envuelve un almacén con su función de camino.
    #[must_use]
    pub fn nuevo(almacen: A, camino: C) -> Self {
        Self { almacen, camino }
    }

    /// Acceso de solo lectura al almacén.
    #[must_use]
    pub fn almacen(&self) -> &A {
        &self.almacen
    }

    /// Acceso mutable al almacén.
    pub fn almacen_mut(&mut self) -> &mut A {
        &mut self.almacen
    }

    /// Función de camino.
    #[must_use]
    pub fn camino(&self) -> &C {
        &self.camino
    }

    /// Raíz del árbol de `familia`.
    ///
    /// # Errors
    /// Si el almacén no puede leer.
    pub fn raiz_familia(&self, familia: u8) -> Result<Hash32, Error> {
        self.almacen.raiz(familia)
    }

    /// Raíces de todas las familias con árbol.
    ///
    /// # Errors
    /// Si el almacén no puede leer.
    pub fn raices(&self) -> Result<Vec<(u8, Hash32)>, Error> {
        self.almacen.raices()
    }

    /// Raíz de 32 B del estado: las raíces de las familias del diseño más `h_escalares`.
    ///
    /// # Errors
    /// Si el almacén no puede leer.
    pub fn raiz_estado(&self, h_escalares: &Hash32) -> Result<Hash32, Error> {
        Ok(raiz_estado(&self.almacen.raices()?, h_escalares))
    }

    /// Aplica un lote (con `hilos` para las lecturas) y devuelve las raíces de familia tocadas.
    ///
    /// # Errors
    /// Si falta un nodo, hay bytes mal formados o el almacén rechaza la escritura.
    pub fn aplicar(
        &mut self,
        cambios: &[Cambio],
        hilos: usize,
    ) -> Result<Vec<(u8, Hash32)>, Error> {
        lote::aplicar(&mut self.almacen, &self.camino, cambios, hilos)
    }

    /// Genera la prueba de `clave` en `familia`.
    ///
    /// # Errors
    /// Si falta un nodo o hay bytes mal formados.
    pub fn prueba(&self, familia: u8, clave: &[u8]) -> Result<Prueba, Error> {
        prueba::prueba(&self.almacen, &self.camino, familia, clave)
    }

    /// Verifica una prueba contra la raíz de `familia`.
    #[must_use]
    pub fn verificar(
        &self,
        raiz: &Hash32,
        familia: u8,
        clave: &[u8],
        valor: Option<&[u8]>,
        prueba: &Prueba,
    ) -> bool {
        prueba::verificar(&self.camino, raiz, familia, clave, valor, prueba)
    }

    /// Reconstruye el árbol de `familia` desde el índice de hojas (oráculo desde cero).
    ///
    /// # Errors
    /// Si el almacén no puede leer o el árbol reconstruido no cabe en el formato.
    pub fn reconstruir_familia(&self, familia: u8) -> Result<Hash32, Error> {
        reconstruir_familia(&self.almacen, &self.camino, familia)
    }
}
