//! Los cuatro tipos que `subspace-proof-of-time` necesita, reescritos sin Substrate
//! y sin nightly. Son newtypes sobre [u8;16]; no hay criptografía aquí salvo blake3
//! (crate auditado, adoptado sin modificar).
use core::ops::{Deref, DerefMut};

macro_rules! bytes16 {
    ($n:ident) => {
        #[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
        #[repr(C)]
        pub struct $n([u8; 16]);
        impl $n { pub const SIZE: usize = 16; }
        impl From<[u8; 16]> for $n { fn from(v: [u8; 16]) -> Self { Self(v) } }
        impl AsRef<[u8; 16]> for $n { fn as_ref(&self) -> &[u8; 16] { &self.0 } }
        impl Deref for $n { type Target = [u8; 16]; fn deref(&self) -> &[u8; 16] { &self.0 } }
        impl DerefMut for $n { fn deref_mut(&mut self) -> &mut [u8; 16] { &mut self.0 } }
    };
}
bytes16!(PotKey);
bytes16!(PotSeed);
bytes16!(PotOutput);

impl PotSeed {
    /// blake3(seed)[..16] — idéntico a subspace-core-primitives/src/pot.rs:183
    pub fn key(&self) -> PotKey {
        let mut k = PotKey::default();
        k.copy_from_slice(&blake3::hash(&self.0).as_bytes()[..Self::SIZE]);
        k
    }
}
impl PotOutput {
    /// Reinterpreta una rebanada de `[u8; 16]` como `PotOutput`. Igual que pot.rs:299.
    pub const fn slice_from_repr(v: &[[u8; 16]]) -> &[Self] {
        // SAFETY: `PotOutput` es `#[repr(C)]` con un único campo `[u8; 16]`: mismo tamaño,
        // alineación y disposición, así que las dos rebanadas tienen el mismo diseño en memoria.
        unsafe { core::mem::transmute(v) }
    }
    /// Reinterpreta una rebanada de `PotOutput` como `[u8; 16]`.
    pub const fn repr_from_slice(v: &[Self]) -> &[[u8; 16]] {
        // SAFETY: mismo diseño en memoria que en `slice_from_repr` (`#[repr(C)]` sobre `[u8; 16]`).
        unsafe { core::mem::transmute(v) }
    }
    /// Reinterpreta una rebanada mutable de `PotOutput` como `[u8; 16]`.
    pub fn repr_from_slice_mut(v: &mut [Self]) -> &mut [[u8; 16]] {
        // SAFETY: mismo diseño en memoria que en `slice_from_repr`; el préstamo mutable es único.
        unsafe { core::mem::transmute(v) }
    }
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct PotCheckpoints([PotOutput; 8]);
impl PotCheckpoints {
    pub const NUM_CHECKPOINTS: core::num::NonZeroU8 = core::num::NonZeroU8::new(8).unwrap();
    pub fn output(&self) -> PotOutput { self.0[7] }
}
impl Deref for PotCheckpoints { type Target = [PotOutput; 8]; fn deref(&self) -> &Self::Target { &self.0 } }
impl DerefMut for PotCheckpoints { fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 } }
