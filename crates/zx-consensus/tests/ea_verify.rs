//! Firmas BLS reales, fixtures deterministas y oráculo de conjuntos independiente.
#![allow(
    clippy::indexing_slicing,
    reason = "fixtures de prueba con tamaños controlados"
)]

use std::collections::{BTreeMap, BTreeSet};
use zx_bls::{
    ClaveSecreta, ClavesPreparadas, ErrorBLS, Firma, agregar_firmas, firmar, probar_posesion,
    verificar_posesion,
};
use zx_consensus::evidencia_agregados::{
    Clave48, ErrorContexto, ErrorVerificacion, EvidenciaVerificada, NumeroObjeto, PerfilCoste,
    ProveedorContexto, TablaContexto, UnidadesCoste, unidades_coste, verificar,
    verificar_con_observador,
};
use zx_core::evidencia_agregados::{
    ClavesExplicitas, ContenidoObjeto, ErrorEvidenciaAgregados, EvidenciaAgregadosV3,
    ObjetoEvidencia, OrigenReferencia, POSICION_SUBRED, codificar, decodificar,
};
use zx_core::{ClavePublica, VotoPesoEvidencia};
use zx_votos::agregacion::{Reparto, subred};
use zx_votos::bls::DOMINIO_VOTO;
use zx_votos::peso::mensaje_voto_peso;
use zx_votos::tipos::{Clave, Tabla};

type Fallo = Box<dyn std::error::Error>;
const SEMILLA: u64 = 0xea00_0000_0000_0003;

struct Clavero {
    secretas: BTreeMap<Clave48, ClaveSecreta>,
    claves: Vec<Clave48>,
}

impl Clavero {
    fn nuevo(n: usize) -> Result<Self, Fallo> {
        let mut secretas = BTreeMap::new();
        for i in 0..n {
            let mut ikm = [0u8; 32];
            ikm[..8].copy_from_slice(&SEMILLA.to_le_bytes());
            ikm[8..16].copy_from_slice(&(i as u64).to_le_bytes());
            ikm[16..24].copy_from_slice(&(!(i as u64)).to_le_bytes());
            ikm[24..].copy_from_slice(&0x5a5a_a5a5_0303_0000u64.to_le_bytes());
            let sk = ClaveSecreta::generar(&ikm)?;
            secretas.insert(sk.clave_publica().bytes(), sk);
        }
        let claves = secretas.keys().copied().collect();
        Ok(Self { secretas, claves })
    }

    fn firmas(&self, voto: VotoPesoEvidencia) -> Result<BTreeMap<Clave48, Firma>, Fallo> {
        let m = mensaje_voto_peso(
            voto.n,
            &voto.candidato,
            &voto.h_t_siguiente,
            &voto.raiz_estado,
        );
        self.secretas
            .iter()
            .map(|(k, sk)| Ok((*k, firmar(sk, DOMINIO_VOTO, &m)?)))
            .collect()
    }

    fn conocidas(&self) -> Result<BTreeSet<Clave48>, Fallo> {
        for sk in self.secretas.values() {
            verificar_posesion(&sk.clave_publica(), &probar_posesion(sk))?;
        }
        Ok(self.claves.iter().copied().collect())
    }
}

struct Contexto {
    tablas: [Vec<Clave48>; 2],
    puntos: [Option<ClavesPreparadas>; 2],
    conocidas: BTreeSet<Clave48>,
    fallo: [Option<ErrorContexto>; 2],
}

impl Contexto {
    fn nuevo(
        clavero: &Clavero,
        tablas: [Vec<Clave48>; 2],
        preparadas: bool,
    ) -> Result<Self, Fallo> {
        let puntos = if preparadas {
            [
                Some(ClavesPreparadas::desde_bytes(&tablas[0])?),
                Some(ClavesPreparadas::desde_bytes(&tablas[1])?),
            ]
        } else {
            [None, None]
        };
        Ok(Self {
            tablas,
            puntos,
            conocidas: clavero.conocidas()?,
            fallo: [None, None],
        })
    }
}

impl ProveedorContexto for Contexto {
    fn tabla_original<'a>(
        &'a self,
        objeto: &ObjetoEvidencia<'_>,
        origen: &OrigenReferencia,
    ) -> Result<TablaContexto<'a>, ErrorContexto> {
        let i = match origen.bloque_origen[0] {
            1 => 0,
            2 => 1,
            _ => return Err(ErrorContexto::Invalido),
        };
        if origen.h_actual != [10 + i as u8; 32] {
            return Err(ErrorContexto::Invalido);
        }
        let posicion = match objeto.contenido {
            ContenidoObjeto::SubredReferencia { .. } => POSICION_SUBRED,
            ContenidoObjeto::CertificadoReferencia { .. } => 3,
            ContenidoObjeto::ActaReferencia { .. } => 4,
            _ => return Err(ErrorContexto::Invalido),
        };
        if origen.posicion != posicion {
            return Err(ErrorContexto::Invalido);
        }
        if let Some(fallo) = self.fallo[i] {
            return Err(fallo);
        }
        match &self.puntos[i] {
            Some(p) => Ok(TablaContexto::Preparadas(p)),
            None => Ok(TablaContexto::Bytes(&self.tablas[i])),
        }
    }
    fn posesion_conocida(&self, clave: &Clave48) -> bool {
        self.conocidas.contains(clave)
    }
}

#[derive(Clone, Copy, Debug)]
enum ClaseObjeto {
    S,
    LRef,
    LExp,
    CRef,
    CExp,
    ARef,
    AExp,
}
const CLASES: [ClaseObjeto; 7] = [
    ClaseObjeto::S,
    ClaseObjeto::LRef,
    ClaseObjeto::LExp,
    ClaseObjeto::CRef,
    ClaseObjeto::CExp,
    ClaseObjeto::ARef,
    ClaseObjeto::AExp,
];

impl ClaseObjeto {
    fn local(self) -> bool {
        matches!(self, Self::LRef | Self::LExp)
    }
}

struct ObjetoPropio {
    clase: ClaseObjeto,
    voto: VotoPesoEvidencia,
    firmantes: Vec<Clave48>,
    lista: Vec<u8>,
    mapa: Vec<u8>,
    origen: OrigenReferencia,
    subred: u16,
}

fn voto(n: u64, candidato: u8) -> VotoPesoEvidencia {
    VotoPesoEvidencia {
        n,
        candidato: [candidato; 32],
        h_t_siguiente: [0x42; 32],
        raiz_estado: [0x93; 32],
        firma: [0; 96],
    }
}

fn tabla_votos(claves: &[Clave48]) -> Tabla {
    Tabla {
        n: 0,
        claves: claves
            .iter()
            .map(|k| Clave {
                clave: k.to_vec(),
                peso: 0,
                activo: false,
                prueba: false,
                garantia: 0,
            })
            .collect(),
    }
}

impl ObjetoPropio {
    fn nuevo(
        clase: ClaseObjeto,
        mut voto: VotoPesoEvidencia,
        tabla: &[Clave48],
        seleccion: &[Clave48],
        lado: usize,
        firmas: &BTreeMap<Clave48, Firma>,
    ) -> Result<Self, Fallo> {
        let mut firmantes = seleccion.to_vec();
        firmantes.sort();
        let sub = subred(firmantes.first().ok_or("seleccion vacia")?, 64)?;
        if matches!(clase, ClaseObjeto::S) && firmantes.len() != 1 {
            return Err("S exige singleton".into());
        }
        if clase.local() && firmantes.iter().any(|k| subred(k, 64).ok() != Some(sub)) {
            return Err("seleccion L de otra subred".into());
        }
        let refs = firmantes
            .iter()
            .map(|k| firmas.get(k).ok_or("falta firma".into()))
            .collect::<Result<Vec<_>, Fallo>>()?;
        voto.firma = agregar_firmas(&refs)?.bytes();
        let lista = firmantes.iter().flat_map(|k| *k).collect();
        let alcance: Vec<Clave48> = if clase.local() {
            let t = tabla_votos(tabla);
            Reparto::construir(&t, 64)?
                .claves_de(sub)
                .iter()
                .map(|i| tabla[*i])
                .collect()
        } else {
            tabla.to_vec()
        };
        let mut mapa = vec![0u8; alcance.len().div_ceil(8)];
        for k in &firmantes {
            let pos = alcance.iter().position(|x| x == k).ok_or("no en tabla")?;
            mapa[pos >> 3] |= 1 << (pos & 7);
        }
        let origen = OrigenReferencia {
            h_actual: [10 + lado as u8; 32],
            bloque_origen: [1 + lado as u8; 32],
            posicion: match clase {
                ClaseObjeto::LRef => POSICION_SUBRED,
                ClaseObjeto::ARef => 4,
                _ => 3,
            },
        };
        Ok(Self {
            clase,
            voto,
            firmantes,
            lista,
            mapa,
            origen,
            subred: sub,
        })
    }

    fn vista(&self) -> Result<ObjetoEvidencia<'_>, Fallo> {
        let contenido = match self.clase {
            ClaseObjeto::S => ContenidoObjeto::Voto {
                clave: *self.firmantes.first().ok_or("S vacio")?,
            },
            ClaseObjeto::LRef => ContenidoObjeto::SubredReferencia {
                origen: self.origen,
                subred: self.subred,
                mapa: &self.mapa,
            },
            ClaseObjeto::CRef => ContenidoObjeto::CertificadoReferencia {
                origen: self.origen,
                mapa: &self.mapa,
            },
            ClaseObjeto::ARef => ContenidoObjeto::ActaReferencia {
                origen: self.origen,
                mapa: &self.mapa,
            },
            ClaseObjeto::LExp => ContenidoObjeto::SubredExplicita {
                subred: self.subred,
                claves: ClavesExplicitas::desde_bytes(&self.lista)?,
            },
            ClaseObjeto::CExp => ContenidoObjeto::CertificadoExplicito {
                claves: ClavesExplicitas::desde_bytes(&self.lista)?,
            },
            ClaseObjeto::AExp => ContenidoObjeto::ActaExplicita {
                claves: ClavesExplicitas::desde_bytes(&self.lista)?,
            },
        };
        Ok(ObjetoEvidencia {
            voto: self.voto,
            contenido,
        })
    }
}

fn evidencia<'a>(
    uno: &'a ObjetoPropio,
    dos: &'a ObjetoPropio,
) -> Result<EvidenciaAgregadosV3<'a>, Fallo> {
    Ok(EvidenciaAgregadosV3 {
        reportero: ClavePublica::desde_bytes([0x88; 32]),
        objeto1: uno.vista()?,
        objeto2: dos.vista()?,
    })
}

fn oraculo(uno: &[Clave48], dos: &[Clave48]) -> Vec<Clave48> {
    // Cuenta independiente por búsqueda completa; no usa mapas, posiciones ni código del verificador.
    let mut comunes: Vec<_> = uno.iter().filter(|k| dos.contains(k)).copied().collect();
    comunes.sort();
    comunes.dedup();
    comunes
}

fn observar(
    e: &EvidenciaAgregadosV3<'_>,
    c: &Contexto,
) -> (Result<EvidenciaVerificada, ErrorVerificacion>, [u32; 2]) {
    let mut cuenta = [0; 2];
    let r = verificar_con_observador(e, c, &mut |objeto| match objeto {
        NumeroObjeto::Uno => cuenta[0] += 1,
        NumeroObjeto::Dos => cuenta[1] += 1,
    });
    (r, cuenta)
}

#[test]
fn ea_matriz_todas_las_parejas_modos_ventanas_y_tamanos() -> Result<(), Fallo> {
    let clavero = Clavero::nuevo(2047)?;
    let mut casos = 0;
    for n in [4, 64, 1024] {
        let tablas = [
            clavero.claves[..n].to_vec(),
            clavero.claves[n - 1..2 * n - 1].to_vec(),
        ];
        let comun = tablas[0][n - 1];
        let sub = subred(&comun, 64)?;
        assert_eq!(tablas[1][0], comun);
        for distintas in [false, true] {
            let v1 = voto(7, 1);
            let v2 = voto(if distintas { 8 } else { 7 }, 2);
            let f1 = clavero.firmas(v1)?;
            let f2 = clavero.firmas(v2)?;
            for preparada in [false, true] {
                let contexto = Contexto::nuevo(&clavero, tablas.clone(), preparada)?;
                for tipo1 in CLASES {
                    for tipo2 in CLASES {
                        let seleccionar = |tipo: ClaseObjeto, t: &[Clave48]| -> Vec<Clave48> {
                            if matches!(tipo, ClaseObjeto::S) {
                                return vec![comun];
                            }
                            t.iter()
                                .filter(|k| !tipo.local() || subred(*k, 64).ok() == Some(sub))
                                .copied()
                                .collect()
                        };
                        let s1 = seleccionar(tipo1, &tablas[0]);
                        let s2 = seleccionar(tipo2, &tablas[1]);
                        let o1 = ObjetoPropio::nuevo(tipo1, v1, &tablas[0], &s1, 0, &f1)?;
                        let o2 = ObjetoPropio::nuevo(tipo2, v2, &tablas[1], &s2, 1, &f2)?;
                        let bytes = codificar(&evidencia(&o1, &o2)?)?;
                        let e = decodificar(&bytes)?;
                        let (r, cuenta) = observar(&e, &contexto);
                        assert_eq!(
                            r?,
                            EvidenciaVerificada {
                                claves_comunes: oraculo(&s1, &s2),
                                requiere_hecho_cadena: distintas
                            },
                            "N={n} {tipo1:?}/{tipo2:?} preparada={preparada}"
                        );
                        assert_eq!(cuenta, [1, 1]);
                        casos += 1;
                    }
                }
            }
        }
    }
    assert_eq!(casos, 588);
    eprintln!(
        "EXACTO matriz: {casos} casos; N=4,64,1024; 49 combinaciones orientadas; 2 relaciones de ventana; 2 representaciones de contexto; semilla={SEMILLA:#x}"
    );
    Ok(())
}

#[test]
fn ea_tablas_distintas_posiciones() -> Result<(), Fallo> {
    let k = Clavero::nuevo(7)?;
    let t = [k.claves[..4].to_vec(), k.claves[3..].to_vec()];
    let c = Contexto::nuevo(&k, t.clone(), false)?;
    let a = ObjetoPropio::nuevo(
        ClaseObjeto::CRef,
        voto(7, 1),
        &t[0],
        &t[0],
        0,
        &k.firmas(voto(7, 1))?,
    )?;
    let b = ObjetoPropio::nuevo(
        ClaseObjeto::ARef,
        voto(8, 2),
        &t[1],
        &t[1],
        1,
        &k.firmas(voto(8, 2))?,
    )?;
    assert_eq!(a.mapa, b.mapa);
    assert_eq!(
        verificar(&evidencia(&a, &b)?, &c)?.claves_comunes,
        vec![k.claves[3]]
    );
    Ok(())
}

#[test]
fn ea_solo_en_un_objeto_no_acusa() -> Result<(), Fallo> {
    let k = Clavero::nuevo(4)?;
    let c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], false)?;
    let a = ObjetoPropio::nuevo(
        ClaseObjeto::CExp,
        voto(7, 1),
        &k.claves,
        &k.claves[..3],
        0,
        &k.firmas(voto(7, 1))?,
    )?;
    let b = ObjetoPropio::nuevo(
        ClaseObjeto::AExp,
        voto(8, 2),
        &k.claves,
        &k.claves[1..],
        1,
        &k.firmas(voto(8, 2))?,
    )?;
    assert_eq!(
        verificar(&evidencia(&a, &b)?, &c)?.claves_comunes,
        k.claves[1..3]
    );
    Ok(())
}

#[test]
fn ea_contador_1_y_1024() -> Result<(), Fallo> {
    let k = Clavero::nuevo(1024)?;
    let f1 = k.firmas(voto(7, 1))?;
    let f2 = k.firmas(voto(8, 2))?;
    for preparada in [false, true] {
        let c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], preparada)?;
        for n in [1, 1024] {
            for (tipo1, tipo2) in [
                (ClaseObjeto::CRef, ClaseObjeto::ARef),
                (ClaseObjeto::CExp, ClaseObjeto::AExp),
                (ClaseObjeto::CRef, ClaseObjeto::AExp),
            ] {
                let a = ObjetoPropio::nuevo(tipo1, voto(7, 1), &k.claves, &k.claves[..n], 0, &f1)?;
                let b = ObjetoPropio::nuevo(tipo2, voto(8, 2), &k.claves, &k.claves[..n], 1, &f2)?;
                let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
                assert_eq!(r?.claves_comunes, k.claves[..n]);
                assert_eq!(cuenta, [1, 1], "{n} comunes: exactamente dos ecuaciones");
                eprintln!(
                    "EXACTO contador: comunes={n} preparada={preparada} {tipo1:?}/{tipo2:?} ecuaciones={cuenta:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn ea_propiedad_interseccion_vacia_una_varias_total() -> Result<(), Fallo> {
    let k = Clavero::nuevo(64)?;
    let f1 = k.firmas(voto(7, 1))?;
    let f2 = k.firmas(voto(7, 2))?;
    let c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], false)?;
    let mut casos = 0;
    for mascara in 0..256u64 {
        let s1: Vec<_> = k
            .claves
            .iter()
            .enumerate()
            .filter(|(i, _)| mascara & (1 << (i & 7)) != 0 || *i == 0)
            .map(|(_, k)| *k)
            .collect();
        let s2: Vec<_> = k
            .claves
            .iter()
            .enumerate()
            .filter(|(i, _)| mascara.rotate_left(3) & (1 << (i & 7)) != 0 || *i == 63)
            .map(|(_, k)| *k)
            .collect();
        let a = ObjetoPropio::nuevo(ClaseObjeto::CRef, voto(7, 1), &k.claves, &s1, 0, &f1)?;
        let b = ObjetoPropio::nuevo(ClaseObjeto::AExp, voto(7, 2), &k.claves, &s2, 1, &f2)?;
        let esperado = oraculo(&s1, &s2);
        let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
        if esperado.is_empty() {
            assert_eq!(r, Err(ErrorVerificacion::SinClavesComunes));
            assert_eq!(cuenta, [0, 0]);
        } else {
            assert_eq!(r?.claves_comunes, esperado);
            assert_eq!(cuenta, [1, 1]);
        }
        casos += 1;
    }
    for n in [0, 1, 7, 64] {
        let s1 = k.claves[..32.max(n)].to_vec();
        let mut s2 = k.claves[..n].to_vec();
        if s2.is_empty() {
            s2.push(k.claves[63]);
        }
        let a = ObjetoPropio::nuevo(ClaseObjeto::CExp, voto(7, 1), &k.claves, &s1, 0, &f1)?;
        let b = ObjetoPropio::nuevo(ClaseObjeto::ARef, voto(7, 2), &k.claves, &s2, 1, &f2)?;
        let (r, _) = observar(&evidencia(&a, &b)?, &c);
        if n == 0 {
            assert_eq!(r, Err(ErrorVerificacion::SinClavesComunes));
        } else {
            assert_eq!(r?.claves_comunes, k.claves[..n]);
        }
    }
    eprintln!(
        "EXACTO propiedad: {casos}+4 casos, oráculo búsqueda K48 completa; semilla={SEMILLA:#x}"
    );
    Ok(())
}

#[test]
fn ea_firma_otro_mensaje_subconjunto_y_bit_no_firmante_ambos_objetos() -> Result<(), Fallo> {
    let k = Clavero::nuevo(4)?;
    let c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], false)?;
    let v1 = voto(7, 1);
    let v2 = voto(8, 2);
    for lado in [0, 1] {
        for defecto in [0, 1, 2, 3, 4, 5] {
            let mut a = ObjetoPropio::nuevo(
                ClaseObjeto::CRef,
                v1,
                &k.claves,
                &k.claves[..3],
                0,
                &k.firmas(v1)?,
            )?;
            let mut b = ObjetoPropio::nuevo(
                ClaseObjeto::AExp,
                v2,
                &k.claves,
                &k.claves[..3],
                1,
                &k.firmas(v2)?,
            )?;
            let o = if lado == 0 { &mut a } else { &mut b };
            let numero = if lado == 0 {
                NumeroObjeto::Uno
            } else {
                NumeroObjeto::Dos
            };
            match defecto {
                0 => o.voto.candidato[0] ^= 1,
                1 => o.voto.h_t_siguiente[0] ^= 1,
                2 => o.voto.raiz_estado[0] ^= 1,
                3 => {
                    let f = k.firmas(o.voto)?;
                    o.voto.firma = f[&k.claves[0]].bytes();
                }
                4 => {
                    o.clase = ClaseObjeto::CRef;
                    o.origen.posicion = 3;
                    o.mapa[0] |= 8;
                }
                _ => {
                    let m = mensaje_voto_peso(
                        o.voto.n,
                        &o.voto.candidato,
                        &o.voto.h_t_siguiente,
                        &o.voto.raiz_estado,
                    );
                    o.voto.firma = firmar(
                        k.secretas.get(&k.claves[0]).ok_or("sk")?,
                        b"dominio equivocado",
                        &m,
                    )?
                    .bytes();
                }
            }
            let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
            assert_eq!(
                r,
                Err(ErrorVerificacion::FirmaFalsa {
                    objeto: numero,
                    error: ErrorBLS::VerificacionFallida
                }),
                "lado={lado} defecto={defecto}"
            );
            assert_eq!(
                cuenta,
                [1, 1],
                "también se verifica la otra firma tras una ecuación falsa"
            );
        }
    }
    Ok(())
}

#[test]
fn ea_mapas_longitud_sobrantes_y_vacio_antes_de_curvas() -> Result<(), Fallo> {
    let k = Clavero::nuevo(4)?;
    let c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], false)?;
    let f1 = k.firmas(voto(7, 1))?;
    let f2 = k.firmas(voto(8, 2))?;
    for lado in [0, 1] {
        for defecto in [0, 1, 2, 3] {
            let mut a =
                ObjetoPropio::nuevo(ClaseObjeto::CRef, voto(7, 1), &k.claves, &k.claves, 0, &f1)?;
            let mut b =
                ObjetoPropio::nuevo(ClaseObjeto::ARef, voto(8, 2), &k.claves, &k.claves, 1, &f2)?;
            let o = if lado == 0 { &mut a } else { &mut b };
            let num = if lado == 0 {
                NumeroObjeto::Uno
            } else {
                NumeroObjeto::Dos
            };
            let esperado = match defecto {
                0 => {
                    o.mapa.push(0);
                    ErrorVerificacion::MapaLongitud {
                        objeto: num,
                        esperada: 1,
                        obtenida: 2,
                    }
                }
                1 => {
                    o.mapa[0] |= 0x80;
                    ErrorVerificacion::MapaFueraTabla { objeto: num }
                }
                2 => {
                    o.mapa.clear();
                    ErrorVerificacion::Forma(ErrorEvidenciaAgregados::MapaVacio)
                }
                _ => {
                    o.mapa.fill(0);
                    ErrorVerificacion::Forma(ErrorEvidenciaAgregados::MapaVacio)
                }
            };
            // Firma G2 inválida en el otro objeto: el rechazo barato debe precederla.
            if lado == 0 {
                b.voto.firma = [0; 96]
            } else {
                a.voto.firma = [0; 96]
            }
            let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
            assert_eq!(r, Err(esperado));
            assert_eq!(cuenta, [0, 0]);
        }
    }
    Ok(())
}

#[test]
fn ea_subred_local_ref_y_explicita_otra_subred() -> Result<(), Fallo> {
    let k = Clavero::nuevo(1024)?;
    let t = tabla_votos(&k.claves);
    let reparto = Reparto::construir(&t, 64)?;
    let sub = (0..64)
        .find(|s| reparto.claves_de(*s).len() >= 3)
        .ok_or("subred")?;
    let indices = reparto.claves_de(sub);
    let seleccion: Vec<_> = indices[..3].iter().map(|i| k.claves[*i]).collect();
    let c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], true)?;
    let f1 = k.firmas(voto(7, 1))?;
    let f2 = k.firmas(voto(8, 2))?;
    let mut a = ObjetoPropio::nuevo(ClaseObjeto::LRef, voto(7, 1), &k.claves, &seleccion, 0, &f1)?;
    let mut b = ObjetoPropio::nuevo(ClaseObjeto::LExp, voto(8, 2), &k.claves, &seleccion, 1, &f2)?;
    assert_eq!(
        verificar(&evidencia(&a, &b)?, &c)?.claves_comunes,
        seleccion
    );
    // Un mapa global no se acepta como mapa local.
    a.mapa = vec![1; 128];
    let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
    assert_eq!(
        r,
        Err(ErrorVerificacion::MapaLongitud {
            objeto: NumeroObjeto::Uno,
            esperada: indices.len().div_ceil(8),
            obtenida: 128
        })
    );
    assert_eq!(cuenta, [0, 0]);
    a = ObjetoPropio::nuevo(ClaseObjeto::LRef, voto(7, 1), &k.claves, &seleccion, 0, &f1)?;
    b.subred = (sub + 1) % 64;
    let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
    assert_eq!(
        r,
        Err(ErrorVerificacion::ClaveOtraSubred {
            objeto: NumeroObjeto::Dos,
            clave: seleccion[0]
        })
    );
    assert_eq!(cuenta, [0, 0]);
    // El mismo fallo en el primer objeto explícito.
    a.clase = ClaseObjeto::LExp;
    a.subred = b.subred;
    b.subred = sub;
    assert_eq!(
        observar(&evidencia(&a, &b)?, &c).0,
        Err(ErrorVerificacion::ClaveOtraSubred {
            objeto: NumeroObjeto::Uno,
            clave: seleccion[0]
        })
    );
    Ok(())
}

#[test]
fn ea_posesion_desconocida_cualquier_sumando_y_s() -> Result<(), Fallo> {
    let k = Clavero::nuevo(4)?;
    let mut c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], false)?;
    c.conocidas.remove(&k.claves[3]);
    for lado in [0, 1] {
        let a = ObjetoPropio::nuevo(
            if lado == 0 {
                ClaseObjeto::CExp
            } else {
                ClaseObjeto::CRef
            },
            voto(7, 1),
            &k.claves,
            &k.claves,
            0,
            &k.firmas(voto(7, 1))?,
        )?;
        let b = ObjetoPropio::nuevo(
            if lado == 1 {
                ClaseObjeto::AExp
            } else {
                ClaseObjeto::ARef
            },
            voto(8, 2),
            &k.claves,
            &k.claves,
            1,
            &k.firmas(voto(8, 2))?,
        )?;
        let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
        assert_eq!(
            r,
            Err(ErrorVerificacion::PosesionDesconocida {
                objeto: if lado == 0 {
                    NumeroObjeto::Uno
                } else {
                    NumeroObjeto::Dos
                },
                clave: k.claves[3]
            })
        );
        assert_eq!(cuenta, [0, 0]);
    }
    let a = ObjetoPropio::nuevo(
        ClaseObjeto::S,
        voto(7, 1),
        &k.claves,
        &k.claves[3..],
        0,
        &k.firmas(voto(7, 1))?,
    )?;
    let b = ObjetoPropio::nuevo(
        ClaseObjeto::S,
        voto(8, 2),
        &k.claves,
        &k.claves[3..],
        1,
        &k.firmas(voto(8, 2))?,
    )?;
    assert_eq!(
        observar(&evidencia(&a, &b)?, &c).0,
        Err(ErrorVerificacion::PosesionDesconocida {
            objeto: NumeroObjeto::Uno,
            clave: k.claves[3]
        })
    );
    Ok(())
}

#[test]
fn ea_contexto_no_disponible_distinto_de_invalido() -> Result<(), Fallo> {
    let k = Clavero::nuevo(4)?;
    let a = ObjetoPropio::nuevo(
        ClaseObjeto::CRef,
        voto(7, 1),
        &k.claves,
        &k.claves,
        0,
        &k.firmas(voto(7, 1))?,
    )?;
    let b = ObjetoPropio::nuevo(
        ClaseObjeto::ARef,
        voto(8, 2),
        &k.claves,
        &k.claves,
        1,
        &k.firmas(voto(8, 2))?,
    )?;
    for lado in [0, 1] {
        for fallo in [ErrorContexto::NoDisponible, ErrorContexto::Invalido] {
            let mut c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], false)?;
            c.fallo[lado] = Some(fallo);
            let numero = if lado == 0 {
                NumeroObjeto::Uno
            } else {
                NumeroObjeto::Dos
            };
            let esperado = match fallo {
                ErrorContexto::NoDisponible => {
                    ErrorVerificacion::ContextoNoDisponible { objeto: numero }
                }
                ErrorContexto::Invalido => ErrorVerificacion::ContextoInvalido { objeto: numero },
            };
            let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
            assert_eq!(r, Err(esperado));
            assert_eq!(cuenta, [0, 0]);
        }
    }
    Ok(())
}

#[test]
fn ea_tabla_no_canonica_antes_de_curvas() -> Result<(), Fallo> {
    let k = Clavero::nuevo(4)?;
    let a = ObjetoPropio::nuevo(
        ClaseObjeto::CRef,
        voto(7, 1),
        &k.claves,
        &k.claves,
        0,
        &k.firmas(voto(7, 1))?,
    )?;
    let b = ObjetoPropio::nuevo(
        ClaseObjeto::ARef,
        voto(8, 2),
        &k.claves,
        &k.claves,
        1,
        &k.firmas(voto(8, 2))?,
    )?;
    for lado in [0, 1] {
        for defecto in [0, 1, 2, 3] {
            let mut c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], false)?;
            c.tablas[lado] = match defecto {
                0 => vec![],
                1 => vec![k.claves[0]; 65537],
                2 => vec![k.claves[0]; 4],
                _ => k.claves.iter().rev().copied().collect(),
            };
            let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
            assert_eq!(
                r,
                Err(ErrorVerificacion::TablaNoCanonica {
                    objeto: if lado == 0 {
                        NumeroObjeto::Uno
                    } else {
                        NumeroObjeto::Dos
                    }
                })
            );
            assert_eq!(cuenta, [0, 0]);
        }
    }
    Ok(())
}

fn de_hex(s: &str) -> Result<Clave48, Fallo> {
    let mut k = [0u8; 48];
    if s.len() != 96 {
        return Err("hex corto".into());
    }
    for (b, t) in k.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        *b = u8::from_str_radix(std::str::from_utf8(t)?, 16)?;
    }
    Ok(k)
}

#[test]
fn ea_claves_fuera_subgrupo_torsion_cancelada_firmantes() -> Result<(), Fallo> {
    let mas = de_hex(
        "931192eb3aafbd3a4ba776147132a606ba94e8a514d80852d2baf8017169433e1725d90339d74a9dca0a5489bd7d83c8",
    )?;
    let menos = de_hex(
        "81740d0b015b7566a810bb52cd483fc5a588b521fa7398bf826871e9ce42760892f247913ed3e5d512c1d529678f8724",
    )?;
    let mut claves = vec![mas, menos];
    claves.sort();
    let k = Clavero::nuevo(4)?;
    let c = Contexto {
        tablas: [claves.clone(), claves.clone()],
        puntos: [None, None],
        conocidas: claves.iter().copied().collect(),
        fallo: [None, None],
    };
    for lado in [0, 1] {
        let mut a = ObjetoPropio::nuevo(
            ClaseObjeto::CRef,
            voto(7, 1),
            &k.claves,
            &k.claves[..2],
            0,
            &k.firmas(voto(7, 1))?,
        )?;
        let mut b = ObjetoPropio::nuevo(
            ClaseObjeto::ARef,
            voto(8, 2),
            &k.claves,
            &k.claves[..2],
            1,
            &k.firmas(voto(8, 2))?,
        )?;
        // Firmas reales de los componentes primos de la fixture; la torsión se cancela al sumar.
        for o in [&mut a, &mut b] {
            let m = mensaje_voto_peso(
                o.voto.n,
                &o.voto.candidato,
                &o.voto.h_t_siguiente,
                &o.voto.raiz_estado,
            );
            let fa = firmar(&ClaveSecreta::generar(&[0x61; 32])?, DOMINIO_VOTO, &m)?;
            let fb = firmar(&ClaveSecreta::generar(&[0x62; 32])?, DOMINIO_VOTO, &m)?;
            o.voto.firma = agregar_firmas(&[&fa, &fb])?.bytes();
            o.mapa = vec![3];
        }
        if lado == 1 {
            a.clase = ClaseObjeto::AExp;
            a.lista = claves.iter().flat_map(|k| *k).collect();
        }
        let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
        // Ambos objetos incluyen las mismas K: primera aparición en objeto1 siempre.
        assert_eq!(
            r,
            Err(ErrorVerificacion::ClaveInvalida {
                objeto: NumeroObjeto::Uno,
                clave: claves[0],
                error: ErrorBLS::ClaveInvalida {
                    motivo: "el punto no esta en el subgrupo"
                }
            })
        );
        assert_eq!(cuenta, [0, 0]);
    }
    assert!(ClavesPreparadas::desde_bytes(&claves).is_err());
    Ok(())
}

#[test]
fn ea_suma_infinita_ambos_objetos() -> Result<(), Fallo> {
    let k = Clavero::nuevo(4)?;
    let p = k.claves[0];
    let mut negada = p;
    negada[0] ^= 0x20;
    let mut tabla = vec![p, negada, k.claves[1]];
    tabla.sort();
    let c = Contexto {
        tablas: [tabla.clone(), tabla.clone()],
        puntos: [
            Some(ClavesPreparadas::desde_bytes(&tabla)?),
            Some(ClavesPreparadas::desde_bytes(&tabla)?),
        ],
        conocidas: tabla.iter().copied().collect(),
        fallo: [None, None],
    };
    for lado in [0, 1] {
        let mut a = ObjetoPropio::nuevo(
            ClaseObjeto::CRef,
            voto(7, 1),
            &k.claves,
            &k.claves[..1],
            0,
            &k.firmas(voto(7, 1))?,
        )?;
        let mut b = ObjetoPropio::nuevo(
            ClaseObjeto::ARef,
            voto(8, 2),
            &k.claves,
            &k.claves[..1],
            1,
            &k.firmas(voto(8, 2))?,
        )?;
        let bit = |clave: &Clave48| 1u8 << tabla.iter().position(|x| x == clave).unwrap_or(7);
        let buenos = bit(&p);
        let infinita = bit(&p) | bit(&negada);
        a.mapa = vec![if lado == 0 { infinita } else { buenos }];
        b.mapa = vec![if lado == 1 { infinita } else { buenos }];
        let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
        assert_eq!(
            r,
            Err(ErrorVerificacion::SumaInfinita {
                objeto: if lado == 0 {
                    NumeroObjeto::Uno
                } else {
                    NumeroObjeto::Dos
                }
            })
        );
        assert_eq!(cuenta, [0, 0]);
    }
    Ok(())
}

#[test]
fn ea_firma_g2_invalida_ambos_objetos() -> Result<(), Fallo> {
    let k = Clavero::nuevo(4)?;
    let c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], false)?;
    for lado in [0, 1] {
        let mut a = ObjetoPropio::nuevo(
            ClaseObjeto::S,
            voto(7, 1),
            &k.claves,
            &k.claves[..1],
            0,
            &k.firmas(voto(7, 1))?,
        )?;
        let mut b = ObjetoPropio::nuevo(
            ClaseObjeto::S,
            voto(8, 2),
            &k.claves,
            &k.claves[..1],
            1,
            &k.firmas(voto(8, 2))?,
        )?;
        if lado == 0 {
            a.voto.firma = [0; 96]
        } else {
            b.voto.firma = [0; 96]
        }
        let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
        assert!(
            matches!(r,Err(ErrorVerificacion::FirmaInvalida {objeto,error:ErrorBLS::FirmaInvalida {..}}) if objeto==if lado==0{NumeroObjeto::Uno}else{NumeroObjeto::Dos})
        );
        assert_eq!(cuenta, [0, 0]);
    }
    Ok(())
}

#[test]
fn ea_s_s_comun_solo_con_clave_igual_y_mensajes_ordenados() -> Result<(), Fallo> {
    let k = Clavero::nuevo(4)?;
    let c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], false)?;
    let a = ObjetoPropio::nuevo(
        ClaseObjeto::S,
        voto(7, 1),
        &k.claves,
        &k.claves[..1],
        0,
        &k.firmas(voto(7, 1))?,
    )?;
    let b = ObjetoPropio::nuevo(
        ClaseObjeto::S,
        voto(8, 2),
        &k.claves,
        &k.claves[1..2],
        1,
        &k.firmas(voto(8, 2))?,
    )?;
    assert_eq!(
        observar(&evidencia(&a, &b)?, &c),
        (Err(ErrorVerificacion::SinClavesComunes), [0, 0])
    );
    let mut e = evidencia(&a, &b)?;
    e.objeto2.voto = e.objeto1.voto;
    assert_eq!(
        observar(&e, &c).0,
        Err(ErrorVerificacion::Forma(
            ErrorEvidenciaAgregados::MensajesIguales
        ))
    );
    e = evidencia(&a, &b)?;
    std::mem::swap(&mut e.objeto1, &mut e.objeto2);
    assert_eq!(
        observar(&e, &c).0,
        Err(ErrorVerificacion::Forma(
            ErrorEvidenciaAgregados::MensajesInvertidos
        ))
    );
    Ok(())
}

#[test]
fn ea_coste_cuenta_independiente_frio_caliente_y_falsas() -> Result<(), Fallo> {
    let k = Clavero::nuevo(64)?;
    let f1 = k.firmas(voto(7, 1))?;
    let f2 = k.firmas(voto(8, 2))?;
    let mut casos = 0;
    for preparado1 in [false, true] {
        for preparado2 in [false, true] {
            let mut c = Contexto::nuevo(&k, [k.claves.clone(), k.claves.clone()], false)?;
            if preparado1 {
                c.puntos[0] = Some(ClavesPreparadas::desde_bytes(&k.claves)?)
            }
            if preparado2 {
                c.puntos[1] = Some(ClavesPreparadas::desde_bytes(&k.claves)?)
            }
            for tipo1 in CLASES {
                for tipo2 in CLASES {
                    let seleccion = |tipo: ClaseObjeto, lado: usize| -> Vec<Clave48> {
                        if matches!(tipo, ClaseObjeto::S) {
                            return vec![k.claves[0]];
                        }
                        k.claves
                            .iter()
                            .enumerate()
                            .filter(|(i, pk)| {
                                (i % 3 != lado)
                                    && (!tipo.local()
                                        || subred(*pk, 64).ok() == subred(&k.claves[0], 64).ok())
                                    || *i == 0
                            })
                            .map(|(_, k)| *k)
                            .collect()
                    };
                    let s1 = seleccion(tipo1, 0);
                    let s2 = seleccion(tipo2, 1);
                    let mut a = ObjetoPropio::nuevo(tipo1, voto(7, 1), &k.claves, &s1, 0, &f1)?;
                    let mut b = ObjetoPropio::nuevo(tipo2, voto(8, 2), &k.claves, &s2, 1, &f2)?;
                    a.voto.firma = [0; 96];
                    b.voto.firma = [0; 96];
                    c.conocidas.clear();
                    let referencia = |t: ClaseObjeto| {
                        matches!(t, ClaseObjeto::LRef | ClaseObjeto::CRef | ClaseObjeto::ARef)
                    };
                    let mut union = s1.clone();
                    for pk in &s2 {
                        if !union.contains(pk) {
                            union.push(*pk)
                        }
                    }
                    let garantizadas: Vec<_> = union
                        .iter()
                        .filter(|pk| {
                            (preparado1 && referencia(tipo1) && s1.contains(pk))
                                || (preparado2 && referencia(tipo2) && s2.contains(pk))
                        })
                        .copied()
                        .collect();
                    for perfil in [PerfilCoste::Frio, PerfilCoste::Caliente] {
                        let d = match perfil {
                            PerfilCoste::Frio => union.len(),
                            PerfilCoste::Caliente => {
                                union.iter().filter(|pk| !garantizadas.contains(pk)).count()
                            }
                        };
                        assert_eq!(
                            unidades_coste(&evidencia(&a, &b)?, &c, perfil)?,
                            UnidadesCoste {
                                claves_a_descomprimir: d as u32,
                                apariciones_a_sumar: (s1.len() + s2.len()) as u32,
                                ecuaciones: 2
                            }
                        );
                        casos += 1;
                    }
                }
            }
        }
    }
    assert_eq!(casos, 392);
    eprintln!("EXACTO coste: {casos} cuentas independientes; E=2 incluso firmas/PoP inválidas");
    Ok(())
}

#[test]
fn ea_coste_sin_comunes_y_sin_descompresion() -> Result<(), Fallo> {
    let mut claves = vec![[0x11; 48], [0x22; 48]];
    claves.sort();
    let c = Contexto {
        tablas: [claves.clone(), claves.clone()],
        puntos: [None, None],
        conocidas: BTreeSet::new(),
        fallo: [None, None],
    };
    let e = EvidenciaAgregadosV3 {
        reportero: ClavePublica::desde_bytes([0x88; 32]),
        objeto1: ObjetoEvidencia {
            voto: voto(7, 1),
            contenido: ContenidoObjeto::Voto { clave: claves[0] },
        },
        objeto2: ObjetoEvidencia {
            voto: voto(8, 2),
            contenido: ContenidoObjeto::Voto { clave: claves[1] },
        },
    };
    assert_eq!(
        unidades_coste(&e, &c, PerfilCoste::Frio)?,
        UnidadesCoste {
            claves_a_descomprimir: 2,
            apariciones_a_sumar: 2,
            ecuaciones: 2
        }
    );
    Ok(())
}

#[test]
fn ea_modulo_sin_llamantes_en_transicion() -> Result<(), Fallo> {
    fn recorrer(p: &std::path::Path) -> Result<(), Fallo> {
        for entrada in std::fs::read_dir(p)? {
            let ruta = entrada?.path();
            if ruta.is_dir() {
                recorrer(&ruta)?
            } else if ruta.extension().is_some_and(|e| e == "rs") {
                let texto = std::fs::read_to_string(&ruta)?;
                assert!(
                    !texto.contains("evidencia_agregados"),
                    "llamante nuevo en {}",
                    ruta.display()
                );
            }
        }
        Ok(())
    }
    recorrer(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/transicion"))?;
    Ok(())
}

#[test]
fn ea_interseccion_por_los_48_bytes_y_rechazo_barato() -> Result<(), Fallo> {
    let a = [0x11; 48];
    let mut b = a;
    b[47] ^= 1;
    let c = Contexto {
        tablas: [vec![], vec![]],
        puntos: [None, None],
        conocidas: [a, b].into_iter().collect(),
        fallo: [None, None],
    };
    let e = EvidenciaAgregadosV3 {
        reportero: ClavePublica::desde_bytes([0x88; 32]),
        objeto1: ObjetoEvidencia {
            voto: voto(7, 1),
            contenido: ContenidoObjeto::Voto { clave: a },
        },
        objeto2: ObjetoEvidencia {
            voto: voto(8, 2),
            contenido: ContenidoObjeto::Voto { clave: b },
        },
    };
    assert_eq!(
        observar(&e, &c),
        (Err(ErrorVerificacion::SinClavesComunes), [0, 0])
    );
    Ok(())
}

#[test]
fn ea_clave_invalida_fuera_del_mapa_no_se_descomprime() -> Result<(), Fallo> {
    let k = Clavero::nuevo(2)?;
    let tabla = vec![[0; 48], k.claves[0]];
    let c = Contexto {
        tablas: [tabla.clone(), tabla],
        puntos: [None, None],
        conocidas: k.conocidas()?,
        fallo: [None, None],
    };
    let mut a = ObjetoPropio::nuevo(
        ClaseObjeto::CRef,
        voto(7, 1),
        &k.claves,
        &k.claves[..1],
        0,
        &k.firmas(voto(7, 1))?,
    )?;
    let mut b = ObjetoPropio::nuevo(
        ClaseObjeto::ARef,
        voto(8, 2),
        &k.claves,
        &k.claves[..1],
        1,
        &k.firmas(voto(8, 2))?,
    )?;
    a.mapa = vec![2];
    b.mapa = vec![2];
    assert_eq!(
        verificar(&evidencia(&a, &b)?, &c)?.claves_comunes,
        k.claves[..1]
    );
    Ok(())
}

#[test]
fn ea_clave_curva_infinito_y_fuera_subgrupo_cada_objeto() -> Result<(), Fallo> {
    let k = Clavero::nuevo(2)?;
    let mut infinito = [0u8; 48];
    infinito[0] = 0xc0;
    let torsion = de_hex(
        "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )?;
    for mala in [[0; 48], infinito, torsion] {
        for lado in [0, 1] {
            let mut tabla = vec![mala, k.claves[0]];
            tabla.sort();
            let conocidas = tabla.iter().copied().collect();
            let c = Contexto {
                tablas: [tabla.clone(), tabla.clone()],
                puntos: [None, None],
                conocidas,
                fallo: [None, None],
            };
            let mut a = ObjetoPropio::nuevo(
                ClaseObjeto::S,
                voto(7, 1),
                &k.claves,
                &k.claves[..1],
                0,
                &k.firmas(voto(7, 1))?,
            )?;
            let mut b = ObjetoPropio::nuevo(
                ClaseObjeto::S,
                voto(8, 2),
                &k.claves,
                &k.claves[..1],
                1,
                &k.firmas(voto(8, 2))?,
            )?;
            let o = if lado == 0 { &mut a } else { &mut b };
            o.clase = if lado == 0 {
                ClaseObjeto::CRef
            } else {
                ClaseObjeto::ARef
            };
            o.origen.posicion = if lado == 0 { 3 } else { 4 };
            o.mapa = vec![3];
            let esperado = zx_bls::ClavePublica::desde_bytes(&mala)
                .err()
                .ok_or("fixture debe ser inválida")?;
            let (r, cuenta) = observar(&evidencia(&a, &b)?, &c);
            assert_eq!(
                r,
                Err(ErrorVerificacion::ClaveInvalida {
                    objeto: if lado == 0 {
                        NumeroObjeto::Uno
                    } else {
                        NumeroObjeto::Dos
                    },
                    clave: mala,
                    error: esperado
                })
            );
            assert_eq!(cuenta, [0, 0]);
        }
    }
    Ok(())
}

#[test]
fn ea_matriz_interseccion_vacia_varias_total_tablas_distintas() -> Result<(), Fallo> {
    let k = Clavero::nuevo(2048)?;
    let f1 = k.firmas(voto(7, 1))?;
    let f2 = k.firmas(voto(7, 2))?;
    let mut casos = 0;
    for n in [4, 64, 1024] {
        // N-1 comunes, con un relleno distinto en cada tabla; posiciones globales desplazadas.
        let t1 = k.claves[..n].to_vec();
        let t2 = k.claves[1..n + 1].to_vec();
        let compartidas = &k.claves[1..n];
        let comun = compartidas[0];
        let sub = subred(&comun, 64)?;
        let c = Contexto::nuevo(&k, [t1.clone(), t2.clone()], true)?;
        for tipo1 in CLASES {
            for tipo2 in CLASES {
                let seleccionar = |tipo: ClaseObjeto| -> Vec<Clave48> {
                    if matches!(tipo, ClaseObjeto::S) {
                        return vec![comun];
                    }
                    compartidas
                        .iter()
                        .filter(|pk| !tipo.local() || subred(*pk, 64).ok() == Some(sub))
                        .copied()
                        .collect()
                };
                let s1 = seleccionar(tipo1);
                let s2 = seleccionar(tipo2);
                let a = ObjetoPropio::nuevo(tipo1, voto(7, 1), &t1, &s1, 0, &f1)?;
                let b = ObjetoPropio::nuevo(tipo2, voto(7, 2), &t2, &s2, 1, &f2)?;
                assert_eq!(
                    verificar(&evidencia(&a, &b)?, &c)?.claves_comunes,
                    oraculo(&s1, &s2)
                );
                casos += 1;
                // Mismos tipos y modos, dos singleton distintos: siempre intersección vacía.
                let ajena = t2.iter().find(|pk| {
                    **pk != comun && (!tipo2.local() || subred(*pk, 64).ok() == Some(sub))
                });
                if let Some(ajena) = ajena {
                    let a = ObjetoPropio::nuevo(tipo1, voto(7, 1), &t1, &[comun], 0, &f1)?;
                    let b = ObjetoPropio::nuevo(tipo2, voto(7, 2), &t2, &[*ajena], 1, &f2)?;
                    assert_eq!(
                        observar(&evidencia(&a, &b)?, &c),
                        (Err(ErrorVerificacion::SinClavesComunes), [0, 0])
                    );
                    casos += 1;
                }
            }
        }
    }
    eprintln!(
        "EXACTO matriz intersecciones adicionales: {casos} casos; N=4,64,1024; tablas distintas; comunes múltiples/total y vacío donde el alcance lo admite"
    );
    Ok(())
}
