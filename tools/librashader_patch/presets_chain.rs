// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::ctypes::{libra_error_t, libra_shader_preset_t};
use crate::error::{assert_non_null, LibrashaderError};
use crate::ffi::ffi_body;
use crate::presets::{libra_preset_get_runtime_params, libra_preset_param_list_t};
use librashader::preprocess::parameter_order::parameter_order;
use librashader::preprocess::ShaderSource;
use librashader::presets::{ShaderFeatures, ShaderPreset, TextureConfig};
use std::collections::HashSet;
use std::ffi::{c_char, CStr};
use std::mem::MaybeUninit;
use std::path::Path;
use std::ptr::NonNull;

#[derive(Default)]
struct ChainNames {
    textures: HashSet<String>,
    uniforms: HashSet<String>,
    parameters: HashSet<String>,
}

impl ChainNames {
    fn of(preset: &ShaderPreset) -> Result<ChainNames, LibrashaderError> {
        let mut names = ChainNames::default();
        for pass in &preset.passes {
            let source = ShaderSource::load(&pass.path, preset.features)?;
            names
                .parameters
                .extend(source.parameters.keys().map(|id| id.to_string()));
            for name in [pass.meta.alias.as_ref(), source.name.as_ref()]
                .into_iter()
                .flatten()
            {
                if name.trim().is_empty() {
                    continue;
                }
                names.textures.insert(name.to_string());
                names.textures.insert(format!("{name}Feedback"));
                names.uniforms.insert(format!("{name}Size"));
                names.uniforms.insert(format!("{name}FeedbackSize"));
            }
        }
        for texture in &preset.textures {
            names.textures.insert(texture.meta.name.to_string());
            names.uniforms.insert(format!("{}Size", texture.meta.name));
        }
        Ok(names)
    }

    fn clashes(&self, other: &ChainNames) -> bool {
        !self.textures.is_disjoint(&other.textures)
            || !self.uniforms.is_disjoint(&other.uniforms)
            || !self.uniforms.is_disjoint(&other.parameters)
            || !self.parameters.is_disjoint(&other.uniforms)
    }

    fn absorb(&mut self, other: ChainNames) {
        self.textures.extend(other.textures);
        self.uniforms.extend(other.uniforms);
        self.parameters.extend(other.parameters);
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn same_texture(kept: &TextureConfig, texture: &TextureConfig) -> bool {
    kept.meta.name == texture.meta.name
        && kept.meta.wrap_mode == texture.meta.wrap_mode
        && kept.meta.filter_mode == texture.meta.filter_mode
        && kept.meta.mipmap == texture.meta.mipmap
        && same_file(&kept.path, &texture.path)
}

fn parse(filename: *const c_char) -> Result<ShaderPreset, LibrashaderError> {
    assert_non_null!(filename);
    let filename = unsafe { CStr::from_ptr(filename) }.to_str()?;
    Ok(ShaderPreset::try_parse(filename, ShaderFeatures::NONE)?)
}

fn append(
    chain: &mut ShaderPreset,
    names: &mut ChainNames,
    mut next: ShaderPreset,
) -> Result<(), LibrashaderError> {
    next.textures
        .retain(|texture| !chain.textures.iter().any(|kept| same_texture(kept, texture)));
    let next_names = ChainNames::of(&next)?;
    if names.clashes(&next_names) {
        return Err(LibrashaderError::InvalidParameter(
            "two presets of the chain declare the same name",
        ));
    }
    names.absorb(next_names);
    for pass in &mut next.passes {
        pass.meta.id += chain.pass_count;
    }
    chain.pass_count += next.pass_count;
    chain.passes.append(&mut next.passes);
    chain.textures.append(&mut next.textures);
    chain.parameters.append(&mut next.parameters);
    chain.features |= next.features;
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn libra_preset_create_chain(
    filenames: *const *const c_char,
    count: usize,
    out: *mut MaybeUninit<libra_shader_preset_t>,
) -> libra_error_t {
    ffi_body!({
        assert_non_null!(filenames);
        assert_non_null!(out);
        if count == 0 {
            return Err(LibrashaderError::InvalidParameter("count"));
        }
        let files = unsafe { std::slice::from_raw_parts(filenames, count) };
        let mut chain = parse(files[0])?;
        if files.len() > 1 {
            let mut names = ChainNames::of(&chain)?;
            for &file in &files[1..] {
                append(&mut chain, &mut names, parse(file)?)?;
            }
        }
        unsafe {
            out.write(MaybeUninit::new(NonNull::new(Box::into_raw(Box::new(chain)))))
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn libra_preset_get_runtime_params_ordered(
    preset: *const libra_shader_preset_t,
    out: *mut MaybeUninit<libra_preset_param_list_t>,
) -> libra_error_t {
    ffi_body!({
        assert_non_null!(preset);
        assert_non_null!(out);
        let Some(chain) = (unsafe { *preset }) else {
            return Err(LibrashaderError::InvalidParameter("preset"));
        };
        let chain = unsafe { chain.as_ref() };
        let mut order = Vec::new();
        for pass in &chain.passes {
            for id in parameter_order(&pass.path, chain.features)? {
                if !order.contains(&id) {
                    order.push(id);
                }
            }
        }
        if let Some(error) = unsafe { libra_preset_get_runtime_params(preset, out) } {
            return Err(unsafe { *Box::from_raw(error.as_ptr()) });
        }
        let list = unsafe { (*out).assume_init_ref() };
        let parameters =
            unsafe { std::slice::from_raw_parts_mut(list.parameters.cast_mut(), list.length as usize) };
        parameters.sort_by_key(|parameter| {
            let name = unsafe { CStr::from_ptr(parameter.name) }.to_bytes();
            order.iter().position(|id| id.as_bytes() == name).unwrap_or(order.len())
        });
    })
}
