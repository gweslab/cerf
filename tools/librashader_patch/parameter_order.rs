// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::include::read_source;
use crate::pragma::parse_pragma_meta;
use crate::PreprocessError;
use librashader_common::map::ShortString;
use librashader_common::shader_features::ShaderFeatures;
use std::path::Path;

pub fn parameter_order(
    path: impl AsRef<Path>,
    features: ShaderFeatures,
) -> Result<Vec<ShortString>, PreprocessError> {
    let source = read_source(path, features)?;
    Ok(parse_pragma_meta(&source)?
        .parameters
        .into_iter()
        .map(|parameter| parameter.id)
        .collect())
}
