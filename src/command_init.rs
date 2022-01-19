use std::{fs::{self, OpenOptions}};

use anyhow::{Result, bail};

use crate::args;

fn expand_msix_node_from_metadata(a: toml::Value) -> Option<toml::Value> {
    a.get("package")?.get("metadata")?.get("msix").map(|v| v.clone())
}

pub fn run_command_init(_cli_args: &args::Cli, metadata: &cargo_metadata::Metadata) -> Result<()> {
    let root_package = &metadata.root_package().unwrap();

    let manifest_path = root_package.manifest_path.clone();
    let manifest_root_path = manifest_path.parent().unwrap();
    let msix_root_path = manifest_root_path.join("msix");
    let packagelayout_path = msix_root_path.join("packagelayout.xml");
    let appxmanifest_path = msix_root_path.join("appxmanifest.xml");

    let manifest_content_raw = fs::read_to_string(manifest_path).unwrap();
    let manifest_content: toml::Value = toml::from_str(&manifest_content_raw)?;

    if expand_msix_node_from_metadata(manifest_content).is_some() {
        bail!("There is already a MSIX configuration in this project.");
    }

    if packagelayout_path.exists() {
        bail!("A package layout file already exists at {}", packagelayout_path);        
    }

    if appxmanifest_path.exists() {
        bail!("A appx manifest file already exists at {}", appxmanifest_path);
    }

    std::fs::create_dir_all(msix_root_path).unwrap();

    let mut appxmanifest_file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(appxmanifest_path)
        .unwrap();
    appxmanifest_file.set_len(0).unwrap();

    let mut packagelayout_file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(packagelayout_path)
        .unwrap();
    packagelayout_file.set_len(0).unwrap();

    let appxmanifest_template = mustache::compile_str(include_str!("../templates/template_appxmanifest.xml")).unwrap();
    let packagelayout_template = mustache::compile_str(include_str!("../templates/template_packagelayout.xml")).unwrap();

    let data = mustache::MapBuilder::new()
        .insert_str("PackageName", &root_package.name)
        .insert_vec("Targets", |builder| {
            let mut builder = builder;
            for target in &root_package.targets {
                if target.kind.contains(&"bin".to_string()) {
                    let mut sanitized_target_name = target.name.clone();
                    sanitized_target_name.retain(|c| c.is_alphanumeric());
                    builder = builder.push_map(|builder2| {
                        builder2
                            .insert_str("Target", &target.name)
                            .insert_str("TargetSanitized", &sanitized_target_name)
                    });
                }
            }
            builder
        })
        .build();

    appxmanifest_template.render_data(&mut appxmanifest_file, &data).unwrap();
    packagelayout_template.render_data(&mut packagelayout_file, &data).unwrap();

    Ok(())
}
