#[macro_use]
extern crate yaserde_derive;
pub mod packagelayout;

use std::{path::PathBuf, env::{current_dir, set_current_dir}};

use cargo_metadata::camino::Utf8PathBuf;
use clap::Parser;
use log::info;
use anyhow::{anyhow,Result};
use windows::{Win32::{System::Com::{CoInitialize, StructuredStorage::{STGM_CREATE, STGM_WRITE, STGM_SHARE_EXCLUSIVE, STGM_READ}, CreateUri, Uri_CREATE_CANONICALIZE, CoCreateInstance, CLSCTX_INPROC_SERVER, IStream}, UI::Shell::{SHCreateStreamOnFileEx, SHCreateMemStream}, Storage::Packaging::Appx::{APPX_PACKAGE_SETTINGS, IAppxFactory, AppxFactory, IAppxPackageWriter, APPX_COMPRESSION_OPTION_MAXIMUM, IAppxBundleWriter, IAppxBundleFactory, AppxBundleFactory, IAppxBundleWriter4}, Foundation::BOOL}, core::Interface};
use yaserde::de::from_str;

#[derive(Parser)]
#[clap(name="cargo-msix", version)]
struct Cli {
    #[clap(flatten)]
    manifest: clap_cargo::Manifest,
    #[clap(flatten)]
    workspace: clap_cargo::Workspace,
    #[clap(flatten)]
    features: clap_cargo::Features,
}

fn main() -> Result<()> {
    human_panic::setup_panic!(human_panic::Metadata {
        name: "cargo-msix".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        authors: "".into(),
        homepage: "https://github.com/davidanthoff/cargo-msix".into(),
    });

    let env = env_logger::Env::new();
    env_logger::init_from_env(env);

    info!("Parsing command line arguments.");
    let args = Cli::parse();

    unsafe { CoInitialize(std::ptr::null_mut()) }.unwrap();

    let mut metadata_cmd = args.manifest.metadata();

    args.features.forward_metadata(&mut metadata_cmd);

    let metadata = metadata_cmd.exec().unwrap();

    
    

    run_command_default(&metadata)?;

    Ok(())
}

fn create_appx_package_writer(stream: &IStream) -> Result<IAppxPackageWriter> {
    // let stream = unsafe {
    //     SHCreateStreamOnFileEx(
    //         filename.to_str().unwrap(),
    //         STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE,
    //         0, // default file attribute
    //         true,
    //         None)
    // }.unwrap();

    let hash_method = unsafe {
        CreateUri(
            "http://www.w3.org/2001/04/xmlenc#sha256",
            Uri_CREATE_CANONICALIZE,
            0)
        }.unwrap();

    let writer_settings = APPX_PACKAGE_SETTINGS {
        forceZip32: BOOL::from(false),
        hashMethod: Some(hash_method),
    };

    let appx_factory: IAppxFactory = unsafe {
        CoCreateInstance(
            &AppxFactory,
            None,
            CLSCTX_INPROC_SERVER).unwrap()
    };

    let writer = unsafe {
        appx_factory.CreatePackageWriter(stream, &writer_settings)
    }.unwrap();

    Ok(writer)
}

fn create_appx_bundle_writer(filename: &PathBuf) -> Result<IAppxBundleWriter> {
    let stream = unsafe {
        SHCreateStreamOnFileEx(
            filename.to_str().unwrap(),
            STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE,
            0, // default file attribute
            true,
            None)
    }.unwrap();

    let appx_bundle_factory: IAppxBundleFactory = unsafe {
        CoCreateInstance(
            &AppxBundleFactory,
            None,
            CLSCTX_INPROC_SERVER).unwrap()
    };

    let writer = unsafe {
        appx_bundle_factory.CreateBundleWriter(stream, 0)
    }.unwrap();

    Ok(writer)
}

fn create_manifest(appmanifest_path: &PathBuf, version: &str, processor_architecture: &str) -> Result<IStream> {
    let template = mustache::compile_path(&appmanifest_path).unwrap();
    let data = mustache::MapBuilder::new()
        .insert_str("Version", version.to_string() + ".0")
        .insert_str("ProcessorArchitecture", processor_architecture)
        .build();
    let manifestcontent = template.render_data_to_string(&data).unwrap();

    let mut parsedcontent: minidom::Element = manifestcontent.parse().unwrap();

    let identity_element = parsedcontent
        .get_child_mut("Identity", "http://schemas.microsoft.com/appx/manifest/foundation/windows10").unwrap();
    
    let old_publisher = identity_element.attr("Publisher").unwrap();
    let new_publisher = format!("{old_publisher}, OID.2.25.311729368913984317654407730594956997722=1");

    identity_element.set_attr("Publisher", new_publisher);

    let manifestcontent = String::from(&parsedcontent);

    let manifest_stream = unsafe {
        SHCreateMemStream(manifestcontent.as_ptr(), manifestcontent.len() as u32)
    }.unwrap();

    Ok(manifest_stream)
}

fn run_command_default(metadata: &cargo_metadata::Metadata) -> Result<()> {
    let root_package = metadata.root_package().unwrap();

    let output_root_path = metadata.target_directory.join("msix");
    std::fs::create_dir_all(&output_root_path).unwrap();
    

    

    for (_bundle_name, bundle_packagelayout_path_as_string) in metadata.root_package().unwrap().metadata["msix"].as_object().unwrap() {
        let mut bundle_packagelayout_path = Utf8PathBuf::from(&metadata.workspace_root);
        bundle_packagelayout_path.push(bundle_packagelayout_path_as_string.as_str().unwrap());
        let bundle_packagelayout_path = bundle_packagelayout_path.canonicalize().unwrap();

        eprintln!("NOW THE PATH IS {:?}", bundle_packagelayout_path);

        if !bundle_packagelayout_path.exists() {
            return Err(anyhow!("File doesn't exist."));
        }

        let packagelayout_template = mustache::compile_path(&bundle_packagelayout_path).unwrap();
        let data = mustache::MapBuilder::new()
            .insert_str("version", root_package.version.to_string() + ".0")
         .build();
        let packagelayout_content = packagelayout_template.render_data_to_string(&data).unwrap();

        let packagelayout_parsed: packagelayout::PackagingLayout = from_str(&packagelayout_content).unwrap();

        let output_name = format!("{}.msixbundle", packagelayout_parsed.child.id);
        let output_path = output_root_path.join(&output_name);

        if output_path.exists() {
            std::fs::remove_file(&output_path).unwrap();
        }

        let mut manifest_path = Utf8PathBuf::from(bundle_packagelayout_path.parent().unwrap().to_string_lossy().to_string());
        manifest_path.push(packagelayout_parsed.child.manifest_path);
        let manifest_path = manifest_path.canonicalize().unwrap();

        let appx_bundle_writer = create_appx_bundle_writer(&output_path.as_std_path().to_path_buf()).unwrap();

        for package in packagelayout_parsed.child.children {
            let manifest_stream = create_manifest(&manifest_path, &format!("{}.{}.{}", root_package.version.major, root_package.version.minor, root_package.version.patch), &package.processor_architecture).unwrap();

            let package_stream = unsafe {
                SHCreateMemStream(std::ptr::null_mut(), 0)
            }.unwrap();

            let appx_package_writer = create_appx_package_writer(&package_stream).unwrap();

            for file in package.files.children {
                match file.source_path {
                    Some(source_path) => {
                        let old_working_dir = current_dir().unwrap();
                        set_current_dir(bundle_packagelayout_path.parent().unwrap()).unwrap();

                        for file2 in capturing_glob::glob(&source_path).unwrap() {
                            eprintln!("file2: {:?}", file2);
                            let file2 = file2.unwrap();

                            eprintln!("file2: {:?}", file2);
                        }

                        // let filepath = bundle_packagelayout_path.parent().unwrap().join(source_path);

                        // eprintln!("filepath = {:?}", filepath);
        
                        // let filestream = unsafe {
                        //     SHCreateStreamOnFileEx(
                        //         filepath.to_string_lossy().to_string(),
                        //         STGM_READ | STGM_SHARE_EXCLUSIVE,
                        //         0,
                        //         false,
                        //         None
                        //     )
                        // }.unwrap();
                                
                        set_current_dir(old_working_dir).unwrap();
                        // unsafe {
                        //     appx_package_writer.AddPayloadFile(file.destination_path, "application/octet-stream", APPX_COMPRESSION_OPTION_MAXIMUM, filestream)
                        // }.unwrap();
                    },
                    None => {
                        let source_target = file.source_target.unwrap();
                        let source_platform = file.source_platform.unwrap();

                        let filepath = metadata.target_directory.join(source_platform).join("debug").join(format!("{source_target}.exe"));

                        eprintln!("filepath = {:?}", filepath);
        
                        let filestream = unsafe {
                            SHCreateStreamOnFileEx(
                                filepath.to_string(),
                                STGM_READ | STGM_SHARE_EXCLUSIVE,
                                0,
                                false,
                                None
                            )
                        }.unwrap();
                                
                        unsafe {
                            appx_package_writer.AddPayloadFile(file.destination_path, "application/octet-stream", APPX_COMPRESSION_OPTION_MAXIMUM, filestream)
                        }.unwrap();
                    }
                }
                
            }

            unsafe { appx_package_writer.Close(&manifest_stream) }.unwrap();

            eprintln!("Latest error is at: {}", format!("{}.msix", package.id));

            unsafe{ appx_bundle_writer.cast::<IAppxBundleWriter4>().unwrap().AddPayloadPackage(format!("{}.msix", package.id), &package_stream, false) }.unwrap();
        }

        unsafe { appx_bundle_writer.Close() }.unwrap();
    }

    // let package = metadata.root_package().unwrap();

    // eprintln!("We are in {}", metadata.workspace_root);
    // let msix_root_path = metadata.workspace_root.join("msix");
    // let msix_appmanifest_path = msix_root_path.join("appxmanifest.xml");

    // let output_root_path = metadata.target_directory.join("msix");
    // let name = package.name.clone() + ".msix";
    // let output_path = output_root_path.join(&name);

    // if output_path.exists() {
    //     std::fs::remove_file(&output_path).unwrap();
    // }

    // std::fs::create_dir_all(&output_root_path).unwrap();

    // let writer = create_appx_package_writer(&output_path.into_std_path_buf())?;

    // for target in &package.targets {
    //     if target.kind.contains(&"bin".to_string()) {
    //         eprintln!("FOUND TARGET {:?}", target);            

    //         let mut filename = Utf8PathBuf::new();
    //         filename.push(&target.name);
    //         filename.set_extension("exe");

    //         let filepath = metadata.target_directory.join("debug").join(&filename);

    //         eprintln!("Trying to load file at {:?}", filepath);

    //         let filestream = unsafe {
    //             SHCreateStreamOnFileEx(
    //                 filepath.to_string(),
    //                 STGM_READ | STGM_SHARE_EXCLUSIVE,
    //                 0,
    //                 false,
    //                 None
    //             )
    //         }.unwrap();
        
    //         unsafe {
    //             writer.AddPayloadFile(filename.to_string(), "application/octet-stream", APPX_COMPRESSION_OPTION_MAXIMUM, filestream)
    //         }.unwrap();
    //     }
    // }


    // unsafe { writer.Close(manifest_stream) }?;

    Ok(())
}
