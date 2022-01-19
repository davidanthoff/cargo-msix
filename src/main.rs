#[macro_use]
extern crate yaserde_derive;
pub mod packagelayout;

use std::{
    env::{current_dir, set_current_dir},
    path::PathBuf,
};

use anyhow::{anyhow, Context, Result};
use cargo_metadata::camino::Utf8PathBuf;
use clap::Parser;
use log::info;
use windows::{
    core::Interface,
    Win32::{
        Foundation::BOOL,
        Storage::Packaging::Appx::{
            AppxBundleFactory, AppxFactory, IAppxBundleFactory, IAppxBundleWriter,
            IAppxBundleWriter4, IAppxFactory, IAppxPackageWriter, APPX_COMPRESSION_OPTION_MAXIMUM,
            APPX_PACKAGE_SETTINGS,
        },
        System::Com::{
            CoCreateInstance, CoInitialize, CreateUri, IStream,
            StructuredStorage::{STGM_CREATE, STGM_READ, STGM_SHARE_EXCLUSIVE, STGM_WRITE},
            Uri_CREATE_CANONICALIZE, CLSCTX_INPROC_SERVER, STREAM_SEEK_SET,
        },
        UI::Shell::{SHCreateMemStream, SHCreateStreamOnFileEx},
    },
};
use yaserde::de::from_str;

#[derive(Debug, Parser)]
#[clap(name = "cargo")]
#[clap(bin_name = "cargo")]
#[clap(
    setting = clap::AppSettings::DeriveDisplayOrder,
    setting = clap::AppSettings::DontCollapseArgsInUsage
)]
enum Command {
    #[clap(name = "msix")]
    #[clap(about, author, version)]
    #[clap(
        setting = clap::AppSettings::DeriveDisplayOrder,
        setting = clap::AppSettings::DontCollapseArgsInUsage
    )]
    Msix(Cli),
}

#[derive(Debug, Clone, clap::Args)]
struct Cli {
    #[clap(flatten)]
    manifest: clap_cargo::Manifest,
    #[clap(flatten)]
    workspace: clap_cargo::Workspace,
    #[clap(flatten)]
    features: clap_cargo::Features,
    #[clap(long)]
    release: bool,
    #[clap(long)]
    unsigned: bool,
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
    let Command::Msix(ref args) = Command::parse();

    unsafe { CoInitialize(std::ptr::null_mut()) }.unwrap();

    let mut metadata_cmd = args.manifest.metadata();

    args.features.forward_metadata(&mut metadata_cmd);

    let metadata = metadata_cmd.exec()?;

    let profile = if args.release { "release" } else { "debug" };

    run_command_default(&args, &metadata, &profile.to_string())?;

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
            0,
        )
    }
    .unwrap();

    let writer_settings = APPX_PACKAGE_SETTINGS {
        forceZip32: BOOL::from(false),
        hashMethod: Some(hash_method),
    };

    let appx_factory: IAppxFactory =
        unsafe { CoCreateInstance(&AppxFactory, None, CLSCTX_INPROC_SERVER).unwrap() };

    let writer = unsafe { appx_factory.CreatePackageWriter(stream, &writer_settings) }.unwrap();

    Ok(writer)
}

fn create_appx_bundle_writer(filename: &PathBuf) -> Result<IAppxBundleWriter> {
    let stream = unsafe {
        SHCreateStreamOnFileEx(
            filename.to_str().unwrap(),
            STGM_CREATE | STGM_WRITE | STGM_SHARE_EXCLUSIVE,
            0, // default file attribute
            true,
            None,
        )
    }
    .unwrap();

    let appx_bundle_factory: IAppxBundleFactory =
        unsafe { CoCreateInstance(&AppxBundleFactory, None, CLSCTX_INPROC_SERVER).unwrap() };

    let writer = unsafe { appx_bundle_factory.CreateBundleWriter(stream, 0) }.unwrap();

    Ok(writer)
}

fn create_manifest(
    cli_args: &Cli,
    appmanifest_path: &PathBuf,
    version: &str,
    processor_architecture: &str,
) -> Result<IStream> {
    let template = mustache::compile_path(&appmanifest_path).unwrap();
    let data = mustache::MapBuilder::new()
        .insert_str("Version", version.to_string())
        .insert_str("ProcessorArchitecture", processor_architecture)
        .build();
    let manifestcontent = template.render_data_to_string(&data).unwrap();

    let mut parsedcontent: minidom::Element = manifestcontent.parse()
        .with_context(|| anyhow!("Cannot parse app manifest file {:?}", appmanifest_path))?;

    if cli_args.unsigned {
        let identity_element = parsedcontent
            .get_child_mut(
                "Identity",
                "http://schemas.microsoft.com/appx/manifest/foundation/windows10",
            )
            .unwrap();
        let old_publisher = identity_element.attr("Publisher").unwrap();
        let new_publisher =
            format!("{old_publisher}, OID.2.25.311729368913984317654407730594956997722=1");
        identity_element.set_attr("Publisher", new_publisher);
    }

    let manifestcontent = String::from(&parsedcontent);

    let manifest_stream =
        unsafe { SHCreateMemStream(manifestcontent.as_ptr(), manifestcontent.len() as u32) }
            .unwrap();

    Ok(manifest_stream)
}

fn run_command_default(
    cli_args: &Cli,
    metadata: &cargo_metadata::Metadata,
    profile: &String,
) -> Result<()> {
    let root_package = metadata.root_package().unwrap();

    let output_root_path = metadata.target_directory.join("msix");
    std::fs::create_dir_all(&output_root_path).unwrap();

    let root_package_msix_metadata = root_package.metadata["msix"]
        .as_object()
        .ok_or_else(|| anyhow!("Cargo.toml is missing the [package.metadata.msix] table"))?;

    for (_bundle_name, bundle_packagelayout_path_as_string) in root_package_msix_metadata {
        let bundle_packagelayout_path_as_string = bundle_packagelayout_path_as_string.as_str().unwrap();
        let mut bundle_packagelayout_path = Utf8PathBuf::from(&metadata.workspace_root);
        bundle_packagelayout_path.push(&bundle_packagelayout_path_as_string);
        let bundle_packagelayout_path = bundle_packagelayout_path.canonicalize()
            .map_err(|_| anyhow!("Cannot find the package layout file '{}' for the msix entry '{}' in Cargo.toml", bundle_packagelayout_path, _bundle_name))?;

        if !bundle_packagelayout_path.exists() {
            return Err(anyhow!("File doesn't exist."));
        }

        let packagelayout_template = mustache::compile_path(&bundle_packagelayout_path).unwrap();
        let data = mustache::MapBuilder::new()
            .insert_str("Version", root_package.version.to_string())
            .build();
        let packagelayout_content = packagelayout_template.render_data_to_string(&data).unwrap();

        let packagelayout_parsed: packagelayout::PackagingLayout = from_str::<packagelayout::PackagingLayout>(&packagelayout_content)
            .map_err(|err| anyhow!("{}", err))
            .with_context(|| anyhow!("Cannot parse package layout file {:?}", bundle_packagelayout_path))?;

        for package_family in packagelayout_parsed.package_families {
            let output_name = package_family.filename;
            let output_path = output_root_path.join(&output_name);

            if output_path.exists() {
                std::fs::remove_file(&output_path).unwrap();
            }

            let mut manifest_path = Utf8PathBuf::from(
                bundle_packagelayout_path
                    .parent()
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
            );
            manifest_path.push(package_family.manifest_path);
            let manifest_path = manifest_path.canonicalize()
                .map_err(|_| anyhow!("Cannot find manifest file {} that is specified in the package layout file.", manifest_path))?;

            let appx_bundle_writer =
                create_appx_bundle_writer(&output_path.as_std_path().to_path_buf()).unwrap();

            for package in package_family.packages {
                let manifest_stream = create_manifest(
                    cli_args,
                    &manifest_path,
                    &format!(
                        "{}.{}.{}",
                        root_package.version.major,
                        root_package.version.minor,
                        root_package.version.patch
                    ),
                    &package.processor_architecture,
                )?;

                let package_stream = if !package_family.flat_bundle {
                    unsafe { SHCreateMemStream(std::ptr::null_mut(), 0) }.unwrap()
                } else {
                    unsafe {
                        SHCreateStreamOnFileEx(
                            output_root_path.join(&package.filename).to_string(),
                            STGM_CREATE | STGM_READ | STGM_WRITE | STGM_SHARE_EXCLUSIVE,
                            0,
                            false,
                            None,
                        )
                    }
                    .unwrap()
                };

                let appx_package_writer = create_appx_package_writer(&package_stream).unwrap();

                for file in package.files.files {
                    let filepath = bundle_packagelayout_path
                        .parent()
                        .unwrap()
                        .join(file.source_path);

                    let filestream = unsafe {
                        SHCreateStreamOnFileEx(
                            filepath.to_string_lossy().to_string(),
                            STGM_READ | STGM_SHARE_EXCLUSIVE,
                            0,
                            false,
                            None,
                        )}
                        .with_context(|| anyhow!("Cannot read the file {:?} that is listed as a <File> in the package layout.", filepath))?;


                    unsafe {
                        appx_package_writer.AddPayloadFile(
                            file.destination_path,
                            "application/octet-stream",
                            APPX_COMPRESSION_OPTION_MAXIMUM,
                            filestream,
                        )
                    }
                    .unwrap();
                }

                for buildoutput in package.files.buildoutputs {
                    let source_target = buildoutput.source_target;
                    let source_platform = buildoutput.source_platform;

                    let filepath = metadata
                        .target_directory
                        .join(source_platform)
                        .join(profile)
                        .join(format!("{source_target}.exe"));

                    let filestream = unsafe {
                        SHCreateStreamOnFileEx(
                            filepath.to_string(),
                            STGM_READ | STGM_SHARE_EXCLUSIVE,
                            0,
                            false,
                            None,
                        )}
                        .with_context(|| anyhow!("Cannot read the file {:?} that is listed as a <BuildOutput> in the package layout.", filepath))?;

                    unsafe {
                        appx_package_writer.AddPayloadFile(
                            buildoutput.destination_path,
                            "application/octet-stream",
                            APPX_COMPRESSION_OPTION_MAXIMUM,
                            filestream,
                        )
                    }
                    .unwrap();
                }

                for filepattern in package.files.filepatterns {
                    let old_working_dir = current_dir().unwrap();
                    let new_working_dir = bundle_packagelayout_path
                        .parent()
                        .unwrap()
                        .join(filepattern.source_root);
                    set_current_dir(&new_working_dir)
                        .with_context(|| anyhow!("Cannot find the path {:?} that is specified as the SourceRoot in a <FilePattern> in the package layout.", new_working_dir))?;

                    let destination_root = filepattern.destination_root;

                    for file2 in glob::glob(&filepattern.source_pattern).unwrap() {
                        let file2 = file2.unwrap();

                        let source_filename = new_working_dir.join(&file2);

                        if source_filename.is_file() {
                            let filestream = unsafe {
                                SHCreateStreamOnFileEx(
                                    source_filename.to_string_lossy().to_string(),
                                    STGM_READ | STGM_SHARE_EXCLUSIVE,
                                    0,
                                    false,
                                    None,
                                )}
                                .with_context(|| anyhow!("Cannot read the file {:?} that is specified from a <FilePattern> in the package layout.", source_filename))?;
                            
                            let destination_filename =
                                PathBuf::from(&destination_root).join(&file2);

                            unsafe {
                                appx_package_writer.AddPayloadFile(
                                    destination_filename.to_string_lossy().to_string(),
                                    "application/octet-stream",
                                    APPX_COMPRESSION_OPTION_MAXIMUM,
                                    filestream,
                                )
                            }
                            .unwrap();
                        } else if !source_filename.is_dir() {
                            eprintln!("Warning: Skipping file {:?}.", source_filename);
                        }
                    }

                    set_current_dir(old_working_dir).unwrap();
                }

                unsafe { appx_package_writer.Close(&manifest_stream) }.unwrap();

                if package_family.flat_bundle {
                    unsafe { package_stream.Seek(0, STREAM_SEEK_SET) }.unwrap();
                    let package_stream = unsafe {
                        SHCreateStreamOnFileEx(
                            output_root_path.join(&package.filename).to_string(),
                            STGM_READ | STGM_SHARE_EXCLUSIVE,
                            0,
                            false,
                            None,
                        )
                    }
                    .unwrap();

                    unsafe {
                        appx_bundle_writer
                            .cast::<IAppxBundleWriter4>()
                            .unwrap()
                            .AddPackageReference(package.filename, &package_stream, false)
                    }
                    .unwrap();
                } else {
                    unsafe {
                        appx_bundle_writer
                            .cast::<IAppxBundleWriter4>()
                            .unwrap()
                            .AddPayloadPackage(package.filename, &package_stream, false)
                    }
                    .unwrap();
                }
            }

            unsafe { appx_bundle_writer.Close() }.unwrap();
        }
    }

    Ok(())
}
