#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct PackagingLayout {
    #[yaserde(child, rename = "PackageFamily")]
    pub child: PackageFamily
}

#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct PackageFamily {
    #[yaserde(attribute, rename = "ID")]
    pub id: String,
    #[yaserde(attribute, rename = "FlatBundle")]
    pub flat_bundle: bool,
    #[yaserde(attribute, rename = "ManifestPath")]
    pub manifest_path: String,
    #[yaserde(attribute, rename = "ResourceManager")]
    pub resource_manager: bool,
    #[yaserde(rename = "Package")]
    pub children: Vec<Package>,
}

#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct Package {
    #[yaserde(attribute, rename = "ID")]
    pub id: String,
    #[yaserde(attribute, rename = "ProcessorArchitecture")]
    pub processor_architecture: String,
    #[yaserde(rename = "Files")]
    pub files: Files,
}

#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct Files {
    #[yaserde(rename = "File")]
    pub children: Vec<File>,
}

#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct File {
    #[yaserde(attribute, rename = "DestinationPath")]
    pub destination_path: Option<String>,
    #[yaserde(attribute, rename = "DestinationRoot")]
    pub destination_root: Option<String>,
    #[yaserde(attribute, rename = "SourcePath")]
    pub source_path: Option<String>,
    #[yaserde(attribute, rename = "SourceRoot")]
    pub source_root: Option<String>,
    #[yaserde(attribute, rename = "SourcePattern")]
    pub source_pattern: Option<String>,
    #[yaserde(attribute, rename = "SourceTarget")]
    pub source_target: Option<String>,
    #[yaserde(attribute, rename = "SourcePlatform")]
    pub source_platform: Option<String>,
}
