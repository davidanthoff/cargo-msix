#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct PackagingLayout {
    #[yaserde(child, rename = "PackageFamily")]
    pub package_families: Vec<PackageFamily>,
}

#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct PackageFamily {
    #[yaserde(attribute, rename = "Filename")]
    pub filename: String,
    #[yaserde(attribute, rename = "FlatBundle")]
    pub flat_bundle: bool,
    #[yaserde(attribute, rename = "ManifestPath")]
    pub manifest_path: String,
    #[yaserde(rename = "Package")]
    pub packages: Vec<Package>,
}

#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct Package {
    #[yaserde(attribute, rename = "Filename")]
    pub filename: String,
    #[yaserde(attribute, rename = "ProcessorArchitecture")]
    pub processor_architecture: String,
    #[yaserde(rename = "Files")]
    pub files: Files,
}

#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct Files {
    #[yaserde(rename = "File")]
    pub files: Vec<File>,
    #[yaserde(rename = "FilePattern")]
    pub filepatterns: Vec<FilePattern>,
    #[yaserde(rename = "BuildOutput")]
    pub buildoutputs: Vec<BuildOutput>,
}

#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct FilePattern {
    #[yaserde(attribute, rename = "DestinationRoot")]
    pub destination_root: String,
    #[yaserde(attribute, rename = "SourceRoot")]
    pub source_root: String,
    #[yaserde(attribute, rename = "SourcePattern")]
    pub source_pattern: String,
}

#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct BuildOutput {
    #[yaserde(attribute, rename = "DestinationPath")]
    pub destination_path: String,
    #[yaserde(attribute, rename = "SourceTarget")]
    pub source_target: String,
    #[yaserde(attribute, rename = "SourcePlatform")]
    pub source_platform: String,
}

#[derive(Default, PartialEq, Debug, YaDeserialize)]
pub struct File {
    #[yaserde(attribute, rename = "DestinationPath")]
    pub destination_path: String,
    #[yaserde(attribute, rename = "SourcePath")]
    pub source_path: String,
}
