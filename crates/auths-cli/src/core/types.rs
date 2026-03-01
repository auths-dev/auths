use clap::ValueEnum;

#[derive(ValueEnum, Clone, Debug)]
pub enum ExportFormat {
    Pem,
    Pub,
    Enc,
}
