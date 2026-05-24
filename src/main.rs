mod local;
mod platform;
mod server;
mod store;
mod types;

#[cfg(feature = "intune")]
mod intune;
#[cfg(feature = "jamf")]
mod jamf;
#[cfg(feature = "fleet")]
mod fleet;
#[cfg(feature = "kandji")]
mod kandji;

use rmcp::{ServiceExt, transport::stdio};
use server::DeviceServer;
use store::DeviceStore;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let store = Arc::new(DeviceStore::new());

    // Always detect local device
    store.detect_local();

    // TODO: If MDM backends configured, sync their devices too
    // #[cfg(feature = "intune")]
    // if let Some(backend) = intune::IntuneBackend::from_env() {
    //     for device in backend.list_devices().await? { store.add_device(device); }
    // }

    let server = DeviceServer { store };
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
