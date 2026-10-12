use crate::error::Result;
use async_trait::async_trait;

pub fn env_dependencies() -> &'static [&'static str] {
    &[]
}

#[derive(Default)]
pub struct SealedProvider;

impl SealedProvider {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

#[async_trait]
impl crate::providers::Provider for SealedProvider {
    fn capabilities(&self) -> Vec<crate::providers::ProviderCapability> {
        vec![crate::providers::ProviderCapability::RemoteStorage]
    }

    async fn get_secret(&self, value: &str) -> Result<String> {
        Ok(value.to_string())
    }

    async fn put_secret(&self, key: &str, value: &str) -> Result<String> {
        Ok(crate::sealed::seal(key, value)?.placeholder)
    }

    async fn test_connection(&self) -> Result<()> {
        crate::sealed::list().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Provider;
    use serde_json::json;

    #[test]
    fn get_returns_the_stored_placeholder_without_the_device() {
        let (_g, mock) = crate::sealed::testing::install();
        let provider = SealedProvider::new().unwrap();
        assert_eq!(
            futures::executor::block_on(provider.get_secret("seven_ph_9")).unwrap(),
            "seven_ph_9"
        );
        assert!(mock.ops().is_empty());
        crate::sealed::set_transport(None);
    }

    #[test]
    fn put_seals_under_the_secret_name_and_returns_the_placeholder() {
        let (_g, mock) = crate::sealed::testing::install();
        mock.reply(json!({ "v": 1, "placeholder": "seven_ph_2", "state": "active" }));
        let provider = SealedProvider::new().unwrap();
        assert_eq!(
            futures::executor::block_on(provider.put_secret("GITHUB_TOKEN", "ghp_x")).unwrap(),
            "seven_ph_2"
        );
        let sent = mock.requests.lock().unwrap()[0].clone();
        assert_eq!(sent["name"], json!("GITHUB_TOKEN"));
        crate::sealed::set_transport(None);
    }
}
