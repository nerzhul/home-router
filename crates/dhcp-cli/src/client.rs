use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub struct ApiClient {
    base_url: String,
    client: Client,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            client: Client::new(),
        }
    }

    pub async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("Request failed with status: {}", response.status());
        }

        let data = response.json().await?;
        Ok(data)
    }

    pub async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.post(&url).json(body).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("Request failed with status: {}", response.status());
        }

        let data = response.json().await?;
        Ok(data)
    }

    #[allow(dead_code)]
    pub async fn put<T: Serialize>(&self, path: &str, body: &T) -> Result<()> {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.put(&url).json(body).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("Request failed with status: {}", response.status());
        }

        Ok(())
    }

    pub async fn delete(&self, path: &str) -> Result<()> {
        let url = format!("{}{}", self.base_url, path);
        let response = self.client.delete(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("Request failed with status: {}", response.status());
        }

        Ok(())
    }
}
