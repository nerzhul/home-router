use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector, Uri};
use serde::{Deserialize, Serialize};

pub enum ApiClient {
    Unix {
        client: Client<UnixConnector, Full<Bytes>>,
        socket_path: String,
    },
    Http {
        client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
        base_url: String,
    },
}

impl ApiClient {
    pub fn new_unix(socket_path: &str) -> Self {
        let client = Client::unix();
        Self::Unix {
            client,
            socket_path: socket_path.to_string(),
        }
    }

    pub fn new_http(base_url: &str) -> Self {
        let client = Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
        Self::Http {
            client,
            base_url: base_url.to_string(),
        }
    }

    fn build_uri(&self, path: &str) -> hyper::Uri {
        match self {
            Self::Unix { socket_path, .. } => Uri::new(socket_path, path).into(),
            Self::Http { base_url, .. } => format!("{}{}", base_url, path).parse().unwrap(),
        }
    }

    pub async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let uri = self.build_uri(path);
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Full::default())?;

        let response = match self {
            Self::Unix { client, .. } => client.request(req).await?,
            Self::Http { client, .. } => client.request(req).await?,
        };

        if response.status() != StatusCode::OK {
            anyhow::bail!("Request failed with status: {}", response.status());
        }

        let body = response.into_body().collect().await?.to_bytes();
        let data = serde_json::from_slice(&body)?;
        Ok(data)
    }

    pub async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let uri = self.build_uri(path);
        let body_bytes = serde_json::to_vec(body)?;

        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))?;

        let response = match self {
            Self::Unix { client, .. } => client.request(req).await?,
            Self::Http { client, .. } => client.request(req).await?,
        };

        if !response.status().is_success() {
            anyhow::bail!("Request failed with status: {}", response.status());
        }

        let body = response.into_body().collect().await?.to_bytes();
        let data = serde_json::from_slice(&body)?;
        Ok(data)
    }

    #[allow(dead_code)]
    pub async fn put<T: Serialize>(&self, path: &str, body: &T) -> Result<()> {
        let uri = self.build_uri(path);
        let body_bytes = serde_json::to_vec(body)?;

        let req = Request::builder()
            .method("PUT")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))?;

        let response = match self {
            Self::Unix { client, .. } => client.request(req).await?,
            Self::Http { client, .. } => client.request(req).await?,
        };

        if !response.status().is_success() {
            anyhow::bail!("Request failed with status: {}", response.status());
        }

        Ok(())
    }

    pub async fn delete(&self, path: &str) -> Result<()> {
        let uri = self.build_uri(path);
        let req = Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(Full::default())?;

        let response = match self {
            Self::Unix { client, .. } => client.request(req).await?,
            Self::Http { client, .. } => client.request(req).await?,
        };

        if !response.status().is_success() {
            anyhow::bail!("Request failed with status: {}", response.status());
        }

        Ok(())
    }
}
