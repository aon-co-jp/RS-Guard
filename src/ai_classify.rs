//! AI二次判定クライアント。[`aruaru-llm`]の`POST /v1/classify-security`を
//! 呼び、静的ルール([`crate::repo_scan`])に引っかからなかったコード片を
//! 意味的類似度で再評価する。
//!
//! **なぜ二次判定が要るか**: 正規表現ベースの静的検出は、パターンを
//! 少しでも言い換えられる(変数名を変える・処理を分割する・別APIで
//! 同じことをする)と取り逃がす。aruaru-llm側は`open-cuda`の
//! `opencuda-bert`(multilingual-e5-small)で文を埋め込みベクトルへ変換し、
//! 「マルウェア/スパイウェア(無断の情報収集)/持ち出し/常駐・自動巡回/
//! 正常」の代表例とのコサイン類似度で分類するため、字面が違っても
//! 意味が近ければ拾える可能性がある。
//!
//! **正直な開示(最重要)**:
//! - これは**マルウェアで訓練した分類器ではなく、汎用の文埋め込みモデルに
//!   よる類似度ヒューリスティック**。静的ルールの「二次意見」であって、
//!   単独で信頼できる判定ではない。
//! - 「分身の術」構成: aruaru-llmは1インスタンスを複数のサイト/ツールが
//!   共有する設計なので、RS-Guardはモデル(470MB)を自前で持たず
//!   HTTPで問い合わせるだけ。オフラインでは当然使えない。
//! - **接続できないときに黙って「安全」とは言わない**——エラーを
//!   呼び出し側へ返し、静的結果のみで判断していることを明示させる。

use serde::Deserialize;
use std::time::Duration;

/// aruaru-llmの`/v1/classify-security`が返す判定。
#[derive(Debug, Clone, Deserialize)]
pub struct AiVerdict {
    pub label: String,
    #[serde(default)]
    pub description: String,
    pub score: f32,
    pub is_suspicious: bool,
    /// aruaru-llm側が自己申告する実装方式(誇張を避けるため常に受け取る)。
    pub engine: String,
}

#[derive(Debug)]
pub enum AiError {
    /// ネットワーク到達不能・タイムアウト等。
    Unreachable(String),
    /// 到達したが想定外のステータス/ボディだった。
    BadResponse(String),
}

impl std::fmt::Display for AiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiError::Unreachable(e) => write!(f, "AI service unreachable: {e}"),
            AiError::BadResponse(e) => write!(f, "AI service returned an unexpected response: {e}"),
        }
    }
}

pub struct AiClassifier {
    client: reqwest::Client,
    base_url: String,
}

/// 1回の判定へ送るコード片の最大文字数。埋め込みモデルの入力長には上限が
/// あり、長文を丸ごと送っても先頭以外は効かない上に遅くなるだけなので
/// 切り詰める(切り詰めた事実は呼び出し側のdocに明記)。
const MAX_SNIPPET_CHARS: usize = 2000;

impl AiClassifier {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("RS-Guard")
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
            base_url: base_url.into(),
        }
    }

    /// `text`(コード片)を分類する。長すぎる入力は先頭
    /// [`MAX_SNIPPET_CHARS`]文字へ切り詰めてから送る。
    pub async fn classify(&self, text: &str) -> Result<AiVerdict, AiError> {
        let snippet: String = text.chars().take(MAX_SNIPPET_CHARS).collect();
        let url = format!("{}/v1/classify-security", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "text": snippet, "tenant": "rs-guard" }))
            .send()
            .await
            .map_err(|e| AiError::Unreachable(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(AiError::BadResponse(format!("HTTP {}", resp.status())));
        }
        resp.json::<AiVerdict>().await.map_err(|e| AiError::BadResponse(e.to_string()))
    }

    /// サービスが生きているか(`/healthz`)。`--ai`指定時に最初に1回だけ
    /// 呼び、落ちていれば「AI判定はスキップした」と正直に伝えるために使う。
    pub async fn health_check(&self) -> Result<bool, AiError> {
        let url = format!("{}/healthz", self.base_url.trim_end_matches('/'));
        let resp = self.client.get(&url).send().await.map_err(|e| AiError::Unreachable(e.to_string()))?;
        Ok(resp.status().is_success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unreachable_service_reports_error_rather_than_claiming_safe() {
        // ポート1へは通常何も待ち受けていない。「安全」を返さずErrになることが要点
        // (黙って安全側に倒すと、AIが落ちているだけなのに検査済みと誤認される)。
        let ai = AiClassifier::new("http://127.0.0.1:1");
        let err = ai.classify("cp ~/.ssh/id_rsa /tmp").await.unwrap_err();
        assert!(matches!(err, AiError::Unreachable(_)), "expected Unreachable, got {err:?}");
    }

    #[tokio::test]
    async fn health_check_on_unreachable_service_is_an_error() {
        let ai = AiClassifier::new("http://127.0.0.1:1");
        assert!(ai.health_check().await.is_err());
    }

    #[test]
    fn base_url_trailing_slash_is_normalized() {
        // 末尾スラッシュ有無で二重スラッシュのURLにならないこと。
        let ai = AiClassifier::new("http://example.test/");
        assert_eq!(ai.base_url.trim_end_matches('/'), "http://example.test");
    }
}
