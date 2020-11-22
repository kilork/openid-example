use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Logout {
    pub(crate) id_token: String,
    pub(crate) logout_url: Option<Url>,
}
