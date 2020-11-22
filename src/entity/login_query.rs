use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub(crate) struct LoginQuery {
    pub(crate) code: String,
    pub(crate) state: Option<String>,
}
