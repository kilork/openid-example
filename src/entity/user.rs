use crate::entity::Sessions;
use actix_identity::Identity;
use actix_web::{dev::Payload, error::ErrorUnauthorized, web, Error, FromRequest, HttpRequest};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin, sync::RwLock};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct User {
    pub(crate) id: String,
    pub(crate) login: Option<String>,
    pub(crate) first_name: Option<String>,
    pub(crate) last_name: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) image_url: Option<String>,
    pub(crate) activated: bool,
    pub(crate) lang_key: Option<String>,
    pub(crate) authorities: Vec<String>,
}

impl FromRequest for User {
    type Config = ();
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<User, Error>>>>;

    fn from_request(req: &HttpRequest, pl: &mut Payload) -> Self::Future {
        let fut = Identity::from_request(req, pl);
        let sessions: Option<&web::Data<RwLock<Sessions>>> = req.app_data();
        if sessions.is_none() {
            eprintln!("sessions is none!");
            return Box::pin(async { Err(ErrorUnauthorized("unauthorized")) });
        }
        let sessions = sessions.unwrap().clone();

        Box::pin(async move {
            if let Some(identity) = fut.await?.identity() {
                if let Some(user) = sessions
                    .read()
                    .unwrap()
                    .map
                    .get(&identity)
                    .map(|x| x.0.clone())
                {
                    return Ok(user);
                }
            };

            Err(ErrorUnauthorized("unauthorized"))
        })
    }
}
