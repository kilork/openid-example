#[macro_use]
extern crate actix_web;

use actix::prelude::*;
use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::{
    dev::Payload, error::ErrorUnauthorized, http, middleware, web, App, Error, FromRequest,
    HttpRequest, HttpResponse, HttpServer, Responder,
};
use exitfailure::ExitFailure;
use openid::{
    Claims, Client, CompactJson, CustomClaims, Discovered, Options, StandardClaims, Token, Userinfo,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, pin::Pin, sync::RwLock};
use url::Url;

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html")
        .body(include_str!("../src/index.html"))
}

#[derive(Debug, Serialize, Deserialize)]
struct OurClaims {
    #[serde(flatten)]
    standard_claims: StandardClaims,
}

impl CustomClaims for OurClaims {
    fn standard_claims(&self) -> &StandardClaims {
        &self.standard_claims
    }
}

impl CompactJson for OurClaims {}

type DiscoveredClient = Client<Discovered, OurClaims>;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    login: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    image_url: Option<String>,
    activated: bool,
    lang_key: Option<String>,
    authorities: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Logout {
    id_token: String,
    logout_url: Option<Url>,
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

struct Sessions {
    map: HashMap<String, (User, Token<OurClaims>, Userinfo)>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Failure {
    error: String,
}

#[get("/oauth2/authorization/oidc")]
async fn authorize(oidc_client: web::Data<DiscoveredClient>) -> impl Responder {
    let auth_url = oidc_client.auth_url(&Options {
        scope: Some("email profile".into()),
        ..Default::default()
    });

    eprintln!("authorize: {}", auth_url);

    HttpResponse::Found()
        .header(http::header::LOCATION, auth_url.to_string())
        .finish()
}

#[get("/account")]
async fn account(user: User) -> impl Responder {
    web::Json(user)
}

#[derive(Deserialize, Debug)]
struct LoginQuery {
    code: String,
}

async fn request_token(
    oidc_client: web::Data<DiscoveredClient>,
    query: web::Query<LoginQuery>,
) -> Result<Option<(Token<OurClaims>, Userinfo)>, ExitFailure> {
    let mut token: Token<OurClaims> = oidc_client.request_token(&query.code).await?.into();
    if let Some(mut id_token) = token.id_token.as_mut() {
        oidc_client.decode_token(&mut id_token)?;
        oidc_client.validate_token(&id_token, None, None)?;
        let claims = id_token.payload()?;
        eprintln!("token: {:?}", id_token);
        let userinfo = claims.userinfo().clone();
        eprintln!("user info: {:?}", userinfo);
        Ok(Some((token, userinfo)))
    } else {
        return Ok(None);
    }
}

#[get("/login/oauth2/code/oidc")]
async fn login(
    oidc_client: web::Data<DiscoveredClient>,
    query: web::Query<LoginQuery>,
    sessions: web::Data<RwLock<Sessions>>,
    identity: Identity,
) -> impl Responder {
    eprintln!("login: {:?}", query);

    match request_token(oidc_client, query).await {
        Ok(Some((token, userinfo))) => {
            let id = uuid::Uuid::new_v4().to_string();

            let login = userinfo.preferred_username.clone();
            let email = userinfo.email.clone();

            let user = User {
                id: userinfo.sub.clone().unwrap_or_default(),
                login,
                last_name: userinfo.family_name.clone(),
                first_name: userinfo.name.clone(),
                email,
                activated: userinfo.email_verified,
                image_url: userinfo.picture.clone().map(|x| x.to_string()),
                lang_key: Some("en".to_string()),
                authorities: vec!["ROLE_USER".to_string()], //FIXME: read from token
            };

            identity.remember(id.clone());
            sessions
                .write()
                .unwrap()
                .map
                .insert(id, (user, token, userinfo));

            HttpResponse::Found()
                .header(http::header::LOCATION, host("/"))
                .finish()
        }
        Ok(None) => {
            eprintln!("login error in call: no id_token found");

            HttpResponse::Unauthorized().finish()
        }
        Err(err) => {
            eprintln!("login error in call: {:?}", err);

            HttpResponse::Unauthorized().finish()
        }
    }
}

#[post("/logout")]
async fn logout(
    oidc_client: web::Data<DiscoveredClient>,
    sessions: web::Data<RwLock<Sessions>>,
    identity: Identity,
) -> impl Responder {
    if let Some(id) = identity.identity() {
        identity.forget();
        if let Some((user, token, _userinfo)) = sessions.write().unwrap().map.remove(&id) {
            eprintln!("logout user: {:?}", user);

            let id_token = token.bearer.access_token.into();
            let logout_url = oidc_client.config().end_session_endpoint.clone();

            return HttpResponse::Ok().json(Logout {
                id_token,
                logout_url,
            });
        }
    }

    HttpResponse::Unauthorized().finish()
}

/// This host is the address, where user would be redirected after initial authorization.
/// For DEV environment with WebPack this is usually something like `http://localhost:9000`.
/// We are using `http://localhost:8080` in all-in-one example.
fn host(path: &str) -> String {
    env::var("REDIRECT_URL").unwrap_or("http://localhost:8080".to_string()) + path
}

#[actix_rt::main]
async fn main() -> Result<(), ExitFailure> {
    dotenv::dotenv().ok();
    let client_id = env::var("CLIENT_ID").unwrap_or("<client id>".to_string());
    let client_secret = env::var("CLIENT_SECRET").unwrap_or("<client secret>".to_string());
    let issuer_url = env::var("ISSUER").unwrap_or("https://accounts.google.com".to_string());
    let redirect = Some(host("/login/oauth2/code/oidc"));
    let issuer = reqwest::Url::parse(&issuer_url)?;
    eprintln!("redirect: {:?}", redirect);
    eprintln!("issuer: {}", issuer);
    let client = DiscoveredClient::discover(client_id, client_secret, redirect, issuer).await?;

    eprintln!("discovered config: {:?}", client.config());

    let client = web::Data::new(client);

    let sessions = web::Data::new(RwLock::new(Sessions {
        map: HashMap::new(),
    }));

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth-openid")
                    .secure(false),
            ))
            .app_data(client.clone())
            .app_data(sessions.clone())
            .service(index)
            .service(authorize)
            .service(login)
            .service(web::scope("/api").service(account).service(logout))
    })
    .bind("localhost:8080")?
    .run()
    .await?;

    Ok(())
}
