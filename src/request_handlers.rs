use crate::entity::{LoginQuery, Logout, Sessions, User};
use actix_identity::Identity;
use actix_web::{get, http, post, web, HttpResponse, Responder};
use exitfailure::ExitFailure;
use openid::{DiscoveredClient, Options, Token, Userinfo};
use std::{env, sync::RwLock};

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html")
        .body(include_str!("index.html"))
}

#[get("/oauth2/authorization/oidc")]
async fn authorize(oidc_client: web::Data<DiscoveredClient>) -> impl Responder {
    let origin_url = env::var("ORIGIN").unwrap_or(host(""));
    let auth_url = oidc_client.auth_url(&Options {
        scope: Some("openid email profile".into()),
        state: Some(origin_url),
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

async fn request_token(
    oidc_client: web::Data<DiscoveredClient>,
    query: &web::Query<LoginQuery>,
) -> Result<Option<(Token, Userinfo)>, ExitFailure> {
    let mut token: Token = oidc_client.request_token(&query.code).await?.into();
    if let Some(mut id_token) = token.id_token.as_mut() {
        oidc_client.decode_token(&mut id_token)?;
        oidc_client.validate_token(&id_token, None, None)?;
        eprintln!("token: {:?}", id_token);
    } else {
        return Ok(None);
    }
    let userinfo = oidc_client.request_userinfo(&token).await?;

    eprintln!("user info: {:?}", userinfo);
    Ok(Some((token, userinfo)))
}

pub async fn check_request_token(
    state: &Option<String>,
    sessions: web::Data<RwLock<Sessions>>,
    identity: Identity,
    request_token: Result<Option<(Token, Userinfo)>, ExitFailure>,
) -> impl Responder {
    match request_token {
        Ok(Some((token, userinfo))) => {
            let id = uuid::Uuid::new_v4().to_string();

            let login_ = userinfo.preferred_username.clone();
            let email = userinfo.email.clone();

            let user = User {
                id: userinfo.sub.clone().unwrap_or_default(),
                login: login_,
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

            let redirect_url = state.clone().unwrap_or_else(|| host("/"));
            HttpResponse::Found()
                .header(http::header::LOCATION, redirect_url)
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

#[get("/login/oauth2/code/oidc")]
async fn login(
    oidc_client: web::Data<DiscoveredClient>,
    query: web::Query<LoginQuery>,
    sessions: web::Data<RwLock<Sessions>>,
    identity: Identity,
) -> impl Responder {
    eprintln!("login: {:?}", query);
    let request_token = request_token(oidc_client, &query).await;
    check_request_token(&query.state, sessions, identity, request_token).await
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
pub fn host(path: &str) -> String {
    env::var("REDIRECT_URL").unwrap_or("http://localhost:8080".to_string()) + path
}
