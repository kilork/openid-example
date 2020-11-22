use actix_identity::{CookieIdentityPolicy, Identity, IdentityService};
use actix_web::{get, middleware, web, App, HttpServer, Responder};
use exitfailure::ExitFailure;
use openid::{provider::microsoft, DiscoveredClient, Token, Userinfo};
use std::{env, sync::RwLock};

use openid_example::{
    account, authorize, check_request_token, host, index, logout, LoginQuery, Sessions,
};

async fn microsoft_request_token(
    oidc_client: web::Data<DiscoveredClient>,
    query: &web::Query<LoginQuery>,
) -> Result<Option<(Token, Userinfo)>, ExitFailure> {
    let token: Token = microsoft::authenticate(&oidc_client, &query.code, None, None).await?;
    let userinfo = oidc_client.request_userinfo(&token).await?;
    eprintln!("user info: {:?}", userinfo);
    Ok(Some((token, userinfo)))
}

#[get("/login/oauth2/code/oidc")]
async fn microsoft_login(
    oidc_client: web::Data<DiscoveredClient>,
    query: web::Query<LoginQuery>,
    sessions: web::Data<RwLock<Sessions>>,
    identity: Identity,
) -> impl Responder {
    eprintln!("login: {:?}", query);
    let request_token = microsoft_request_token(oidc_client, &query).await;
    check_request_token(&query.state, sessions, identity, request_token).await
}

#[actix_rt::main]
async fn main() -> Result<(), ExitFailure> {
    let client_id = env::var("CLIENT_ID").unwrap_or("<client id>".to_string());
    let client_secret = env::var("CLIENT_SECRET").unwrap_or("<client secret>".to_string());
    let issuer_url = env::var("ISSUER")
        .unwrap_or("https://login.microsoftonline.com/organizations/v2.0/".to_string());
    let redirect = Some(host("/login/oauth2/code/oidc"));
    let issuer = reqwest::Url::parse(&issuer_url)?;
    eprintln!("redirect: {:?}", redirect);
    eprintln!("issuer: {}", issuer);
    let client = DiscoveredClient::discover(client_id, client_secret, redirect, issuer).await?;

    eprintln!("discovered config: {:?}", client.config());

    let client = web::Data::new(client);

    let sessions = web::Data::new(RwLock::new(Sessions::default()));

    let origin_url = env::var("ORIGIN").unwrap_or(host(""));
    eprintln!("allowed origin: {}", origin_url);

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .wrap(
                middleware::DefaultHeaders::new()
                    .header("Access-Control-Allow-Origin", &origin_url)
                    .header("Access-Control-Allow-Credentials", "true"),
            )
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&[0; 32])
                    .name("auth-openid")
                    .secure(false),
            ))
            .app_data(client.clone())
            .app_data(sessions.clone())
            .service(index)
            .service(authorize)
            .service(microsoft_login)
            .service(web::scope("/api").service(account).service(logout))
    })
    .bind("localhost:8080")?
    .run()
    .await?;

    Ok(())
}
