use actix_identity::{CookieIdentityPolicy, IdentityService};
use actix_web::{middleware, web, App, HttpServer};
use exitfailure::ExitFailure;
use openid::DiscoveredClient;
use std::{env, sync::RwLock};

use openid_example::{account, authorize, host, index, login, logout, Sessions};

#[actix_web::main]
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
            .service(login)
            .service(web::scope("/api").service(account).service(logout))
    })
    .bind("localhost:8080")?
    .run()
    .await?;

    Ok(())
}
