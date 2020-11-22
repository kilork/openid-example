use crate::entity::User;
use openid::{Token, Userinfo};
use std::collections::HashMap;

#[derive(Default)]
pub struct Sessions {
    pub(crate) map: HashMap<String, (User, Token, Userinfo)>,
}
