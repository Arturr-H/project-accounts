/*- Imports -*/
use crate::utils;
use responder::{response::{ Respond, ResponseType }, Stream};
use serde_json;
use crate::user::User;
use std::{
    net::TcpStream, hash::Hash, collections::HashMap,
};
use mongodb::{
    bson::doc,
    sync::Collection,
};

/*- Functions -*/
pub(crate) fn get_all_accounts(
    stream : &mut Stream,
) -> () {
    /*- Establish the mongodb connection -*/
    let collection:Collection<User> = utils::establish_mclient::<User>("users");

    /*- Get users -*/
    let users:Vec<User> = collection.find(None, None).unwrap().map(|user| user.unwrap()).collect();
    
    /*- Respond with the userdata -*/
    stream.respond(
        200u16,
        Respond::new()
            .json(
                &serde_json::to_string(
                    &users
                ).unwrap_or(String::new())
            )
    );
}
pub(crate) fn delete_account(
    stream : &mut Stream,
) -> () {
    /*- Establish the mongodb connection -*/
    let collection:Collection<User> = utils::establish_mclient::<User>("users");
    let suid:&str = match stream.params.get("suid") {
        Some(e) => e,
        None => return stream.respond_status(404)
    };

    if suid == "all" {
        /*- Delete users -*/
        stream.respond_status(200);
        collection.delete_many(doc! {}, None).ok();
        return;
    };

    /*- Delete users -*/
    match collection.delete_one(doc!{
        "suid": suid
    }, None) {
        Ok(e) => stream.respond(200, Respond::new().text(&format!("Deleted {}", e.deleted_count))),
        Err(_) => stream.respond_status(404)
    }
}

