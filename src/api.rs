/*- Global allowances -*/
#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    unused_assignments
)]

/*- Imports -*/
use crate::{
    utils,
    utils::get_required_headers,
    safe_user::SafeUser,
};
use crate::dict::DICTIONARY;
use responder::response::{ Respond, ResponseType };
use serde::{ Serialize, Deserialize };
use chunked_transfer::{ Encoder, Decoder };
use serde_json;
use image;
use base64;
use jsonwebtoken::{
    encode, decode, Header,
    Algorithm, Validation,
    EncodingKey, DecodingKey
};
use responder::prelude::*;
use regex::Regex;
use crate::user::{
    User, UserClaims, AuthorizationStatus,
    get_expiration_time, generate_uuid,
    generate_suid, authenticate, check_email,
};
use std::{
    io::{
        Read,
        Write
    },
    ops, net::TcpStream,
    collections::HashMap, hash::Hash,
    borrow::Borrow, default, path::Path,
};
use mongodb::{
    bson::{ doc, Document },
    sync::{
        Client,
        Collection,
        Database, Cursor
    },
};

/*- Statics & Constants -*/
pub(crate) const MONGO_DATABASE_NAME:      &'static str = "users";
pub(crate) const MONGO_CLIENT_URI_STRING:  &'static str = "mongodb://localhost:27017"; //mongodb://mongo:27017 if in production

/*- All the functions' required headers.
    Accessing these is done via a function
    that lies somewhere in utils.rs -*/
pub(crate) const REQUIRED_HEADERS: &'static [(&'static str, &[&'static str])] = &[
    ("create_account",  &["username", "displayname", "password", "email"]),
    ("login",           &["email", "password"]),
    ("check_jws_token", &["token"]),
];

/*- Functions -*/
pub(super) fn create_account(stream: &mut Stream) -> () {
    /*- Require some headers to be specified -*/
    if stream.expect_headers_ignore_caps(get_required_headers("create_account")) {
        return stream.respond(400, do_json(400, "Invalid headers"));
    };

    /*- Get the headers -*/
    let user:User = match utils::get_headers_checked(
        &stream.headers,
        &["username", "displayname", "password", "email"]
    ) {
        Some(values) => {
            /*- Initialize the user -*/
            User {
                username: values[0].to_string(),
                displayname: values[1].to_string(),
                password: utils::hash(values[2]),
                email: values[3].to_string(),
                uid         : generate_uuid(),
                suid        : generate_suid(),
            }
        },
        None => return stream.respond(405, do_json(405, "Error parsing userdata"))
    };
    dbg!(2);

    /*- If the email is invalid -*/
    if !check_email(&user.email) {
        return stream.respond(
            400u16,
            do_json(400, DICTIONARY.error.invalid.email)
        );
    };

    /*- Establish the mongodb connection -*/
    let collection:Collection<User> = utils::establish_mclient::<User>("users");

    /*- Check if username already exists -*/
    let username_exists = collection.find(doc!{"username": user.username.clone()}, None).unwrap().next().is_some();
    if username_exists {
        return stream.respond(
            409u16,
            do_json(409, DICTIONARY.error.in_use.username)
        );
    };
    
    /*- Check if email already exists -*/
    let email_exists = collection.find(doc!{"email": user.email.clone()}, None).unwrap().next().is_some();
    if email_exists {
        return stream.respond(
            409u16,
            do_json(409, DICTIONARY.error.in_use.email)
        );
    };
    
    /*- Insert the document -*/
    collection.insert_one(&user, None).ok();

    /*- Respond success -*/
    stream.respond(
        200u16,
        do_json(200, "Success!")
    );
}
/*- Make quick json response -*/
fn do_json(status: u16, message: &str) -> Respond {
    let response = Respond::new().json(
        &format!(
            "{{\"status\": {}, \"message\": \"{}\"}}",
            status, message
        )
    );

    response
}

/*- Login accounts -*/
pub(super) fn login(stream: &mut Stream) -> () {
    /*- Require some headers to be specified -*/
    if stream.expect_headers_ignore_caps(get_required_headers("login")) {
        return stream.respond(400, do_json(400, "Invalid headers"));
    };

    /*- Initialize the user -*/
    let password:String;
    let email:String;

    /*- Get the values -*/
    (password, email) = match (
        stream.headers.get("password"),
        stream.headers.get("email")
    ) {
        /*- If parsing headers was unsuccessful -*/
        (Some(pass), Some(email)) => (pass.to_string(), email.to_string()),
        (_, _) => return stream.respond(400, do_json(400, "Invalid headers")),
    };

    /*- Establish the mongodb connection -*/
    let collection:Collection<User> = utils::establish_mclient::<User>("users");

    /*- Check if email exists -*/
    let email_exists = match collection.find(doc!{"email": email.to_string()}, None) {
        Ok(cursor) => cursor,
        Err(_) => return stream.respond(500, do_json(500, "Internal server error"))
    }.next().is_some();
    if !email_exists {
        return stream.respond(
            404u16,
            do_json(404, DICTIONARY.error.invalid.email)
        );
    };

    /*- Get the user -*/
    let user = match match match collection.find(doc!{"email": email.to_string()}, None) {
        Ok(cursor) => cursor,
        Err(_) => return stream.respond(500, do_json(500, "Internal server error"))
    }.next() {
        Some(user) => user,
        None => return stream.respond(500, do_json(500, "Internal server error"))
    } {
        Ok(user) => user,
        Err(_) => return stream.respond(500, do_json(500, "Internal server error"))
    };

    /*- Check if password is correct -*/
    if &user.password != &utils::hash(&password) {
        return stream.respond(
            401u16,
            do_json(401, DICTIONARY.error.login)
        );
    };

    /*- Create the token -*/
    let token = match User::generate_JWT(user.clone()) {
        Ok(token) => token,
        Err(_)  => {
            return stream.respond(
                500u16,
                do_json(500, DICTIONARY.error.login)
            );
        },
    };

    /*- Respond with a account data -*/
    stream.respond(
        200u16,

        /*- Format some JSON -*/
        Respond::new()
            .json(&format!(
                "{{\"status\": {},\"token\":\"{}\",\"suid\":\"{}\"}}",
                200, &token, &user.suid
            ))
    );
}

/*- Valdidate JWS token -*/
pub(crate) fn check_jws_token(stream: &mut Stream) -> () {
    /*- Require some headers to be specified -*/
    if stream.expect_headers_ignore_caps(get_required_headers("check_jws_token")) { return; };
    let token:&str = match stream.headers.get("token") {
        Some(e) => e,
        None => return stream.respond_status(401)
    };

    /*- Decode token -*/
    let user_claims:UserClaims = match User::decode__JWT__token(token) {
        Ok(claims) => claims,
        Err(_) => return stream.respond_status(401)
    };

    /*- Respond -*/
    match User::decode__JWT__token(token) {
        Ok(e) => {
            stream.respond(200, Respond::new().json(
                &format!("{{\"suid\":\"{}\"}}", e.suid)
            ))
        },
        Err(_) => {
            stream.respond_status(401)
        }
    };
}

/*- Get other user's profile -*/
pub(crate) fn profile_data_suid(stream: &mut Stream) -> () {
    /*- No headers required, the requested users'
        suid is specified in the URL-params -*/
    let request_suid:&str = match &stream.params.get("suid") {
        Some(e) => e,
        None => return stream.respond_status(410)
    };

    /*- Establish the mongodb connection -*/
    let collection:Collection<User> = utils::establish_mclient::<User>("users");

    /*- Check if the user exists -*/
    let user_exists = collection.find_one(
        doc!{
            "suid": request_suid.to_string()
        }, None
    );

    /*- Get the userdata or respond 404 if not available,
        and convert the user to a SafeUser for safety -*/
    let user_data:SafeUser = User::to_safe(match user_exists {
        Ok(async_cursor) => {
            match async_cursor {
                Some(user_data) => user_data,
                None => return stream.respond_status(404)
            }
        },
        Err(_) => return stream.respond_status(404)
    });

    /*- Respond with the userdata -*/
    stream.respond(
        200u16,
        Respond::new()
            .json(
                &serde_json::to_string(
                    &user_data
                ).unwrap_or(String::new())
            )
    );
}
pub(crate) fn profile_data_name(stream: &mut Stream) -> () {
    /*- No headers required, the requested users'
        username is specified in the URL-params -*/
    let request_username:&str = match &stream.params.get("name") {
        Some(e) => e,
        None => return stream.respond_status(410)
    };

    /*- Establish the mongodb connection -*/
    let collection:Collection<User> = utils::establish_mclient::<User>("users");

    /*- Check if the user exists -*/
    let user_exists = collection.find(
        doc!{
            "username": request_username.to_string()
        }, None
    );

    /*- Get the userdata or respond 404 if not available,
        and convert the user to a SafeUser for safety  -*/
    let user_data:SafeUser = User::to_safe(match user_exists {
        Ok(mut async_cursor) => {
            match async_cursor.next() {
                Some(user_data) => match user_data {
                    Ok(user_data) => user_data,
                    Err(_) => return stream.respond_status(404)
                },
                None => return stream.respond_status(404)
            }
        },
        Err(_) => return stream.respond_status(404)
    });

    /*- Respond with the userdata -*/
    stream.respond(
        200u16,
        Respond::new()
            .json(
                &serde_json::to_string(
                    &user_data
                ).unwrap_or(String::new())
            )
    );
}

/*- Get a users profile image -*/
pub(crate) fn profile_image(stream: &mut Stream,) -> () {
    
    /*- Get the param named 'profile_image' -*/
    let profile_image:&str = match &stream.params.get("profile_image") {
        Some(e) => e,
        None => return stream.respond_status(410)
    };

    /*- Search for the image in the static/ dir -*/
    let image_path:String  = format!("uploads/{}.jpg", profile_image);
    let pfp_not_found:&str = &"static/images/default-user.jpg";

    /*- Buffers -*/
    let mut buf = Vec::new();
    let file = std::fs::File::open(image_path);

    /*- Error handling -*/
    let mut file = match file {
        Ok(file) => file,
        Err(_) => match std::fs::File::open(pfp_not_found) {
            Ok(file) => file,
            Err(_) => return stream.respond_status(404u16)
        }
    };
    
    file.read_to_end(&mut buf).unwrap_or_default();
    
    /*- Encode -*/
    let mut encoded = Vec::new();
    {
        let mut encoder = Encoder::with_chunks_size(&mut encoded, 64);
        encoder.write_all(&buf).unwrap_or_default();
    }

    /*- Create the response -*/
    let headers = [
        "HTTP/1.1 200 OK",
        "Content-type: image/png",
        "Transfer-Encoding: chunked",
        "\r\n"
    ];
    let mut response = headers.join("\r\n")
        .to_string()
        .into_bytes();
        response.extend(encoded);

    /*- Respond with the image -*/
    stream.get_mut_inner_ref().write(&response).unwrap_or_default();
}

/*- Upload profile picture -*/
pub(crate) fn upload_profile_image(stream: &mut Stream) -> () {
    /*- Get the token from the headers -*/
    let token:&str = &stream.headers
        .get("token")
        .unwrap_or(&&"")
        .to_string();

    /*- Get the user from the token -*/
    let u_claims:UserClaims = match User::decode__JWT__token(token) {
        Ok(e) => e,
        Err(_) => return stream.respond_status(401u16)
    };

    /*- Get the user suid (We'll name the image the users suid) -*/
    let suid:&str = &u_claims.suid;

    /*- Binary image in body -*/
    let image:&str = &&stream.body;
    println!("{image:?}");

    /*- Create the image path -*/
    let image_path:String = format!("uploads/{}.png", suid);

    /*- Create the file -*/
    let mut file = match std::fs::File::create(image_path) {
        Ok(file) => file,
        Err(_) => return stream.respond_status(500u16)
    };

    /*- Write the image to the file -*/
    file.write_all(image.as_bytes()).unwrap_or_default();

    /*- Respond with a success message -*/
    stream.respond_status(200u16);
}




