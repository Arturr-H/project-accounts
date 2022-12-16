/*- Global allowances -*/
#![allow(
    dead_code,
    unused_variables,
    unused_imports
)]

/*- Imports -*/
use crate::{
    api::{
        MONGO_CLIENT_URI_STRING,
        REQUIRED_HEADERS
    },
    user::User
};
use responder;
use sha3::{ Digest, Sha3_256 };
use mongodb::{
    bson::{
        doc,
        Document
    },
    sync::{
        Client,
        Collection,
        Database
    },
};
use std::{time::{
    SystemTime,
    UNIX_EPOCH
}, collections::HashMap, hash::Hash};

/*- Quick way of establishing a connection with the mongo client -*/
pub(super) fn establish_mclient<Type__>(collection_name:&str) -> Collection<Type__> {
    /*- Establish the mongodb connection -*/
    let client:Client = Client::with_uri_str(
        MONGO_CLIENT_URI_STRING
    ).expect("Failed to initialize standalone client.");

    /*- Get the database -*/
    let db:Database = client.database("test");

    /*- Get the collection -*/
    let collection:Collection<Type__> = db.collection::<Type__>(collection_name);

    /*- Return the collection -*/
    collection
}

/*- Most endpoints will require headers, and
    the required headers will be stored in an
    array that might be difficult to search in.
    This function makes that process easier -*/
pub(super) fn get_required_headers(name:&'static str) -> &[&str] {
    /*- Iterate over all and try find a matching function -*/
    for (key, value) in REQUIRED_HEADERS {
        if key == &name { return value };
    };

    /*- If no match was found, return an empty array -*/
    return &[];
}


/*- Hash a string using the SHA-3 algorithm -*/
pub(super) fn hash(value:&str) -> String {
    /*- Hash the string -*/
    let mut hasher = Sha3_256::new();

    /*- Hash the string -*/
    hasher.update(value);

    /*- Return the hash -*/
    return format!("{:x}", hasher.finalize());
}

/*- Get unix epoch time -*/
pub(super) fn get_unix_epoch_time() -> u64 {
    /*- Get the current time -*/
    let current_time = SystemTime::now();

    /*- Convert to unix epoch time -*/
    return current_time.duration_since(UNIX_EPOCH).unwrap().as_secs();
}
use std::convert::TryInto;

/*- This function takes an array of requested headers as input and searches for
    them in headers. Will return an option of that array if all values existed -*/
pub fn get_headers_checked<'e, T: Eq + Hash + Copy, const N:usize>(headers:&'e HashMap<T, T>, keys:&'e [T; N]) -> Option<Vec<T>> {
    let mut value_vec:Vec<T> = Vec::with_capacity(N);

    /*- Search -*/
    for key in keys {
        match headers.get(key) {
            Some(e) => value_vec.push(*e),
            None => return None
        };
    };

    /*- Return -*/
    Some(value_vec)
}



