/*- Imports -*/
use std::{ net::TcpStream, collections::HashMap };
use responder::Stream;

/*- Main -*/
pub fn origin_control(stream:&Stream) -> Result<(), u16> {
    
    /*- Request has to have a host -*/
    match stream.headers.get("Host") {
        Some(host) => {
            if host != &"" { Ok(()) }
            else {
                Err(401)
            }
        },
        None => {
            Err(401)
        },
    }
}
