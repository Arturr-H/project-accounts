/*- Global allowances -*/
#![allow(
    dead_code,
    unused_variables,
    unused_imports
)]

/*- Imports -*/
mod api;
mod utils;
mod user;
mod safe_user;
mod origin_control;
#[path = "debugging/debug_routes.rs"] mod debug_routes;
#[path = "resources/dict.rs"] mod dict;
use responder::prelude::*;

/*- Startup -*/
fn main() -> () {
    /*- The api routes -*/
    let routes = &[
        Route::Get("login",           api::login),
        Route::Post("create-account", api::create_account),
        
        Route::Stack("profile", &[
            Route::Stack("data", &[
                Route::Get("by_name/:name:", api::profile_data_name),
                Route::Get("by_suid/:suid:", api::profile_data_suid),
            ]),
            Route::Get("image/:profile_image:", api::profile_image),
            Route::Get("verify-token",          api::check_jws_token),
            Route::Post("upload-image",         api::upload_profile_image)
        ]),

        Route::Stack("leaderboards", &[
            Route::Get("default", leaderboard)
        ]),

        Route::Stack("debug", &[
            Route::Get("accounts",      debug_routes::get_all_accounts),
            Route::Get("delete/:suid:", debug_routes::delete_account),
        ])
    ];

    /*- Start the server -*/
    Server::new()
        .address("127.0.0.1")
        .port(8081)
        .serve("./static")
        .threads(6)
        // .origin_control(origin_control::origin_control)
        .routes(routes)
        .start()
        .unwrap();
}
fn leaderboard(stream: &mut Stream) -> () {

}


