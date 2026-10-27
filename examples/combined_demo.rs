mod registration_demo;
mod authentication_demo;

use std::time::Instant;
fn main() {
    let total_time = Instant::now();
    println!("=================================");
    println!("REGISTRATION");
    println!("=================================");
    let start = Instant::now();
    registration_demo::run_registration_demo();
    println!("[Time ] for registration is: {:?}",start.elapsed());

    println!();
    let start = Instant::now();
    println!("=================================");
    println!("AUTHENTICATION");
    println!("=================================");


    authentication_demo::run_authentication_demo();
    println!("[Time ] for authentication is: {:?}",start.elapsed());
    println!("[Time] for both process : {:?}",total_time.elapsed());
}