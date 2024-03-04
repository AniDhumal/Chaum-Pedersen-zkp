pub mod auth {
    include!("./auth.rs");
}
use auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};
use chaum_pedersen_zkp::{
    constants::{self, Q},
    ZKP,
};

use num_bigint::BigUint;
use std::sync::Mutex;
use std::{collections::HashMap, str::FromStr};
use tonic::{transport::Server, Code, Request, Response, Status};

#[derive(Debug, Default)]
struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    pub auth_id_to_user: Mutex<HashMap<String, String>>,
}

#[derive(Debug, Default, Clone)]
pub struct UserInfo {
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    pub r1: BigUint,
    pub r2: BigUint,
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let request = request.into_inner();
        let user_name = request.user;
        let y1 = BigUint::from_bytes_be(&request.y1);
        let y2 = BigUint::from_bytes_be(&request.y2);

        let mut user_info = UserInfo::default();
        user_info.user_name = user_name.clone();
        user_info.y1 = y1;
        user_info.y2 = y2;

        let mut user_info_map = &mut self.user_info.lock().unwrap();
        user_info_map.insert(user_name, user_info.clone());

        println!("{:?}", user_info);

        Result::Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let request = request.into_inner();
        let user_name = request.user;
        let mut user_info_map = &mut self.user_info.lock().unwrap();
        let user_id = user_info_map.get_mut(&user_name);
        match user_id {
            Some(user_info) => {
                user_info.r1 = BigUint::from_bytes_be(&request.r1);
                user_info.r2 = BigUint::from_bytes_be(&request.r2);
                let q = BigUint::from_bytes_be(&hex::decode(constants::Q).unwrap());
                println!("{:?}", q);
                let c = ZKP::generate_random(&q);
                let auth_id = ZKP::generate_random_string(12_usize);
                user_info.c = c.clone();
                let id_to_user = &mut self.auth_id_to_user.lock().unwrap();
                id_to_user.insert(auth_id.clone(), user_name.clone());
                return Ok(Response::new(AuthenticationChallengeResponse {
                    auth_id: auth_id,
                    c: c.to_bytes_be(),
                }));
            }
            None => {
                return Err(Status::new(
                    Code::NotFound,
                    format!("User {} not found", user_name),
                ))
            }
        };
    }

    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let p = BigUint::from_bytes_be(&hex::decode(constants::P).unwrap());
        let q = BigUint::from_bytes_be(&hex::decode(constants::Q).unwrap());
        let alpha = BigUint::from_bytes_be(&hex::decode(constants::ALPHA).unwrap());
        let beta = alpha.modpow(&ZKP::generate_random(&q), &p);
        let zkp = ZKP {
            p: p.clone(),
            q: q.clone(),
            alpha: alpha.clone(),
            beta: beta.clone(),
        };
        let request = request.into_inner();
        let auth_id = request.auth_id;
        let mut id_to_user = self.auth_id_to_user.lock().unwrap();
        let user_name = id_to_user.get_mut(&auth_id);
        match user_name {
            Some(user) => {
                let mut user_info_map = self.user_info.lock().unwrap();
                let user_info = user_info_map.get_mut(user).expect("AuthId invalid");
                let c = user_info.c.clone();
                let s = BigUint::from_bytes_be(&hex::decode(&request.s).unwrap());
                let verify_result = zkp.verify(
                    &user_info.r1,
                    &user_info.r2,
                    &user_info.y1,
                    &user_info.y2,
                    &c,
                    &s,
                );
                let _ = match verify_result {
                    true => {
                        let session_id = ZKP::generate_random_string(12_usize);
                        return Ok(Response::new(AuthenticationAnswerResponse { session_id }));
                    }
                    _ => {
                        return Err(Status::new(
                            Code::PermissionDenied,
                            format!("Solution {} incorrect for auth id {}", s, auth_id),
                        ))
                    }
                };
            }
            None => {
                return Err(Status::new(
                    Code::NotFound,
                    format!("AuthId {} not found", auth_id),
                ));
            }
        }
    }
}

#[tokio::main] //for async functionality
async fn main() {
    let addr = "127.0.0.1:50051".to_string();
    println!("✅ Running the server on {}", addr);

    let auth_impl = AuthImpl::default();

    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("address error"))
        .await
        .unwrap();
}
