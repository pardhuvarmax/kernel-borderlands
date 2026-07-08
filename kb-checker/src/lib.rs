pub mod grpc_health_v1 {
    tonic::include_proto!("grpc.health.v1");
}

pub mod kb {
    tonic::include_proto!("kb");
}

pub mod checker {
    tonic::include_proto!("checker");
}

pub mod integrity;
pub mod service_check;
pub mod report;
pub mod grpc;
