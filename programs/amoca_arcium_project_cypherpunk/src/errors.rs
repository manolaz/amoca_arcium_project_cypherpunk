use anchor_lang::prelude::*;

#[error_code]
pub enum ErrorCode {
    #[msg("The computation was aborted")]
    AbortedComputation,
    #[msg("Invalid appointment status")]
    InvalidAppointmentStatus,
    #[msg("Unauthorized access")]
    UnauthorizedAccess,
    #[msg("Doctor not verified")]
    DoctorNotVerified,
    #[msg("Arithmetic overflow occurred")]
    ArithmeticOverflow,
    #[msg("Cluster not set")]
    ClusterNotSet,
}


