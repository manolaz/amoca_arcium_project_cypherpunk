use anchor_lang::prelude::*;

#[event]
pub struct PatientRegisteredEvent {
    pub patient: Pubkey,
    pub authority: Pubkey,
    pub name: String,
}

#[event]
pub struct DoctorRegisteredEvent {
    pub doctor: Pubkey,
    pub authority: Pubkey,
    pub name: String,
    pub specialization: String,
}

#[event]
pub struct DoctorVerifiedEvent {
    pub doctor: Pubkey,
}

#[event]
pub struct AppointmentCreatedEvent {
    pub appointment: Pubkey,
    pub patient: Pubkey,
    pub doctor: Pubkey,
    pub appointment_time: i64,
}

#[event]
pub struct AppointmentCompletedEvent {
    pub appointment: Pubkey,
}

#[event]
pub struct AppointmentCancelledEvent {
    pub appointment: Pubkey,
}

#[event]
pub struct MedicalRecordStoredEvent {
    pub medical_record: Pubkey,
    pub patient: Pubkey,
    pub doctor: Pubkey,
}

#[event]
pub struct MedicalRecordRetrievedEvent {
    pub medical_record: Pubkey,
    pub decrypted_data: [u8; 32],
}


