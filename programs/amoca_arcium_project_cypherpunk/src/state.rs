use anchor_lang::prelude::*;

#[account]
pub struct Patient {
    pub authority: Pubkey,
    pub name: String,
    pub date_of_birth: i64,
    pub contact_info: String,
    pub created_at: i64,
    pub bump: u8,
}

#[account]
pub struct Doctor {
    pub authority: Pubkey,
    pub name: String,
    pub specialization: String,
    pub license_number: String,
    pub consultation_fee: u64,
    pub is_verified: bool,
    pub total_consultations: u64,
    pub created_at: i64,
    pub bump: u8,
}

#[account]
pub struct Appointment {
    pub patient: Pubkey,
    pub doctor: Pubkey,
    pub appointment_time: i64,
    pub notes: String,
    pub status: AppointmentStatus,
    pub created_at: i64,
    pub bump: u8,
}

#[account]
pub struct MedicalRecord {
    pub patient: Pubkey,
    pub doctor: Pubkey,
    pub record_id: u64,
    pub record_type: String,
    pub timestamp: i64,
    pub encrypted_data: [u8; 32],
    pub encrypted_nonce: [u8; 16],
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum AppointmentStatus {
    Scheduled,
    Completed,
    Cancelled,
}


