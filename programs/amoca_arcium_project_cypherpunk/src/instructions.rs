use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

use crate::errors::ErrorCode;
use crate::state::*;

// arcium helpers referenced from lib.rs macro context
use crate::AddTogetherCallback;
use crate::AddTogetherOutput;

#[inline(never)]
pub fn register_patient(ctx: Context<crate::RegisterPatient>, name: String, date_of_birth: i64, contact_info: String) -> Result<()> {
    let patient = &mut ctx.accounts.patient;
    patient.authority = ctx.accounts.authority.key();
    patient.name = name;
    patient.date_of_birth = date_of_birth;
    patient.contact_info = contact_info;
    patient.created_at = Clock::get()?.unix_timestamp;
    patient.bump = ctx.bumps.patient;

    emit!(crate::events::PatientRegisteredEvent {
        patient: patient.key(),
        authority: patient.authority,
        name: patient.name.clone(),
    });

    Ok(())
}

#[inline(never)]
pub fn update_patient(ctx: Context<crate::UpdatePatient>, name: Option<String>, contact_info: Option<String>) -> Result<()> {
    let patient = &mut ctx.accounts.patient;
    if let Some(new_name) = name { patient.name = new_name; }
    if let Some(new_contact) = contact_info { patient.contact_info = new_contact; }
    Ok(())
}

#[inline(never)]
pub fn register_doctor(ctx: Context<crate::RegisterDoctor>, name: String, specialization: String, license_number: String, consultation_fee: u64) -> Result<()> {
    let doctor = &mut ctx.accounts.doctor;
    doctor.authority = ctx.accounts.authority.key();
    doctor.name = name;
    doctor.specialization = specialization;
    doctor.license_number = license_number;
    doctor.consultation_fee = consultation_fee;
    doctor.is_verified = false;
    doctor.total_consultations = 0;
    doctor.created_at = Clock::get()?.unix_timestamp;
    doctor.bump = ctx.bumps.doctor;

    emit!(crate::events::DoctorRegisteredEvent {
        doctor: doctor.key(),
        authority: doctor.authority,
        name: doctor.name.clone(),
        specialization: doctor.specialization.clone(),
    });
    Ok(())
}

#[inline(never)]
pub fn verify_doctor(ctx: Context<crate::VerifyDoctor>) -> Result<()> {
    let doctor = &mut ctx.accounts.doctor;
    doctor.is_verified = true;
    emit!(crate::events::DoctorVerifiedEvent { doctor: doctor.key() });
    Ok(())
}

#[inline(never)]
pub fn update_doctor(ctx: Context<crate::UpdateDoctor>, specialization: Option<String>, consultation_fee: Option<u64>) -> Result<()> {
    let doctor = &mut ctx.accounts.doctor;
    if let Some(new_spec) = specialization { doctor.specialization = new_spec; }
    if let Some(new_fee) = consultation_fee { doctor.consultation_fee = new_fee; }
    Ok(())
}

#[inline(never)]
pub fn create_appointment(ctx: Context<crate::CreateAppointment>, appointment_time: i64, notes: String) -> Result<()> {
    require!(ctx.accounts.doctor.is_verified, ErrorCode::DoctorNotVerified);
    let appointment = &mut ctx.accounts.appointment;
    appointment.patient = ctx.accounts.patient.key();
    appointment.doctor = ctx.accounts.doctor.key();
    appointment.appointment_time = appointment_time;
    appointment.notes = notes;
    appointment.status = AppointmentStatus::Scheduled;
    appointment.created_at = Clock::get()?.unix_timestamp;
    appointment.bump = ctx.bumps.appointment;
    emit!(crate::events::AppointmentCreatedEvent {
        appointment: appointment.key(),
        patient: appointment.patient,
        doctor: appointment.doctor,
        appointment_time,
    });
    Ok(())
}

#[inline(never)]
pub fn complete_appointment(ctx: Context<crate::UpdateAppointment>) -> Result<()> {
    let appointment = &mut ctx.accounts.appointment;
    require_keys_eq!(ctx.accounts.authority.key(), ctx.accounts.doctor.authority, ErrorCode::UnauthorizedAccess);
    require!(appointment.status == AppointmentStatus::Scheduled, ErrorCode::InvalidAppointmentStatus);
    appointment.status = AppointmentStatus::Completed;
    let doctor = &mut ctx.accounts.doctor;
    doctor.total_consultations = doctor.total_consultations.checked_add(1).ok_or(ErrorCode::ArithmeticOverflow)?;
    emit!(crate::events::AppointmentCompletedEvent { appointment: appointment.key() });
    Ok(())
}

#[inline(never)]
pub fn cancel_appointment(ctx: Context<crate::UpdateAppointment>) -> Result<()> {
    let appointment = &mut ctx.accounts.appointment;
    require_keys_eq!(ctx.accounts.authority.key(), ctx.accounts.doctor.authority, ErrorCode::UnauthorizedAccess);
    require!(appointment.status == AppointmentStatus::Scheduled, ErrorCode::InvalidAppointmentStatus);
    appointment.status = AppointmentStatus::Cancelled;
    emit!(crate::events::AppointmentCancelledEvent { appointment: appointment.key() });
    Ok(())
}

#[inline(never)]
pub fn create_medical_record(ctx: Context<crate::CreateMedicalRecord>, record_id: u64, record_type: String, timestamp: i64) -> Result<()> {
    require_keys_eq!(ctx.accounts.authority.key(), ctx.accounts.doctor.authority, ErrorCode::UnauthorizedAccess);
    require!(ctx.accounts.doctor.is_verified, ErrorCode::DoctorNotVerified);
    let medical_record = &mut ctx.accounts.medical_record;
    medical_record.patient = ctx.accounts.patient.key();
    medical_record.doctor = ctx.accounts.doctor.key();
    medical_record.record_id = record_id;
    medical_record.record_type = record_type;
    medical_record.timestamp = timestamp;
    medical_record.encrypted_data = [0u8; 32];
    medical_record.encrypted_nonce = [0u8; 16];
    medical_record.bump = ctx.bumps.medical_record;
    Ok(())
}

#[inline(never)]
fn build_args_store(data: &[u8], pub_key: [u8; 32], nonce: u128) -> Vec<Argument> {
    let mut ciphertext = [0u8; 32];
    let len = core::cmp::min(data.len(), 32);
    ciphertext[..len].copy_from_slice(&data[..len]);
    vec![
        Argument::ArcisPubkey(pub_key),
        Argument::PlaintextU128(nonce),
        Argument::EncryptedU8(ciphertext),
    ]
}

#[inline(never)]
fn build_args_retrieve(record: &MedicalRecord, pub_key: [u8; 32]) -> Vec<Argument> {
    let nonce_u128 = u128::from_le_bytes(record.encrypted_nonce);
    vec![
        Argument::ArcisPubkey(pub_key),
        Argument::PlaintextU128(nonce_u128),
        Argument::EncryptedU8(record.encrypted_data),
    ]
}

#[inline(never)]
pub fn store_encrypted_medical_data(
    ctx: Context<crate::StoreEncryptedMedicalData>,
    computation_offset: u64,
    data: Vec<u8>,
    pub_key: [u8; 32],
    nonce: u128,
) -> Result<()> {
    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    let payer_key = ctx.accounts.payer.key();
    require!(
        payer_key == ctx.accounts.patient.authority || payer_key == ctx.accounts.doctor.authority,
        ErrorCode::UnauthorizedAccess
    );
    let args = build_args_store(&data, pub_key, nonce);
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        None,
        vec![AddTogetherCallback::callback_ix(&[])],
    )?;
    Ok(())
}

#[inline(never)]
pub fn add_together_callback(
    ctx: Context<crate::AddTogetherCallback>,
    output: ComputationOutputs<AddTogetherOutput>,
) -> Result<()> {
    let o = match output {
        ComputationOutputs::Success(AddTogetherOutput { field_0 }) => field_0,
        _ => return Err(ErrorCode::AbortedComputation.into()),
    };
    let medical_record = &mut ctx.accounts.medical_record;
    let is_storing = medical_record.encrypted_data == [0u8; 32];
    if is_storing {
        medical_record.encrypted_data = o.ciphertexts[0];
        medical_record.encrypted_nonce = o.nonce.to_le_bytes();
        emit!(crate::events::MedicalRecordStoredEvent {
            medical_record: medical_record.key(),
            patient: medical_record.patient,
            doctor: medical_record.doctor,
        });
    } else {
        emit!(crate::events::MedicalRecordRetrievedEvent {
            medical_record: medical_record.key(),
            decrypted_data: o.ciphertexts[0],
        });
    }
    Ok(())
}

#[inline(never)]
pub fn retrieve_medical_data(
    ctx: Context<crate::RetrieveMedicalData>,
    computation_offset: u64,
    pub_key: [u8; 32],
) -> Result<()> {
    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    let payer_key = ctx.accounts.payer.key();
    require!(
        payer_key == ctx.accounts.patient.authority || payer_key == ctx.accounts.doctor.authority,
        ErrorCode::UnauthorizedAccess
    );
    let args = build_args_retrieve(&ctx.accounts.medical_record, pub_key);
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        None,
        vec![AddTogetherCallback::callback_ix(&[])],
    )?;
    Ok(())
}


