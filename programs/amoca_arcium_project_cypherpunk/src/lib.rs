use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

const COMP_DEF_OFFSET_ENCRYPT_MEDICAL_RECORD: u32 = comp_def_offset("encrypt_medical_record");
const COMP_DEF_OFFSET_DECRYPT_MEDICAL_RECORD: u32 = comp_def_offset("decrypt_medical_record");

declare_id!("JBSqhd6sYtYnUdXTYKwLENdgHyWbACDKLRvSqigcpqUf");

#[arcium_program]
pub mod amoca_arcium_project_cypherpunk {
    use super::*;

    // ==================== Patient Instructions ====================

    pub fn register_patient(
        ctx: Context<RegisterPatient>,
        name: String,
        date_of_birth: i64,
        contact_info: String,
    ) -> Result<()> {
        let patient = &mut ctx.accounts.patient;
        patient.authority = ctx.accounts.authority.key();
        patient.name = name;
        patient.date_of_birth = date_of_birth;
        patient.contact_info = contact_info;
        patient.created_at = Clock::get()?.unix_timestamp;
        patient.bump = ctx.bumps.patient;
        
        emit!(PatientRegisteredEvent {
            patient: patient.key(),
            authority: patient.authority,
            name: patient.name.clone(),
        });
        
        Ok(())
    }

    pub fn update_patient(
        ctx: Context<UpdatePatient>,
        name: Option<String>,
        contact_info: Option<String>,
    ) -> Result<()> {
        let patient = &mut ctx.accounts.patient;
        
        if let Some(new_name) = name {
            patient.name = new_name;
        }
        
        if let Some(new_contact) = contact_info {
            patient.contact_info = new_contact;
        }
        
        Ok(())
    }

    // ==================== Doctor Instructions ====================

    pub fn register_doctor(
        ctx: Context<RegisterDoctor>,
        name: String,
        specialization: String,
        license_number: String,
        consultation_fee: u64,
    ) -> Result<()> {
        let doctor = &mut ctx.accounts.doctor;
        doctor.authority = ctx.accounts.authority.key();
        doctor.name = name;
        doctor.specialization = specialization;
        doctor.license_number = license_number;
        doctor.consultation_fee = consultation_fee;
        doctor.is_verified = false; // Requires admin verification
        doctor.total_consultations = 0;
        doctor.created_at = Clock::get()?.unix_timestamp;
        doctor.bump = ctx.bumps.doctor;
        
        emit!(DoctorRegisteredEvent {
            doctor: doctor.key(),
            authority: doctor.authority,
            name: doctor.name.clone(),
            specialization: doctor.specialization.clone(),
        });
        
        Ok(())
    }

    pub fn verify_doctor(ctx: Context<VerifyDoctor>) -> Result<()> {
        let doctor = &mut ctx.accounts.doctor;
        doctor.is_verified = true;
        
        emit!(DoctorVerifiedEvent {
            doctor: doctor.key(),
        });
        
        Ok(())
    }

    pub fn update_doctor(
        ctx: Context<UpdateDoctor>,
        specialization: Option<String>,
        consultation_fee: Option<u64>,
    ) -> Result<()> {
        let doctor = &mut ctx.accounts.doctor;
        
        if let Some(new_spec) = specialization {
            doctor.specialization = new_spec;
        }
        
        if let Some(new_fee) = consultation_fee {
            doctor.consultation_fee = new_fee;
        }
        
        Ok(())
    }

    // ==================== Appointment Instructions ====================

    pub fn create_appointment(
        ctx: Context<CreateAppointment>,
        appointment_time: i64,
        notes: String,
    ) -> Result<()> {
        // Ensure only verified doctors can accept appointments
        require!(ctx.accounts.doctor.is_verified, ErrorCode::DoctorNotVerified);
        let appointment = &mut ctx.accounts.appointment;
        appointment.patient = ctx.accounts.patient.key();
        appointment.doctor = ctx.accounts.doctor.key();
        appointment.appointment_time = appointment_time;
        appointment.notes = notes;
        appointment.status = AppointmentStatus::Scheduled;
        appointment.created_at = Clock::get()?.unix_timestamp;
        appointment.bump = ctx.bumps.appointment;
        
        emit!(AppointmentCreatedEvent {
            appointment: appointment.key(),
            patient: appointment.patient,
            doctor: appointment.doctor,
            appointment_time,
        });
        
        Ok(())
    }

    pub fn complete_appointment(ctx: Context<UpdateAppointment>) -> Result<()> {
        let appointment = &mut ctx.accounts.appointment;
        // Only the doctor who owns this appointment may complete it
        require_keys_eq!(
            ctx.accounts.authority.key(),
            ctx.accounts.doctor.authority,
            ErrorCode::UnauthorizedAccess
        );
        require!(
            appointment.status == AppointmentStatus::Scheduled,
            ErrorCode::InvalidAppointmentStatus
        );
        
        appointment.status = AppointmentStatus::Completed;
        
        let doctor = &mut ctx.accounts.doctor;
        doctor.total_consultations = doctor
            .total_consultations
            .checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        
        emit!(AppointmentCompletedEvent {
            appointment: appointment.key(),
        });
        
        Ok(())
    }

    pub fn cancel_appointment(ctx: Context<UpdateAppointment>) -> Result<()> {
        let appointment = &mut ctx.accounts.appointment;
        // Only the doctor who owns this appointment may cancel it (patient flow can be added)
        require_keys_eq!(
            ctx.accounts.authority.key(),
            ctx.accounts.doctor.authority,
            ErrorCode::UnauthorizedAccess
        );
        require!(
            appointment.status == AppointmentStatus::Scheduled,
            ErrorCode::InvalidAppointmentStatus
        );
        
        appointment.status = AppointmentStatus::Cancelled;
        
        emit!(AppointmentCancelledEvent {
            appointment: appointment.key(),
        });
        
        Ok(())
    }

    // ==================== Medical Record Instructions (Encrypted) ====================

    pub fn init_encrypt_medical_record_comp_def(
        ctx: Context<InitEncryptMedicalRecordCompDef>,
    ) -> Result<()> {
        init_comp_def(ctx.accounts, true, 0, None, None)?;
        Ok(())
    }

    pub fn init_decrypt_medical_record_comp_def(
        ctx: Context<InitDecryptMedicalRecordCompDef>,
    ) -> Result<()> {
        init_comp_def(ctx.accounts, true, 0, None, None)?;
        Ok(())
    }

    pub fn create_medical_record(
        ctx: Context<CreateMedicalRecord>,
        record_id: u64,
        record_type: String,
        timestamp: i64,
    ) -> Result<()> {
        // Ensure only verified doctors can create medical records
        require!(ctx.accounts.doctor.is_verified, ErrorCode::DoctorNotVerified);
        let medical_record = &mut ctx.accounts.medical_record;
        medical_record.patient = ctx.accounts.patient.key();
        medical_record.doctor = ctx.accounts.doctor.key();
        medical_record.record_id = record_id;
        medical_record.record_type = record_type;
        medical_record.timestamp = timestamp;
        medical_record.encrypted_data = [0u8; 32]; // Will be set by callback
        medical_record.encrypted_nonce = [0u8; 16];
        medical_record.bump = ctx.bumps.medical_record;
        
        Ok(())
    }

    pub fn store_encrypted_medical_data(
        ctx: Context<StoreEncryptedMedicalData>,
        computation_offset: u64,
        data: Vec<u8>,
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        // Access control: only the patient or the doctor may write encrypted data
        let payer_key = ctx.accounts.payer.key();
        require!(
            payer_key == ctx.accounts.patient.authority || payer_key == ctx.accounts.doctor.authority,
            ErrorCode::UnauthorizedAccess
        );
        
        // Convert data to fixed-size array (ciphertext)
        let mut ciphertext = [0u8; 32];
        let len = data.len().min(32);
        ciphertext[..len].copy_from_slice(&data[..len]);
        
        let args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce),
            Argument::EncryptedU8(ciphertext),
        ];

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![StoreEncryptedMedicalDataCallback::callback_ix(&[])],
        )?;

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "encrypt_medical_record")]
    pub fn store_encrypted_medical_data_callback(
        ctx: Context<StoreEncryptedMedicalDataCallback>,
        output: ComputationOutputs<EncryptMedicalRecordOutput>,
    ) -> Result<()> {
        let o = match output {
            ComputationOutputs::Success(EncryptMedicalRecordOutput { field_0 }) => field_0,
            _ => return Err(ErrorCode::AbortedComputation.into()),
        };

        let medical_record = &mut ctx.accounts.medical_record;
        medical_record.encrypted_data = o.ciphertexts[0];
        medical_record.encrypted_nonce = o.nonce.to_le_bytes();
        
        emit!(MedicalRecordStoredEvent {
            medical_record: medical_record.key(),
            patient: medical_record.patient,
            doctor: medical_record.doctor,
        });
        
        Ok(())
    }

    pub fn retrieve_medical_data(
        ctx: Context<RetrieveMedicalData>,
        computation_offset: u64,
        pub_key: [u8; 32],
    ) -> Result<()> {
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
        // Access control: only the patient or the doctor may request decryption
        let payer_key = ctx.accounts.payer.key();
        require!(
            payer_key == ctx.accounts.patient.authority || payer_key == ctx.accounts.doctor.authority,
            ErrorCode::UnauthorizedAccess
        );
        
        let medical_record = &ctx.accounts.medical_record;
        let nonce_u128 = u128::from_le_bytes(medical_record.encrypted_nonce);
        
        let args = vec![
            Argument::ArcisPubkey(pub_key),
            Argument::PlaintextU128(nonce_u128),
            Argument::EncryptedU8(medical_record.encrypted_data),
        ];

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            None,
            vec![RetrieveMedicalDataCallback::callback_ix(&[])],
        )?;

        Ok(())
    }

    #[arcium_callback(encrypted_ix = "decrypt_medical_record")]
    pub fn retrieve_medical_data_callback(
        ctx: Context<RetrieveMedicalDataCallback>,
        output: ComputationOutputs<DecryptMedicalRecordOutput>,
    ) -> Result<()> {
        let o = match output {
            ComputationOutputs::Success(DecryptMedicalRecordOutput { field_0 }) => field_0,
            _ => return Err(ErrorCode::AbortedComputation.into()),
        };

        emit!(MedicalRecordRetrievedEvent {
            medical_record: ctx.accounts.medical_record.key(),
            decrypted_data: o.ciphertexts[0],
        });
        
        Ok(())
    }
}

// ==================== Account Structs ====================

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

// ==================== Context Structs ====================

#[derive(Accounts)]
pub struct RegisterPatient<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 100 + 8 + 200 + 8 + 1,
        seeds = [b"patient", authority.key().as_ref()],
        bump
    )]
    pub patient: Account<'info, Patient>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdatePatient<'info> {
    #[account(
        mut,
        seeds = [b"patient", authority.key().as_ref()],
        bump = patient.bump,
        has_one = authority
    )]
    pub patient: Account<'info, Patient>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct RegisterDoctor<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 100 + 100 + 50 + 8 + 1 + 8 + 8 + 1,
        seeds = [b"doctor", authority.key().as_ref()],
        bump
    )]
    pub doctor: Account<'info, Doctor>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyDoctor<'info> {
    #[account(
        mut,
        seeds = [b"doctor", doctor.authority.as_ref()],
        bump = doctor.bump
    )]
    pub doctor: Account<'info, Doctor>,
    pub admin: Signer<'info>, // Should be verified admin
}

#[derive(Accounts)]
pub struct UpdateDoctor<'info> {
    #[account(
        mut,
        seeds = [b"doctor", authority.key().as_ref()],
        bump = doctor.bump,
        has_one = authority
    )]
    pub doctor: Account<'info, Doctor>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(appointment_time: i64)]
pub struct CreateAppointment<'info> {
    #[account(
        init,
        payer = patient_authority,
        space = 8 + 32 + 32 + 8 + 200 + 1 + 8 + 1,
        seeds = [
            b"appointment",
            patient.key().as_ref(),
            doctor.key().as_ref(),
            &appointment_time.to_le_bytes()
        ],
        bump
    )]
    pub appointment: Account<'info, Appointment>,
    #[account(
        seeds = [b"patient", patient_authority.key().as_ref()],
        bump = patient.bump
    )]
    pub patient: Account<'info, Patient>,
    #[account(
        seeds = [b"doctor", doctor.authority.as_ref()],
        bump = doctor.bump
    )]
    pub doctor: Account<'info, Doctor>,
    #[account(mut)]
    pub patient_authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateAppointment<'info> {
    #[account(
        mut,
        seeds = [
            b"appointment",
            appointment.patient.as_ref(),
            appointment.doctor.as_ref(),
            &appointment.appointment_time.to_le_bytes()
        ],
        bump = appointment.bump
    )]
    pub appointment: Account<'info, Appointment>,
    #[account(mut)]
    pub doctor: Account<'info, Doctor>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(record_id: u64)]
pub struct CreateMedicalRecord<'info> {
    #[account(
        init,
        payer = doctor_authority,
        space = 8 + 32 + 32 + 8 + 50 + 8 + 32 + 16 + 1,
        seeds = [
            b"medical_record",
            patient.key().as_ref(),
            &record_id.to_le_bytes()
        ],
        bump
    )]
    pub medical_record: Account<'info, MedicalRecord>,
    pub patient: Account<'info, Patient>,
    #[account(
        seeds = [b"doctor", doctor_authority.key().as_ref()],
        bump = doctor.bump,
        has_one = doctor_authority
    )]
    pub doctor: Account<'info, Doctor>,
    #[account(mut)]
    pub doctor_authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("encrypt_medical_record", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct StoreEncryptedMedicalData<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        seeds = [
            b"medical_record",
            medical_record.patient.as_ref(),
            &medical_record.record_id.to_le_bytes()
        ],
        bump = medical_record.bump
    )]
    pub medical_record: Account<'info, MedicalRecord>,
    #[account(
        seeds = [b"patient", patient.authority.as_ref()],
        bump = patient.bump,
        constraint = medical_record.patient == patient.key()
    )]
    pub patient: Account<'info, Patient>,
    #[account(
        seeds = [b"doctor", doctor.authority.as_ref()],
        bump = doctor.bump,
        constraint = medical_record.doctor == doctor.key()
    )]
    pub doctor: Account<'info, Doctor>,
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, SignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(mut, address = derive_mempool_pda!())]
    /// CHECK: checked by arcium program
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!())]
    /// CHECK: checked by arcium program
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset))]
    /// CHECK: checked by arcium program
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_ENCRYPT_MEDICAL_RECORD))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(mut, address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("encrypt_medical_record")]
#[derive(Accounts)]
pub struct StoreEncryptedMedicalDataCallback<'info> {
    #[account(mut)]
    pub medical_record: Account<'info, MedicalRecord>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_ENCRYPT_MEDICAL_RECORD))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

#[queue_computation_accounts("decrypt_medical_record", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct RetrieveMedicalData<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        seeds = [
            b"medical_record",
            medical_record.patient.as_ref(),
            &medical_record.record_id.to_le_bytes()
        ],
        bump = medical_record.bump
    )]
    pub medical_record: Account<'info, MedicalRecord>,
    #[account(
        seeds = [b"patient", patient.authority.as_ref()],
        bump = patient.bump,
        constraint = medical_record.patient == patient.key()
    )]
    pub patient: Account<'info, Patient>,
    #[account(
        seeds = [b"doctor", doctor.authority.as_ref()],
        bump = doctor.bump,
        constraint = medical_record.doctor == doctor.key()
    )]
    pub doctor: Account<'info, Doctor>,
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, SignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(mut, address = derive_mempool_pda!())]
    /// CHECK: checked by arcium program
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!())]
    /// CHECK: checked by arcium program
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset))]
    /// CHECK: checked by arcium program
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_DECRYPT_MEDICAL_RECORD))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(mut, address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("decrypt_medical_record")]
#[derive(Accounts)]
pub struct RetrieveMedicalDataCallback<'info> {
    pub medical_record: Account<'info, MedicalRecord>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_DECRYPT_MEDICAL_RECORD))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

#[init_computation_definition_accounts("encrypt_medical_record", payer)]
#[derive(Accounts)]
pub struct InitEncryptMedicalRecordCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by arcium program
    pub comp_def_account: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("decrypt_medical_record", payer)]
#[derive(Accounts)]
pub struct InitDecryptMedicalRecordCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: checked by arcium program
    pub comp_def_account: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

// ==================== Events ====================

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

// ==================== Errors ====================

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
}
