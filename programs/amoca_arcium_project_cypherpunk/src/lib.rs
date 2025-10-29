#![allow(unexpected_cfgs)]
#![allow(deprecated)]

use anchor_lang::prelude::*;
use anchor_lang::Discriminator;
use arcium_anchor::prelude::*;

mod state;
mod events;
mod errors;
mod instructions;

use state::*;
use errors::ErrorCode;

// Alias required by arcium macros to reference the crate root
pub use crate as __client_accounts_crate;

const COMP_DEF_OFFSET_ADD_TOGETHER: u32 = comp_def_offset("add_together");

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
        instructions::register_patient(ctx, name, date_of_birth, contact_info)
    }

    pub fn update_patient(
        ctx: Context<UpdatePatient>,
        name: Option<String>,
        contact_info: Option<String>,
    ) -> Result<()> { instructions::update_patient(ctx, name, contact_info) }

    // ==================== Doctor Instructions ====================

    pub fn register_doctor(
        ctx: Context<RegisterDoctor>,
        name: String,
        specialization: String,
        license_number: String,
        consultation_fee: u64,
    ) -> Result<()> { instructions::register_doctor(ctx, name, specialization, license_number, consultation_fee) }

    pub fn verify_doctor(ctx: Context<VerifyDoctor>) -> Result<()> { instructions::verify_doctor(ctx) }

    pub fn update_doctor(
        ctx: Context<UpdateDoctor>,
        specialization: Option<String>,
        consultation_fee: Option<u64>,
    ) -> Result<()> { instructions::update_doctor(ctx, specialization, consultation_fee) }

    // ==================== Appointment Instructions ====================

    pub fn create_appointment(
        ctx: Context<CreateAppointment>,
        appointment_time: i64,
        notes: String,
    ) -> Result<()> { instructions::create_appointment(ctx, appointment_time, notes) }

    pub fn complete_appointment(ctx: Context<UpdateAppointment>) -> Result<()> { instructions::complete_appointment(ctx) }

    pub fn cancel_appointment(ctx: Context<UpdateAppointment>) -> Result<()> { instructions::cancel_appointment(ctx) }

    // ==================== Medical Record Instructions (Encrypted) ====================

    pub fn init_encrypt_medical_record_comp_def(
        ctx: Context<InitEncryptMedicalRecordCompDef>,
    ) -> Result<()> { init_comp_def(ctx.accounts, true, 0, None, None) }

    pub fn init_decrypt_medical_record_comp_def(
        ctx: Context<InitDecryptMedicalRecordCompDef>,
    ) -> Result<()> { init_comp_def(ctx.accounts, true, 0, None, None) }

    pub fn create_medical_record(
        ctx: Context<CreateMedicalRecord>,
        record_id: u64,
        record_type: String,
        timestamp: i64,
    ) -> Result<()> { instructions::create_medical_record(ctx, record_id, record_type, timestamp) }

    pub fn store_encrypted_medical_data(
        ctx: Context<StoreEncryptedMedicalData>,
        computation_offset: u64,
        data: Vec<u8>,
        pub_key: [u8; 32],
        nonce: u128,
    ) -> Result<()> { instructions::store_encrypted_medical_data(ctx, computation_offset, data, pub_key, nonce) }

    #[arcium_callback(encrypted_ix = "add_together")]
    pub fn add_together_callback(
        ctx: Context<AddTogetherCallback>,
        output: ComputationOutputs<AddTogetherOutput>,
    ) -> Result<()> {
        instructions::add_together_callback(ctx, output)
    }

    pub fn retrieve_medical_data(
        ctx: Context<RetrieveMedicalData>,
        computation_offset: u64,
        pub_key: [u8; 32],
    ) -> Result<()> { instructions::retrieve_medical_data(ctx, computation_offset, pub_key) }

    // Single callback for the `add_together` confidential instruction
}

// account state moved to state.rs

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
    pub patient: Box<Account<'info, Patient>>,
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
    pub patient: Box<Account<'info, Patient>>,
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
    pub doctor: Box<Account<'info, Doctor>>,
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
    pub doctor: Box<Account<'info, Doctor>>,
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
    pub doctor: Box<Account<'info, Doctor>>,
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
    pub appointment: Box<Account<'info, Appointment>>,
    #[account(
        seeds = [b"patient", patient_authority.key().as_ref()],
        bump = patient.bump
    )]
    pub patient: Box<Account<'info, Patient>>,
    #[account(
        seeds = [b"doctor", doctor.authority.as_ref()],
        bump = doctor.bump
    )]
    pub doctor: Box<Account<'info, Doctor>>,
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
    pub appointment: Box<Account<'info, Appointment>>,
    #[account(mut)]
    pub doctor: Box<Account<'info, Doctor>>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(record_id: u64)]
pub struct CreateMedicalRecord<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 32 + 8 + 50 + 8 + 32 + 16 + 1,
        seeds = [
            b"medical_record",
            patient.key().as_ref(),
            &record_id.to_le_bytes()
        ],
        bump
    )]
    pub medical_record: Box<Account<'info, MedicalRecord>>,
    pub patient: Box<Account<'info, Patient>>,
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        seeds = [b"doctor", authority.key().as_ref()],
        bump = doctor.bump
    )]
    pub doctor: Box<Account<'info, Doctor>>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("add_together", payer)]
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
    pub medical_record: Box<Account<'info, MedicalRecord>>,
    #[account(
        seeds = [b"patient", patient.authority.as_ref()],
        bump = patient.bump,
        constraint = medical_record.patient == patient.key()
    )]
    pub patient: Box<Account<'info, Patient>>,
    #[account(
        seeds = [b"doctor", doctor.authority.as_ref()],
        bump = doctor.bump,
        constraint = medical_record.doctor == doctor.key()
    )]
    pub doctor: Box<Account<'info, Doctor>>,
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
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_ADD_TOGETHER))]
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

#[callback_accounts("add_together")]
#[derive(Accounts)]
pub struct AddTogetherCallback<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut)]
    pub medical_record: Box<Account<'info, MedicalRecord>>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_ADD_TOGETHER))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: checked by account constraint
    pub instructions_sysvar: AccountInfo<'info>,
}

#[queue_computation_accounts("add_together", payer)]
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
    pub medical_record: Box<Account<'info, MedicalRecord>>,
    #[account(
        seeds = [b"patient", patient.authority.as_ref()],
        bump = patient.bump,
        constraint = medical_record.patient == patient.key()
    )]
    pub patient: Box<Account<'info, Patient>>,
    #[account(
        seeds = [b"doctor", doctor.authority.as_ref()],
        bump = doctor.bump,
        constraint = medical_record.doctor == doctor.key()
    )]
    pub doctor: Box<Account<'info, Doctor>>,
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
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_ADD_TOGETHER))]
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

// Removed duplicate callback_accounts for the same encrypted ix to avoid type redefinitions

#[init_computation_definition_accounts("add_together", payer)]
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

#[init_computation_definition_accounts("add_together", payer)]
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

// events moved to events.rs

// errors moved to errors.rs
