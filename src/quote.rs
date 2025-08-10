use std::cell::RefCell;

use eyre::Result;

use crate::constants::{
    ENCLAVE_REPORT_LEN, HEADER_LEN, SGX_TEE_TYPE, TD10_REPORT_LEN, TDX_TEE_TYPE,
};

#[derive(Debug)]
pub struct Quote {
    pub header: Header,
    pub body: Vec<u8>,
    pub signature: QuoteSignatureData,
    pub rest: Vec<u8>,
}

impl Quote {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut offset = 0;
        let header_bytes = &bytes[offset..Header::SIZE];
        let header = Header::from_bytes(header_bytes)?;

        offset += Header::SIZE;
        let body_len = header.tee_type.body_size();
        let body = bytes[offset..offset + body_len].to_vec();

        offset += body_len;
        let signature_length = u32::from_le_bytes(bytes[offset..offset + 4].try_into()?) as usize;

        offset += 4;
        let signature = QuoteSignatureData::from_bytes(&bytes[offset..offset + signature_length])?;

        offset += signature_length;
        let rest = bytes[offset..].to_vec();

        Ok(Self {
            header,
            body,
            signature,
            rest,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend_from_slice(&self.header.to_bytes());
        result.extend_from_slice(&self.body);
        result.extend_from_slice(&self.signature.to_bytes());
        result.extend_from_slice(&self.rest);

        result
    }
}

#[derive(Debug)]
pub struct Header {
    pub tee_type: TeeType,
    pub raw: [u8; HEADER_LEN],
}

impl Header {
    const SIZE: usize = HEADER_LEN;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            eyre::bail!("Invalid header length: {}", bytes.len());
        }

        let tee_type = match u32::from_le_bytes(bytes[4..8].try_into()?) {
            SGX_TEE_TYPE => TeeType::Sgx,
            TDX_TEE_TYPE => TeeType::Tdx,
            type_id => eyre::bail!("Unknonw TEE type: {type_id}"),
        };

        Ok(Self {
            tee_type,
            raw: bytes.try_into()?,
        })
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        self.raw
    }
}

#[derive(Debug)]
pub struct QuoteSignatureData {
    pub sig: [u8; 64],
    pub key: [u8; 64],
    pub cert_data: CertData,
}

impl QuoteSignatureData {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= 128 {
            eyre::bail!("Length must be larger than 128");
        }

        let mut offset = 0;
        let sig = bytes[offset..64].try_into()?;

        offset += 64;
        let key = bytes[offset..offset + 64].try_into()?;

        offset += 64;
        let cert_data_len = u32::from_le_bytes(bytes[offset + 2..offset + 6].try_into()?) as usize;
        if bytes[offset + 6..].len() != cert_data_len {
            eyre::bail!("Cert data length mismatch");
        }

        let cert_data = CertData::from_bytes(&bytes[offset..])?;

        Ok(Self {
            sig,
            key,
            cert_data,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = vec![];

        let cert_data = self.cert_data.to_bytes();

        result.extend_from_slice(
            &((self.sig.len() + self.key.len() + cert_data.len()) as u32).to_le_bytes(),
        );
        result.extend_from_slice(&self.sig);
        result.extend_from_slice(&self.key);
        result.extend_from_slice(&cert_data);

        result
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum CertData {
    Certificates(Vec<u8>),
    QeReportCertData(QeReportCertData),
}

impl CertData {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let cert_type = u16::from_le_bytes(bytes[0..2].try_into()?);
        let cert_data_len = u32::from_le_bytes(bytes[2..6].try_into()?) as usize;

        if bytes.len() != cert_data_len + 6 {
            eyre::bail!("Invalid bytes length");
        }

        if cert_type == 5 {
            Ok(Self::Certificates(bytes[6..].to_vec()))
        } else if cert_type == 6 {
            Ok(Self::QeReportCertData(QeReportCertData::from_bytes(
                &bytes[6..],
            )?))
        } else {
            eyre::bail!("Unsupported cert data type: {cert_type}");
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = vec![];

        match self {
            CertData::Certificates(payload) => {
                result.extend_from_slice(&5u16.to_le_bytes());

                result.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                result.extend_from_slice(payload);
            }
            CertData::QeReportCertData(payload) => {
                result.extend_from_slice(&6u16.to_le_bytes());

                let payload = payload.to_bytes();
                result.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                result.extend_from_slice(&payload);
            }
        }

        result
    }
}

#[derive(Debug)]
pub struct QeReportCertData {
    pub qe_report: [u8; 384],
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: Vec<u8>,
    pub qe_cert_data: Box<RefCell<CertData>>,
}

impl QeReportCertData {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 384 + 64 + 2 {
            eyre::bail!("Invalid bytes length");
        }

        let mut offset = 0;
        let qe_report = bytes[offset..offset + 384].try_into()?;

        offset += 384;
        let qe_report_signature = bytes[offset..offset + 64].try_into()?;

        offset += 64;
        let auth_data_len = u16::from_le_bytes(bytes[offset..offset + 2].try_into()?) as usize;

        offset += 2;
        let qe_auth_data = bytes[offset..offset + auth_data_len].to_vec();

        offset += auth_data_len;
        let qe_cert_data = Box::new(RefCell::new(CertData::from_bytes(&bytes[offset..])?));

        Ok(Self {
            qe_report,
            qe_report_signature,
            qe_auth_data,
            qe_cert_data,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = vec![];

        result.extend_from_slice(&self.qe_report);
        result.extend_from_slice(&self.qe_report_signature);
        result.extend_from_slice(&(self.qe_auth_data.len() as u16).to_le_bytes());
        result.extend_from_slice(&self.qe_auth_data);
        result.extend_from_slice(&self.qe_cert_data.borrow().to_bytes());

        result
    }
}

#[derive(Debug)]
pub enum TeeType {
    Sgx,
    Tdx,
}

impl TeeType {
    const fn body_size(&self) -> usize {
        match self {
            Self::Sgx => ENCLAVE_REPORT_LEN,
            Self::Tdx => TD10_REPORT_LEN,
        }
    }
}
