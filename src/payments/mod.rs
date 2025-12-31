mod stripe;
mod lemonsqueezy;

pub use stripe::*;
pub use lemonsqueezy::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentProvider {
    Stripe,
    LemonSqueezy,
}

impl PaymentProvider {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "stripe" => Some(PaymentProvider::Stripe),
            "lemonsqueezy" | "ls" => Some(PaymentProvider::LemonSqueezy),
            _ => None,
        }
    }
}
