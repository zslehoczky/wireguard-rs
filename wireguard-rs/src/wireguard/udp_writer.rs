use wg_traits::udp::{self, UDP, Writer as _};

use crate::router::RouterError;

pub struct UdpWriter<B: UDP> {
    enabled: bool,
    wrapped: Option<B::Writer>,
}

impl<B: UDP> UdpWriter<B> {
    pub fn new() -> Self {
        Self {
            enabled: true,
            wrapped: None,
        }
    }

    pub fn send_checked(&self, msg: &[u8], endpoint: &mut B::Endpoint) -> Result<(), RouterError> {
        if self.enabled {
            return self
                .wrapped
                .as_ref()
                .ok_or(RouterError::SendError)
                .and_then(|bind| {
                    bind.write(msg, endpoint)
                        .map_err(|_| RouterError::SendError)
                });
        }

        Ok(())
    }

    pub fn send_unchecked(
        &self,
        msg: &[u8],
        endpoint: &mut B::Endpoint,
    ) -> Result<(), <B::Writer as udp::Writer<B::Endpoint>>::Error> {
        if self.enabled
            && let Some(bind) = self.wrapped.as_ref()
        {
            return bind.write(msg, endpoint);
        }

        Ok(())
    }

    pub fn set_enabled(&mut self, value: bool) {
        self.enabled = value;
    }

    pub fn set_writer(&mut self, new: B::Writer) {
        self.wrapped = Some(new);
    }
}

impl<B: UDP> Default for UdpWriter<B> {
    fn default() -> Self {
        Self::new()
    }
}
