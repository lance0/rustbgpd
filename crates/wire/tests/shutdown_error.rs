use std::error::Error;

use rustbgpd_wire::NotificationMessage;
use rustbgpd_wire::notification::{
    NotificationCode, ShutdownCommunicationError, cease_subcode, extract_shutdown_communication,
};

fn extract(notification: &NotificationMessage) -> Result<Option<&str>, Box<dyn Error>> {
    Ok(extract_shutdown_communication(notification)?)
}

#[test]
fn shutdown_errors_propagate_to_downstream_error_handlers() {
    let valid = NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::ADMINISTRATIVE_SHUTDOWN,
        vec![2, b'o', b'k'].into(),
    );
    assert_eq!(extract(&valid).unwrap(), Some("ok"));

    for (subcode, data, expected, text) in [
        (
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            vec![2, b'x'],
            ShutdownCommunicationError::InvalidLength,
            "invalid shutdown communication length",
        ),
        (
            cease_subcode::ADMINISTRATIVE_RESET,
            vec![1, 0xff],
            ShutdownCommunicationError::InvalidUtf8,
            "shutdown communication is not valid UTF-8",
        ),
        (
            cease_subcode::HARD_RESET,
            vec![6],
            ShutdownCommunicationError::MalformedHardResetEnvelope,
            "malformed Hard Reset notification envelope",
        ),
    ] {
        let notification = NotificationMessage::new(NotificationCode::Cease, subcode, data.into());
        let error = extract(&notification).unwrap_err();
        assert_eq!(
            error.downcast_ref::<ShutdownCommunicationError>(),
            Some(&expected)
        );
        assert_eq!(error.to_string(), text);
        assert!(error.source().is_none());
    }
}
