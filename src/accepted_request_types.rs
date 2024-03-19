pub fn private_accepted_request_types() -> Vec<&'static str>
{
    return vec![
        "publishNewOrderType",
        "logInToPasswordEncryptedAccount"
    ]
}

pub fn public_accepted_request_types() -> Vec<&'static str>
{
    return vec![
        "requestEncryptedInitiation",
        "submitEncryptedResponse"

    ]
}

