from unittest import mock

import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})

def test_operator_name():
    encrypt_object = Encrypt()
    assert encrypt_object.operator_name() == "encrypt"

from presidio_anonymizer.operators import OperatorType
def test_operator_type():
    encrypt_object = Encrypt()
    assert encrypt_object.operator_type() == OperatorType.Anonymize


@mock.patch.object(AESCipher, "is_valid_key_size")
def test_invalid_non_str_key(mock_is_valid_key_size):
    mock_is_valid_key_size.return_value = False
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})

@pytest.mark.parametrize(
    # fmt: off
    "key",
    [
        ("128bitslengthkey"), #string: 16 bytes
        ("128bitslengthkeyengthkey"), #string: 24 bytes
        ("128bitslengthkey128bitslengthkey"), #string: 32 bytes
        (b'1111111111111111'), #bytes: 16 bytes
        (b'111111111111111111111111'), #bytes: 24 bytes
        (b'11111111111111111111111111111111'), #bytes: 32 bytes
        
    ],
    # fmt: on
)
def test_given_valid_keys(key):
    Encrypt().validate(params={"key": key})