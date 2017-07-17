import base64
import json
import os
import unittest

from unittest.mock import patch


class ValidatorTest(unittest.TestCase):

    def setUp(self):
        fixtures = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data/fixtures.json')
        good_profile = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data/profile-good.json')
        bad_profile = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data/profile-bad.json')

        with open(fixtures) as artifacts:
            self.test_artifacts = json.load(artifacts)

        self.good_profile = json.loads(open(good_profile).read())
        self.bad_profile = json.loads(open(bad_profile).read())


        self.good_profile = json.dumps(self.good_profile).encode('utf-8')
        self.bad_profile = json.dumps(self.bad_profile).encode('utf-8')


        os.environ['AWS_DEFAULT_REGION'] = self.test_artifacts['dummy_aws_region']
        os.environ['CIS_ARN_MASTER_KEY'] = self.test_artifacts['dummy_kms_arn']
        os.environ['CIS_KINESIS_STREAM_ARN'] = self.test_artifacts['dummy_kinesis_arn']

    @patch('cis.streams.kinesis')
    @patch('cis.encryption.kms')
    @patch('cis.encryption.os')
    def test_main_handler_success(self, mock_os, mock_kms, mock_kinesis):
        import main

        # This is the dummy data key used in mocking.
        test_kms_data = {
            'Plaintext': base64.b64decode(self.test_artifacts['Plaintext']),
            'CiphertextBlob': base64.b64decode(self.test_artifacts['CiphertextBlob'])
        }

        test_iv = base64.b64decode(self.test_artifacts['IV'])

        mock_kms.generate_data_key.return_value = test_kms_data
        mock_kms.decrypt.return_value = test_kms_data
        mock_os.urandom.return_value = test_iv

        from cis.encryption import encrypt
        # This is a mocked user profile in a "good" state.
        event = encrypt(self.good_profile)
        mock_kms.generate_data_key.assert_called_once_with(
            KeyId=self.test_artifacts['dummy_kms_arn'],
            KeySpec='AES_256',
            EncryptionContext={}
        )

        event['ciphertext'] = base64.b64encode(event['ciphertext'])
        event['ciphertext_key'] = base64.b64encode(event['ciphertext_key'])
        event['tag'] = base64.b64encode(event['tag'])
        event['iv'] = base64.b64encode(event['iv'])
        event['publisher'] = base64.b64encode("test-publisher".encode('utf-8'))

        assert event['publisher'] is not None
        result = main.handle(event, context = {})

        assert result is True

    @patch('cis.streams.kinesis')
    @patch('cis.encryption.kms')
    @patch('cis.encryption.os')
    def test_main_handler_fail(self, mock_os, mock_kms, mock_kinesis):
        import main

        # This is the dummy data key used in mocking.
        test_kms_data = {
            'Plaintext': base64.b64decode(self.test_artifacts['Plaintext']),
            'CiphertextBlob': base64.b64decode(self.test_artifacts['CiphertextBlob'])
        }

        test_iv = base64.b64decode(self.test_artifacts['IV'])

        mock_kms.generate_data_key.return_value = test_kms_data
        mock_kms.decrypt.return_value = test_kms_data
        mock_os.urandom.return_value = test_iv

        from cis.encryption import encrypt
        # This is a mocked user profile in a "good" state.
        event = encrypt(self.bad_profile)
        mock_kms.generate_data_key.assert_called_once_with(
            KeyId=self.test_artifacts['dummy_kms_arn'],
            KeySpec='AES_256',
            EncryptionContext={}
        )

        event['ciphertext'] = base64.b64encode(event['ciphertext'])
        event['ciphertext_key'] = base64.b64encode(event['ciphertext_key'])
        event['tag'] = base64.b64encode(event['tag'])
        event['iv'] = base64.b64encode(event['iv'])
        event['publisher'] = base64.b64encode("test-publisher".encode('utf-8'))

        assert event['publisher'] is not None
        result = main.handle(event, context = {})

        assert result is False