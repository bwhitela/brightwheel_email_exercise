import io
import json
import logging
import os
import unittest
import unittest.mock

import requests
import requests.exceptions

import emailer


def make_email_json(to_email='alice@example.com', to_name='Alice',
                    from_email='bob@example.com', from_name='Bob',
                    subject='Test Email', body='Hello World!'):
    email_json = {'to': to_email,
                  'to_name': to_name,
                  'from': from_email,
                  'from_name': from_name,
                  'subject': subject,
                  'body': body}
    to_del = []
    for key, val in email_json.items():
        if val is None:
            to_del.append(key)
    for key in to_del:
        del email_json[key]
    return email_json, json.dumps(email_json)


class TestEmail(unittest.TestCase):
    """Test the Email class."""

    def test_good_email_plain_text(self):
        email_json, email_json_str = make_email_json()
        email = emailer.Email(email_json_str)
        self.assertEqual(email.to_email, email_json['to'])
        self.assertEqual(email.to_name, email_json['to_name'])
        self.assertEqual(email.from_email, email_json['from'])
        self.assertEqual(email.from_name, email_json['from_name'])
        self.assertEqual(email.subject, email_json['subject'])
        self.assertEqual(email.body, email_json['body'])

    def test_good_email_html(self):
        body_html = '<html><head><meta name="author" content="Bob"></head>' \
                    '<body><h1>Test Page</h1>\n' \
                    '<p>Hello World!</p></body></html>'
        body_text = 'Test Page\nHello World!'
        email_json, email_json_str = make_email_json(body=body_html)
        email = emailer.Email(email_json_str)
        self.assertEqual(email.to_email, email_json['to'])
        self.assertEqual(email.to_name, email_json['to_name'])
        self.assertEqual(email.from_email, email_json['from'])
        self.assertEqual(email.from_name, email_json['from_name'])
        self.assertEqual(email.subject, email_json['subject'])
        self.assertEqual(email.body, body_text)

    def test_malformed_json_string_email(self):
        bad_json_str = '("hello world)"}'
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          bad_json_str)

    def test_misformatted_json_email(self):
        email_json, _ = make_email_json()
        bad_json = []
        for key, val in email_json.items():
            bad_json.append((key, val))
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          json.dumps(bad_json))

    def test_wrong_field_email(self):
        email_json, _ = make_email_json()
        email_json['extra'] = 'rubbish'
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          json.dumps(email_json))
        del email_json['subject']
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          json.dumps(email_json))

    def test_missing_to_email(self):
        _, email_json_str = make_email_json(to_email=None)
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          email_json_str)

    def test_missing_to_name_email(self):
        _, email_json_str = make_email_json(to_name=None)
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          email_json_str)

    def test_missing_from_email(self):
        _, email_json_str = make_email_json(from_email=None)
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          email_json_str)

    def test_missing_from_name_email(self):
        _, email_json_str = make_email_json(from_name=None)
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          email_json_str)

    def test_missing_subject_email(self):
        _, email_json_str = make_email_json(subject=None)
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          email_json_str)

    def test_missing_body_email(self):
        _, email_json_str = make_email_json(body=None)
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          email_json_str)

    def test_malformed_to_email(self):
        _, email_json_str = make_email_json(to_email='alice@example')
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          email_json_str)

    def test_malformed_from_email(self):
        _, email_json_str = make_email_json(from_email='@example.com')
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          email_json_str)

    @unittest.mock.patch('emailer.BeautifulSoup')
    def test_maformed_html_body_email(self, beautiful_soup_mock):
        beautiful_soup_mock.side_effect = Exception()
        _, email_json_str = make_email_json()
        self.assertRaises(emailer.MalformedEmailError, emailer.Email,
                          email_json_str)


def make_default_email():
    _, email_json_str = make_email_json()
    return emailer.Email(email_json_str)


def make_response_mock(status_code):
    mock_resp = unittest.mock.Mock()
    mock_resp.status_code = status_code
    mock_resp.text = 'Response body'
    return mock_resp


class TestMailgun(unittest.TestCase):
    """Test the Mailgun class."""

    def setUp(self):
        self.api_key = 'DEADBEEF'
        self.mailgun = emailer.Mailgun(self.api_key)

    @unittest.mock.patch('requests.post')
    def test_successful_send(self, requests_post):
        requests_post.return_value = make_response_mock(200)

        email = make_default_email()
        self.mailgun.send_email(email)

        expected_url = self.mailgun._url % (email.from_email.split('@')[1],)
        expected_auth = ('api', self.api_key)
        from_field = '%s <%s>' % (email.from_name, email.from_email)
        to_field = '%s <%s>' % (email.to_name, email.to_email)
        expected_data = {'from': from_field,
                         'to': to_field,
                         'subject': email.subject,
                         'text': email.body}
        requests_post.assert_called_once_with(expected_url,
                                              auth=expected_auth,
                                              data=expected_data)

    @unittest.mock.patch('requests.post')
    def test_malformed_request(self, requests_post):
        requests_post.return_value = make_response_mock(400)
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceMalformedRequestError,
                          self.mailgun.send_email, email)

    @unittest.mock.patch('requests.post')
    def test_failed_auth_request(self, requests_post):
        requests_post.return_value = make_response_mock(401)
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceAuthError,
                          self.mailgun.send_email, email)

    @unittest.mock.patch('requests.post')
    def test_unexpected_response_request(self, requests_post):
        requests_post.return_value = make_response_mock(404)
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceUnexpectedError,
                          self.mailgun.send_email, email)

    @unittest.mock.patch('requests.post')
    def test_internal_server_error_request(self, requests_post):
        requests_post.return_value = make_response_mock(500)
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceSystemError,
                          self.mailgun.send_email, email)

    @unittest.mock.patch('requests.post')
    def test_connection_error_request(self, requests_post):
        requests_post.side_effect = requests.exceptions.ConnectionError()
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceConnectionError,
                          self.mailgun.send_email, email)

    @unittest.mock.patch('requests.post')
    def test_connection_timeout_request(self, requests_post):
        requests_post.side_effect = requests.exceptions.Timeout()
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceConnectionError,
                          self.mailgun.send_email, email)


class TestSendGrid(unittest.TestCase):
    """Test the SendGrid class."""

    def setUp(self):
        self.api_key = 'DEADBEEF'
        self.sendgrid = emailer.SendGrid(self.api_key)

    @unittest.mock.patch('requests.post')
    def test_successful_send(self, requests_post):
        requests_post.return_value = make_response_mock(200)

        email = make_default_email()
        self.sendgrid.send_email(email)

        expected_headers = {'Authorization': 'Bearer %s' % (self.api_key,)}
        expected_data = {'content': [{'type': 'text/plain',
                                      'value': email.body}],
                         'from': {'email': email.from_email,
                                  'name': email.from_name},
                         'personalizations': [
                                {'to': [{'email': email.to_email,
                                         'name': email.to_name}]}],
                         'subject': email.subject}

        requests_post.assert_called_once_with(self.sendgrid._url,
                                              headers=expected_headers,
                                              json=expected_data)

    @unittest.mock.patch('requests.post')
    def test_malformed_request(self, requests_post):
        requests_post.return_value = make_response_mock(400)
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceMalformedRequestError,
                          self.sendgrid.send_email, email)

    @unittest.mock.patch('requests.post')
    def test_failed_auth_request(self, requests_post):
        requests_post.return_value = make_response_mock(401)
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceAuthError,
                          self.sendgrid.send_email, email)

    @unittest.mock.patch('requests.post')
    def test_unexpected_response_request(self, requests_post):
        requests_post.return_value = make_response_mock(404)
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceUnexpectedError,
                          self.sendgrid.send_email, email)

    @unittest.mock.patch('requests.post')
    def test_internal_server_error_request(self, requests_post):
        requests_post.return_value = make_response_mock(500)
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceSystemError,
                          self.sendgrid.send_email, email)

    @unittest.mock.patch('requests.post')
    def test_connection_error_request(self, requests_post):
        requests_post.side_effect = requests.exceptions.ConnectionError()
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceConnectionError,
                          self.sendgrid.send_email, email)

    @unittest.mock.patch('requests.post')
    def test_connection_timeout_request(self, requests_post):
        requests_post.side_effect = requests.exceptions.Timeout()
        email = make_default_email()
        self.assertRaises(emailer.MailerServiceConnectionError,
                          self.sendgrid.send_email, email)


class TestEmailerApp(unittest.TestCase):
    """Test the main EmailerApp class."""

    def setUp(self):
        self.clear_environ()

    def tearDown(self):
        self.clear_environ()

    def clear_environ(self):
        if os.environ.get(emailer.MAILER_SERVICE_ENV):
            del os.environ[emailer.MAILER_SERVICE_ENV]
        if os.environ.get(emailer.MAILER_SERVICE_KEY_ENV):
            del os.environ[emailer.MAILER_SERVICE_KEY_ENV]

    def set_environ_config(self, service=emailer.MAILER_SERVICE_ENV_MAILGUN,
                           api_key='DEADBEEF'):
        if service:
            os.environ[emailer.MAILER_SERVICE_ENV] = service
        if api_key:
            os.environ[emailer.MAILER_SERVICE_KEY_ENV] = api_key

    def make_environ_dict(self, method='POST', path='/email',
                          ctype='application/json', body=make_email_json()[1]):
        body_bytes = body.encode()
        environ = {'REQUEST_METHOD': method,
                   'PATH_INFO': path,
                   'CONTENT_TYPE': ctype,
                   'CONTENT_LENGTH': len(body_bytes),
                   'wsgi.input': io.BytesIO(body_bytes)}
        return environ

    def test_no_service_config(self):
        self.set_environ_config(service=None)
        self.assertRaises(KeyError, emailer.EmailerApp)

    def test_no_api_key_config(self):
        self.set_environ_config(api_key=None)
        self.assertRaises(KeyError, emailer.EmailerApp)

    def test_bad_service_config(self):
        self.set_environ_config(service='Rubbish')
        self.assertRaises(Exception, emailer.EmailerApp)

    def test_configures_mailgun(self):
        self.set_environ_config()
        email_app = emailer.EmailerApp()
        self.assertTrue(isinstance(email_app.mailer_service, emailer.Mailgun))

    def test_configures_sendgrid(self):
        self.set_environ_config(service=emailer.MAILER_SERVICE_ENV_SENDGRID)
        email_app = emailer.EmailerApp()
        self.assertTrue(isinstance(email_app.mailer_service, emailer.SendGrid))

    def _validation_failure_test_base(self, environ, response_code):
        self.set_environ_config()
        email_app = emailer.EmailerApp()
        mailer_service_mock = unittest.mock.Mock(emailer.MailerService)
        email_app.mailer_service = mailer_service_mock

        start_response_mock = unittest.mock.Mock()
        ret = email_app(environ, start_response_mock)

        mailer_service_mock.send_email.assert_not_called()
        self.assertEqual(ret, '')
        start_response_mock.assert_called_once_with(
            response_code, [('Content-type', 'text/plain')])

    def test_bad_method_request(self):
        environ = self.make_environ_dict(method='PUT')
        response_code = emailer.BadMethodError.ERROR_CODE
        self._validation_failure_test_base(environ, response_code)

    def test_bad_path_request(self):
        environ = self.make_environ_dict(path='/rubbish')
        response_code = emailer.NotFoundError.ERROR_CODE
        self._validation_failure_test_base(environ, response_code)

    def test_bad_content_type_request(self):
        environ = self.make_environ_dict(ctype='text/plain')
        response_code = emailer.BadRequestError.ERROR_CODE
        self._validation_failure_test_base(environ, response_code)

    def test_bad_body_request(self):
        environ = self.make_environ_dict(body='Malformed body.')
        response_code = emailer.BadRequestError.ERROR_CODE
        self._validation_failure_test_base(environ, response_code)

    def _service_error_test_base(self, raise_error, response_code):
        self.set_environ_config()
        email_app = emailer.EmailerApp()
        mailer_service_mock = unittest.mock.Mock(emailer.MailerService)
        mailer_service_mock.send_email.side_effect = raise_error()
        email_app.mailer_service = mailer_service_mock
        environ = self.make_environ_dict()

        start_response_mock = unittest.mock.Mock()
        ret = email_app(environ, start_response_mock)

        # Proper Email object passing is validated in test_successful_request.
        mailer_service_mock.send_email.assert_called_once()
        self.assertEqual(ret, '')
        start_response_mock.assert_called_once_with(response_code,
            [('Content-type', 'text/plain')])

    def test_service_malformed_request_error(self):
        raise_error = emailer.MailerServiceMalformedRequestError
        response_code = emailer.BadRequestError.ERROR_CODE
        self._service_error_test_base(raise_error, response_code)

    def test_service_connection_error(self):
        raise_error = emailer.MailerServiceConnectionError
        response_code = emailer.InternalServerError.ERROR_CODE
        self._service_error_test_base(raise_error, response_code)

    def test_unexpected_internal_exception(self):
        raise_error = Exception
        response_code = emailer.InternalServerError.ERROR_CODE
        self._service_error_test_base(raise_error, response_code)

    def test_successful_request(self):
        self.set_environ_config()
        email_app = emailer.EmailerApp()
        mailer_service_mock = unittest.mock.Mock(emailer.MailerService)
        email_app.mailer_service = mailer_service_mock

        email_json, email_json_str = make_email_json()
        environ = self.make_environ_dict(body=email_json_str)

        start_response_mock = unittest.mock.Mock()
        ret = email_app(environ, start_response_mock)

        mailer_service_mock.send_email.assert_called_once()
        submitted_email = mailer_service_mock.send_email.call_args[0][0]
        self.assertEqual(submitted_email.to_email, email_json['to'])
        self.assertEqual(submitted_email.to_name, email_json['to_name'])
        self.assertEqual(submitted_email.from_email, email_json['from'])
        self.assertEqual(submitted_email.from_name, email_json['from_name'])
        self.assertEqual(submitted_email.subject, email_json['subject'])
        self.assertEqual(submitted_email.body, email_json['body'])

        self.assertEqual(ret, '')
        start_response_mock.assert_called_once_with('202 Accepted',
            [('Content-type', 'text/plain')])


if __name__ == '__main__':
    logging.disable(logging.CRITICAL)
    unittest.main()
