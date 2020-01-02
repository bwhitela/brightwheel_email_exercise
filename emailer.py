"""EmailerApp WSGI Web Application.

This file contains a web application for sending email either via Mailgun or
SendGrid. All related classes are contained within this file, so no additional
files are required to run this application.

The third-party library BeautifulSoup is used to convert HTML email bodies into
plain text. The widely used Requests library is used to send HTTP requests to
both delivery services.
"""

import argparse
import json
import logging
import os
import re
import sys
from wsgiref.simple_server import make_server

from bs4 import BeautifulSoup
import requests
import requests.exceptions


# Mailer service environmental variables:
MAILER_SERVICE_ENV = 'MAILER_SERVICE'
MAILER_SERVICE_ENV_MAILGUN = 'Mailgun'
MAILER_SERVICE_ENV_SENDGRID = 'SendGrid'
MAILER_SERVICE_KEY_ENV = 'MAILER_SERVICE_KEY'


class MalformedEmailError(Exception):
    """Error raised by the Email class when an email cannot be created."""
    pass


class Email():
    """Class to represent an email.

    This object is created from a serialized JSON string which contains an
    object with all the following keys: 'to', 'to_name', 'from', 'from_name',
    'subject', 'body'

    Some relevant attributes:

    'to_email': The email's 'to' field.
    'to_name': The email recipient's name.
    'from_email': The email's 'from' field.
    'from_name': The email sender's name.
    'subject': The email's 'subject' field.
    'html_body': The email's original HTML body.
    'body': The email's HTML body converted to plain text.
    """

    # Regex to match probably 99% of email addresses:
    EMAIL_REGEX = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'

    def __init__(self, json_str):
        self._log = logging.getLogger('Email')
        self._email_re = re.compile(Email.EMAIL_REGEX)

        self._parse_json_str(json_str)
        self._convert_html_body()

    def _parse_json_str(self, json_str):
        try:
            self._log.debug('Trying to de-serialize JSON string: %s', json_str)
            email_json = json.loads(json_str)
            self._log.debug('JSON object: %s', email_json)
        except json.JSONDecodeError as err:
            self._log.error('JSON string could not be decoded.')
            raise MalformedEmailError()

        if not isinstance(email_json, dict):
            self._log.error('JSON is not a dictionary.')
            raise MalformedEmailError()
        if len(email_json) != 6:
            self._log.error('JSON dictionary does not have enough keys.')
            raise MalformedEmailError()

        try:
            self.to_email = email_json['to']
            self.to_name = email_json['to_name']
            self.from_email = email_json['from']
            self.from_name = email_json['from_name']
            self.subject = email_json['subject']
            self.html_body = email_json['body']
        except KeyError as err:
            self._log.error('JSON dictionary missing a field. %s', err)
            raise MalformedEmailError()

        if not self._email_re.match(self.to_email):
            self._log.error('To field is malformed: %s', self.to_email)
            raise MalformedEmailError()
        if not self._email_re.match(self.from_email):
            self._log.error('From field is malformed: %s', self.from_email)
            raise MalformedEmailError()

    def _convert_html_body(self):
        try:
            self._log.debug('Converting HTML to text for: %s', self.html_body)
            soup = BeautifulSoup(self.html_body, 'html.parser')
            self.body = soup.get_text()
            self._log.debug('Plain text from HTML: %s', self.body)
        # Blanket exception handling is bad practice but the BeautifulSoup
        # documentation does not provide a clear answer to what type of
        # exception is raised when parsing fails.
        except Exception as err:
            self._log.exception('HTML could not be parsed. %s', err)
            raise MalformedEmailError()


class MailerServiceError(Exception):
    """General/Base error for the 3rd party mailer service."""
    pass


class MailerServiceConnectionError(MailerServiceError):
    """Error when connection error occurs with the 3rd party mailer service."""
    pass


class MailerServiceAuthError(MailerServiceError):
    """Error when authentication fails with the 3rd party mailer service."""
    pass


class MailerServiceMalformedRequestError(MailerServiceError):
    """Error when the 3rd party mailer service claims request is malformed."""
    pass


class MailerServiceSystemError(MailerServiceError):
    """Error when the 3rd party mailer service is down/inaccessible."""
    pass


class MailerServiceUnexpectedError(MailerServiceError):
    """Encapsulates unanticipated errors with the 3rd party mailer service."""
    pass


class MailerService():
    """Interface definition for 3rd party email delivery services."""

    def __init__(self, api_key):
        raise NotImplementedError

    def send_email(self, email_object):
        """Sends the email to the service for delivery.

        'email_object': Should be an Email object.

        raises: Various MailerServiceError's depending on errors incurred while
            interacting with the 3rd party email delivery service.
        """
        raise NotImplementedError


class Mailgun(MailerService):
    """Class to represent the Mailgun email delivery service."""

    def __init__(self, api_key):
        self._log = logging.getLogger('Mailgun')
        self._url = 'https://api.mailgun.net/v3/%s/messages'
        self._api_key = api_key

    def send_email(self, email_object):
        """Sends the email to the Mailgun service for delivery.

        'email_object': Should be an Email object.

        raises: Various MailerServiceError's depending on errors incurred while
            interacting with the Mailgun email delivery service.
        """
        domain = email_object.from_email.split('@')[1]
        url = self._url % (domain,)
        self._log.debug('Mailgun URL for request: %s', url)

        from_field = '%s <%s>' % (email_object.from_name,
                                  email_object.from_email)
        to_field = '%s <%s>' % (email_object.to_name,
                                email_object.to_email)
        form_data = {'from': from_field,
                     'to': to_field,
                     'subject': email_object.subject,
                     'text': email_object.body}
        self._log.debug('Form data submitted to Mailgun: %s', form_data)
        try:
            resp = requests.post(url, auth=('api', self._api_key),
                                 data=form_data)
            self._log.info('Mailgun response code: %s, response body: %s',
                           resp.status_code, resp.text)
            if resp.status_code == 400:
                raise MailerServiceMalformedRequestError()
            elif resp.status_code == 401:
                raise MailerServiceAuthError()
            elif resp.status_code >= 500:
                raise MailerServiceSystemError()
            elif resp.status_code >= 300:
                raise MailerServiceUnexpectedError()
        except requests.exceptions.ConnectionError as err:
            self._log.error('Connection error to Mailgun: %s', err)
            raise MailerServiceConnectionError()
        except requests.exceptions.Timeout as err:
            self._log.error('Timeout to Mailgun: %s', err)
            raise MailerServiceConnectionError()


class SendGrid(MailerService):
    """Class to represent the SendGrid email delivery service."""

    def __init__(self, api_key):
        self._log = logging.getLogger('SendGrid')
        self._url = 'https://api.sendgrid.com/v3/mail/send'
        self._api_key = api_key

    def send_email(self, email_object):
        """Sends the email to the SendGrid service for delivery.

        'email_object': Should be an Email object.

        raises: Various MailerServiceError's depending on errors incurred while
            interacting with the SendGrid email delivery service.
        """
        headers = {'Authorization': 'Bearer %s' % (self._api_key,)}
        json_data = {'content': [{'type': 'text/plain',
                                  'value': email_object.body}],
                     'from': {'email': email_object.from_email,
                              'name': email_object.from_name},
                     'personalizations': [
                         {'to': [{'email': email_object.to_email,
                                  'name': email_object.to_name}]}],
                     'subject': email_object.subject}
        self._log.debug('JSON data submitted to SendGrid: %s', json_data)
        try:
            resp = requests.post(self._url, headers=headers, json=json_data)
            self._log.info('SendGrid response code: %s, response body: %s',
                           resp.status_code, resp.text)
            if resp.status_code == 400:
                raise MailerServiceMalformedRequestError()
            elif resp.status_code in (401, 403):
                raise MailerServiceAuthError()
            elif resp.status_code >= 500:
                raise MailerServiceSystemError()
            elif resp.status_code >= 300:
                raise MailerServiceUnexpectedError()
        except requests.exceptions.ConnectionError as err:
            self._log.error('Connection error to SendGrid: %s', err)
            raise MailerServiceConnectionError()
        except requests.exceptions.Timeout as err:
            self._log.error('Timeout to SendGrid: %s', err)
            raise MailerServiceConnectionError()


# HTTP Errors:


class HTTPError(Exception):
    """Generic HTTP error."""
    ERROR_CODE = '500 Internal Server Error'


class BadRequestError(HTTPError):
    """400 Bad Request error."""
    ERROR_CODE = '400 Bad Request'


class BadMethodError(HTTPError):
    """405 Method Not Allowed error."""
    ERROR_CODE = '405 Method Not Allowed'


class NotFoundError(HTTPError):
    """404 Not Found error."""
    ERROR_CODE = '404 Not Found'


class InternalServerError(HTTPError):
    """500 Internal Server Error error."""
    ERROR_CODE = '500 Internal Server Error'


# WSGI application:
class EmailerApp():
    """WSGI-compliant web service to redirect email to third-party senders."""

    def __init__(self):
        self._log = logging.getLogger('EmailerApp')
        try:
            mailer_service_config = os.environ[MAILER_SERVICE_ENV]
            mailer_service_api_key = os.environ[MAILER_SERVICE_KEY_ENV]
        except KeyError as err:
            self._log.exception('Missing configuration environmental variable.')
            raise
        if mailer_service_config == MAILER_SERVICE_ENV_MAILGUN:
            self.mailer_service = Mailgun(mailer_service_api_key)
        elif mailer_service_config == MAILER_SERVICE_ENV_SENDGRID:
            self.mailer_service = SendGrid(mailer_service_api_key)
        else:
            self._log.error('Mailer service env configuration invalid: %s',
                            mailer_service_config)
            raise Exception('Invalid mailer service.')
        self._log.info('Running the EmailerApp with the %s mailer service.',
                       mailer_service_config)

    def __call__(self, environ, start_response):
        try:
            body = self._validate_request(environ)
            try:
                email = Email(body)
                self.mailer_service.send_email(email)
            except MalformedEmailError as err:
                self._log.error('Malformed email submitted.')
                raise BadRequestError()
            except MailerServiceMalformedRequestError as err:
                self._log.error('Email malformed according to service.')
                raise BadRequestError()
            except (MailerServiceConnectionError, MailerServiceAuthError,
                    MailerServiceSystemError, MailerServiceUnexpectedError) \
                    as err:
                self._log.exception('Error when communicating with mailer '
                                    'service. %s', err)
                raise InternalServerError()

        except HTTPError as err:
            start_response(err.ERROR_CODE, [('Content-type', 'text/plain')])
            return ''
        except Exception as err:
            self._log.exception('Unexpected error occurred: %s', err)
            start_response('500 Internal Server Error',
                           [('Content-type', 'text/plain')])
            return ''

        start_response('202 Accepted', [('Content-type', 'text/plain')])
        return ''

    def _validate_request(self, environ):
        """Raise HTTP error for malformed request, otherwise return body."""
        method = environ['REQUEST_METHOD']
        path = environ['PATH_INFO']
        content_type = environ['CONTENT_TYPE']
        content_length = environ['CONTENT_LENGTH']

        body = ''
        if content_length and int(content_length):
            body = environ['wsgi.input'].read(int(content_length))

        if method != 'POST':
            self._log.error('Incorrect method requested: %s', method)
            raise BadMethodError()
        if path != '/email':
            self._log.error('Incorrect resource requested: %s', path)
            raise NotFoundError()
        if content_type != 'application/json':
            self._log.error('Incorrect content type: %s', content_type)
            raise BadRequestError()

        return body


# The stuff below is not strictly part of the web application but in place for
# convenience, so running the file will start up a web server hosting the
# application. This is not intended for production use. The application should
# be run behind something like mod_wsgi or uWSGI.


def parse_args():
    """Parses all the command line arguments and options."""
    parser = argparse.ArgumentParser(description='EmailerApp server')
    parser.add_argument('--hostname', default='localhost',
                        help='Hostname for EmailerApp. Default: localhost')
    parser.add_argument('--port', '-p', type=int, default=8080,
                        help='Port to run EmailerApp on. Default: 8080')
    parser.add_argument('--verbose', '-v', action='store_true', default=False,
                        help='Include debug logging.')
    parser.add_argument('--apikey', default=None,
                        help='Will overwrite env variable MAILER_SERVICE_KEY. '
                        'An API key MUST be specified (as an env variable or '
                        'option) or else the application will not run.')
    parser.add_argument('--service', default=None,
                        help='Will overwrite env variable MAILER_SERVICE. '
                        'Possible values are \'%s\' and \'%s\'. A service MUST '
                        'be specified (as an env variable or option) or else '
                        'the application will not run.' %
                        (MAILER_SERVICE_ENV_MAILGUN,
                         MAILER_SERVICE_ENV_SENDGRID))
    return parser.parse_args()


def main():
    """The main function, which sets up and runs an EmailerApp server."""
    args = parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, stream=sys.stdout)

    if args.apikey:
        os.environ[MAILER_SERVICE_KEY_ENV] = args.apikey
    if args.service:
        os.environ[MAILER_SERVICE_ENV] = args.service

    email_app = EmailerApp()
    httpd = make_server(args.hostname, args.port, email_app)
    logging.info('Starting server...')
    httpd.serve_forever()


if __name__ == "__main__":
    main()
