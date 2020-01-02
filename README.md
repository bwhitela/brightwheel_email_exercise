# Brett Whitelaw's Brightwheel Email Exercise

This is Brett Whitelaw's Brightwheel interview exercise written in Python 3.

## Install

This web service application was written in Python 3, so please ensure your system is able to run Python 3 and has it installed.

An effort was made to utilize as few 3rd party packages as possible but two will be needed to run this application. These are the often used BeautifulSoup library and the, almost standard, Requests library. These have both been specified in a `requirements.txt` file for use with the Python package manager `pip`. If you choose to use something other than `pip`, please reference the package names and versions in the requirements file.

Additionally, you may find it convenient to make use of a virtualized Python environment. I made use of `virtualenv` in the development of this application. You can find a good guide to virtualized Python environments at [https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/).

Now, assuming you have Python 3 available on your system, you have `pip` available for package management, and you, potentially, have set up a virtual Python environment, we can proceed to install the necessary 3rd party packages. Simply run the following command from within the root directory of the project:

    pip install -r requirements.txt

In an effort to keep things simple, there is no further installation process necessary. The entire application is self-contained in `emailer.py`. The application is WSGI-compliant, however, so if you would like to make use of something like mod_wsgi for Apache web servers or uWSGI in conjunction with something like Nginx, you are free to do so, but for demonstration and some test purposes, these are not necessary.

## Running

In an effort to keep things simple, configuration was kept to a minimum. There are only two pieces of configuration information needed and these are controlled through environment variables. These are:

* `MAILER_SERVICE` - Can be one of two values (`Mailgun` or `SendGrid`) depending on which mailer service you want to utilize.
* `MAILER_SERVICE_KEY` - This should be the API key for use with the specified service.

You can set these in your shell as you would normally set environment variables or, for convenience, you can make use of some command line options when running the application.

As I have said above, simplicity was key, here, so to run the application, all you have to do is run the `emailer.py` file with Python 3. Here is the command line usage prompt:

    usage: emailer.py [-h] [--hostname HOSTNAME] [--port PORT] [--verbose]
                      [--apikey APIKEY] [--service SERVICE]

    EmailerApp server

    optional arguments:
      -h, --help            show this help message and exit
      --hostname HOSTNAME   Hostname for EmailerApp. Default: localhost
      --port PORT, -p PORT  Port to run EmailerApp on. Default: 8080
      --verbose, -v         Include debug logging.
      --apikey APIKEY       Will overwrite env variable MAILER_SERVICE_KEY. An API
                            key MUST be specified (as an env variable or option)
                            or else the application will not run.
      --service SERVICE     Will overwrite env variable MAILER_SERVICE. Possible
                            values are 'Mailgun' and 'SendGrid'. A service MUST be
                            specified (as an env variable or option) or else the
                            application will not run.

I have made use of the standard Python logging system, but have simply left it in the default mode of logging to standard out, so you will see logging on the command line as you run the application.

## Languages, Frameworks, Packages, and Why

I wrote this application in Python because I am very well versed in this language. Python 3 was selected over Python 2 because Python 2 is losing support. Python is widely used for web service applications, so is fitting for this application.

Because this application is so simple, I elected to not use any framework and simply code against the WSGI standard. Things like Django are too heavy handed for something so simple and even using a simple framework like Flask would likely end up being more work.

Every effort was made to reduce the usage of 3rd party packages. However, to simplify implementation I made the call to use two packages. I have used the BeautifulSoup package to do the conversion of HTML into plain-text. This library is widely used in the industry, and simplifies the parsing of HTML, immensely. Additionally, I have made use of the Requests HTTP library because it is simple and is pretty much treated as built-in by the Python community.

### Implementation Notes

I just wanted to call out a few things to keep in mind while reviewing this exercise.

The specification states that the service should do appropriate validations on the input fields of the submitted JSON, but makes no further clarifications. I took this to mean that the email address fields should be checked for validity. Full validation of email addresses is not so simple and is probably best determined by simply sending email to it. In lieu of this, I have made use of a regex that should match nearly all valid email addresses. It can be found in the `Email` class as `EMAIL_REGEX`.

The goal of this exercise is to develop something that is tolerant to failures of an external service, allowing for fail-over. This full functionality is not required by the exercise, as the directions say fail-over would be done with a configuration change and re-deploy. This is what I have implemented. It would be much better, however, if the application held all service configuration information, with a priority list, and automatically try the next service when one fails. Additionally, while failure information is captured in the logs that my application writes, it would be better if hooks were added in, in conjunction with a monitoring service, to keep the operator informed of problems with the external services.

Lastly, depending on what WSGI-compliant application wrapper is used for a production deployment, it might be necessary to add in additional configuration handling to set up the logging system in a way that is more compatible with the application wrapper or system setup.

## Testing

I have written a very thorough test suite to ensure that the application works as specified. No additional 3rd party packages are necessary, as all the tests are written with the built-in `unittest` module and make use of the built-in `mock` module. All tests are contained in the `tests.py` file, so all that is needed to execute the test cases is run the file with Python 3 (e.g. `python tests.py`).
