# James' IndieAuth Endpoint

This repository contains the code for my IndieAuth endpoint. This endpoint has been developed to comply with the [IndieAuth specification](https://indieauth.spec.indieweb.org), a method of authentication built on top of OAuth 2.0.

Using this project, you can authenticate yourself to a service by using RelMeAuth. RelMeAuth requires you have rel="me" links on your blog that link to social profiles. At the moment, this project only supports the following rel=me links:

- GitHub
- Twitter

You can also authenticate using Okta Verify's passwordless solution. To do so, you will need to have an active Okta developer account.

## Screenshot

![Authorization page on the IndieAuth endpoint](screenshot.png)

## Setup

To setup this project, first install the required dependencies. You can do this using the following command:

    pip3 install -r requirements.txt

Next, you will need to add some configration variables to a file called config.py.

Create a file called config.py in the root directory of the project. Add the following value to the file:

    ME="https://yourdomain.com"
    
Next, add your Twitter API keys to the file like so (leave all values you do not want to specify as ""):

    TWITTER_OAUTH_KEY="KEY"
    TWITTER_OAUTH_SECRET="SECRET"

These values can be obtained from [Twitter](https://developer.twitter.com). You will need a Twitter Developer account to obtain these values.

Then add your GitHub OAuth API keys (leave all values you do not want to specify as ""):

    GITHUB_CLIENT_ID = "ID"
    GITHUB_OAUTH_REDIRECT = "URL"
    GITHUB_CLIENT_SECRET = "SECRET"

You can retrieve these pieces of information by following the GitHub "[Creating an OAuth App](https://docs.github.com/en/developers/apps/building-oauth-apps/creating-an-oauth-app)" guide.

Next, add your Okta API keys (leave all values you do not want to specify as ""):

    OKTA_DOMAIN = "https://dev-23456okta.com"
    OKTA_ACCESS_TOKEN = "TOKEN"
    OKTA_USER_ID = "ID"
    OKTA_FACTOR_ID = "ID"

You can learn more about Okta and their APIs by reading the [Okta API documentation](https://developer.okta.com/docs/api/getting-started/).

Using the keys above, this application will be able to authenticate you using Twitter, GitHub, and Okta.

Next, run the IndieAuth server using Flask:

    python3 app.py

If you plan to deploy the server on production, please use an appropriate production deployment method (i.e. using Gunicorn) as you would for any other Flask application.

## Licence

This project is licensed under the [MIT License](LICENSE)

## Contributors

- capjamesg