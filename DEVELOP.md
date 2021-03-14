# DWF reqeust tools

The form lives at https://iwantacve.org
The bot executes seperatly about every ten seconds

# How to develop

You will need some environment variables to make this work

GH_REPO
The repo URL. This is the repo the bot and web form will be working with
For example the prod repo is "distributedweaknessfiling/dwflist"

GH_USERNAME
The username you will auth against github with (this is dwfbot in prod)

GH_TOKEN
This is a github token that is used to modify the repo
(add instructions for generating this)

GH_CLIENT_ID
GH_OAUTH_SECRET
The two above get you from github after creating an OAuth application
Instructions to create this application can be found here
https://docs.github.com/en/developers/apps/creating-an-oauth-app
Your homepage URL can be http://localhost:3000 for local development


SESSION_KEY
This can be literally anything. It's the key used to encrypt the session
cookie.

# webform

The webform is a node.js app that uses express to serve all the content.
For local development run it using `npm run local`
