import parseopt2, OAuth2Flow, json, os, httpclient, strutils


type
  Options = object of RootObj
    setup: bool
    accessToken: string
    refreshToken: string
    expiresIn: BiggestInt
    clientId: string
    clientSecret: string
    fromField: string
    toField: string
    subjectField: string
    bodyField: string
  OptionsParseException = object of Exception
  OptionsValidateException = object of Exception
  ConfigFileParseException = object of Exception
  SendException = object of Exception


proc isNullOrEmpty(temp: string): bool =
  ## Return true if the string is null or empty, false otherwise
  return temp == nil or temp == ""


proc printUsage() =
  ## Print executable usage
  echo "Usage:"
  echo "--help:             print this message"
  echo "--setup:            initialize the access token and create the the config file"
  echo "  --clientId:       sets the client id"
  echo "  --clientSecret:   sets the client secret"
  echo "--from:             sets the email from field"
  echo "--to:               sets the email to field"
  echo "--subject:          sets the email subject field"
  echo "--body:             sets the email body field"
  echo ""
  echo "Examples:"
  echo "./executable --setup --clientId:yourclientid --clientSecret:--yourclientsecret"
  echo "./executable --from:\"sender\" --to:\"receiver\" --subject:\"thesubject\" --body:\"thebody\""


proc readOptionsFromCommandLine(options: var Options) =
  ## Read the options from the command line args
  for kind, key, val in getopt():
    case kind
    of cmdLongOption:
      case key
      of "setup": options.setup = true
      of "from": options.fromField = val
      of "to": options.toField = val
      of "subject": options.subjectField = val
      of "body": options.bodyField = val
      of "clientId": options.clientId = val
      of "clientSecret": options.clientSecret = val
      else: raise newException(OptionsParseException, "Unexpected option key")
    else:
      raise newException(OptionsParseException, "Unexpected option " & $kind & " " & key & val)


proc validateOptions(fileName: string, options: Options) =
  ## Validate the options
  if options.setup:
    if options.clientId.isNullOrEmpty:
      raise newException(OptionsValidateException, "--clientId is missing")
    if options.clientSecret.isNullOrEmpty:
      raise newException(OptionsValidateException, "--clientSecret is missing")
  else:
    if not existsFile(fileName):
      raise newException(OptionsValidateException, "No credential file found. Rerun with --setup")
    if options.fromField.isNullOrEmpty:
      raise newException(OptionsValidateException, "--fromField is missing")
    if options.toField.isNullOrEmpty:
      raise newException(OptionsValidateException, "--toField is missing")


proc writeOptionsToConfigFile(fileName: string, options: Options) =
  ## Write the options to the given config file
  let json = newJObject()
  json["accessToken"] = newJString(options.accessToken)
  json["refreshToken"] = newJString(options.refreshToken)
  json["expiresIn"] = newJInt(options.expiresIn)
  json["clientId"] = newJString(options.clientId)
  json["clientSecret"] = newJString(options.clientSecret)
  writeFile(fileName, json.pretty)


proc readOptionsFromConfigFile(fileName: string, options: var Options) =
  ## Read the options from the given config file
  let json = parseFile(fileName)
  if json.kind != JObject:
    raise newException(ConfigFileParseException, "JsonObject expected")
  let accessToken = json["accessToken"].str
  if accessToken.isNullOrEmpty:
    raise newException(ConfigFileParseException, "No accessToken in config file")
  let refreshToken = json["refreshToken"].str
  if refreshToken.isNullOrEmpty:
    raise newException(ConfigFileParseException, "No refreshToken in config file")
  let expiresIn = json["expiresIn"].num
  let clientId = json["clientId"].str
  if clientId.isNullOrEmpty:
    raise newException(ConfigFileParseException, "No clientId in config file")
  let clientSecret = json["clientSecret"].str
  if clientSecret.isNullOrEmpty:
    raise newException(ConfigFileParseException, "No clientSecret in config file")
  options.accessToken = accessToken
  options.refreshToken = refreshToken
  options.expiresIn = expiresIn
  options.clientId = clientId
  options.clientSecret = clientSecret

proc refreshAccessToken(clientId: string, clientSecret: string,
                        refreshToken: string): Credentials =
  let
    scopes = ["https://www.googleapis.com/auth/gmail.send"]
    redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    authUri = "https://accounts.google.com/o/oauth2/auth"
    tokenUri = "https://accounts.google.com/o/oauth2/token"
  let flow = newOAuth2Flow(clientId, clientSecret, scopes,
                           redirectUri, authUri, tokenUri)
  result.refreshToken = refreshToken
  flow.refreshAccessToken(result)

proc setupAccessToken(clientId: string, clientSecret: string): Credentials = 
  ## Obtain an access token
  let
    scopes = ["https://www.googleapis.com/auth/gmail.send"]
    redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    authUri = "https://accounts.google.com/o/oauth2/auth"
    tokenUri = "https://accounts.google.com/o/oauth2/token"

  # Create a flow
  let flow = newOAuth2Flow(clientId, clientSecret, scopes,
                           redirectUri, authUri, tokenUri)

  # Obtain the access code
  let userGrantUrl = flow.step1GetAuthorizeUrl()
  echo "Open your browser at the following url for obtaining an access code"
  echo userGrantUrl
  echo "Paste the obtained access code here:"
  let accessCode = readLine(stdin)

  # Exchange the access code for access token
  let credentials = flow.step2Exchange(accessCode)
  echo "Access token obtained successfully"
  return credentials


proc sendEmail(options: Options) =
  let url = "https://www.googleapis.com/upload/gmail/v1/users/me/messages/send"
  let extraHeadersTemplate = "Authorization: Bearer $accessToken\nContent-Type: message/rfc822"
  let bodyTemplate = "From:$fromField\nTo:$toField\nSubject:$subjectField\n\n$bodyField\n"

  let extraHeaders = format(extraHeadersTemplate, ["accessToken", options.accessToken])
  let body = format(bodyTemplate,["fromField", options.fromField,
                                  "toField", options.toField,
                                  "subjectField", options.subjectField,
                                  "bodyField", options.bodyField])

  let response = post(url, extraHeaders, body)
  if not response.status.startsWith("200"):
    raise newException(SendException, response.body)

proc mainProc() =
  let fileName = "credentials.json"
  var options: Options
  if existsFile(fileName):
    readOptionsFromConfigFile(fileName, options)
  readOptionsFromCommandLine(options)
  validateOptions(fileName, options)
  if options.setup:
    let credentials = setupAccessToken(options.clientId, options.clientSecret)
    options.accessToken = credentials.accessToken
    options.refreshToken = credentials.refreshToken
    options.expiresIn = credentials.expiresIn
    writeOptionsToConfigFile(fileName, options)
  else:
    let credentials = refreshAccessToken(options.clientId, options.clientSecret,
                                         options.refreshToken)
    options.accessToken = credentials.accessToken
    options.expiresIn = credentials.expiresIn
    writeOptionsToConfigFile(fileName, options)
    sendEmail(options)
  quit()

if isMainModule:
  try:
    programResult = QuitFailure
    mainProc()
    programResult = QuitSuccess
  except OptionsParseException:
    echo "An exception occured:"
    echo getCurrentException().msg
    printUsage()
  except OptionsValidateException:
    echo "An exception occured:"
    echo getCurrentException().msg
    printUsage()
  except:
    echo "An exception occured:"
    echo getCurrentException().msg
    echo getCurrentException().getStackTrace()
