import httpclient, tables, cgi, json

type
  TStringConverter = proc (str: string): string {.nimcall.}
  TUrlQueryArgs = Table[string, string]
  EInvalidGrant = object of Exception
  OAuth2Flow* = ref object of RootObj
    clientId: string
    clientSecret: string
    scopes: seq[string]
    redirectUri: string
    authUri: string
    tokenUri: string
  Credentials* = object of RootObj
    accessToken*: string
    refreshToken*: string
    expiresIn*: BiggestInt

let
  DefaultStringConverter = proc (str: string): string = result = str


proc newOAuth2Flow*(clientId: string, clientSecret: string,
                    scopes: openarray[string], redirectUri: string,
                    authUri: string, tokenUri: string): OAuth2Flow =
  ## Create a new oauth flow
  new(result)
  result.clientId = clientId
  result.clientSecret = clientSecret
  result.scopes = @scopes
  result.redirectUri = redirectUri
  result.authUri = authUri
  result.tokenUri = tokenUri


proc createQuery(args: TUrlQueryArgs, 
                 procedure: TStringConverter = DefaultStringConverter): string = 
  ## Encode the given args for be inserted in a url
  result = ""
  var first = true
  for pair in args.pairs:
    let separator = if first: "" else: "&"
    result &= separator & pair[0] & "=" & procedure(pair[1])
    first = false


proc createUrl(url: string, args: TUrlQueryArgs,
               procedure: TStringConverter = DefaultStringConverter): string =
  ## Create an url by appending the given arguments
  result = url
  if args.len > 0: 
    result &= "?" & createQuery(args, procedure)


proc checkResponse(json: JsonNode) =
  ## Check if the given json contains an error 
  let hasError = json.hasKey("error")
  if not hasError:
    return
  let error = json["error"].str
  case error
  of "invalid_grant":
    raise newException(EInvalidGrant, error)
  else:
    raise newException(Exception, error)


proc concatAndEncodeScopes(scopes: openarray[string]): string =
  ## Concat and encode scopes
  result = ""
  for scope in scopes:
    if scope != scopes[0]:
        result &= " "
    result &= scope
  result = encodeUrl(result)


proc step1GetAuthorizeUrl*(flow: OAuth2Flow): string =
  ## Obtain the authorization url
  var args = initTable[string, string]()
  args["response_type"] = "code"
  args["client_id"] = flow.clientId
  args["redirect_uri"] = flow.redirectUri
  args["scope"] = concatAndEncodeScopes(flow.scopes)
  return createUrl(flow.authUri, args)


proc step2Exchange*(flow: OAuth2Flow, accessCode: string): Credentials =
  ## Exchange the access code for an access token
  var args = initTable[string, string]()
  args["code"] = accessCode
  args["client_id"] = flow.clientId
  args["client_secret"] = flow.clientSecret
  args["redirect_uri"] = flow.redirectUri
  args["grant_type"] = "authorization_code"
  let headers = "Content-Type: application/x-www-form-urlencoded\c\L"
  let response = post(flow.tokenUri, headers, createQuery(args))
  let json = parseJson(response.body)
  checkResponse(json)
  result.accessToken = json["access_token"].str
  result.refreshToken = json["refresh_token"].str
  result.expiresIn = json["expires_in"].num
  
proc refreshAccessToken*(flow: OAuth2Flow, credentials: var Credentials) =
  ## Refresh an access token
  var args = initTable[string, string]()
  args["client_id"] = flow.clientId
  args["client_secret"] = flow.clientSecret
  args["refresh_token"] = credentials.refreshToken
  args["grant_type"] = "refresh_token"
  let headers = "Content-Type: application/x-www-form-urlencoded\c\L"
  let response = post(flow.tokenUri, headers, createQuery(args))
  let json = parseJson(response.body)
  checkResponse(json)
  credentials.accessToken = json["access_token"].str
  credentials.expiresIn = json["expires_in"].num
  
