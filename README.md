# SendMailNim
Simple application for sending email through your GMail account

# Install
Simply invoke
```
nimble build
```

# Usage
First you need obtain a clientId and a clientSecret
from google by creating an application on your google api
console.

Once you have a clientId and clientSecret invoke
the application as follows
```
SendMail --setup --clientId:yourClientId --clientSecret:yourClientSecret
```
Follow the instruction for obtaining an access token

Once you correctly obtained an access token invoke
the application as follows:
```
SendMail --from:"fromEmail" --to:"toEmail" --subject:"yourSubject" --body:"yourEmailBody"
```

Enjoy