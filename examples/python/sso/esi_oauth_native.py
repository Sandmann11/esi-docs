import base64
import hashlib
import secrets

from shared_flow import print_auth_url
from shared_flow import send_token_request
from shared_flow import handle_sso_token_response


def main():

    # Generate the PKCE code challenge
    
    random = base64.urlsafe_b64encode(secrets.token_bytes(32))
    m = hashlib.sha256()
    m.update(random)
    d = m.digest()
    code_challenge = base64.urlsafe_b64encode(d).decode().replace("=", "")
    print(random)
    print(code_challenge)
    client_id = "b09e2123bd9346338dcecaf66e7f15b1"

    print_auth_url(client_id, code_challenge=code_challenge)

    auth_code = input("Copy the \"code\" query parameter and enter it here: ")

    code_verifier = random

    form_values = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": auth_code,
        "code_verifier": code_verifier
    }

    print("\nBecause this is using PCKE protocol, your application never has "
          "to share its secret key with the SSO. Instead, this next request "
          "will send the base 64 encoded unhashed value of the code "
          "challenge, called the code verifier, in the request body so EVE's "
          "SSO knows your application was not tampered with since the start "
          "of this process. The code verifier generated for this program is "
          "{} derived from the raw string {}".format(code_verifier, random))

    input("\nPress any key to continue:")

    res = send_token_request(form_values)

    handle_sso_token_response(res)


if __name__ == "__main__":
    main()
