from jwt_token import create_token

TEST_ISSUER = 'user:transhap'
TEST_SCOPE = []
TEST_SUBJECT = 'demo:user'

def test_create_token():
    token = create_token(TEST_ISSUER, TEST_SUBJECT, TEST_SCOPE)
    assert token is not None
    assert type(token) == bytes