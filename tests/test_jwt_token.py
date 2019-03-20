from jwt_token import create_token

def test_create_token():
    token = create_token('user:transhap')
    assert token is not None
    assert type(token) == bytes