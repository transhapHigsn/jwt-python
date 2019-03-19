import jwt
import pendulum

from config import SECRET, ALGORITHM, ALLOWED_ALGORITHMS, TZ


def create_token(issuer, audience=None):
    """[Creates JWT]
    """

    payload = {
        'name': 'higsn',
        'exp': pendulum.now(TZ).add(minutes=3),
        'nbf': pendulum.now(TZ).add(seconds=10),
        'iat': pendulum.now(TZ),
        'iss': issuer   
    }

    if audience:
        payload['audience'] = audience

    return jwt.encode(payload, SECRET, algorithm=ALGORITHM)


def token_age(token, aud=None):
    """[Finds age of the token in seconds]
    
    Arguments:
        token {[string]} -- [A JWT]
    
    Returns:
        [tuple] -- [(error/success, response)]
    """

    kwargs = {'algorithms': ALLOWED_ALGORITHMS}
    if aud:
        kwargs.update({'aud': aud})

    try:
        payload = jwt.decode(token, SECRET, **kwargs)
    except:
        return ('error', 'Error while decoding token.')

    issued_time = payload.get('iat')
    if not issued_time:
        return ('error', 'No information regarding issue time in token')

    return ('success', pendulum.from_timestamp(issued_time, tz=TZ).diff(None, False).in_seconds())
