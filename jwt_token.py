import jwt
import pendulum
from uuid import uuid4

from config import SECRET, ALGORITHM, ALLOWED_ALGORITHMS, TZ
from defaults import TOKEN_EXPIRY_TIME_IN_MINUTES, TOKEN_NBF_IN_SECONDS

from jwt.exceptions import ExpiredSignatureError, InvalidAudienceError, ImmatureSignatureError, InvalidTokenError


def create_token(issuer, subject, scope, audience=None, expiry_time=TOKEN_EXPIRY_TIME_IN_MINUTES, nbf=TOKEN_NBF_IN_SECONDS):
    """[Creates JWT]
    """

    payload = {
        'exp': pendulum.now(TZ).add(minutes=expiry_time),
        'nbf': pendulum.now(TZ).add(seconds=nbf),
        'iat': pendulum.now(TZ),
        'iss': issuer,
        'jti': uuid4().hex,
        'sub': subject,
        'scope': scope  
    }

    headers = {
        'alg': ALGORITHM,
        'typ': 'JWT'
    }

    if audience:
        payload['aud'] = audience

    return jwt.encode(payload, SECRET, algorithm=ALGORITHM, headers=headers)


def token_age(token, audience=None):
    """[Finds age of the token in seconds]
    
    Arguments:
        token {[string]} -- [A JWT]
    
    Returns:
        [tuple] -- [(error/success, response)]
    """

    kwargs = {'algorithms': ALLOWED_ALGORITHMS}
    if audience:
        kwargs.update({'audience': audience})

    try:
        payload = jwt.decode(token, SECRET, **kwargs)
    except ExpiredSignatureError:
        return ('error', 'Token expired')
    except ImmatureSignatureError:
        return ('error', 'Token immature')
    except InvalidAudienceError:
        return ('error', 'Invalid audience specified')
    except InvalidTokenError:
        return ('error', 'Error while decoding token')

    issued_time = payload.get('iat')
    if not issued_time:
        return ('error', 'No information regarding issue time in token')

    return ('success', pendulum.from_timestamp(issued_time, tz=TZ).diff(None, False).in_seconds())
