"""
Tests for JWT Token Revocation (Security Finding #6) and jti uniqueness.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import timedelta
from jwt.exceptions import PyJWTError as JWTError

from auth.jwt import create_access_token, decode_access_token, revoke_token
import auth.jwt as jwt_module


def test_access_token_has_unique_jti():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    with patch.object(jwt_module, "_redis_client", mock_redis):
        token1 = create_access_token({"sub": "user_1"})
        token2 = create_access_token({"sub": "user_1"})
        
        payload1 = decode_access_token(token1)
        payload2 = decode_access_token(token2)
        
        assert "jti" in payload1
        assert "jti" in payload2
        assert payload1["jti"] != payload2["jti"]


def test_decode_revoked_token_raises_jwt_error():
    mock_redis = MagicMock()
    mock_redis.get.return_value = b"revoked"
    
    token = create_access_token({"sub": "user_2"})
    
    with patch.object(jwt_module, "_redis_client", mock_redis):
        with pytest.raises(JWTError, match="Token has been revoked"):
            decode_access_token(token)
            
        mock_redis.get.assert_called_once()


def test_revoke_token_sets_redis_blacklist():
    mock_redis = MagicMock()
    
    token = create_access_token({"sub": "user_3"}, expires_delta=timedelta(minutes=30))
    
    with patch.object(jwt_module, "_redis_client", mock_redis):
        success = revoke_token(token)
        assert success is True
        mock_redis.setex.assert_called_once()
        args = mock_redis.setex.call_args[0]
        assert args[0].startswith("jwt_blacklist:")
        assert args[2] == "revoked"


def test_decode_token_fails_closed_when_redis_unavailable():
    token = create_access_token({"sub": "user_4"})

    with patch.object(jwt_module, "_redis_client", None):
        with pytest.raises(JWTError, match="Authentication store unavailable"):
            decode_access_token(token)
