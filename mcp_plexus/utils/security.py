# mcp_plexus/utils/security.py
import logging
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from base64 import urlsafe_b64decode

logger = logging.getLogger(__name__)


def generate_fernet_key() -> str:
    """Generates a new Fernet key and returns it as a string."""
    key_bytes = Fernet.generate_key()
    return key_bytes.decode('utf-8')


class FernetEncryptor:
    """Handles encryption and decryption using Fernet symmetric encryption."""
    
    def __init__(self, encryption_key: Optional[str]):
        """
        Initialize the encryptor with a Fernet-compatible key.
        
        Args:
            encryption_key: Base64-encoded Fernet key string, or None
        """
        if not encryption_key:
            logger.critical(
                "CRITICAL: PLEXUS_ENCRYPTION_KEY is not set. "
                "API key encryption/decryption will fail."
            )
            self.fernet_instance: Optional[Fernet] = None
            self.key_valid = False
        else:
            try:
                key_bytes = encryption_key.encode('utf-8')
                
                # Validate that the key decodes to exactly 32 bytes as required by Fernet
                decoded_key_bytes = urlsafe_b64decode(key_bytes)
                if len(decoded_key_bytes) != 32:
                    logger.error(
                        f"Invalid PLEXUS_ENCRYPTION_KEY length after base64 decoding. "
                        f"Expected 32 bytes, got {len(decoded_key_bytes)}."
                    )
                    self.fernet_instance = None
                    self.key_valid = False
                else:
                    self.fernet_instance = Fernet(key_bytes)
                    self.key_valid = True
                    logger.info("FernetEncryptor initialized successfully with a valid key.")
            except Exception as e:
                logger.error(
                    f"Failed to initialize FernetEncryptor with provided key. Error: {e}",
                    exc_info=True
                )
                self.fernet_instance = None
                self.key_valid = False

    def encrypt(self, data: str) -> Optional[str]:
        """
        Encrypt a string using Fernet encryption.
        
        Args:
            data: Plain text string to encrypt
            
        Returns:
            Encrypted data as a string, or None if encryption fails
        """
        if not self.fernet_instance or not self.key_valid:
            logger.error("Cannot encrypt: Fernet instance not available or key is invalid.")
            return None
        try:
            return self.fernet_instance.encrypt(data.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption failed: {e}", exc_info=True)
            return None

    def decrypt(self, encrypted_data: str) -> Optional[str]:
        """
        Decrypt a Fernet-encrypted string.
        
        Args:
            encrypted_data: Encrypted data string to decrypt
            
        Returns:
            Decrypted plain text string, or None if decryption fails
        """
        if not self.fernet_instance or not self.key_valid:
            logger.error("Cannot decrypt: Fernet instance not available or key is invalid.")
            return None
        try:
            return self.fernet_instance.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')
        except InvalidToken:
            logger.error(
                "Decryption failed: Invalid token. "
                "This may be due to an incorrect key or corrupted data."
            )
            return None
        except Exception as e:
            logger.error(f"Decryption failed: {e}", exc_info=True)
            return None