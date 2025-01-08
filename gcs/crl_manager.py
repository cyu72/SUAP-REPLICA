import json
import logging
from datetime import datetime
import threading
from typing import Set

class CRLManager:
    def __init__(self, config):
        self.config = config
        self.revoked_certificates = set()  
        self.last_update = datetime.utcnow()
        self._lock = threading.Lock()
    
    def add_revoked_cert(self, serial_number: str) -> None:
        """Add a certificate to the revocation list"""
        with self._lock:
            self.revoked_certificates.add(serial_number)  
            self.last_update = datetime.utcnow()
    
    def is_cert_revoked(self, serial_number: str) -> bool:
        """Check if a certificate is revoked"""
        return serial_number in self.revoked_certificates  
    
    def load_crl_from_file(self, filepath: str) -> None:
        """Load CRL from a file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                with self._lock:
                    self.revoked_certificates = set(data.get('revoked_certificates', []))  
                    self.last_update = datetime.fromisoformat(data.get('last_update', datetime.utcnow().isoformat()))
        except Exception as e:
            logging.error(f"Failed to load CRL: {str(e)}")
    
    def save_crl_to_file(self, filepath: str) -> None:
        """Save CRL to a file"""
        with self._lock:
            data = {
                'last_update': self.last_update.isoformat(),
                'revoked_certificates': list(self.revoked_certificates)  
            }
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)

    def initialize_empty_crl(filepath: str) -> None:
        """Create a new empty CRL file with correct format"""
        crl_data = {
            'version': '1.0',
            'last_update': datetime.utcnow().isoformat(),
            'next_update': (datetime.utcnow() + timedelta(days=1)).isoformat(),
            'revoked_certificates': []
        }
        
        with open(filepath, 'w') as f:
            json.dump(crl_data, f, indent=4)