#############################################################################
# Settings for the MFA Portal application, including database configuration #
#############################################################################

class Settings:
    def __init__(self):
        self.config_path = "mfaportal/settings.conf"

    def load(self, setting: str):
        # Load settings from a configuration file
        with open(self.config_path, 'r') as file:
            for line in file:
                # Skip comments and empty lines
                if line.startswith('#') or not line.strip():
                    continue

                # Parse setting
                if line.startswith(setting):
                    return line.split('=')[1].strip()
