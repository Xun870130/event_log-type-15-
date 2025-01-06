import configparser


class SmbiosType15:
    """
    A class to parse and manage SMBIOS Type 15 configuration from an .ini file.
    """
    def __init__(self, file_path:str="smbios_type15.ini"):
        """
        Initialize the parser and rebuild the dictionary from the specified .ini file.

        :param file_path: Path to the SMBIOS Type 15 configuration file.
        """
        self.config = configparser.ConfigParser()
        self.type15 = {}
        self.file_path = file_path
        self.build()  

    def expanded_keys(self, section_dict:dict)->dict:
        """
        Expand range keys into individual key-value pairs.

        :param section_dict: Dictionary containing keys and values from a section.
        :return: Expanded dictionary with individual key-value pairs.
        """
        parsed = {}
        for key, value in section_dict.items():
            key = key.strip('"')  
            value = value.strip('"')  
            if '-' in key:  
                start, end = key.split('-')
                for i in range(int(start, 16), int(end, 16) + 1):  
                    parsed[f"{i:02X}"] = value
            else:
                parsed[key] = value  
        return parsed

    def build(self):
        """
        Read the .ini file and rebuild the internal dictionary.
        """
        self.config.optionxform = str 
        with open(self.file_path, "r", encoding="utf-8") as file:
            self.config.read_file(file)

        for section in self.config.sections():
            raw_dict = dict(self.config[section])
            self.type15[section] = self.expanded_keys(raw_dict)

    def print_type(self):
        """
        Print the parsed SMBIOS Type 15 configuration.
        """
        for section, data in self.type15.items():
            print(f"[{section}]")
            for key, value in data.items():
                print(f"{key} = {value}")

    def get(self, section:str, key:str)->str:
        """
        Retrieve a value from the parsed configuration.

        :param section: Section name in the .ini file.
        :param key: Key within the section.
        :return: The corresponding value.
        :raises KeyError: If the key is not found in the section.
        """
        if section in self.type15 and key in self.type15[section]:
            return self.type15[section][key]
        raise KeyError(f"Key '{key}' not found in section '{section}'.")



if __name__ == "__main__":
    smbios = SmbiosType15("smbios_type15.ini")  
    smbios.print_type()  