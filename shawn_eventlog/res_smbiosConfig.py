import configparser


class SmbiosType15:
    def __init__(self, file_path:str="smbios_type15.ini"):
        """
        Reads the specified .ini file and rebuilds the dictionary during initialization.
        """
        self.config = configparser.ConfigParser()
        self.type15 = {}
        self.file_path = file_path
        self.build()  # 在初始化時自動建立字典

    def expanded_keys(self, section_dict:dict)->dict:
        """
        Convert range keys to expanded key-value pairs.
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
        Reads the specified .ini file and rebuilds the dictionary during initialization.
        """
        self.config.optionxform = str  # 保持鍵的大小寫
        with open(self.file_path, "r", encoding="utf-8") as file:
            self.config.read_file(file)

        for section in self.config.sections():
            raw_dict = dict(self.config[section])
            self.type15[section] = self.expanded_keys(raw_dict)

    def print_type(self):
        
        for section, data in self.type15.items():
            print(f"[{section}]")
            for key, value in data.items():
                print(f"{key} = {value}")

    def get(self, section:str, key:str)->str:
        """
        First check whether the built-in get method can be used directly,
        If not found, the reconstructed range key is used to retrieve it.
        """
        if section in self.type15 and key in self.type15[section]:
            return self.type15[section][key]
        raise KeyError(f"Key '{key}' not found in section '{section}'.")



if __name__ == "__main__":
    smbios = SmbiosType15("smbios_type15.ini")  # 指定檔案路徑
    smbios.print_type()  # 測試輸出
