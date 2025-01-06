import res_smbiosConfig


class SmbiosAnalyzer:
    def __init__(self, type15_file:str="smbios_type15.ini"):
        """
        Initialize the analyzer and read the configuration file of type15.
        """
        self.type15 = res_smbiosConfig.SmbiosType15(type15_file)

    def type15_matrix(self, matrix:list)->bool:
        """ Check if it is type 15 """
        return matrix[0][0] == "0F"

    def parse_access_method_address(self, data: bytes, access_method: str)->dict:
        """
        Parse AccessMethodAddress data.
        """
        if len(data) != 4:
            raise ValueError("資料長度必須為 4 個字節")

        if access_method == "IO":
            index_addr = int.from_bytes(data[:2], byteorder="little")
            data_addr = int.from_bytes(data[2:], byteorder="little")
            return {"IndexAddr": hex(index_addr), "DataAddr": hex(data_addr)}

        elif access_method == "PhysicalAddr32":
            physical_addr = int.from_bytes(data, byteorder="little")
            return {"PhysicalAddr32": hex(physical_addr)}

        elif access_method == "GPNVHandle":
            gpnv_handle = int.from_bytes(data[:2], byteorder="little")
            return {"GPNVHandle": hex(gpnv_handle)}

        else:
            raise ValueError("未知的 Access Method: 必須是 'IO', 'PhysicalAddr32' 或 'GPNVHandle'")

    def hex_analyze(self,matrix:list)->list:
        """ analyze hex matrix for type 15"""
        flattened = [item for row in matrix for item in row]
        split_sizes = [1, 1, 2, 2, 2, 2, 1, 1, 4, 4, 1, 1, 1]
        partitions = []
        index = 0

        for size in split_sizes:
            partitions.append(flattened[index:index + size])
            index += size

        # 處理剩餘元素（若有多餘的元素）
        if index < len(flattened):
            partitions.append(flattened[index:])

        # 為每段生成帶有條件判斷的物件
        obj = []
        for i, part in enumerate(partitions):
            
            if i==0 : #type
                if part == ['0F']:
                    obj.append("type:15")
                else:
                    obj.append("type:Unknow")

            elif i==1 : #length
                length = int(part[0] ,16)
                msg = f"Length: {length}"
                obj.append(msg)

            elif i==2 : #handle
                handle = int(part[1]+part[0] ,16)
                msg = f"Handle: {hex(handle)}({handle})"
                obj.append(msg)

            elif i==3 : #Log Area Length 
                word = int(part[1]+part[0],16)
                msg = f"Log Area Length: {word}"
                obj.append(msg)  

            elif i==4 : #Log Header Start Offset
                word = int(part[1]+part[0],16)
                msg = f"Log Header Start Offset: {word}"
                obj.append(msg)  

            elif i==5 : #Log Data Start Offset
                word = int(part[1]+part[0],16)
                msg = f"Log Data Start Offset: {hex(word)}"
                obj.append(msg)

            elif i==6 : #Access Method 
                byte = part[0]
                msg = f"Access Method: {self.type15.get('access_method',byte)}" 
                obj.append(msg)

            elif i==7 : #Log Status
                byte = part[0]
                msg = f"Log Status: {self.type15.get('log_status',byte)}" 
                obj.append(msg)

            elif i == 8:  # Log Change Token
                token = ""  
                s = len(part) - 1  
                while s >= 0:
                    token += part[s] 
                    s -= 1  
                token = int(token, 16) 
                msg = f"Log Change Token: {hex(token)}"  
                obj.append(msg) 

            elif i == 9:  # Access Method Address
                if isinstance(part, list) and all(isinstance(x, str) for x in part):
                    # 將字串轉為整數，並組裝成 bytes
                    part_bytes = bytes(int(x, 16) for x in part)
                else:
                    raise ValueError("part 的類型必須是包含十六進位字串的列表")
                AM_address = self.parse_access_method_address(part_bytes, 'PhysicalAddr32')
                obj.append(f"Access Method Address: {AM_address}")


            elif i==10 : #Log Header Format 
                byte = part[0]
                msg = f"Log Header Format: {self.type15.get('log_header_format',byte)}"
                obj.append(msg)

            elif i==11 : #Number of Supported Log Type Descriptors
                byte = part[0]
                x = int(byte,16)
                msg = f"Number of Supported Log Type Descriptors: {x}"
                obj.append(msg)

            elif i==12 : #Length of each Log Type Descriptor, y
                byte = part[0]
                y = int(byte,16)
                msg = f"Length of each Log Type Descriptor: {y}"
                obj.append(msg)

            elif i==13 : #List of Supported Event Log Type Descriptor
                obj.append("List of Supported Event Log Type Descriptor:")
                if len(part) < (x*y):
                    raise ValueError("輸入數據不足以分組")
                
                for i in range(0, (x*y), y):
                    msg = f"\033[92m System Event Log Type: {self.type15.get("log_types",part[i])} \033[0m"
                    obj.append(msg)
                    msg = f"\033[92m Event Log Variable Data Format Types: {self.type15.get("log_variable_data_format_type",part[i+1])} \033[0m"
                    obj.append(msg)
            else:
                pass

    #print(f"處理的物件: {obj}")
        return obj

if __name__ == "__main__":
    S = SmbiosAnalyzer()
    print(S.hex_analyze())