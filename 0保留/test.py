import re
import res_smbiosConfig

type15 = res_smbiosConfig.SmbiosType15()


def extract_hex_blocks(file_path):
    """ 從檔案提取十六進位區塊 """
    hex_blocks = []
    current_block = []
    block_count = 0
    hex_line_pattern = re.compile(r"^[0-9A-Fa-f]{8}:")
    terminate_keyword = "SMBIOS 3.0 (64-bit) Entry Point Structure:"
    pass_line = "Formatted Area:"

    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()

            if pass_line in line:
                next(file)  # 跳過下一行
                continue

            if terminate_keyword in line:
                if current_block:
                    block_count += 1
                    hex_blocks.append(f"Block {block_count}:\n" + "\n".join(current_block))
                break

            if hex_line_pattern.match(line):
                current_block.append(line)
            else:
                if current_block:
                    block_count += 1
                    hex_blocks.append(f"Block {block_count}:\n" + "\n".join(current_block))
                    current_block = []

        if current_block:
            block_count += 1
            hex_blocks.append(f"Block {block_count}:\n" + "\n".join(current_block))

    return hex_blocks


def mk_hex_matrix(data):
    """ 將區塊轉為矩陣 """
    block_pattern = re.compile(r"^(Block \d+:)|(?<=: )(.*?)(?= \*)")
    results = []
    current_matrix = []
    current_block = None

    for line in data.splitlines():
        match = block_pattern.search(line)
        if match:
            if match.group(1):  # 區塊標籤
                if current_matrix:
                    results.append((current_block, current_matrix))
                    current_matrix = []
                current_block = match.group(1)
            elif match.group(2):  # 十六進位數據
                hex_line = match.group(2).replace("-", " ").split()
                current_matrix.append(hex_line)

    if current_matrix:
        results.append((current_block, current_matrix))

    return results


def parse_access_method_address(data: bytes, access_method: str):
    """
    解析 AccessMethodAddress 資料。

    :param data: 4 字節的二進位數據 (bytes)，例如 b'\x00\x00\x00\x00'
    :param access_method: 指定解析方法，值為 'IO', 'PhysicalAddr32', 或 'GPNVHandle'
    :return: 解析後的結果
    """
    if len(data) != 4:
        raise ValueError("資料長度必須為 4 個字節")

    if access_method == "IO":
        index_addr = int.from_bytes(data[:2], byteorder='little')
        data_addr = int.from_bytes(data[2:], byteorder='little')
        return {"IndexAddr": hex(index_addr), "DataAddr": hex(data_addr)}

    elif access_method == "PhysicalAddr32":
        physical_addr = int.from_bytes(data, byteorder='little')
        return {"PhysicalAddr32": hex(physical_addr)}

    elif access_method == "GPNVHandle":
        gpnv_handle = int.from_bytes(data[:2], byteorder='little')
        return {"GPNVHandle": hex(gpnv_handle)}

    else:
        raise ValueError("未知的 Access Method: 必須是 'IO', 'PhysicalAddr32' 或 'GPNVHandle'")


def type15_matrix(matrix):
    """ 檢測是否為 type 15 """
    return matrix[0][0] == "0F"


def hex_analyze(matrix):
    """ 分析十六進位矩陣 """
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
            msg = f"Access Method: {type15.get('access_method',byte)}" 
            obj.append(msg)

        elif i==7 : #Log Status
            byte = part[0]
            msg = f"Log Status: {type15.get('log_status',byte)}" 
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
            AM_address = parse_access_method_address(part_bytes, 'PhysicalAddr32')
            obj.append(f"Access Method Address: {AM_address}")


        elif i==10 : #Log Header Format 
            byte = part[0]
            msg = f"Log Header Format: {type15.get('log_header_format',byte)}"
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
                msg = f"\033[92mSystem Event Log Type: {type15.get("log_types",part[i])}\033[0m"
                obj.append(msg)
                msg = f"\033[92mEvent Log Variable Data Format Types: {type15.get("log_variable_data_format_type",part[i+1])}\033[0m"
                obj.append(msg)
        else:
            pass

    #print(f"處理的物件: {obj}")
    return obj


def log2matrix():
    file_path = r"D:\VScode\project\event_log\example\smbios.log"
    hex_blocks = extract_hex_blocks(file_path)
    hex_blocks_combined = "\n".join(hex_blocks)
    processed_blocks = mk_hex_matrix(hex_blocks_combined)

    if processed_blocks:
        print("Extracted Hex Blocks as Matrices:")
        T_F_valu = 0
        for block_label, matrix in processed_blocks:
            #print(f"\n{block_label}")
            # 處理矩陣
            
            detection_results = type15_matrix(matrix)
            
            event = []
            if detection_results:
                event = hex_analyze(matrix)
            else:
                T_F_valu += 1
                
            for i in event:
                print(f"\n{i}")

        print(f"\n\n\n\033[31mnone type 15: {T_F_valu}\033[0m\n\n\n")
        #print(rainbow_text(f"\n\n\nnone type 15: {T_F_valu}\n\n\n"))
    else:
        print("No hex blocks found!")

def rainbow_text(text):
    colors = [
        "\033[91m",  # 紅色
        "\033[93m",  # 黃色
        "\033[92m",  # 綠色
        "\033[94m",  # 藍色
        "\033[95m",  # 紫色
        "\033[96m",  # 青色
    ]
    reset = "\033[0m"  # 重置顏色
    colored_text = ""
    for i, char in enumerate(text):
        colored_text += colors[i % len(colors)] + char
    return colored_text + reset

# 呼叫主函式
log2matrix()
