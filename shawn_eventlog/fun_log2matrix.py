import re

class Log2matrix:
    def __init__(self,file_path:str = r"D:\VScode\project\event_log\example\smbios.log"):
        self.file_path = file_path
    def extract_hex_blocks(self)->list:
        """
        The first time the data is processed, 
        if a hexadecimal number is detected, this line will be stored.
        """
        hex_blocks = []
        current_block = []
        block_count = 0  # 記錄區塊編號

        
        hex_line_pattern = re.compile(
            r"^[0-9A-Fa-f]{8}:"
        )
        
        terminate_keyword = "SMBIOS 3.0 (64-bit) Entry Point Structure:"
        with open(self.file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()

                
                if terminate_keyword in line:
                    if current_block:
                        block_count += 1
                        hex_blocks.append(f"Block {block_count}:\n" + "\n".join(current_block))
                    break

                
                if hex_line_pattern.match(line):
                    current_block.append(line)
                else:
                    # 碰到非十六進制行，結束當前塊
                    if current_block:
                        block_count += 1
                        hex_blocks.append(f"Block {block_count}:\n" + "\n".join(current_block))
                        current_block = []

            # 最後再檢查一次
            if current_block:
                block_count += 1
                hex_blocks.append(f"Block {block_count}:\n" + "\n".join(current_block))

        return hex_blocks


    def mk_hex_matrix(self,data:list)->list:
        """
        Process the data for the second time, 
        remove the head and tail and keep only the middle two digits of hexadecimal.
        """
        self.data = data
    # 保留區塊標籤，提取並轉換十六進制數據為矩陣
        block_pattern = re.compile(r"^(Block \d+:)|(?<=: )(.*?)(?= \*)")

        results = []
        current_matrix = []
        current_block = None

        for line in self.data.splitlines():
            match = block_pattern.search(line)
            if match:
                if match.group(1):  # 如果是分區標籤
                    if current_matrix:  # 保存上一個區塊的矩陣
                        results.append((current_block, current_matrix))
                        current_matrix = []
                    current_block = match.group(1)  # 更新區塊標籤
                elif match.group(2):  # 如果是十六進制數據
                    hex_line = match.group(2).replace("-", " ").split()  # 去掉 "-" 並分割
                    current_matrix.append(hex_line)

        # 保存最後一個區塊的矩陣
        if current_matrix:
            results.append((current_block, current_matrix))

        return results
    def log2matrix(self):
        
        hex_blocks = self.extract_hex_blocks()

        
        hex_blocks_combined = "\n".join(hex_blocks)

        
        processed_blocks = self.mk_hex_matrix(hex_blocks_combined)

        if processed_blocks:
            print("Extracted Hex Blocks as Matrices:")
            for block_label, matrix in processed_blocks:
                print(f"\n{block_label}")
                for row in matrix:
                    print(row)
        else:
            print("No hex blocks found!")

##========================================
#test function
if __name__ == "__main__":
    l=Log2matrix()
    l.log2matrix()